#!/usr/bin/env python3
"""Run the real controller -> gateway-agent -> patched dae management path.

This review fixture deliberately stops at the native management boundary. It
does not attach eBPF, send proxy traffic, or claim OPNsense qualification. The
controller, gateway-agent, NativeEngine, Unix control server, and browser are
the implementations under test; no fake publisher is installed.
"""

from __future__ import annotations

import argparse
from contextlib import nullcontext
import base64
import hashlib
import hmac
import http.client
import http.cookiejar
import http.server
import json
import os
import platform
from pathlib import Path
import secrets
import signal
import socket
import socketserver
import ssl
import subprocess
import tempfile
import time
import threading
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "engine/dae/fixtures"
DEFAULT_DAE = Path("/mnt/vibe-coding-share/test/egressdeck-dae-r05")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def run(command, *, cwd=None, env=None, timeout=300, receipt=None):
    if receipt is not None:
        receipt.append({"cwd": str(cwd or Path.cwd()), "argv": [str(x) for x in command]})
    return subprocess.run(command, cwd=cwd, env=env, check=True, timeout=timeout,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def certs(directory: Path) -> dict[str, Path]:
    """Create a private CA and localhost server/client identities."""
    ca = directory / "ca.pem"
    ca_key = directory / "ca.key"
    server = directory / "server.pem"
    server_key = directory / "server.key"
    client = directory / "client.pem"
    client_key = directory / "client.key"
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=EgressDeck review CA", "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", str(ca_key), "-out", str(ca)], timeout=30)
    for name, key, cert, subj, ext in [
        ("server", server_key, server, "/CN=localhost", "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1"),
        ("client", client_key, client, "/CN=EgressDeck review controller", "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth"),
    ]:
        csr = directory / (name + ".csr")
        extfile = directory / (name + ".ext")
        extfile.write_text(ext + "\n", encoding="utf-8")
        run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", subj,
             "-keyout", str(key), "-out", str(csr)], timeout=30)
        run(["openssl", "x509", "-req", "-days", "1", "-CA", str(ca), "-CAkey", str(ca_key),
             "-CAcreateserial", "-in", str(csr), "-out", str(cert), "-extfile", str(extfile)], timeout=30)
        key.chmod(0o600)
    return {"ca": ca, "server": server, "server_key": server_key, "client": client, "client_key": client_key}


class Controller:
    def __init__(self, endpoint: str, identity_key: str):
        self.endpoint = endpoint.rstrip("/")
        self.identity_key = identity_key
        self.subject = "native-cross-layer-review"
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.private = [identity_key]

    def request(self, path, method="GET", payload=None, expected=None, extra=None):
        headers = dict(extra or {})
        if payload is not None:
            headers["Content-Type"] = "application/json"
        if method != "GET":
            for cookie in self.jar:
                if cookie.name == "egressdeck_csrf":
                    headers["X-CSRF-Token"] = cookie.value
        data = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(self.endpoint + path, data=data, method=method, headers=headers)
        try:
            response = self.opener.open(request, timeout=20)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read()
            if expected is not None and response.status != expected:
                raise RuntimeError(f"{method} {path}: HTTP {response.status}, expected {expected}: {raw[:400]!r}")
            if response.headers.get("Content-Type", "").startswith("application/json"):
                return response.status, json.loads(raw)
            return response.status, raw

    def login(self):
        signature = hmac.new(self.identity_key.encode(), (self.subject + "\0admin").encode(), hashlib.sha256).digest()
        encoded = base64.urlsafe_b64encode(signature).decode().rstrip("=")
        self.private.append(encoded)
        self.request("/api/v1/auth/login", "POST", expected=201, extra={
            "X-Auth-Request-User": self.subject,
            "X-Auth-Request-Role": "admin",
            "X-Auth-Request-Signature": encoded,
        })

    def get(self, path):
        return self.request(path, expected=200)[1]

    def mutate(self, path, payload, expected, **kwargs):
        return self.request(path, "POST", payload, expected, kwargs)[1]


def wait_http(controller: Controller, path="/readyz", timeout=40):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            controller.request(path, expected=200)
            return
        except (OSError, urllib.error.URLError, RuntimeError):
            time.sleep(0.15)
    raise RuntimeError("controller did not become ready")


def stop(process):
    if process is None or process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


class UnixFaultProxy:
    """Forward actual Unix HTTP; only hold/drop requests at chosen boundaries."""

    def __init__(self, path: Path, target: Path):
        self.mode = None
        self.hit = threading.Event()
        self.release = threading.Event()
        self.lock = threading.Lock()
        self.selection_operations = []
        owner = self

        class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
            daemon_threads = True

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_):
                pass

            def do_GET(self):
                self.forward()

            def do_POST(self):
                self.forward()

            def do_PUT(self):
                self.forward()

            def forward(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                fault = None
                if self.command == "POST" and self.path == "/v1/selection":
                    with owner.lock:
                        owner.selection_operations.append(json.loads(body).get("operation_id"))
                        fault, owner.mode = owner.mode, None
                if fault == "before_send":
                    owner.hit.set()
                    owner.release.wait(30)
                    self.close_connection = True
                    return
                connection = http.client.HTTPConnection("localhost", timeout=30)
                connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                connection.sock.connect(str(target))
                try:
                    headers = {key: value for key, value in self.headers.items() if key.lower() not in {"host", "connection"}}
                    connection.request(self.command, self.path, body=body, headers=headers)
                    response = connection.getresponse()
                    data = response.read()
                    if fault == "after_commit":
                        if response.status != 200:
                            raise RuntimeError("fault fixture expected a committed native selection")
                        owner.hit.set()
                        owner.release.wait(30)
                        self.close_connection = True
                        return
                    self.send_response(response.status)
                    for key, value in response.getheaders():
                        if key.lower() not in {"connection", "content-length", "transfer-encoding", "date", "server"}:
                            self.send_header(key, value)
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except (OSError, http.client.HTTPException):
                    self.close_connection = True
                finally:
                    connection.close()

        self.server = Server(str(path), Handler)
        path.chmod(0o600)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def arm(self, mode):
        self.hit.clear()
        self.release.clear()
        with self.lock:
            self.mode = mode

    def close(self):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def group_payload(group, node_ids):
    return {"id": group["id"], "name": group["name"], "gateway_id": group["gateway_id"],
            "node_ids": node_ids, "mode": "manual", "replacement_policy": "block"}


def assert_group(group, candidates):
    if group.get("applied_revision") != group["revision"] or group.get("observed_revision") != group["revision"]:
        raise RuntimeError("group configuration did not converge on desired revision")
    for field in ("node_ids", "applied_node_ids", "observed_node_ids"):
        if set(group.get(field, [])) != set(candidates):
            raise RuntimeError("group candidate readback mismatch: " + field)


def select(api, group_id, gateway_id, node_id, key, expected=202):
    selections = api.get(f"/api/v1/outbound-groups/{group_id}/selection")["items"]
    revisions = {transport: next((row["revision"] for row in selections if row["scope"]["transport"] == transport), 0) for transport in ("tcp", "udp")}
    return api.request(f"/api/v1/outbound-groups/{group_id}/selection", "PUT", {
        "gateway_id": gateway_id, "node_id": node_id, "transport_scopes": ["tcp", "udp"], "expected_revisions": revisions,
    }, expected=expected, extra={"If-Match": str(revisions["tcp"]), "Idempotency-Key": key})[1]


def assert_selected(api, group_id, node_id):
    selections = api.get(f"/api/v1/outbound-groups/{group_id}/selection")["items"]
    if {row["scope"]["transport"] for row in selections} != {"tcp", "udp"}:
        raise RuntimeError("selection readback does not include both TCP and UDP")
    for row in selections:
        if any(row.get(field) != node_id for field in ("desired_node_id", "applied_node_id", "observed_node_id")):
            raise RuntimeError("shared selection failed to converge")
    return selections


def source_hashes(source: Path, manifest: Path) -> dict[str, str]:
    pinned = json.loads(manifest.read_text(encoding="utf-8"))
    got = {}
    base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    if base != pinned["base_commit"]:
        raise RuntimeError("dae source HEAD differs from source-manifest.json")
    for entry in pinned["files"]:
        path = source / entry["path"]
        if sha256(path) != entry["sha256"] or path.stat().st_size != entry["bytes"]:
            raise RuntimeError("dae source differs from manifest: " + entry["path"])
        got[entry["path"]] = entry["sha256"]
    for entry in pinned["patches"]:
        path = manifest.parent / entry["path"]
        if sha256(path) != entry["sha256"]:
            raise RuntimeError("exported dae patch differs from manifest")
    for path in (source / "control/bpf_bpfel.go", source / "control/bpf_bpfel.o"):
        got[str(path.relative_to(source))] = sha256(path)
    for path in source.rglob("*.go"):
        if path.is_file():
            got[str(path.relative_to(source))] = sha256(path)
    for path in (source / "go.mod", source / "go.sum"):
        got[str(path.relative_to(source))] = sha256(path)
    return got


def repo_hashes():
    paths = [path for name in ("cmd", "internal", "migrations", "apps/web/src", "apps/web/dist", "tests/integration") for path in (ROOT / name).rglob("*") if path.is_file() and "__pycache__" not in path.parts and "artifacts" not in path.parts]
    paths += [ROOT / name for name in ("go.mod", "go.sum", "apps/web/package.json", "apps/web/package-lock.json", "engine/dae/source-manifest.json", "engine/dae/patches/0001-native-hot-provider-runtime.patch") if (ROOT / name).is_file()]
    paths += [path for path in FIXTURE.iterdir() if path.is_file()]
    return {str(path.relative_to(ROOT)): sha256(path) for path in sorted(paths)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dae-source", type=Path, default=DEFAULT_DAE)
    parser.add_argument("--go", type=Path, default=Path("/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.0.linux-amd64/bin/go"))
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--browser", action="store_true", help="run the Playwright shared-selection assertion")
    parser.add_argument("--browser-channel", default=os.environ.get("PLAYWRIGHT_CHANNEL", ""))
    args = parser.parse_args()
    source = args.dae_source.resolve()
    go = args.go.resolve()
    if not source.is_dir() or not go.is_file():
        raise SystemExit("--dae-source and --go must identify existing paths")
    receipt = {"status": "FAIL", "scope": "real controller -> mTLS gateway-agent -> NativeEngine -> patched dae Unix control plane; no eBPF or traffic qualification", "host": platform.node(), "started_at": datetime.now(timezone.utc).isoformat(), "commands": [], "source_sha256": {}, "passed": False}
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    processes = []
    installed = []
    logs = []
    proxy = None
    temporary = None
    try:
        receipt["source_sha256"] = source_hashes(source, ROOT / "engine/dae/source-manifest.json")
        receipt["source_manifest_sha256"] = sha256(ROOT / "engine/dae/source-manifest.json")
        receipt["source_base_commit"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
        receipt["repository_base_commit"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        receipt["repository_dirty_paths"] = subprocess.check_output(["git", "status", "--porcelain=v1"], cwd=ROOT, text=True).splitlines()
        run(["npm", "--prefix", "apps/web", "run", "build"], cwd=ROOT, receipt=receipt["commands"], timeout=180)
        receipt["repository_sha256"] = repo_hashes()
        temporary = tempfile.TemporaryDirectory(prefix="egressdeck-review-", dir="/tmp")
        with nullcontext(temporary.name) as tmp_name:
            tmp = Path(tmp_name)
            (tmp / "gotmp").mkdir(mode=0o700)
            env = dict(os.environ, EGRESSDECK_NATIVE_HARNESS_DIR=str(tmp), DAE_HOT_STATE_KEY=secrets.token_hex(32), TMPDIR="/tmp", GOTMPDIR=str(tmp / "gotmp"))
            def start(name, command, cwd, process_env):
                log_path = tmp / f"{name}-{len(logs)}.log"
                log = log_path.open("w+")
                logs.append((name, log))
                receipt["commands"].append({"cwd": str(cwd), "argv": command, "process": name})
                process = subprocess.Popen(command, cwd=cwd, env=process_env, stdout=log, stderr=subprocess.STDOUT)
                processes.append(process)
                return process
            helpers = {source / "control/egressdeck_hot_harness.go": FIXTURE / "control_harness.go.tmpl", source / "cmd/egressdeck_hot_harness_test.go": FIXTURE / "cmd_harness_test.go.tmpl"}
            for destination, template in helpers.items():
                with destination.open("xb") as output:
                    output.write(template.read_bytes())
                installed.append(destination)
            daemon_binary = tmp / "dae-harness.test"
            run([str(go), "test", "-c", "-tags=egressdeck_hot_harness", "-o", str(daemon_binary), "./cmd"], cwd=source, env=env, receipt=receipt["commands"], timeout=360)
            controller_binary = tmp / "controller"
            agent_binary = tmp / "gateway-agent"
            run([str(go), "build", "-o", str(controller_binary), "./cmd/controller"], cwd=ROOT, env=env, receipt=receipt["commands"], timeout=180)
            run([str(go), "build", "-o", str(agent_binary), "./cmd/gateway-agent"], cwd=ROOT, env=env, receipt=receipt["commands"], timeout=180)
            receipt["binary_sha256"] = {"controller": sha256(controller_binary), "gateway-agent": sha256(agent_binary), "dae-source-harness": sha256(daemon_binary)}
            (tmp / "certs").mkdir(mode=0o700)
            paths = certs(tmp / "certs")
            daemon_command = [str(daemon_binary), "-test.run=^TestEgressDeckNativeSourceHarness$", "-test.v", "-test.timeout=150s"]
            daemon = start("daemon", daemon_command, source, env)
            deadline = time.monotonic() + 30
            while not (tmp / "ready").exists():
                if daemon.poll() is not None:
                    raise RuntimeError("dae harness exited before ready")
                if time.monotonic() > deadline:
                    raise RuntimeError("dae harness did not become ready")
                time.sleep(0.1)
            proxy = UnixFaultProxy(tmp / "native-proxy.sock", tmp / "control.sock")
            token = secrets.token_urlsafe(32)
            native_key = base64.b64encode(secrets.token_bytes(32)).decode()
            agent_env = dict(env, GATEWAY_AGENT_NATIVE_ENCRYPTION_KEY=native_key, GATEWAY_AGENT_TOKEN=token)
            agent_port = free_port()
            agent_command = [str(agent_binary), "-engine=native", "-native-socket", str(tmp / "native-proxy.sock"), "-listen", f"127.0.0.1:{agent_port}", "-tls-cert", str(paths["server"]), "-tls-key", str(paths["server_key"]), "-client-ca", str(paths["ca"]), "-journal", str(tmp / "agent.jsonl")]
            agent = start("agent", agent_command, ROOT, agent_env)
            endpoint = f"https://127.0.0.1:{agent_port}"
            tls = ssl.create_default_context(cafile=str(paths["ca"]))
            tls.load_cert_chain(str(paths["client"]), str(paths["client_key"]))
            gateway_opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=tls))
            def gateway_inventory():
                request = urllib.request.Request(endpoint + "/v1/readback", headers={"Authorization": "Bearer " + token})
                with gateway_opener.open(request, timeout=15) as response:
                    return json.load(response)
            deadline = time.monotonic() + 20
            while True:
                try:
                    gateway_inventory()
                    break
                except (OSError, urllib.error.URLError):
                    if time.monotonic() > deadline:
                        raise RuntimeError("native gateway did not become ready")
                    time.sleep(0.1)
            group_id = "review-group"
            gateway_id = "review-gateway"
            gateway_config = tmp / "gateways.json"
            gateway_config.write_text(json.dumps({"gateways": [{"id": gateway_id, "endpoint": endpoint, "token": token, "client_cert": str(paths["client"]), "client_key": str(paths["client_key"]), "ca_file": str(paths["ca"]), "runtime": {"enable_provider_publish": True, "enable_selection": True, "expected_implementation": "dae-native-unix", "shared_transport_selection": True, "groups": {group_id: {"name": "egress-a"}}}}]}, indent=2), encoding="utf-8")
            gateway_config.chmod(0o600)
            identity_key = secrets.token_hex(32)
            controller_port = free_port()
            storage = tmp / "controller.json"
            controller_env = dict(env, AUTH_MODE="header", COOKIE_SECURE="false", SESSION_SECRET=secrets.token_hex(32), IDENTITY_HEADER_SECRET=identity_key, APP_ENCRYPTION_KEY=base64.b64encode(secrets.token_bytes(32)).decode(), STORAGE_PATH=str(storage), OPERATION_JOURNAL_PATH=str(tmp / "operations.json"), CONTROLLER_GATEWAYS_FILE=str(gateway_config), STATIC_DIR=str(ROOT / "apps/web/dist"), LISTEN_ADDR=f"127.0.0.1:{controller_port}")
            controller = start("controller", [str(controller_binary)], ROOT, controller_env)
            api = Controller(f"http://127.0.0.1:{controller_port}", identity_key)
            wait_http(api)
            api.login()
            api.request("/api/v1/gateways", "POST", {"id": gateway_id, "name": "Native review gateway", "endpoint": endpoint, "adapter": "dae"}, expected=201)
            api.request("/api/v1/providers", "POST", {"id": "review-provider", "name": "Native review provider", "source": "inline", "format": "local"}, expected=201)
            stage = api.request("/api/v1/providers/review-provider/stage", "POST", {"content": "socks5://source-user:source-private-password@127.0.0.1:19281#Review-A\nsocks5://source-user:source-private-password@127.0.0.1:19282#Review-B", "format": "links"}, expected=202, extra={"Idempotency-Key": "native-review-stage"})[1]
            nodes = stage["revision"]["nodes"]
            if len(nodes) != 2:
                raise RuntimeError("review provider did not produce two nodes")
            receipt["node_ids"] = [node["id"] for node in nodes]
            # Initial native selection must be known before the first provider publication.
            stop(controller)
            config = json.loads(gateway_config.read_text(encoding="utf-8"))
            config["gateways"][0]["runtime"]["groups"][group_id]["initial_node_id"] = nodes[0]["id"]
            gateway_config.write_text(json.dumps(config, indent=2), encoding="utf-8")
            controller = start("controller", [str(controller_binary)], ROOT, controller_env)
            api = Controller(f"http://127.0.0.1:{controller_port}", identity_key)
            wait_http(api)
            api.login()
            api.request("/api/v1/outbound-groups", "POST", {"id": group_id, "name": "Native review group", "gateway_id": gateway_id, "node_ids": [node["id"] for node in nodes], "mode": "manual", "replacement_policy": "block"}, expected=201)
            apply = api.request("/api/v1/providers/review-provider/revisions/1/apply", "POST", {}, expected=202, extra={"If-Match": '"0"', "Idempotency-Key": "native-review-provider-apply"})[1]
            if apply.get("status") != "applied":
                raise RuntimeError("provider publication was not applied: " + json.dumps(apply)[:400])
            group = api.get(f"/api/v1/outbound-groups/{group_id}")
            if group.get("selection_scope") != "shared_tcp_udp":
                raise RuntimeError("native shared selection capability was not exposed")
            assert_group(group, [node["id"] for node in nodes])
            first_selection = select(api, group_id, gateway_id, nodes[0]["id"], "native-review-initial-selection")
            if first_selection.get("status") != "applied":
                raise RuntimeError("initial shared selection did not apply")
            initial_selections = assert_selected(api, group_id, nodes[0]["id"])
            provider_before = api.get("/api/v1/providers/review-provider/revisions")
            native_before = gateway_inventory()
            # Independent group lifecycle: remove B, apply, restore B, apply, without changing provider content.
            revision = group["revision"]
            edit_payload = group_payload(group, [nodes[0]["id"]])
            api.request(f"/api/v1/outbound-groups/{group_id}", "PATCH", edit_payload, expected=200, extra={"If-Match": f'"{revision}"'})
            removed = api.get(f"/api/v1/outbound-groups/{group_id}")
            operations_before_rejection = api.get("/api/v1/operations")["items"]
            rejected = select(api, group_id, gateway_id, nodes[0]["id"], "native-review-unapplied-rejected", expected=409)
            if rejected.get("error", {}).get("code") != "group_configuration_not_applied":
                raise RuntimeError("unapplied group was not rejected with its specific preflight result")
            if api.get("/api/v1/operations")["items"] != operations_before_rejection:
                raise RuntimeError("definite group preflight rejection created an operation")
            if api.get(f"/api/v1/outbound-groups/{group_id}/selection")["items"] != initial_selections:
                raise RuntimeError("definite group preflight rejection changed selection intent")
            remove_apply = api.request(f"/api/v1/outbound-groups/{group_id}/apply", "POST", {}, expected=202, extra={"If-Match": f'"{removed["revision"]}"', "Idempotency-Key": "native-review-group-remove"})[1]
            if remove_apply.get("status") != "applied":
                raise RuntimeError("candidate removal did not apply")
            removed = api.get(f"/api/v1/outbound-groups/{group_id}")
            assert_group(removed, [nodes[0]["id"]])
            select_after_apply = select(api, group_id, gateway_id, nodes[0]["id"], "native-review-select-after-group-apply")
            if select_after_apply.get("status") != "applied":
                raise RuntimeError("selection failed after independent group deployment")
            assert_selected(api, group_id, nodes[0]["id"])
            native_removed = gateway_inventory()
            if native_removed["providers"]["review-provider"]["revision"] != native_before["providers"]["review-provider"]["revision"]:
                raise RuntimeError("group deployment changed provider connection revision")
            if native_removed["groups"][group_id]["node_ids"] != [nodes[0]["id"]]:
                raise RuntimeError("native group did not remove B")
            restored_payload = group_payload(removed, [node["id"] for node in nodes])
            restored = api.request(f"/api/v1/outbound-groups/{group_id}", "PATCH", restored_payload, expected=200, extra={"If-Match": f'"{removed["revision"]}"'})[1]
            group_apply = api.request(f"/api/v1/outbound-groups/{group_id}/apply", "POST", {}, expected=202, extra={"If-Match": f'"{restored["revision"]}"', "Idempotency-Key": "native-review-group-restore"})[1]
            if group_apply.get("status") != "applied":
                raise RuntimeError("group publication was not applied: " + json.dumps(group_apply)[:400])
            restored = api.get(f"/api/v1/outbound-groups/{group_id}")
            assert_group(restored, [node["id"] for node in nodes])
            if api.get("/api/v1/providers/review-provider/revisions") != provider_before:
                raise RuntimeError("independent group deployment mutated provider inventory")
            receipt["group_lifecycle"] = {"initial_revision": revision, "removed_revision": removed["revision"], "restored_revision": restored["revision"], "provider_revision_unchanged": True}
            browser_result = None
            if args.browser:
                fixture = {"endpoint": f"http://127.0.0.1:{controller_port}", "group_id": group_id, "target_node_id": nodes[1]["id"], "target_node_name": nodes[1]["name"], "identity_key": identity_key, "screenshot_path": str(ROOT / "tests/integration/artifacts/native-shared-selection.png")}
                receipt["commands"].append({"cwd": str(ROOT), "argv": ["node", str(ROOT / "tests/integration/review_native_browser.mjs")], "fixture_transport": "private stdin", "browser_channel": args.browser_channel})
                proc = subprocess.run(["node", str(ROOT / "tests/integration/review_native_browser.mjs")], cwd=ROOT, env=dict(env, PLAYWRIGHT_CHANNEL=args.browser_channel), input=json.dumps(fixture), text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
                if proc.returncode != 0:
                    raise RuntimeError("browser regression failed: " + proc.stdout[-4000:])
                browser_result = json.loads(proc.stdout.strip().splitlines()[-1])
                receipt["browser"] = browser_result
            else:
                receipt["browser"] = {"status": "SKIPPED", "reason": "pass --browser to run actual Playwright against the real controller"}
                select(api, group_id, gateway_id, nodes[1]["id"], "native-review-nonbrowser-selection")
            assert_selected(api, group_id, nodes[1]["id"])
            receipt["recovery"] = []
            for fault, target_node in (("before_send", nodes[0]["id"]), ("after_commit", nodes[1]["id"])):
                before = gateway_inventory()
                request_count = len(proxy.selection_operations)
                proxy.arm(fault)
                with ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(select, api, group_id, gateway_id, target_node, "native-review-fault-" + fault)
                    if not proxy.hit.wait(20):
                        proxy.release.set()
                        raise RuntimeError("selection did not reach injected native " + fault + " boundary")
                    agent.kill()
                    agent.wait(timeout=10)
                    proxy.release.set()
                    pending = future.result(timeout=25)
                if pending.get("status") != "outcome_unknown":
                    raise RuntimeError("gateway crash did not preserve unknown controller intent")
                operation_id = pending["operation_id"]
                agent = start("agent", agent_command, ROOT, agent_env)
                stop(controller)
                controller = start("controller", [str(controller_binary)], ROOT, controller_env)
                wait_http(api)
                api.login()
                deadline = time.monotonic() + 40
                while True:
                    operation = api.get("/api/v1/operations/" + operation_id)
                    if operation.get("status") == "applied":
                        break
                    if operation.get("status") == "failed" or time.monotonic() > deadline:
                        raise RuntimeError("native " + fault + " did not reach bounded applied recovery: " + json.dumps(operation)[:500])
                    time.sleep(0.2)
                assert_selected(api, group_id, target_node)
                after = gateway_inventory()
                if after["generation"] != before["generation"] + 1:
                    raise RuntimeError("native recovery repeated or lost a commit")
                native_operations = proxy.selection_operations[request_count:]
                if not native_operations or not native_operations[0] or len(set(native_operations)) != 1:
                    raise RuntimeError("native recovery did not retain the original daemon operation ID")
                if fault == "before_send" and len(native_operations) < 2:
                    raise RuntimeError("pre-send recovery did not resend the durable original operation")
                if fault == "after_commit" and len(native_operations) != 1:
                    raise RuntimeError("committed operation was sent again instead of resolving status")
                receipt["recovery"].append({"boundary": fault, "operation_id": operation_id, "native_operation_id": native_operations[0], "native_dispatches_seen": len(native_operations), "controller_status": operation["status"], "before_generation": before["generation"], "after_generation": after["generation"], "agent_killed": True, "controller_restarted": True})
            # Both daemon and adapter must reconstruct state from encrypted journals.
            before_restart = gateway_inventory()
            stop(controller)
            stop(agent)
            (tmp / "stop").touch(mode=0o600)
            if daemon.wait(timeout=10) != 0:
                raise RuntimeError("daemon did not stop cleanly before restart")
            (tmp / "ready").unlink(missing_ok=True)
            (tmp / "stop").unlink(missing_ok=True)
            daemon = start("daemon", daemon_command, source, env)
            deadline = time.monotonic() + 20
            while not (tmp / "ready").exists():
                if daemon.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("daemon failed journal recovery")
                time.sleep(0.1)
            agent = start("agent", agent_command, ROOT, agent_env)
            controller = start("controller", [str(controller_binary)], ROOT, controller_env)
            wait_http(api)
            api.login()
            restored_inventory = gateway_inventory()
            if restored_inventory["generation"] != before_restart["generation"]:
                raise RuntimeError("journal restart changed the committed generation")
            for field in ("providers", "groups"):
                if restored_inventory[field] != before_restart[field]:
                    raise RuntimeError("native journal restart changed committed " + field)
            def stable_selections(snapshot):
                return {key: {field: row.get(field) for field in ("scope", "desired_node_id", "observed_node_id", "revision")} for key, row in snapshot["selections"].items()}
            if stable_selections(restored_inventory) != stable_selections(before_restart):
                raise RuntimeError("native journal restart changed committed selections")
            assert_group(api.get(f"/api/v1/outbound-groups/{group_id}"), [node["id"] for node in nodes])
            assert_selected(api, group_id, nodes[1]["id"])
            receipt["process_restart"] = {"controller": True, "agent": True, "dae": True, "generation": restored_inventory["generation"]}
            for path in (storage, tmp / "operations.json", tmp / "agent.jsonl", tmp / "state/inventory.json"):
                if b"source-private-password" in path.read_bytes() or b"socks5://" in path.read_bytes():
                    raise RuntimeError("private node link leaked to persisted state")
            receipt["encrypted_persistence"] = True
            final_repository = repo_hashes()
            if final_repository != receipt["repository_sha256"]:
                changed = sorted(name for name in set(final_repository) | set(receipt["repository_sha256"]) if final_repository.get(name) != receipt["repository_sha256"].get(name))
                raise RuntimeError("repository source changed while the cross-layer fixture ran: " + ", ".join(changed))
            for name, expected in receipt["source_sha256"].items():
                if sha256(source / name) != expected:
                    raise RuntimeError("dae source changed during cross-layer run: " + name)
            receipt["http_scenarios"] = ["signed login and CSRF", "real provider staging and publication", "native shared TCP/UDP selection", "group preflight rejects without changing operations or selections", "independent group removal and restoration without provider revision change", "selection after independent group apply", "agent crash before send reconciles original operation", "lost acknowledgement after commit reconciles original operation", "daemon agent and controller process restart"]
            if args.browser:
                receipt["artifact_sha256"] = {"native-shared-selection.png": sha256(Path(receipt["browser"]["screenshot_path"]))}
            receipt["status"] = "PASS"
            receipt["passed"] = True
            receipt["runtime"] = {"controller": "real cmd/controller", "gateway_agent": "real cmd/gateway-agent -engine=native", "daemon": "patched dae source harness", "browser": bool(args.browser)}
    except Exception as error:
        message = str(error)
        for secret in (locals().get("token"), locals().get("native_key"), locals().get("identity_key"), "source-private-password"):
            if secret:
                message = message.replace(secret, "[redacted]")
        receipt["error"] = message[:4000]
        raise
    finally:
        if proxy is not None:
            proxy.close()
        for process in reversed(processes):
            stop(process)
        receipt["process_logs"] = []
        for name, log in logs:
            log.seek(0)
            output = log.read()
            for secret in (locals().get("token"), locals().get("native_key"), locals().get("identity_key"), "source-private-password"):
                if secret:
                    output = output.replace(secret, "[redacted]")
            receipt["process_logs"].append({"process": name, "output": output[-3000:]})
            log.close()
        for destination in installed:
            if destination.exists() and destination.read_bytes() == helpers[destination].read_bytes():
                destination.unlink()
        if temporary is not None:
            temporary.cleanup()
        receipt["finished_at"] = datetime.now(timezone.utc).isoformat()
        args.receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("Receipt: " + str(args.receipt))


if __name__ == "__main__":
    main()
