#!/usr/bin/env python3
"""Run NativeEngine against the actual patched dae HTTP and control-plane code.

Requires a disposable patched source tree with its normal generated BPF objects.
The two build-tagged helpers are installed temporarily; neither opens ingress nor
attaches BPF. Both compiled test processes run on this host and share /tmp sockets.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import subprocess
import tempfile
import time


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dae-source", required=True, type=Path)
    parser.add_argument("--go", default="/usr/local/go/bin/go", type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    fixture = Path(__file__).resolve().parent
    repo = fixture.parents[2]
    source = args.dae_source.resolve()
    go = args.go.resolve()
    if not go.is_absolute() or not go.is_file():
        parser.error("--go must identify an installed Go executable on this host")
    helpers = {
        source / "control/egressdeck_hot_harness.go": fixture / "control_harness.go.tmpl",
        source / "cmd/egressdeck_hot_harness_test.go": fixture / "cmd_harness_test.go.tmpl",
    }
    installed = []
    receipt = {
        "scope": "actual native adapter, Unix HTTP handlers, native dialer construction, publication, selection and encrypted process restart; no kernel attachment or traffic qualification",
        "host": platform.node(),
        "dae_source": str(source),
        "source_sha256": {},
        "commands": [],
        "passed": False,
    }
    # A failed preflight must not leave a successful receipt from an older run.
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    # Bind the same source bytes recorded by the engine patch exporter.
    manifest = repo / "engine/dae/source-manifest.json"
    receipt["source_manifest_sha256"] = digest(manifest)
    pinned = json.loads(manifest.read_text())
    receipt["base_commit"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    if receipt["base_commit"] != pinned["base_commit"]:
        raise RuntimeError("dae source HEAD differs from pinned base")
    for entry in pinned["files"]:
        path = source / entry["path"]
        if digest(path) != entry["sha256"] or path.stat().st_size != entry["bytes"]:
            raise RuntimeError("dae source differs from manifest: " + entry["path"])
        receipt["source_sha256"][entry["path"]] = entry["sha256"]
    for entry in pinned["patches"]:
        path = manifest.parent / entry["path"]
        if digest(path) != entry["sha256"]:
            raise RuntimeError("exported patch differs from manifest")
    receipt["manifest_files_verified"] = len(pinned["files"])
    # These generated build inputs are gitignored upstream but are compiled.
    for name in ("control/bpf_bpfel.go", "control/bpf_bpfel.o"):
        receipt["source_sha256"][name] = digest(source / name)
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=source).split(b"\0")
    for raw in tracked:
        if raw:
            path = source / os.fsdecode(raw)
            if path.is_file() and (path.suffix in {".go", ".o"} or path.name in {"go.mod", "go.sum"}):
                receipt["source_sha256"][str(path.relative_to(source))] = digest(path)
    for path in source.rglob("*hot*.go"):
        if path.is_file():
            receipt["source_sha256"][str(path.relative_to(source))] = digest(path)
    adapter_inputs = list((repo / "internal/gateway").glob("*.go"))
    adapter_inputs += list((repo / "internal/secrets").glob("*.go"))
    adapter_inputs += [repo / "go.mod", repo / "go.sum"]
    receipt["adapter_sha256"] = {
        str(path.relative_to(repo)): digest(path)
        for path in sorted(adapter_inputs)
    }
    receipt["fixture_sha256"] = {
        str(path.name): digest(path) for path in sorted(fixture.iterdir()) if path.is_file()
    }
    processes = []
    try:
        for destination, template in helpers.items():
            with destination.open("xb") as out:
                out.write(template.read_bytes())
            installed.append(destination)
        with tempfile.TemporaryDirectory(prefix="ed-source-", dir="/tmp") as temp:
            run = Path(temp)
            (run / "gotmp").mkdir(mode=0o700)
            env = dict(os.environ, EGRESSDECK_NATIVE_HARNESS_DIR=str(run),
                       DAE_HOT_STATE_KEY=secrets.token_hex(32), TMPDIR="/tmp",
                       GOTMPDIR=str(run / "gotmp"))
            receipt["go_version"] = subprocess.check_output([str(go), "version"], cwd=source, env=env, text=True).strip()
            for cwd, command in [
                (source, [str(go), "test", "-c", "-tags=egressdeck_hot_harness", "-o", str(run / "daemon.test"), "./cmd"]),
                (repo, [str(go), "test", "-c", "-o", str(run / "adapter.test"), "./internal/gateway"]),
            ]:
                receipt["commands"].append({"cwd": str(cwd), "argv": command})
                subprocess.run(command, cwd=cwd, env=env, check=True, timeout=240)

            def start_server():
                for marker in ("ready", "stop"):
                    (run / marker).unlink(missing_ok=True)
                command = [str(run / "daemon.test"), "-test.run=^TestEgressDeckNativeSourceHarness$", "-test.v", "-test.timeout=130s"]
                receipt["commands"].append({"cwd": str(source), "argv": command})
                log = (run / ("server-%d.log" % len(processes))).open("w+")
                process = subprocess.Popen(command, cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT)
                processes.append((process, log))
                deadline = time.monotonic() + 15
                while not (run / "ready").exists():
                    if process.poll() is not None or time.monotonic() > deadline:
                        log.seek(0)
                        raise RuntimeError("source server startup failed: " + log.read())
                    time.sleep(0.025)
                return process

            server = start_server()
            command = [str(run / "adapter.test"), "-test.run=^TestNativeSourcePublicationAndRestart$", "-test.v", "-test.timeout=60s"]
            receipt["commands"].append({"cwd": str(repo), "argv": command})
            client_log = (run / "adapter.log").open("w+")
            client = subprocess.Popen(command, cwd=repo, env=env, stdout=client_log, stderr=subprocess.STDOUT)
            processes.append((client, client_log))
            deadline = time.monotonic() + 65
            restarted = False
            while client.poll() is None:
                if (run / "restart.request").exists() and not restarted:
                    (run / "stop").touch(mode=0o600)
                    if server.wait(timeout=10) != 0:
                        raise RuntimeError("source server did not stop cleanly")
                    server = start_server()
                    restarted = True
                    (run / "restarted").touch(mode=0o600)
                if time.monotonic() > deadline:
                    raise RuntimeError("adapter test timed out")
                time.sleep(0.025)
            (run / "stop").touch(mode=0o600)
            server_exit = server.wait(timeout=10)
            client_log.seek(0)
            receipt["adapter_output"] = client_log.read()
            print(receipt["adapter_output"], end="", flush=True)
            receipt["daemon_outputs"] = []
            for process, log in processes:
                if process is not client:
                    log.seek(0)
                    receipt["daemon_outputs"].append(log.read())
            receipt["process_restart"] = restarted
            receipt["adapter_exit"] = client.returncode
            receipt["daemon_exit"] = server_exit
            if client.returncode != 0 or server_exit != 0 or not restarted:
                raise RuntimeError("native source integration failed")
            drift = [path for path, expected in receipt["source_sha256"].items() if digest(source / path) != expected]
            if drift:
                raise RuntimeError("dae source changed while testing: " + ", ".join(drift))
            drift = [path for path, expected in receipt["adapter_sha256"].items() if digest(repo / path) != expected]
            if drift:
                raise RuntimeError("adapter source changed while testing: " + ", ".join(drift))
            drift = [name for name, expected in receipt["fixture_sha256"].items() if digest(fixture / name) != expected]
            if drift:
                raise RuntimeError("fixture changed while testing: " + ", ".join(drift))
            if digest(manifest) != receipt["source_manifest_sha256"]:
                raise RuntimeError("source manifest changed while testing")
            receipt["passed"] = True
    except Exception as exc:
        receipt["error"] = str(exc)
        raise
    finally:
        for process, log in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            log.close()
        for path in installed:
            if path.exists() and path.read_bytes() == helpers[path].read_bytes():
                path.unlink()
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        print("Receipt: " + str(args.receipt), flush=True)


if __name__ == "__main__":
    main()
