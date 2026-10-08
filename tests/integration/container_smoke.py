#!/usr/bin/env python3
"""Exercise a built controller image, including authenticated restart recovery.

Runs only disposable local containers; no gateway, router, or provider fetch is
configured. Usage: python3 tests/integration/container_smoke.py IMAGE
"""

import base64
import hashlib
import hmac
import http.cookiejar
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


def main():
    image = sys.argv[1] if len(sys.argv) == 2 else "egressdeck-controller:review"
    name = "egressdeck-smoke-" + secrets.token_hex(5)
    identity_key = secrets.token_hex(32)
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    created = False
    with tempfile.TemporaryDirectory(prefix="egressdeck-smoke-") as scratch:
        envfile = os.path.join(scratch, "environment")
        with open(envfile, "w", encoding="utf8") as stream:
            os.chmod(envfile, 0o600)
            stream.write("AUTH_MODE=header\nCOOKIE_SECURE=false\n")
            stream.write("SESSION_SECRET=" + secrets.token_hex(32) + "\n")
            stream.write("IDENTITY_HEADER_SECRET=" + identity_key + "\n")
            stream.write("APP_ENCRYPTION_KEY=" + base64.b64encode(secrets.token_bytes(32)).decode() + "\n")
        try:
            docker("run", "-d", "--name", name, "--env-file", envfile,
                   "--cap-drop=ALL", "--security-opt=no-new-privileges", "-p", "127.0.0.1::8080", image)
            created = True
            endpoint = "http://" + docker("port", name, "8080/tcp").splitlines()[0]

            def request(path, method="GET", payload=None, status=200, headers=None):
                extra = dict(headers or {})
                if payload is not None:
                    extra["Content-Type"] = "application/json"
                if method != "GET":
                    for cookie in jar:
                        if cookie.name == "egressdeck_csrf":
                            extra["X-CSRF-Token"] = cookie.value
                raw = json.dumps(payload).encode() if payload is not None else None
                req = urllib.request.Request(endpoint + path, data=raw, method=method, headers=extra)
                try:
                    response = opener.open(req, timeout=10)
                except urllib.error.HTTPError as error:
                    response = error
                with response:
                    data = response.read()
                    assert response.status == status, (method, path, response.status, status)
                    if response.headers.get("Content-Type", "").startswith("application/json"):
                        return json.loads(data)
                    return data

            def wait_ready():
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    try:
                        request("/readyz")
                        return
                    except (OSError, AssertionError):
                        time.sleep(0.2)
                raise RuntimeError("controller did not become healthy")

            def login(role):
                mac = hmac.new(identity_key.encode(), ("smoke\0" + role).encode(), hashlib.sha256)
                signature = base64.urlsafe_b64encode(mac.digest()).decode().rstrip("=")
                return request("/api/v1/auth/login", "POST", status=201, headers={
                    "X-Auth-Request-User": "smoke", "X-Auth-Request-Role": role,
                    "X-Auth-Request-Signature": signature,
                })

            wait_ready()
            assert b"EgressDeck" in request("/")
            request("/api/v1/devices", status=401)
            request("/api/v1/auth/login", "POST", status=401, headers={
                "X-Auth-Request-User": "unsigned", "X-Auth-Request-Role": "admin",
            })
            login("admin")
            gateway = request("/api/v1/gateways", "POST", {
                "name": "Smoke gateway", "endpoint": "https://unused.invalid", "adapter": "dae",
            }, 201)
            provider = request("/api/v1/providers", "POST", {
                "name": "Smoke provider", "source": "inline", "format": "local",
            }, 201)
            provider_view = request(f"/api/v1/providers/{provider['id']}")
            assert provider_view["source"] == "[redacted]"
            assert provider_view["refreshable"] is False
            assert request(f"/api/v1/providers/{provider['id']}/schedule")["enabled"] is False
            stage = request(f"/api/v1/providers/{provider['id']}/stage", "POST", {
                "content": "socks5://user:container-private-password@proxy.example:1080#Smoke", "format": "links",
            }, 202, {"Idempotency-Key": "smoke-stage"})
            node_id = stage["revision"]["nodes"][0]["id"]
            assert "container-private-password" not in json.dumps(stage)
            policy = request("/api/v1/policies", "POST", {
                "name": "Smoke policy", "default_action": {"kind": "direct"},
                "unknown_domain_action": {"kind": "direct"}, "proxy_failure_action": {"kind": "block"},
            }, 201)
            group = request("/api/v1/device-groups", "POST", {
                "name": "Smoke group", "gateway_id": gateway["id"], "policy_id": policy["id"], "enabled": True,
            }, 201)
            device = request("/api/v1/devices", "POST", {
                "name": "Smoke device", "primary_group_id": group["id"],
                "addresses": [{"address": "192.0.2.78"}],
            }, 201)
            plan = request("/api/v1/deployments/plan", "POST", {"gateway_id": gateway["id"]})
            assert plan["scope"] == "gateway" and len(plan["checksum"]) == 64
            assert plan["deployable"] is False and plan["blockers"]
            events = request("/api/v1/events?limit=1")
            assert events["durable"] is True and events["resumable"] is True
            assert events["items"] and events["next_cursor"]
            request(f"/api/v1/providers/{provider['id']}/revisions/1/apply", "POST", {}, 501,
                    {"If-Match": '"0"', "Idempotency-Key": "smoke-unsupported-apply"})
            state = docker("exec", name, "cat", "/var/lib/homelab-proxy-controller/store.json")
            assert "container-private-password" not in state
            journal = json.loads(docker("exec", name, "cat", "/var/lib/homelab-proxy-controller/operations.json"))
            assert journal["format"] == "egressdeck/deployment-journal" and "envelope" in journal
            assert "container-private-password" not in json.dumps(journal)
            docker("restart", name)
            endpoint = "http://" + docker("port", name, "8080/tcp").splitlines()[0]
            wait_ready()
            login("viewer")
            assert request(f"/api/v1/devices/{device['id']}")["primary_group_id"] == group["id"]
            assert request(f"/api/v1/policies/{policy['id']}")["name"] == "Smoke policy"
            revisions = request(f"/api/v1/providers/{provider['id']}/revisions")["items"]
            assert revisions[0]["nodes"][0]["id"] == node_id
            assert request(f"/api/v1/deployments/plans/{plan['checksum']}")["checksum"] == plan["checksum"]
            assert request("/api/v1/events?cursor=" + events["next_cursor"])["durable"] is True
            assert b"egressdeck_controller_http_requests_total" in request("/api/v1/metrics")
            request("/api/v1/devices", "POST", {"name": "Viewer denied"}, 403)
            missing = request("/api/v1/does-not-exist", status=404)
            assert not (isinstance(missing, bytes) and b"<!doctype html>" in missing.lower())
            print(json.dumps({"status": "PASS", "image": image,
                              "image_id": docker("image", "inspect", image, "--format", "{{.Id}}"),
                              "checks": ["static UI", "signed login", "RBAC", "encrypted staging",
                                         "policy/group/device CRUD", "immutable inventory plan", "resumable events",
                                         "encrypted operation journal", "authenticated metrics",
                                         "unsupported runtime refusal", "restart restore"]}))
        except Exception:
            if created:
                logs = docker("logs", "--tail", "20", name)
                print(logs, file=sys.stderr)
            raise
        finally:
            if created:
                docker("rm", "-f", name)


if __name__ == "__main__":
    main()
