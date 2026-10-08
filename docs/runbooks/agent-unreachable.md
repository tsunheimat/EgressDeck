# Gateway agent unreachable

Controller/API availability does not prove that the data plane is healthy. When the agent cannot be reached, preserve the last-known-good gateway state and do not apply a new enrollment, provider revision, or selection.

## Identify the boundary

From the controller host, record DNS, route, TCP/TLS result, and agent service status without changing firewall policy:

```sh
set -Eeuo pipefail
getent ahosts <gateway-agent-host>
ip route get <gateway-agent-address>
nc -vz -w 5 <gateway-agent-address> <agent-port>
curl --fail --silent --show-error --connect-timeout 5 --max-time 10 \
  --cacert /etc/homelab-proxy-controller/agent-ca.pem \
  --cert /etc/homelab-proxy-controller/agent-client.pem \
  --key /etc/homelab-proxy-controller/agent-client-key.pem \
  https://<gateway-agent-address>:<agent-port>/healthz
```

The exact agent health endpoint and port are deployment-specific until the agent contract is implemented. A connection refused, TLS/authentication error, and timeout are different failures; retain the exact error.

On the gateway console/SSH:

```sh
sudo systemctl status homelab-proxy-agent.service --no-pager
sudo journalctl -u homelab-proxy-agent.service --since '-30 min' --no-pager
sudo ss -lntup | grep -E ':(<agent-port>)\\b' || true
df -h /var/lib/homelab-proxy-agent
```

For OpenWrt, use `logread -e homelab-proxy-agent`, `/etc/init.d/homelab-proxy-agent status`, and `df -h` instead. Do not assume OpenWrt compatibility without the qualification record.

## Recovery

1. Confirm the gateway still forwards the last-known-good policy using an already enrolled canary and an independent path. Do not restart dae merely to make the health check green.
2. Check management routing, ACLs, certificate expiry/SAN, clock skew, disk/inode pressure, process limits, and agent journal errors.
3. If the agent crashed, preserve its journal/core evidence, validate the last-known-good manifest, then restart only the agent:

```sh
sudo systemctl restart homelab-proxy-agent.service
sudo systemctl is-active --quiet homelab-proxy-agent.service
```

4. Reconnect and read back gateway generation, policy/provider revisions, listener/tc identity, and resource counts. Reconcile from the gateway's current generation; do not overwrite an unknown newer state with an old controller snapshot.
5. If the gateway itself is unhealthy, follow the rollback runbook. Keep enrollment unchanged until the canary passes.

If the agent is unreachable and policy enforcement cannot be proven, mark the gateway **unverified** and stop new changes. Use the deliberate, separately authorized bypass or quarantine procedure; never infer fail-open/fail-closed behavior from controller downtime.
