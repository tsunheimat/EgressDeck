# Homelab Proxy Controller runbooks

These runbooks are for the first single-controller/single-gateway deployment described in `docs/homelab-proxy-development-plan.md`. They assume that the management host and gateway have independent recovery access. Replace values in angle brackets before running a command.

The repository currently exposes only the controller health, readiness, capabilities, and CRUD foundation. A capability that is absent or `false` is an explicit stop condition; do not work around it by editing generated dae configuration or by claiming that a mock adapter applied traffic policy.

## Safety rules

1. Record the controller commit/image digest, gateway/dae version, OPNsense version, kernel, interfaces, address families, and current operation ID before changing anything.
2. Export a backup and verify its checksum before an apply, restore, credential change, or rollback. Keep the previous working gateway manifest and OPNsense backup available.
3. Use a canary device first. Do not enroll a whole group until the canary has passed direct, proxy, blocked, DNS, IPv4, IPv6 (if claimed), and management-path checks.
4. Never use `docker compose down -v`, `DROP DATABASE`, an OPNsense factory reset, or a broad firewall reload as a troubleshooting shortcut. These commands destroy state or disrupt unrelated traffic.
5. If readback is unavailable, the result is **unknown**, not successful. Keep the last-known-good state active and escalate with the operation journal and command output.

## Runbook index

| Runbook | Use when |
| --- | --- |
| [Install and first qualification](install.md) | Installing the controller, database, or a qualified gateway |
| [Backup and restore](backup-restore.md) | Taking a backup, testing it, or restoring into an isolated environment |
| [Provider failure](provider-failure.md) | A fetch, parse, stage, or publication fails |
| [Gateway agent unreachable](agent-unreachable.md) | The controller cannot reach the data-plane agent |
| [OPNsense failure](opnsense-failure.md) | Alias/rule API calls fail or steering readback drifts |
| [Stuck or unknown operation](stuck-operation.md) | An operation has no completion or acknowledgement |
| [IPv6 coverage](ipv6.md) | Enrolling dual-stack clients or investigating an IPv6 bypass |
| [DNS failure](dns.md) | DNS loops, leaks, misclassification, or unknown-domain behavior occur |
| [Rollback](rollback.md) | A release, manifest, or policy must be reverted |
| [Credential rotation](credential-rotation.md) | Rotating OIDC, database, OPNsense, agent, or provider credentials |

Every incident report should include the exact commands, UTC timestamps, redacted output, source commit/image digest, operation ID, and whether any traffic was disrupted.
