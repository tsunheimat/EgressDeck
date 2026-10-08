# OpenWrt deployment status

OpenWrt is a qualification target, not an enabled production target. Before
packaging the gateway agent, record the exact device architecture, kernel tc/
eBPF capabilities, firewall backend/order, service manager behavior, writable
storage, IPv4/IPv6 routing, and tested dae build in `docs/compatibility.md`.

Do not install this project on a production router from this directory. A
qualified package must be commit-pinned, include a rollback artifact, and keep
the controller on an independent management host. The agent must retain a
last-known-good manifest and provider snapshots locally so controller downtime
does not remove an applied policy.
