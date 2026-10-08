# Provider service

`Parse` accepts individual/native node links, Base64 link lists, SIP008 JSON,
and a conservative Clash node-inventory subset. A Clash document contributes
only its `proxies` list; listeners, policy, DNS and controller credentials never
become management settings.

Supported parser fields cover TCP Shadowsocks, Trojan, VMess, VLESS, HTTP(S)
and SOCKS5 with the protocol's supported basic authentication and TLS options.
The current parser rejects advanced transports, plugins, Reality, certificate
verification bypasses, unknown node fields, conflicting field aliases, YAML
anchors/aliases, custom tags and duplicate keys. Unsupported entries appear in
the parse report. An import can contain supported and unsupported entries;
`Revision.RequiresApproval` prevents treating that result as safe automatic
publication. Engine support is a separate capability check: parsing a node does
not qualify its protocol or native rendering on a live gateway.

Passwords are preserved exactly. ALPN identifiers preserve order and case.
Provider-specific account credentials participate in a private connection
identity, so two accounts at the same endpoint remain distinct. Independent
parses produce new random public IDs; registry reconciliation retains an ID
when its private identity matches. A credential or transport change without a
trustworthy provider ID produces a new logical node and an ambiguity report.
Display name and entry order do not change the connection revision.

`Registry.Stage` records inventory without changing the active revision.
`Publish` requires the exact active revision, including zero for an initial
publication, and is an explicit approval boundary. Callers must publish to the
gateway, inspect its observed revision, and handle unknown acknowledgements
before recording a successful controller publication. `Refresh` coalesces
concurrent identical fetches and keeps last-attempt and last-success separate.
Failed/empty imports preserve active inventory. Retained history is capped at
128 revisions per provider and returns a capacity error before exceeding that
limit; referenced runtime history is never automatically removed.

`Fetcher` permits verified HTTPS by default and validates resolved addresses at
connection time and redirects. Internal sources require exact administrative
host, port and CIDR allowlist entries. Non-Direct fetch routes require an
explicit verifier and receive validated literal addresses; there is no Direct
fallback. Wire bytes, gzip output, response headers, redirects, parsing and
request duration are bounded. Public errors exclude source path/query,
credentials and untrusted remote error text.

`ExportState` / `ImportState` are **private storage APIs**. Their bytes contain
complete node definitions and private fingerprints and must be authenticated
and encrypted by the persistence layer. Public JSON intentionally omits these
fields. Restore validates the complete snapshot before replacing registry
state, and preserves the configured fetcher and limits.
