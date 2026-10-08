# Deterministic contract fixtures

These fixtures are small, checked-in inputs for the provider, policy, and
gateway contracts. They use stable IDs and content hashes where an engine
snapshot is represented; no fixture depends on generated UUIDs, wall-clock
timestamps, a live subscription, or a live gateway.

`provider/` covers SIP008 JSON, the supported node-list subset of Clash YAML,
native links, and rejected empty/malformed content. Provider tests parse the
same bytes twice and require stable node identity and content hashes. Node
secrets are present only as parser inputs and must not appear in serialized
node output.

`policy/contract.json` keeps device addresses, group membership, ordered
mandatory/direct/reusable rules, explicit defaults, and gateway capability
constraints together. It represents controller intent; it is not dae syntax.

`gateway/` contains a capability declaration and before/after inventory
snapshots. The snapshots model a primary provider refresh while preserving an
unrelated provider, outbound, selection, and open connection. The runtime
contract test uses `FakeEngine` only as a deterministic controller contract;
it does not establish stock dae hot-update or packet-path support.

`agent/journal.jsonl` is a replayable operation journal with explicit UTC
timestamps. Its contract test checks staged publication, hot publication, and
selection persistence order without requiring a running gateway.

Run the fixture contracts with:

```sh
go test ./tests/contract
```
