# Native OPNsense client

`HTTPClient` implements the `Client` boundary against the source-inspected
OPNsense **26.7** API, pinned to core commit
`821598263289e177b40971600f06f5a91d9faef3`. The annotated release tag resolves
through tag object `e879c8f93c637090e3cb71708c65d5cb5cf2837f`.
This is source and local TLS fixture evidence; no appliance or packet-path
qualification is claimed.

The client uses these native endpoints:

| Purpose | Request | Response checked |
| --- | --- | --- |
| Version and credentials | `GET /api/core/firmware/info` | Exact `product_id=opnsense`, `product_version=26.7` before a mutation batch |
| Resolve persisted alias UUID | `POST /api/firewall/alias/search_item` with `current=1`, `rowCount=-1`, `searchPhrase=<name>` | Complete bounded `rows` recordset; exactly one matching name |
| Persisted alias | `GET /api/firewall/alias/get_item/<uuid>` | Enabled Host/Network object; selected **keys** in `type` and `content` option maps |
| Active table existence | `GET /api/firewall/alias_util/aliases` | Alias name present in returned array |
| Active addresses | `POST /api/firewall/alias_util/list/<name>` with complete recordset request | Complete bounded `rows[].ip` |
| Empty active table confirmation | `GET /api/firewall/alias/get_table_size` | Explicit `details[alias].count=0`; missing count or nonzero count is inconclusive |
| Add/delete one address | `POST /api/firewall/alias_util/{add,delete}/<name>` with JSON `{"address":"<IP or network>"}` | `status=done`, then fresh persisted and active readback |
| Modern steering rule | `GET /api/firewall/filter/get_rule/<uuid>` | Complete normalized settings snapshot and required narrow steering shape |

The native add/delete controller persists Host/Network content and updates the
PF table. It accepts **one address**, not an array. Its `done` response does not
establish that PF installed the intended contents. An empty list response also
cannot establish that a table exists, so the separate table inventory is read.
For an empty result, independent table statistics must explicitly confirm zero.
That endpoint reports the maximum planned/active entry count, so pending alias
files can conservatively delay empty-state confirmation until they converge.
The native implementation lacks a compare-and-swap operation. External changes
can still race an individual request; detected drift stops subsequent writes.
Additions use canonical addresses. Deletion preserves the equivalent native
stored spelling because the upstream persistence routine compares strings;
duplicate equivalent entries require review before mutation.

Construction requires HTTPS, nonempty API credentials, the explicit release
pin, and certificate verification. A private CA can be supplied with `RootCAs`.
There is no insecure-TLS option. Redirects, ambient HTTP proxies, compressed
responses, excessive bodies/rows, incomplete recordsets, and malformed field
representations are rejected. Requests have timeouts and honor cancellation.
Returned errors omit credentials, URLs, appliance messages and response bodies.
Credentials/privilege failures remain distinct from protocol/version failures.

An empty `ManagedAliases` configuration is read-only. Registering write scope
requires:

1. An enabled alias's exact UUID, name, type, and description. Native aliases
   have no controller owner-tag field, so `OwnerTag` must be empty.
2. A gateway ID, one client ingress interface, and one address family.
3. Modern rule UUIDs, selected gateway names, expected destination/exclusion,
   and hashes from a reviewed
   `ReadSteeringRule` result. Rule hashes exclude unselected UI options and
   localized labels, while retaining every configured setting and rule order.
4. Recorded reviewer/time and evidence references for existing deny ordering,
   management/transit exclusions, and actual packet-path validation.

Before each address mutation, the client checks alias identity and compares
active/persisted state. It re-reads each rule and requires an enabled inbound
quick pass limited to the exact source alias and interface, correct family and
gateway, protocol `any`, empty ports, and no schedule/divert/explicit reply-to.
The initial rule shape requires ordinary `keep` state tracking and a real
interface rather than floating/interface-group placement. Tagged/TOS/priority
match restrictions are rejected so enrollment covers the reviewed source set.
The reviewed complete snapshot pins destination/exclusions and advanced fields.
The adapter also binds gateway/interface/family/rule IDs to the allowlist.
Policy-review fields are operator evidence; they do not claim the single-rule
API automatically proves global deny precedence or traffic enforcement.

Legacy rules are intentionally unsupported for automatic mutation in this
client. A legacy rule, missing modern rule, denied request, or malformed
response never triggers an implicit attestation fallback. Rule provisioning
and targeted state deletion are not implemented by this client. Ordinary
membership changes do not flush firewall states; strict-transition completeness
must remain gated in the deployment layer.

The current exact release allowlist intentionally rejects patch versions until
their relevant source changes and appliance behavior are qualified. The
firmware-info endpoint also requires a read privilege on the restricted service
account; access to one endpoint does not imply access to the others.

Source inspection (all files at the pinned commit):

- [AliasController.php](https://github.com/opnsense/core/blob/821598263289e177b40971600f06f5a91d9faef3/src/opnsense/mvc/app/controllers/OPNsense/Firewall/Api/AliasController.php): search/get UUID and option-map content.
- [AliasUtilController.php](https://github.com/opnsense/core/blob/821598263289e177b40971600f06f5a91d9faef3/src/opnsense/mvc/app/controllers/OPNsense/Firewall/Api/AliasUtilController.php): one-address mutations, static persistence and active list.
- [ApiControllerBase.php](https://github.com/opnsense/core/blob/821598263289e177b40971600f06f5a91d9faef3/src/opnsense/mvc/app/controllers/OPNsense/Base/ApiControllerBase.php): recordset pagination and `rowCount=-1`.
- [AliasContentField.php](https://github.com/opnsense/core/blob/821598263289e177b40971600f06f5a91d9faef3/src/opnsense/mvc/app/models/OPNsense/Firewall/FieldTypes/AliasContentField.php): selected content keys and address-type semantics.
- [list_table.py](https://github.com/opnsense/core/blob/821598263289e177b40971600f06f5a91d9faef3/src/opnsense/scripts/filter/list_table.py): active `ip` row field and lack of a pfctl error signal.
- [pftablecount.py](https://github.com/opnsense/core/blob/821598263289e177b40971600f06f5a91d9faef3/src/opnsense/scripts/filter/pftablecount.py): explicit table count for independent empty-state confirmation.
- [FilterController.php](https://github.com/opnsense/core/blob/821598263289e177b40971600f06f5a91d9faef3/src/opnsense/mvc/app/controllers/OPNsense/Firewall/Api/FilterController.php), [Filter.xml](https://github.com/opnsense/core/blob/821598263289e177b40971600f06f5a91d9faef3/src/opnsense/mvc/app/models/OPNsense/Firewall/Filter.xml): modern rule get and field types.
- [FirmwareController.php](https://github.com/opnsense/core/blob/821598263289e177b40971600f06f5a91d9faef3/src/opnsense/mvc/app/controllers/OPNsense/Core/Api/FirmwareController.php): installed product/version metadata.
- [alias_util.volt](https://github.com/opnsense/core/blob/821598263289e177b40971600f06f5a91d9faef3/src/opnsense/mvc/app/views/OPNsense/Firewall/alias_util.volt), [opnsense_bootgrid.js](https://github.com/opnsense/core/blob/821598263289e177b40971600f06f5a91d9faef3/src/opnsense/www/js/opnsense_bootgrid.js): native UI uses JSON POST for active table searches despite the generated API overview listing GET.

Implementation and fixtures were independently written from these interface
observations; no upstream source is vendored in this package.
