# Outbound candidates and selections

`Group.NodeIDs` is the current candidate snapshot. `SourceFilters`, when set,
derives that snapshot from normalized provider inventory. Provider and protocol
constraints combine with an OR of included node IDs/names. Exclusions win.
Names match exactly and case-sensitively; no unbounded expression execution is
allowed. Inputs are bounded, normalized and cloned before storage.

`ResolveCandidates` returns sorted IDs from supported nodes. `PreviewInventory`
reports affected groups, added/removed nodes, missing selections and required
blocking without changing anything. `ReconcileInventory` applies the approved
complete inventory under revision preconditions. For a single provider update,
`ReconcileGroups` recomputes only named groups and requires an exact revision
for each, preserving unrelated pending inventories and selections.

Removing an intended selection marks it unavailable and retains the previous
applied/observed evidence. It never inserts Direct or chooses another node.
`replacement_policy: none` rejects selected-node removal; `block` requests
blocking, but controller state alone is not proof the engine enforced it. An
explicit valid replacement selection is required to clear unavailable intent.
Gateways without a verified block publication path must reject or leave the
operation incomplete.

Name filters can make a rename semantically significant. Connect
`ProviderMetadataImpact` to the provider registry's metadata evaluator so a
membership-changing rename becomes staged and preserves active inventory until
publication. Renames that do not change membership remain connection no-ops.

TCP and UDP selections are separate identities scoped to group and gateway.
Desired, applied and observed values remain distinct, with monotonic observed
generations. `Delete` requires exact CAS, no policy references, and no remaining
desired/applied/observed node references. The API supplies policy references
under its serialized persistence boundary.

Snapshot export/import preserves filters, candidates and selection revisions.
Restore validates the entire snapshot before replacing state. Persistence is a
controller responsibility; it must encrypt and authenticate these private state
bytes before writing durable storage.
