# Native hot runtime integration and remaining qualification

The patch is based on dae `e3fee8fbc68a65167af13b685ab0b958757e20ee`. It now
includes a real daemon execution path, native connection lifetime management, and
an authenticated local API. Source/native tests do not establish packet-path
qualification on a real gateway.

## Implemented source boundaries

| Boundary | Implementation |
|---|---|
| Fixed kernel group slots | `component/outbound/hot_inventory.go` fixes name/handle membership; provider refresh cannot create, remove, or renumber routing groups. |
| Prepared native provider inventory | `control/hot_inventory.go` parses every link through `dialer.NewFromLinkContext`, validates stable IDs and selections, and constructs affected groups with inert callbacks. |
| Private resource ownership | `component/outbound/dialer/hot_option.go` gives every hot native dialer private mutable options/cache namespace. Final lease release closes transport then cleans its namespace. |
| TCP admission | `control/dial.go` acquires a native group lease before DialContext; `control/hot_connection.go` transfers ownership into the resulting connection wrapper. |
| UDP admission | `control/udp.go` and `control/udp_endpoint_pool.go` keep the selected lease across dial/retry/adoption; wrapped PacketConn preserves native receiver/batch/lifecycle behavior. |
| Session adoption | `control/session_manager.go` identifies private hot wrappers and avoids claiming their resources through the ordinary baseline runtime. |
| DNS selection | `control/control_plane.go` disables the pointer-bearing selection cache while hot mode is enabled and pins chosen resources. |
| DNS transport | `control/hot_dns.go` uses an exchange-owned forwarder, closes it before releasing the resource lease, and leaves ordinary answer caching intact. |
| Kernel availability | `control/connectivity.go` takes availability ownership for published manual groups, suppresses obsolete baseline callbacks, writes and reads back the existing availability map. Failure fences native mutation/admission and returns outcome unknown. |
| Persistence | `control/hot_inventory.go` keeps a bounded encrypted compact snapshot, serializes mutations, restores exact handle/selection generations, and fences ambiguous persistence. |
| Local daemon API | `cmd/hot_control.go` authenticates Unix peer UID, rejects permissive/symlink paths, bounds input and sanitizes errors; `cmd/run.go` drains requests before shutdown. |

The ordinary control-plane `c.outbounds` slice stays immutable. Unmanaged groups
use the ordinary admission path. Managed data/DNS admissions read the separate
native inventory under its lease protocol, preserving all installed numeric
handles. Baseline configured resources remain under the original runtime until
shutdown; later hot generations are bounded and retire when held flows drain.

Full reload/suspend is rejected in hot mode. That avoids concurrent control
planes writing one journal, snapshot races during policy handoff, and unchanged
baseline code accidentally inheriting an obsolete hot group. Changes to the set
or order of configured routing groups require a separate stop/start policy
procedure; journal handle mismatch fails safely.

## Deliberate implementation restrictions

One provider per managed outbound group; fixed manual selection shared by TCP and
UDP; no automatic health-based failover; no implicit Direct replacement. The
public stable candidate choice is authoritative rather than the native group's
old numeric fixed index. Domain/routing configuration and installed BPF policy are
unchanged by publication.

Each session retains the whole prepared group it uses. Eight retained replacement
batches and 4,096 aggregate candidate memberships per publication bound resource
retention; there is no forced maximum session age. An operator can drain sessions
normally and retry a busy publication. Baseline resources add a fixed startup
inventory footprint.

There is no pre-publication outbound reachability probe. Parsing and native
connection tests cannot prove a remote node will work. DNS hot transport pooling
is disabled, which trades latency/throughput for explicit lifetime correctness.
Existing upstream latency/check APIs still describe their configured baseline;
the new control API reports only actual native inventory and selected identity.
The controller must not present baseline latency as a measurement of a hot node.

At-rest native snapshots require an externally supplied `DAE_HOT_STATE_KEY`;
backup/restore must retain that key separately. A mismatched key or incompatible
handle table fails startup. No plaintext journal migration is implied.

## Remaining acceptance gates

1. Run a real isolated gateway with the patched binary and current agent bridge.
   Compare before/after PID, listener inode identities, tc attachments, routing
   epoch, DNS cache behavior, provider generations and publication-path traces.
   The compiled BPF object is not proof of its runtime path.
2. Keep active real proxy TCP streams and UDP/QUIC conversations for two providers
   while updating only one. Verify existing and unrelated traffic independently;
   check provider fetch counts rather than assuming no unintended fetch occurred.
3. Repeat updates, pinned-node removals, native prepare failures, lost acknowledgments,
   directory fsync failures, kernel availability failures and process restarts.
   Verify readback and retained descriptor/memory/transport counts.
4. Qualify OPNsense source preservation, steering aliases, denies, IPv6, DNS,
   return routes and fail-closed behavior separately. None is established by the
   engine source tests.
5. Add coordinated full policy deployment if required during hot mode, independent
   transport selection, cross-provider groups, probes, and the accepted native
   health/telemetry contracts. Unsupported capabilities remain explicitly absent.
6. Validate the source-bound patched binary/socket identity at installation and
   publish immutable artifacts only after the declared network gates pass.

The stock adapter must stay unsupported for hot publication. The opt-in adapter
may describe the implemented native contract with these restrictions, while the
product release/traffic-verification state remains unqualified.
