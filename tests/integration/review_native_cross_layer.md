The native review regression runs the real controller and gateway-agent binaries
against the real patched dae Unix control server and `ControlPlane`. It generates
disposable mTLS identities, authenticates the controller with signed identity
headers, retains CSRF protection, and imports all provider/group data through
HTTP. The browser uses the Vue bundle served by that controller.

Run on one host with the pinned patched dae checkout, generated BPF build inputs,
Go 1.26, OpenSSL, Node, the installed web dependencies, and an available Playwright
browser. Use a disposable patched dae checkout; the runner temporarily installs
the existing tagged source-fixture helpers and removes them afterwards.

```sh
rtk python3 tests/integration/review_native_cross_layer.py \
  --dae-source /path/to/patched-dae \
  --go /path/to/go1.26/bin/go \
  --browser --browser-channel chrome \
  --receipt tests/integration/artifacts/review-native-cross-layer.json
```

The scenario publishes `{A, B}`, selects A with shared TCP/UDP semantics, edits
the group to `{A}`, verifies that selection is rejected before group application
without changing the operation journal or desired selection, applies that group
without changing provider content, and selects A successfully. It restores B
through another group operation and clicks B in the actual browser. The browser
asserts the combined control, both explicit transport scopes, both revision
preconditions, the durable operation, and both rendered readback rows.

A private Unix forwarding proxy then holds a selection before sending it and
kills the real gateway-agent after its intent is durable. A second case forwards
the mutation to dae, reads dae's actual committed response, withholds that
acknowledgement, and kills the agent. Each case restarts the agent and controller,
requires the original controller operation to converge to `applied`, and requires
exactly one native generation increment. Finally, all three processes restart
from their journals; provider/group/selection state and generation must survive.
The proxy never invents inventory, operation status, or mutation acknowledgements.

The receipt records the repository baseline, dirty paths, all dependent source
hashes, the pinned dae manifest and generated BPF input hashes, built binary
hashes, command invocations, browser request/result, restart generations, and
sanitized process logs. A failed run overwrites the receipt with `passed: false`.
Any source drift during the run fails the receipt. Keys, node links, and session
cookies are generated inside private temporary storage and are not put in the
receipt or process command arguments. Journals must contain no plaintext node
connection links or passwords.

These are native management-path checks. The tagged ControlPlane constructor
omits kernel attachment and traffic ingress, and the fixture makes no eBPF,
proxy-handshake, OPNsense, or client packet-path qualification claim.
