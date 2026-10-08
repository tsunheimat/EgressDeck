# Real-network qualification

This directory defines the release gate. It is intentionally not satisfied by
the deterministic gateway engine or packet-shaped fixture data.

A trusted topology runner must create `artifacts/network/qualification.json`
after a fresh isolated run. That file must bind the controller commit, engine
artifact, topology manifest, and all required checks to redacted artifacts with
SHA-256 hashes. Use `tests/network/qualification.example.json` as a template.
The gate fails when the receipt is missing, when a check is skipped, or when an
artifact cannot be read and verified. A configured environment variable by
itself is not proof that the network ran.

The controller's fake adapter cannot generate this receipt. The expected run
is an OPNsense VM, a pinned dae Linux gateway, two independent clients, a
controlled direct target, a controlled proxy target, and independent recovery
access. Follow `docs/compatibility.md` and `docs/adr/packet-path.md` to collect
packet captures, engine identities, generations, session continuity, and failure
guard observations.

Run the protected GitHub `Network qualification` workflow only after installing
the topology harness on the isolated `egressdeck-network` runner. The workflow
checks out the immutable dispatch commit and verifies `HEAD` against
`GITHUB_SHA` before running the harness. The harness source argument and artifact
name use that verified commit, so a later update to `main` cannot change the
source being qualified. The workflow does not enroll a production network and
is not triggered by pull requests.
