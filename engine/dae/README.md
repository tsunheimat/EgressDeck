# Experimental native dae hot provider backend

This isolated AGPL patch series extends upstream dae at
`e3fee8fbc68a65167af13b685ab0b958757e20ee`. The controller does not link the engine
code. Stock dae still does not implement these operations. The extension is
opt-in development software; real eBPF/OPNsense qualification remains a release
gate.

The patched daemon provides an executable in-process path for one-provider
publication and manual node selection. It prepares native dialers, validates all
candidate references, persists the accepted snapshot, then atomically replaces
only affected groups under their existing kernel outbound handles. It does not
call the reload path, download subscriptions, rebuild routing, replace listeners,
or attach another dae instance.

TCP and UDP acquire a resource lease before dialing. A successful connection owns
that lease until close; failures, retries and rejected session adoption release
it. Existing flows keep their selected native resources. Hot DNS exchanges use
leased, per-exchange forwarders so a replacement using the same display name
cannot reuse an obsolete connection. Ordinary DNS answer caching remains intact.

Outbound-group membership has its own revision and publication operation against
unchanged provider inventory. All Unix mutations use durable operation IDs and
authoritative status readback, including safe exact-ID replay after pre-send crashes.

The native runtime has a compact journal with restart restoration, generation
preconditions, private file permissions, directory locking, and ambiguous-commit
fencing. Kernel availability writes are read back before successful publication
acknowledgement. The local API authenticates the peer UID on a Unix socket.

## Current supported scope

- Predeclare named outbound groups in the normal dae configuration. Their numeric
  handles and names cannot change through the hot API.
- A managed group contains nodes from one provider. Selections are manual and
  shared across TCP/UDP. Independent transport selection and automatic health
  selection are not implemented here.
- Native connection links accepted by the pinned dae parser are supported; every
  node must parse successfully. The controller still applies its stricter import
  allowlist. There is no pre-publication network probe in this extension.
- First publication requires a selected stable candidate. Refresh preserves the
  choice when present; removal requires an explicit valid replacement. Direct is
  never an implicit replacement.
- At most 4,096 total candidate memberships per provider publication, bounded
  input/journal sizes, eight retained replacement batches, and 128 immutable
  revision identities per provider are permitted.
  Busy is returned before another accepted mutation exceeds the bound. Held
  sessions retain their complete group version; there is no forced session expiry.
- The original configured groups remain owned by the ordinary control plane until
  shutdown. Added hot revisions retire after their last lease closes. Each new
  concrete dialer has private options and a private transport-cache namespace.
- Full policy reload and suspend are deliberately rejected while hot mode is
  active. Stop/start with the same predeclared group layout restores the journal.
  A layout mismatch fails startup. A future coordinated policy handoff is required.

## Build and use

Apply [the patch](patches/0001-native-hot-provider-runtime.patch) to a clean clone
at the exact base. The base declares Go 1.26.0; initialize its pinned submodules
and follow its normal `make` build process to generate BPF objects.

```sh
git clone https://github.com/daeuniverse/dae.git dae-r05
git -C dae-r05 checkout --detach e3fee8fbc68a65167af13b685ab0b958757e20ee
git -C dae-r05 apply /path/to/EgressDeck/engine/dae/patches/0001-native-hot-provider-runtime.patch
cd dae-r05
git submodule update --init --recursive
make
```

Run the patched binary with both opt-in flags:

```sh
install -d -m 0700 /run/dae-hot /var/lib/dae-hot
# Supply DAE_HOT_STATE_KEY from an external secret source: exactly 64 hex
# characters encoding a random 32-byte key. Keep it outside journal backups.
dae run -c /etc/dae/config.dae \
  --hot-control-socket /run/dae-hot/control.sock \
  --hot-state-dir /var/lib/dae-hot
```

The socket is mode 0600. Its directory must be owned by the daemon's effective
UID and mode 0700; all ancestor symlinks are rejected. The gateway agent must run
under the same effective UID or an explicitly reviewed local access arrangement.
No unauthenticated TCP management listener is added.

The daemon refuses hot mode when its global or group defaults permit insecure
TLS verification. The external state key is mandatory; missing/wrong keys,
plaintext legacy state and authenticated ciphertext corruption fail closed.

The hosted source-contract workflow is [dae-native.yml](../../.github/workflows/dae-native.yml).
It builds and tests the patch and runs the actual native API/adapter fixture;
its existence does not establish a completed hosted run.

Upgrade only after the previous agent reports no unresolved mutations. Journals
with legacy pending intent lacking operation IDs fail startup with
`upgrade_required`; they cannot be safely labeled never-accepted. Resolve that
intent using the previous source/version and authoritative runtime readback before
upgrading. Settled encrypted state and staged unsent revisions remain readable.

The local contract is documented in [API.md](API.md). Source hashes and dependency
pins are in [source-manifest.json](source-manifest.json); actual test receipts and
remaining acceptance work are in [VALIDATION.md](VALIDATION.md) and
[INTEGRATION.md](INTEGRATION.md).

## License and provenance

Upstream is <https://github.com/daeuniverse/dae>, exact base
`e3fee8fbc68a65167af13b685ab0b958757e20ee`, local patch branch
`egressdeck/hot-inventory-primitives`. Imported/modified engine files retain
`SPDX-License-Identifier: AGPL-3.0-only`. The unmodified upstream license is
preserved in [LICENSE.dae](LICENSE.dae).

Any distribution of a modified dae artifact must include corresponding source,
notices, and applicable AGPL obligations. A separate process does not remove
those obligations. This repository does not publish a qualified patched-engine
release or deploy it to any traffic interface.
