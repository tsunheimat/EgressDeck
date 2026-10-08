# Backup and restore

Backups must reproduce management intent and the last-known-good data-plane state without contacting a live subscription during restore. Keep database data, encryption-key recovery material, agent manifests/provider snapshots, and OPNsense configuration as separate artifacts.

The default controller uses a single-process JSON store at `STORAGE_PATH`.
The controller also stores its deployment journal at `OPERATION_JOURNAL_PATH`
(default: `operations.json` beside `STORAGE_PATH`), including when the inventory
uses PostgreSQL. Back up both together while the controller is stopped. The
journal encrypts complete deployment state, including native engine
configuration and node credentials, with `APP_ENCRYPTION_KEY`; file permissions
remain `0600`. The lifecycle document and provider sources are encrypted too.
The database dump alone does not include the controller's file journal.

Copy the files to protected storage, then restart and check readiness. Restore
to isolated paths before relying on the backup. The PostgreSQL procedure below applies only when
`STORAGE_DSN`/`DATABASE_URL` selects the PostgreSQL adapter; the optional Compose
overlay supplies that backend.

## Backup

Run from a host that can reach PostgreSQL and has enough protected storage. Stop
the controller before capturing the database and controller journal, preserving
one consistent recovery point across their separate persistence boundaries. Set
`BACKUP_DIR` to a filesystem with restricted access; do not use a world-readable
temporary directory.

```sh
set -Eeuo pipefail
umask 077
BACKUP_DIR=/var/backups/homelab-proxy/$(date -u +%Y%m%dT%H%M%SZ)
install -d -m 0700 "$BACKUP_DIR"
pg_dump --host "$PGHOST" --username "$PGUSER" --dbname "$PGDATABASE" \
  --format=custom --no-owner --no-acl \
  >"$BACKUP_DIR/controller.dump"
sha256sum "$BACKUP_DIR/controller.dump" >"$BACKUP_DIR/SHA256SUMS"
test -s "$BACKUP_DIR/controller.dump"
pg_restore --list "$BACKUP_DIR/controller.dump" >/dev/null
# Set this to the controller's configured OPERATION_JOURNAL_PATH.
install -m 0600 /var/lib/homelab-proxy-controller/operations.json \
  "$BACKUP_DIR/operations.json"
sha256sum "$BACKUP_DIR/operations.json" >>"$BACKUP_DIR/SHA256SUMS"
```

Copy, with encryption and access controls provided by the approved backup system, the external application encryption-key recovery material. Record its `APP_ENCRYPTION_KEY_ID` separately; never store a plaintext key next to the dump or journal. Recover the exact key ID as well as its 32-byte key. On the gateway, copy the last-known-good manifest, approved provider snapshots, and operation journal from the managed data directory (for example `/var/lib/homelab-proxy-agent/`) and record `sha256sum` for every file. Export the OPNsense configuration from its UI/API and retain the export checksum.

Record the source commit/image digest, schema version, gateway/dae version, OPNsense version, and UTC time in `backup-meta.txt`. Back up the controller while it is healthy; a dump taken during a failing migration is not a verified backup.

## Restore into an isolated environment

```sh
set -Eeuo pipefail
BACKUP_DIR=/var/backups/homelab-proxy/<timestamp>
sha256sum --check "$BACKUP_DIR/SHA256SUMS"
pg_restore --list "$BACKUP_DIR/controller.dump" >/dev/null
```

Create a new database and restore there. Never restore over the only production database first:

```sh
createdb -h <isolated-db-host> -U <admin> homelab_proxy_restore
pg_restore -h <isolated-db-host> -U <admin> -d homelab_proxy_restore --no-owner --no-acl "$BACKUP_DIR/controller.dump"
```

Restore `operations.json` at the isolated controller's configured journal path
with mode `0600`, alongside the matching store/database snapshot. Supply the
separately recovered `APP_ENCRYPTION_KEY` and matching `APP_ENCRYPTION_KEY_ID`.
An encrypted journal can move to a new path; its authenticated purpose does not
depend on a filename. Opening verifies authentication before loading any
operation, idempotency entry, or fence. Missing/wrong keys, modified ciphertext,
and unsupported formats stop startup without overwriting the file. Encryption
does not establish that a backup is the newest one: verify its recovery-point
metadata and gateway generation before applying anything.

Start a controller pointed at the isolated database and a non-production hostname. Confirm `/healthz`, `/readyz`, list counts, revision/generation state, audit records, operation idempotency/fencing state, and that provider refresh is disabled until explicitly approved. Restore the gateway manifest and snapshots only on a disposable/isolated gateway; do not point it at production OPNsense or production clients.

Exercise one canary restore: read desired state, compare it to the gateway's observed state, and reconcile forward. If the gateway is already ahead of the database snapshot, read back and import/record its current generation before applying anything. Do not overwrite a newer applied generation with an old snapshot.

## Production recovery

Obtain an explicit change record, put enrollment changes on hold, and confirm the recovery console. Stop the controller only after confirming the active policy and management routes remain available. Restore the database to a new instance, validate it, switch the controller's `DATABASE_URL`, and restart/reconcile. Keep the original database read-only until the restored state has passed the canary.

If a restore cannot prove the key material, schema, gateway manifest, or OPNsense binding, stop. Keep the last-known-good gateway policy active and escalate; do not reset the gateway to an empty policy.

## Migrate a legacy plaintext controller journal

Startup deliberately rejects the old plaintext journal format. It never
silently rewrites or replaces it with an empty journal. Perform this one-time
conversion while the controller is stopped, using the migration executable
built from the same checkout/release:

```sh
go build -o ./journal-migrate ./cmd/journal-migrate
```

Take a protected backup of the legacy file first. Arrange for the migration
process to receive `APP_ENCRYPTION_KEY` and `APP_ENCRYPTION_KEY_ID` through the
same protected environment mechanism as the controller. The key must be base64
for exactly 32 random bytes; keep the existing application key and ID when
migrating an installation that already has encrypted inventory/lifecycle state.
Never put the key in command arguments or logs.

```sh
umask 077
./journal-migrate \
  -from /var/lib/homelab-proxy-controller/operations.json \
  -to /var/lib/homelab-proxy-controller/operations.encrypted.json
```

The destination must be distinct and absent. Migration writes and syncs a
private temporary ciphertext file, then publishes it without overwriting an
existing destination. The original remains byte-for-byte unchanged. A failed
conversion leaves it available for recovery; unsupported filesystems or
invalid/corrupt input fail without publishing a partial destination. This
command does not contact agents, alter traffic, or run operations.

Set `OPERATION_JOURNAL_PATH` to the new encrypted path, start the controller in
the intended recovery environment, and verify the operation list, states,
generations, and idempotency behavior before normal use. Retain the legacy copy
only in restricted recovery storage for the required retention window: it still
contains plaintext credentials. Do not point the plaintext journal reader at
the encrypted file; it rejects the format to prevent accidental state loss.

Each encrypted journal snapshot is limited to 16 MiB of plaintext. A write that
exceeds this limit fails without replacing the previous journal or publishing
the attempted in-memory mutation. Monitor journal growth; do not delete active,
uncertain, or rollback-referenced operations to bypass a storage failure.
