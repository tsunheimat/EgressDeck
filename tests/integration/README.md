# PostgreSQL API integration

Run against a disposable PostgreSQL server with a role that can create and drop
databases:

```sh
TEST_DATABASE_URL='postgres://user:password@127.0.0.1:5432/postgres?sslmode=disable' \
  go test -race -count=1 -v ./tests/integration
```

Without `TEST_DATABASE_URL`, the test reports a skip. Each run creates a random
database, applies `migrations/schema.sql` twice, and drops that database during
cleanup. It never migrates or writes to the database named in the supplied URL.

The test exercises the actual HTTP API, PostgreSQL store, canonical schema, and
encrypted `Services.Load` persistence. It creates a provider, stages a private
node inline, and creates an outbound group, selection, rule set, policy, device
group, and dual-stack device through HTTP. It verifies automatically generated
UUIDs, five resource revision conflict boundaries, unchanged SQL resource state
with exactly one appended rejection audit event after rejected writes, and
absence of raw source URLs and node credentials across all
SQL-visible table rows. A new connection pool, server, and service registry must
restore the same identities, content, private node credentials, and selection.
A wrong encryption key must fail to load. Provider refresh after restart must
resolve the original encrypted subscription URL.

The selection adapter returns a fixture readback, and the refresh fetcher returns
fixture subscription content. This test establishes controller/database behavior;
it does not establish live gateway selection, external provider transport,
OPNsense enrollment, or network traffic acceptance.
