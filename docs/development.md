# Development

The workspace layout and the live test suites.

## Layout

| Crate | Role |
|---|---|
| `tessari-oauth-constants` | every limit and alphabet, with its unit and source |
| `tessari-oauth-types` | protocol values as types, and the error taxonomy |
| `tessari-oauth-core` | the protocol core, pure and testable without a server |
| `tessari-oauth-storage` | persistence on TessariDB, by domain |
| `tessari-oauth-infrastructure` | database connection, key custody, guarded outbound HTTP |
| `tessari-oauth-observability` | tracing and metrics, with secrets kept out of logs |
| `tessari-oauth-api` | protocol, account and admin routes |
| `tessari-oauth-daemons` | expiry, key rotation, logout delivery |
| `tessari-oauth-node` | the `tessaridb-oauth` binary |

## Live tests

The storage tests that need a database are marked `ignored` and run against a TessariDB node you name:

```sh
docker run -d --rm --name oauth-live -p 127.0.0.1:39601:9080 \
  -e TESSARIDB_INITIAL_USER=oauth -e TESSARIDB_INITIAL_PASSWORD="$PASSWORD" tessaridb/tessaridb:0.36.2
TESSARIDB_OAUTH_TEST_STORE=127.0.0.1:39601 TESSARIDB_OAUTH_TEST_USER=oauth \
  TESSARIDB_OAUTH_TEST_PASSWORD="$PASSWORD" cargo test -p tessari-oauth-storage --test live -- --ignored
```

Each test works in a namespace of its own; a run removes the namespaces earlier runs left before its first test
starts, so the node holds at most one run's. The suite can run repeatedly against one node. The two TLS
tests also need a node serving TLS (`TESSARIDB_OAUTH_TEST_TLS_STORE`), the PEM of the authority that signed its
certificate (`TESSARIDB_OAUTH_TEST_TLS_AUTHORITY`) and the PEM of an unrelated one
(`TESSARIDB_OAUTH_TEST_TLS_OTHER_AUTHORITY`).
The regions test also needs a second node, standing for another region, with its owner
(`TESSARIDB_OAUTH_TEST_PEER_STORE`, `_PEER_USER`, `_PEER_PASSWORD`).
Without an authority the server reaches its store only at `127.0.0.1` or `[::1]`.
