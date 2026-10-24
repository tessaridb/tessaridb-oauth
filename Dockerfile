# TessariDB OAuth, as a container: the server only. Its state lives in a TessariDB
# node that runs beside it; nothing of the database is inside this image.
#
# Two stages: the builder carries the Rust toolchain, the image somebody runs
# carries one executable and what it needs at run time.

# ── build ───────────────────────────────────────────────────────────────────
# Debian 13 like the image it feeds, so the binary links the C library it runs on.
FROM rust:1.98-slim-trixie@sha256:4cd829461bd5c4d511c32e269da9cb8929223b666519d8004e35fc8d1d771ab7 AS build

WORKDIR /src
COPY . .

# `--locked`: the committed lock file is the dependency graph the tests ran
# against. The sign-in, account and console pages are committed build output,
# so no Node is needed here.
RUN cargo build --release --locked -p tessari-oauth-node --bin tessaridb-oauth

# ── run ─────────────────────────────────────────────────────────────────────
# Distroless: the C runtime and CA certificates, no shell, no package manager.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:e792ab3d241a468a4fd7519ddbbebe66b49b5f365771716ea688ad40b6c6f1c2

COPY --from=build /src/target/release/tessaridb-oauth /usr/local/bin/tessaridb-oauth
COPY LICENSE /usr/share/doc/tessaridb-oauth/LICENSE

# What the server reads is in the README's configuration table. Two addresses
# have a default here, because a container's loopback is reachable from nothing
# outside it: the public listener and the admin console's listener.
#
# Required, and deliberately NOT defaulted: an image carrying a secret hands it
# to everybody who pulls it. The server refuses to start without them.
#
#   TESSARIDB_OAUTH_PUBLIC_URL, _ADMIN_URL      where users and operators reach it
#   TESSARIDB_OAUTH_KEK, _PEPPER                paths of two key files, owned by
#                                               the user the server runs as
#                                               (65532) and readable by it alone
#   TESSARIDB_OAUTH_STORE, _STORE_USER, _STORE_PASSWORD  the TessariDB node
#   TESSARIDB_OAUTH_REGION, _TENANTS
ENV TESSARIDB_OAUTH_PUBLIC_ADDRESS=0.0.0.0:8443 \
    TESSARIDB_OAUTH_ADMIN_ADDRESS=0.0.0.0:9443

EXPOSE 8443/tcp 9443/tcp

USER nonroot

# No init process: the server handles SIGTERM and SIGINT itself, finishing the
# requests in flight within 25 seconds, and starts no child process.
ENTRYPOINT ["/usr/local/bin/tessaridb-oauth"]
