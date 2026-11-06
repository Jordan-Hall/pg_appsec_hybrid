# Pooling and authenticated application principals

## Identity invariant

Every application login session gets a unique PostgreSQL role named `app_s_<32 hex UUID>`. The role is mapped to `(user_id, session_id)` in `appsec.session_principals`. `appsec.uid()` resolves the actual `session_user` through that table and verifies the user is active and the session is unrevoked and unexpired on every protected statement. No custom GUC, request header, JWT-supplied user ID or `SET ROLE` impersonation is used as the authorization identity.

This is deliberately a per-session principal, not one permanent PostgreSQL role per person. It gives each authenticated SurrealDB-style session its own identity and makes logout, refresh-token reuse and session expiry enforceable even when a backend connection remains open.

## Session pooling

Use one pool identity per `app_s_...` role. A backend connection remains attached to one authenticated application session. On logout or expiry, the SQL identity function returns NULL and RLS denies protected access; the auth service also marks the role `NOLOGIN` and revokes its PgBouncer credential.

## Transaction pooling

PgBouncer transaction pooling is safe only when each session role gets a distinct backend pool. Do not set a forced database `user=`. The transaction pool key must include the session-specific username. A backend authenticated as session A must never be checked out for session B.

PgBouncer does not implement PostgreSQL's OAuth validator protocol as a transparent passthrough. The transaction/session pool templates therefore use SCRAM for pooler access. The Rust auth service creates a random, high-entropy database password per authenticated session, stores only its PostgreSQL SCRAM verifier in `appsec.pool_credentials`, and returns the cleartext password once to the authenticated client. PgBouncer obtains the verifier through `appsec.pgbouncer_lookup()` using a dedicated `pgbouncer_auth` login that is granted only `appsec_pool_auth`.

The application client connects to PgBouncer using `user = AuthTokens.user.databaseRole` and `password = AuthTokens.databasePassword`. The database backend also authenticates as that same per-session role. No shared backend user is permitted. Configure the `pgbouncer_auth` password in the pooler's protected `userlist.txt`; do not place application-user passwords there.

## Direct PostgreSQL OAuth

For direct connections, the client uses the same session role as the requested PostgreSQL username and the access token as the OAuth bearer credential. The validator must return that exact role as `authn_id`, without `delegate_ident_mapping`. The token contains `sub`, `sid`, `preferred_username`, `iss`, `aud`, `exp`, `nbf`, `jti`, `scope` and `token_use`. RLS maps the authenticated role to the active session.

## Revocation and cleanup

Logout, password change, account disable, refresh-token reuse and expiry revoke the session, revoke the pool credential and set the session role `NOLOGIN`. Existing backend connections remain physically open until released, but every protected statement fails the session lookup and RLS denies access. Run `AuthService::reap_expired_sessions()` periodically to mark expired roles `NOLOGIN`; a later maintenance job may drop roles only after confirming no backend still uses them and removing their memberships/dependencies.

Per-session roles increase PostgreSQL role and PgBouncer pool cardinality. Load-test realistic concurrent session counts, pool churn, idle eviction and `max_db_connections`. Keep pool sizes small (usually one backend per active session) and enforce global connection limits. This architecture trades role churn for strong per-session isolation.


## PgBouncer reset

`config/pgbouncer-transaction.ini` sets `server_reset_query = DISCARD ALL` and `server_reset_query_always = 1` so session state cannot leak across clients sharing a backend. Never configure a forced database `user=` for application traffic; CI runs `tools/check_pgbouncer_no_forced_user.sh`.
