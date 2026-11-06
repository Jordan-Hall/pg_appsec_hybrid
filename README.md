# Recorda — database-native identity and authorization for PostgreSQL 18

**Status: early prototype / security review required. Not production-ready.** Recorda is an open-source design-and-implementation baseline for a PostgreSQL-native application identity layer. It deliberately does not claim that the included SQL alone delivers complete SurrealDB or Domino parity.

## Project status

Recorda is not a production authentication or authorization system yet. The PostgreSQL 18 OAuth validator currently rejects every token, the extension has not been compiled against PostgreSQL 18, the SQL migrations and adversarial tests have not been executed against a server, and the PgBouncer integration has not been exercised. Do not use it to protect production data or accept real credentials. CI is intended to establish repeatable verification; a green source-level check is not a production-readiness claim.

## Design decision

Each authenticated application session gets a unique PostgreSQL login role (`app_s_<session UUID>`). That role is mapped in `appsec.session_principals` to the application-user record and active session. PostgreSQL authenticates the connection; policies derive identity from `session_user` and verify the session is still active on every protected statement. This session-principal design works with direct PostgreSQL OAuth and with per-session SCRAM credentials through PgBouncer. The caller cannot choose an arbitrary user by setting a GUC. Privileged human operators may additionally have individually managed PostgreSQL roles and memberships. Service identities are separate and explicitly scoped.

The model supports:

- Native PostgreSQL OAuth authentication using a custom PostgreSQL 18 OAuth validator (C ABI module), mapping a signed session-role claim to a database session principal.
- Per-session PostgreSQL login roles for application users, plus separately managed privileged/service principals (hybrid mode).
- Random SCRAM database credentials for pooler access; only PostgreSQL SCRAM verifiers are stored, and PgBouncer retrieves them through a restricted `auth_query`.
- PostgreSQL RLS for document rows and Domino-like Readers/Authors/group rules.
- PostgreSQL column privileges for column exposure.
- JSONB document storage with explicit path-level allowlists and controlled patch APIs. PostgreSQL column grants do **not** secure individual JSONB keys.
- Session pooling and transaction pooling, with pools partitioned by the per-session PostgreSQL role. Each login session has its own pool identity; no backend is shared across application sessions.

## Critical pooling constraint

PgBouncer transaction pooling reuses backend connections between transactions. This design assigns a unique PostgreSQL role to each authenticated application session, so PgBouncer pools are partitioned by `(database, session-role)`. Leave PgBouncer's `user=` forced-user setting unset. The Rust auth service creates a random database password, stores only its SCRAM verifier, and PgBouncer retrieves it through `appsec.pgbouncer_lookup()` using a dedicated `pgbouncer_auth` account. This is separate from the user's human password.

PostgreSQL OAuth is used for direct connections; PgBouncer's standard authentication modes do not transparently forward PostgreSQL's OAuth exchange. The PgBouncer templates therefore use SCRAM, while direct PostgreSQL connections use OAuth. Both authenticate to the same session-specific role, and RLS resolves that role to the active application session.

## Files

- `pg_appsec.control` and `src/lib.rs`: installable pgrx PostgreSQL 18 extension shell plus SQL-callable Argon2id password primitives.
- `sql/install.sql`: generated extension install script; regenerate with `make build-install-sql` after changing migrations.
- `sql/001_roles.sql`: role and schema bootstrap (run as cluster/database administrator).
- `sql/002_schema.sql`: application-user, identity, role mapping, group and Domino ACL tables.
- `sql/003_policies.sql`: document table, native RLS, JSONB field policy helpers and example grants. `create_document` grants initial access only to its creator; sharing requires a separately authorized ACL operation.
- `sql/004_identity_sessions_acl.sql`: application auth/session tables, per-session principals, SCRAM lookup, Domino ACLs, tenant management and session APIs.
- `sql/005_schema_security.sql`: generic tenant/owner RLS and column-grant helpers for application-owned tables.
- `config/pg_hba.oauth.example`: PostgreSQL 18 OAuth HBA example (requires an installed validator).
- `config/pgbouncer-session.ini` and `config/pgbouncer-transaction.ini`: per-session SCRAM pool templates; configure the dedicated `pgbouncer_auth` login.
- `docs/THREAT_MODEL.md`: trust boundaries and mandatory controls.
- `docs/ROADMAP.md`: implementation milestones and parity matrix.
- `oauth-validator/`: PostgreSQL 18 OAuth validator implementation contract and C module skeleton.
- `crates/appsec-auth/`: Rust authentication/session service library; it is not an HTTP server.
- `tests/`: adversarial integration test plan; these tests are not represented as passing.

## Installation order

1. Build the extension with `cargo pgrx init --pg18 /path/to/pg_config` and `cargo pgrx package --pg-config /path/to/pg_config`.
2. Install the package in the PostgreSQL 18 installation and run `CREATE EXTENSION pg_appsec;` as a database administrator. The extension install script applies the ordered SQL migrations. For development, the individual migrations remain available under `sql/001_roles.sql` through `sql/005_schema_security.sql`.
3. Create a private `pg_appsec_auth` login using `examples/auth-service-role.sql`; it must be `NOINHERIT` and a member of `appsec_provisioner`. The trusted Rust auth service provisions one login role per authenticated session using `SET LOCAL ROLE appsec_provisioner`. Never let untrusted application sessions create or grant roles. The service returns a random database password for PgBouncer access; it is not the user's password. Create a separate `pgbouncer_auth` login using `examples/pgbouncer-auth.sql`; it inherits only `appsec_pool_auth`, which exposes the SCRAM lookup function. Configure its own SCRAM secret in PgBouncer's protected `userlist.txt`.
4. Build/install the PostgreSQL 18 OAuth validator following `oauth-validator/README.md`; configure `oauth_validator_libraries` and HBA as described.
5. Configure issuer, audience, allowed algorithms, token type, claim mapping, key rotation, revocation and role mapping in the validator. The skeleton intentionally fails closed and is not a working validator.
6. Run the adversarial tests and pooler matrix against the exact PostgreSQL, libpq, PgBouncer and driver versions in use.

## Authentication flows

### Signup/password

Tenant context is trusted input: the API derives the tenant from a verified invitation, hostname or server-side application context. Never accept an arbitrary tenant ID from the browser as an authorization decision.


Signup creates an application-user record, an Argon2id password hash and an email-verification challenge. It does not create a reusable login role. After successful signin, the service creates a unique `app_s_<session UUID>` PostgreSQL role, inserts the `(session_id,user_id,db_role)` mapping, and creates a random SCRAM password for PgBouncer. The access token carries the signed session role and session ID. The client receives the SCRAM password once; only its PostgreSQL verifier is stored. All role provisioning happens atomically in the trusted Rust auth service. Email uniqueness is tenant-scoped; signin must include the tenant resolved by the trusted backend.

### Pooler authentication

Create the dedicated PgBouncer auth account as a database administrator, then grant it the restricted lookup role:

```sql
CREATE ROLE pgbouncer_auth LOGIN PASSWORD 'replace-with-a-long-random-secret';
GRANT appsec_pool_auth TO pgbouncer_auth;
```

Configure the `pgbouncer_auth` SCRAM verifier in PgBouncer's `userlist.txt` with restrictive file permissions. Per-session application credentials are looked up from `appsec.pool_credentials`; they are not written to the static userlist. Do not configure a forced backend `user=`.

### OAuth / OIDC / Better Auth

For direct PostgreSQL connections, the OAuth validator verifies issuer, audience, signature, expiry, not-before, authorized party/client, scopes and token type. It compares the signed `preferred_username` session-role claim to the exact requested PostgreSQL role and returns that role as `authn_id`. The SQL identity helper maps `session_user` to the application user and verifies that the associated session is active. Do not enable `delegate_ident_mapping`.

External OIDC and Better Auth tokens need an identity-exchange adapter that resolves `(issuer, subject)` through `appsec.identities` and issues a pg_appsec session token. Do not assume a Better Auth session cookie is a PostgreSQL OAuth bearer token. The included OAuth validator is currently a fail-closed skeleton, not a working implementation.

## Guarantees and non-guarantees

- RLS can enforce row visibility and mutation predicates when all application access runs as non-owner principals without `BYPASSRLS`.
- `session_user` is the authenticated database role and cannot be changed by `SET ROLE`; `current_user` can change and is not the identity source used by these policies.
- JSONB is not automatically field-secure. Use the included path-policy pattern only as a starting point; production must provide safe read projections and controlled patch operations.
- SQL superusers, table owners without `FORCE ROW LEVEL SECURITY`, roles with `BYPASSRLS`, unsafe `SECURITY DEFINER` functions and unrestricted replication/maintenance channels remain privileged bypass paths.
- This prototype has not been compiled, installed or tested against PostgreSQL 18 in this environment. Do not deploy it with real credentials or data.

## License

Apache-2.0. See `LICENSE`.

## Added implementation increment

Migration `sql/004_identity_sessions_acl.sql` adds credentials, application sessions, per-session PostgreSQL principals, SCRAM verifier lookup, refresh-token rotation, verification, Domino-style database ACL levels and Readers/Authors (including roles and groups). Access levels are No Access (0), Depositor (1), Reader (2), Author (3), Editor (4), Designer (5) and Manager (6). The TypeScript SDK facade is in `sdk/typescript/index.ts`. The Rust auth-service crate implements transactional signup, email verification, Argon2id password sign-in, one login role per session, random SCRAM credentials for PgBouncer, EdDSA access-token issuance, refresh rotation and reuse-triggered session revocation. It must use a dedicated control-plane connection whose login is a member of `appsec_provisioner`; the crate executes `SET LOCAL ROLE appsec_provisioner` inside each transaction.

The pgrx extension, OAuth module and Rust auth crate are source implementations, not a verified release: no Rust toolchain or PostgreSQL 18 server was available for compilation/integration testing in this environment. The PostgreSQL OAuth validator remains deliberately fail-closed and therefore direct database OAuth login is not yet operational. The auth crate is a library, not a hosted HTTP API; an application adapter must expose its token-gated methods and pass verified bearer tokens, never caller-supplied actor IDs. Do not deploy this package as production authentication until the validator is implemented, built against PostgreSQL 18 headers, and independently reviewed. See `docs/PARITY.md` for the exact remaining gaps.
