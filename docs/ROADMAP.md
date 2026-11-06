# Production roadmap and parity scope

## Implemented source components in this prototype

- Tenant registry and tenant-scoped users, credentials, groups, group memberships and application roles.
- Per-authenticated-session PostgreSQL login roles (`app_s_<session UUID>`) mapped to user/session records; no caller-selected identity GUC.
- Argon2id password hashing/verification; signup; email verification; tenant-scoped password signin; EdDSA access-token issuance; random SCRAM pool credentials; hashed refresh tokens; rotation and reuse-triggered session revocation.
- Session-aware identity resolution from `session_user`; active/expiry/revocation checks occur in the database on protected statements.
- PostgreSQL native RLS for tenant-scoped documents, Domino-style Readers/Authors users/groups/roles, database access levels and author/editor/delete semantics.
- Database ACL role assignments including `documents.create`, `documents.read_public`, `documents.write_public` and `tenants.create` privilege patterns.
- Column-level grants withholding raw JSONB document bodies; security-definer projection and controlled nested-path update APIs.
- JSONB deny-by-default field projection, exact-path write grants, protected-parent replacement rejection and create-time leaf checks.
- Generic tenant/owner RLS policy helper and column-privilege configuration helper for application-owned tables.
- PgBouncer session/transaction templates using per-session SCRAM roles and a restricted auth-query function; direct PostgreSQL OAuth contract and fail-closed C ABI skeleton.
- TypeScript SDK facade and auth transport contract.

## Remaining implementation and release work

- Complete PostgreSQL 18 OAuth validator: cryptographic JWT validation, bounded JWKS refresh/cache, issuer/audience/scope/type checks, key rotation, and exact requested-role binding.
- Implement a hosted Rust HTTP auth service, email delivery, password reset, MFA/TOTP, passkeys/WebAuthn, recovery codes, account linking, external OIDC identity lifecycle and Better Auth exchange adapter.
- Add robust signup policy hooks, username login, IP/device/account rate limiting, anti-enumeration, abuse controls and admin audit workflow.
- Add a janitor that safely drops expired per-session roles after proving no backend uses them and removing role memberships/dependencies. Load-test role churn and pool cardinality.
- Complete Domino ACL parity: inheritance and nested groups, ACL import/export, database design-element and agent execution controls, replication privileges, public document semantics, document-level ACL mutation auditing and all edge-case precedence rules.
- Generalize JSON Schema validation and field-level policy APIs to arbitrary JSONB resources; define safe merge/patch/delete semantics, array-element ACL semantics, schema versioning and generated column-safe views.
- Add audit triggers/events, tamper-resistant audit retention, policy introspection, decision explainability and administrative change history.
- Add policy compiler and safe schema DSL for arbitrary tables; current helpers are reference patterns, not automatic protection for every table or every JSONB column.
- Realtime/live query authorization, graph traversal permissions, FTS/vector integration, backups, replication, cluster operations and failover tests.
- Rust/TypeScript SDK packaging, CLI, migration/introspection tooling, OpenAPI docs and examples.
- Adversarial SQL tests, property/fuzz tests, concurrent signup/refresh/ACL tests, PgBouncer identity-isolation matrix, load/failover/restore tests, independent security review and supported-version CI.

## Release gate

Do not call this production-ready until the OAuth validator is implemented and reviewed, the Rust service and SQL migrations compile/run on supported PostgreSQL 18 minors, all access paths pass adversarial integration tests, PgBouncer session and transaction modes prove identity isolation under concurrency/failure, and an independent security review signs off.
