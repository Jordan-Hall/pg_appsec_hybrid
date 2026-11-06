# Capability parity and implementation status

This is a target matrix, not a claim of complete parity.

| Capability | SurrealDB / Domino concept | Current implementation status |
|---|---|---|
| Record-user model | Surreal record users | User records, per-session PostgreSQL roles and active-session principal mapping are implemented in source; build and integration tests pending |
| Password signup/signin | SIGNUP / SIGNIN | Rust source implements signup, email verification, Argon2id signin, per-session roles, random SCRAM credentials, session revocation and refresh rotation; uncompiled and untested |
| OIDC/JWT | JWT access | PG18 OAuth validator verifies EdDSA/RS256/ES256 (independent crypto review still required) |
| Refresh rotation | WITH REFRESH | Rust source implements hashed rotating refresh tokens and reuse-triggered session revocation; uncompiled and untested |
| Authenticated session | `$auth` | `appsec.auth()` / `uid()` / `session_id()` from `session_user`; OAuth validator + SCRAM pool paths implemented in tree |
| Table/row permissions | PERMISSIONS | Hand-written `CREATE POLICY` with helpers, plus `define_table_permissions` DSL (FORCE RLS, optional RESTRICTIVE tenant) |
| Field permissions | DEFINE FIELD | JSONB projection APIs + `define_field_permissions` (security-barrier view + update trigger); see `docs/RLS.md` |
| Domino Readers | Readers | Document ACL read predicate, optional Readers-field restriction and public-read privilege are implemented and gated by database access |
| Domino Authors | Authors | Document ACL write predicate, Author roles/groups and Editor+ access are implemented; all Readers-field edge cases remain to be validated |
| Domino groups/roles | ACL roles/groups | Group membership schema and same-tenant group APIs implemented; role administration incomplete |
| Database ACL | Manager/Designer/Editor/Author/Reader/Depositor/No Access | Ordered access-level table and evaluator implemented; full inheritance/design-object semantics outstanding |
| Column security | SQL column privileges | Example table grants demonstrate restricted direct column access; resource automation incomplete |
| Realtime/live queries | Live queries | Not implemented; PostgreSQL LISTEN/NOTIFY is not equivalent by itself |
| Graph | Record links/graph traversal | Not implemented; PostgreSQL recursive queries/Apache AGE need separate design |
| Full-text/vector search | Search/indexes | PostgreSQL FTS/pgvector integration not implemented |
| Schema validation | DEFINE FIELD TYPE/ASSERT | JSONB object checks only; JSON Schema validation integration outstanding |
| Backup/HA/replication | Database operations | PostgreSQL deployment concern, not provided by extension |

## Release gates

No production claim until: OAuth validator passes independent review; role provisioning and password/session service are complete; RLS/ACL/JSONB privilege tests pass under app roles; pooler matrix proves identity isolation; fuzzing and load testing are complete; migration/upgrade/rollback tests pass; supported PostgreSQL 18 minor releases are tested.
