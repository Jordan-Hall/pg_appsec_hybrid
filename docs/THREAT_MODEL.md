# Threat model and mandatory controls

## Assets

Application-user identity, tenant boundaries, JSONB document contents, Readers/Authors ACLs, credentials, refresh tokens, signing/JWKS material, audit history and administrative capabilities.

## Trust boundaries

- PostgreSQL authentication establishes the database principal.
- `session_user` is the identity input for policy helpers. Do not use caller-set custom GUCs as identity.
- A PostgreSQL OAuth validator is trusted server code. A bug can authorize arbitrary database logins.
- Role provisioning is privileged control-plane work. Never expose `CREATE ROLE`, `ALTER ROLE`, `GRANT` or ownership changes to application principals.
- RLS is only effective if application roles do not own protected tables, are not superusers, and do not have `BYPASSRLS`.
- `SECURITY DEFINER` functions are privileged code. Pin `search_path`, schema-qualify objects, revoke PUBLIC execute, minimize owner privileges and audit every function.

## Identity invariants

1. Every active application principal maps to exactly one canonical application user.
2. The mapping key is the authenticated PostgreSQL role (`session_user`), not a SQL argument or GUC.
3. Application session roles use either PostgreSQL OAuth (direct connections) or a random per-session SCRAM password (PgBouncer); the human password is never the database password.
4. Application roles cannot inherit another user's role or assume operator/admin roles.
5. The validator compares verified issuer+subject mapping to the requested role; no arbitrary role delegation.
6. Pooling is per database and per-session database role. A shared forced backend user destroys the connection-principal invariant.

## RLS controls

- Enable and FORCE RLS on every tenant/document table.
- Use separate policies for SELECT, INSERT, UPDATE and DELETE.
- Check both `USING` and `WITH CHECK` on UPDATE.
- Deny by default when user/tenant/ACL lookup is absent.
- Protect ACL tables against application writes except through controlled functions.
- Test owner, superuser, `BYPASSRLS`, partition, view, foreign table, trigger and SECURITY DEFINER paths.

## JSONB field controls

A grant on a JSONB column grants access to the whole value. Never represent nested-key confidentiality as column privileges. Use dedicated projection views/functions and controlled patch operations. Ensure writes cannot modify protected keys through merge/replace operations, JSONPath, operators, triggers or alternate APIs. Audit policy changes. Consider splitting highly sensitive fields into separate columns/tables if hard isolation is required.

## Domino ACL semantics

Readers govern read eligibility; Authors govern update eligibility. These are not interchangeable. The sample functions are a minimal starting point and need complete semantics for ACL inheritance, roles, groups, public access, document creation, deletion, replication, agent/service identities and ACL mutation. Do not expose ACL table DML directly to end users.

## Pooling

Session pooling holds one server connection for the client session. Transaction pooling releases it after each transaction. With role-per-session backend identities, PgBouncer's `(database,user)` pools keep authenticated sessions distinct, but this creates more roles and backend pools. Set per-user, per-database and global limits. Never configure a forced shared `user=` for protected application traffic. Verify how client authentication is terminated and how backend authentication is performed; do not assume PostgreSQL OAuth is transparently passed through PgBouncer.

## Operational controls

TLS with certificate verification; secrets in a secret manager; short-lived access tokens; refresh-token rotation and reuse detection; key rotation; rate limiting; account lockout; email verification; password reset abuse controls; backup/restore; audit retention; alerting; schema migration review; dependency scanning; fuzzing; penetration testing; disaster recovery and failover testing.

## Additional controls in the hybrid implementation

- The trusted auth service uses `SET LOCAL ROLE appsec_provisioner` inside every transaction. Each login creates a unique `app_s_<session UUID>` role and random SCRAM password; only the SCRAM verifier is stored in PostgreSQL and returned through the dedicated PgBouncer auth lookup. Its login must be explicitly granted membership in this non-login role. Do not use this credential from web request handlers that also execute user SQL.
- `appsec_provisioner` has `CREATEROLE` and ADMIN OPTION on `appsec_app_base`; this is a high-privilege control-plane identity. Isolate it on a private network, use a dedicated secret manager identity, rotate credentials, and do not expose its pool to application query traffic.
- Per-session roles are derived only from generated UUIDs (`app_s_<32 hex>`), never from user-controlled email, username, JWT role claims or SQL fragments.
- The access token's `preferred_username` is a signed session-role claim. The OAuth validator compares it to PostgreSQL's requested role and returns that exact role as `authn_id`; RLS maps `session_user` through `appsec.session_principals` and verifies the active session row.
- The SQL identity helper checks `users.status='active'` on every invocation. Disabling a user therefore makes RLS predicates deny access on subsequent statements, including already-open sessions. Existing backend connections are denied by session-aware RLS checks; the auth service also sets the role `NOLOGIN`. Physical backend termination is a useful cleanup/defense-in-depth measure, not the sole revocation mechanism.
- Refresh-token reuse revokes the associated session, all refresh tokens and the pool credential. `appsec.uid()` checks the session row on every protected statement, so existing pooled backend connections are denied immediately after revocation. The auth service also sets the session role `NOLOGIN`.
- JSONB creation validates every configured protected path before inserting a document. Reads are deny-by-default projections; writes require an exact configured path grant and cannot replace a parent containing separately secured descendants.
- The JSONB path ACL applies to the `documents.body` API. It does not magically secure arbitrary JSONB columns in arbitrary application tables. Use the same protected API pattern or generated views/functions for each resource.
- The document owner is always retained in Readers and Authors, even when an ACL is replaced.


## Custom RLS helpers and DSL

- `appsec.uid()`, `tenant_id()`, `session_id()`, `has_role(text)`, `auth()` derive identity solely from `session_user` and catalog tables. Caller `set_config` GUCs are ignored.
- `define_table_permissions` / `define_field_permissions` are admin/owner-only, validate expressions, quote identifiers, FORCE RLS, and use RESTRICTIVE policies for optional tenant columns.
- Field select masking uses security-barrier views (`*_secured`); field updates are guarded by triggers. Treat expression validation as defense-in-depth, not a full SQL sandbox.
- Domino ACL remains optional and composable: RESTRICTIVE tenant policies AND with permissive DSL/hand policies; permissive policies OR with each other.


## What is protected and from whom

| Asset / boundary | Protected by | Against whom |
|---|---|---|
| End-user data rows (`documents`, DSL tables) | FORCE RLS + `appsec.uid()`/`tenant_id()` from `session_user` or gateway `current_user` | Other tenants/users, stolen GUCs, shared pool users |
| Connect-time OAuth login | Validator: sig/iss/aud/exp + session-state file + jti denylist/replay + role bind + kid JWKS + max-age fail-closed | Revoked/expired/unknown/stale sessions, alg none/HS*, wrong role, replayed jti |
| Session-state sync | `oauth-state-sync` LISTEN/NOTIFY worker: atomic write (temp+fsync+rename, 0600) | Stale/partial files; validator rejects when `generated_at`/mtime older than max age |
| PgBouncer pool login | Per-session SCRAM via `pgbouncer_lookup` (active sessions only); no forced `user=`; TLS required | Revoked sessions, shared backend user, cleartext pool passwords |
| Opt-in app gateway | `appsec_gateway` has no table privs; `assume_session` verifies HMAC assertion then `SET ROLE` | Spoofed assertions, replay, `SET ROLE` to foreign sessions, post-`RESET ROLE` data access |
| SECURITY DEFINER surface | Fixed `search_path`, `REVOKE PUBLIC`, CI audit | search_path hijack, accidental PUBLIC execute |
| New tables in `appsec` | Event trigger ENABLE+FORCE RLS | Accidentally open tables |
| Audit trail | Append-only hash-chained `security_audit_chain` + `verify_security_audit_chain` + optional `export_audit_chain_head` WORM anchor | Silent ACL/login tampering (detection; superuser can still rewrite if triggers disabled) |
| Database ACL ceiling | `database_acl_caps.max_access_level` | Over-privileged ACL grants |
| Public schema | `REVOKE CREATE` from PUBLIC; TEMP revoked where possible | Object object persistence / temp abuse |

## Hardening round 4 (strict validator state, live sync, least-privilege owners, TEMP, signed checkpoints)

| Area | What is protected | From whom | Mechanism | CI proof |
|---|---|---|---|---|
| Session-state parsing | Connect-time allow/deny decision | Anyone able to influence the state file contents (buggy exporter, partial writes, crafted entries) | Real JSON tokenizer (vendored jsmn v1.1.0, pinned by SHA-256), strict schema: exactly `generated_at` (UTC), `active_sessions` (`sid`+`role` required, only known keys), `revoked_sids`, `denied_jtis`; no escapes, no duplicates, no trailing data, size cap `pg_appsec.oauth_session_state_max_bytes` (default 8 MiB). Any error → login denied. Allow requires sid **and** role in the *same* active entry. | `ci_sync_e2e.sh` A: malformed, trailing, unknown key, substring confusion, escapes, missing generated_at, wrong type, revoked, oversized |
| jti replay file | Single-use access tokens | Token replay across backends | `"<jti> <exp>"` lines, exact match, `flock` + atomic rename, expired entries pruned on every login, `pg_appsec.oauth_jti_max_entries` (default 100000) cap → fail closed; over-long lines → fail closed | B: prune, replay, cap, over-long |
| Revocation latency | Revoked sessions cannot open new connections | Attacker holding a still-unexpired access token | `oauth-state-sync` LISTEN/NOTIFY + 1 s poll → atomic file; validator max-age fail-closed | C: revoke → denied ≤ 5 s (live PG + worker); worker killed → denied after max-age; restart → recovers |
| Role-management helpers | Ability to create/alter session roles | Compromise of any `SECURITY DEFINER` function owner | Owned by `appsec_role_admin` (NOLOGIN, CREATEROLE only, PG16+ semantics: manages only roles it holds ADMIN on, cannot use their privileges); `appsec_provisioner` no longer has CREATEROLE; no appsec `SECURITY DEFINER` function is superuser-owned | `least_privilege_regression.sql`, pooler E2E mints through the helper |
| TEMP | Temp-table/temp-function tricks by app sessions | Session roles | `REVOKE TEMPORARY ON DATABASE <db> FROM PUBLIC` (unconditional in 010). Grant `TEMP` explicitly to a named role only if an application truly needs it. | `app_s_*` `CREATE TEMP TABLE` → 42501 |
| Audit chain vs superuser | Detects history rewrite even if the chain is recomputed consistently | Superuser / DB-host attacker | Worker appends Ed25519-signed head checkpoints (`--audit-checkpoint-file`, `--audit-signing-key-file`, optional `--checkpoint-stdout`); `--verify-checkpoint-with <pub>` checks the signature and `appsec.verify_audit_chain_against_checkpoint` | D: OK, signature tamper, wrong key, consistent superuser rewrite detected |

**WORM shipping:** keep the signing seed off the database host if possible
(or at least unreadable by the `postgres` OS user), ship the checkpoint file
or stdout to append-only storage (S3 Object Lock in compliance mode, Azure
immutable blob, a remote syslog/SIEM), and keep the public key with the
auditors. A superuser can still delete *new* (post-checkpoint) events
undetected until the next checkpoint, and can stop the worker; alert on
checkpoint gaps.
