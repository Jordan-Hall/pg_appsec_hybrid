# Build and verification status

- SQL migrations `001`–`006` install roles, schema, Domino ACL, identity/session principals, schema lockdown, and Surreal-style custom RLS helpers/DSL.
- Rust `pg-appsec-auth` crate: signup/signin, per-session role provisioning, SCRAM verifiers, EdDSA access tokens, refresh rotation, revocation.
- TypeScript SDK facade typechecks under TypeScript 5.8.3.
- PostgreSQL 18 OAuth validator (`oauth-validator/pg_appsec_oauth.c`) verifies EdDSA/RS256/ES256, rejects `none`/HS*, pins iss/aud/scope/`token_use=access`, maps `preferred_username` to `app_s_<sid>`.
- CI: Rust/clippy/fmt + TS; SQL adversarial + security regression (helpers, DSL, ACL, GUC spoof); PgBouncer forced-`user=` ban; OAuth token matrix on PG18.
- **Honest limits:** OAuth crypto and SECURITY DEFINER surface need independent review before production. Session revocation for OAuth is enforced by `appsec.uid()`/RLS after connect (and optional role `NOLOGIN`), not by a connect-time denylist inside the validator. PgBouncer does not passthrough PG OAuth — use SCRAM pool credentials for pooled traffic.
