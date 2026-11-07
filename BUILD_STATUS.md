# Build status

Hardening through Domino/Surreal remaining-risk closures is on `main`.

- Migrations: `sql/001`…`sql/009_close_remaining_risks.sql` (regenerate `install.sql` via `tools/build_install_sql.py`).
- OAuth validator: connect-time session-state + jti denylist + **max-age fail-closed**.
- Sync worker: `crates/oauth-state-sync` (`oauth-state-sync` binary).
- Live pooler: `tests/pooler_e2e.sh`.


## Round 5 (Nov 2026)
- Validator per-tenant issuer map: strict JSON, exact normalised issuer and tenant match; substring helper removed. Tested with negative cases in the OAuth E2E (each denial matched to the logged reason).
- `appsec_state_sync` role (011); CI worker runs as a non-superuser member; regression test `tests/state_sync_role_regression.sql`.
- Live PG18 test of `pg-appsec-auth` (`crates/appsec-auth/tests/live_pg.rs`) in the SQL integration job; it found and fixed two real auth-service bugs (provisioner RLS visibility, tenant row lock).
- Not covered: the live test runs only the password flow (no OAuth/validator path) and does not run the PgBouncer path.
