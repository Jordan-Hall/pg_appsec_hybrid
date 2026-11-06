# Build status

Hardening through Domino/Surreal remaining-risk closures is on `main`.

- Migrations: `sql/001`…`sql/009_close_remaining_risks.sql` (regenerate `install.sql` via `tools/build_install_sql.py`).
- OAuth validator: connect-time session-state + jti denylist + **max-age fail-closed**.
- Sync worker: `crates/oauth-state-sync` (`oauth-state-sync` binary).
- Live pooler: `tests/pooler_e2e.sh`.
