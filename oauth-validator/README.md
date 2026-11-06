# PostgreSQL 18 OAuth validator (`pg_appsec_oauth`)

Fail-closed validator for internal pg_appsec access tokens. Supports **EdDSA**, **RS256**, and **ES256**. Rejects `alg=none` and HMAC (`HS*`) algorithms (no public-key/HMAC confusion).

## Token contract

- Required claims: `iss`, `aud`, `exp`, `nbf`, `iat`, `jti`, `sub`, `sid`, `preferred_username`, `token_use=access`, `scope` containing `pg_appsec`.
- `preferred_username` must equal `app_s_<sid without hyphens>` and must equal the PostgreSQL requested role.
- On success sets `authn_id` to that exact role name. No `delegate_ident_mapping`.

## Configuration (GUCs)

| GUC | Purpose |
|---|---|
| `pg_appsec.oauth_issuer` | Exact issuer URL |
| `pg_appsec.oauth_audience` | Exact audience |
| `pg_appsec.oauth_required_scope` | Required scope token (default `pg_appsec`) |
| `pg_appsec.oauth_pubkey_file` | PEM public key file (Ed25519 / RSA / EC) |
| `pg_appsec.oauth_jwks_file` | Optional JWKS/PEM JSON helper file |
| `pg_appsec.oauth_clock_skew` | Skew seconds (default 60) |

Load with `shared_preload_libraries` / `oauth_validator_libraries = 'pg_appsec_oauth'` and an `oauth` HBA line.

## Build / E2E

```sh
make -C oauth-validator PG_CONFIG=/path/to/pg18/bin/pg_config
# install .so into pkglibdir, configure GUCs + HBA, restart
python3 oauth-validator/mint_tokens.py
# oauth_client injects bearer via PQsetAuthDataHook
```

CI runs the matrix: valid OK; badsig / expired / wrong aud / wrong iss / wrong role / alg none all denied.

## Revocation honesty

Connect-time revocation against `appsec.sessions` is not performed inside the validator (no database handle in the ABI). After connect, `appsec.uid()` / RLS deny revoked or expired sessions; the auth service also sets the role `NOLOGIN`. Optional jti denylist can be added later.

## Risk

Treat this module as security-critical. **Independent cryptographic review is required before production.** Never log raw tokens.
