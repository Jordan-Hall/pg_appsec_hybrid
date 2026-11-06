# PostgreSQL 18 OAuth validator integration

PostgreSQL 18 provides a C callback ABI for OAuth validators. The callback receives the bearer token and requested PostgreSQL role. It must verify the token and return an authenticated identity; by default PostgreSQL requires `authn_id` to match the requested role exactly. This project deliberately avoids `delegate_ident_mapping`.

## pg_appsec token contract

The trusted Rust auth service issues an internal EdDSA access token with:

- `iss`, `aud`, `exp`, `nbf`, `iat`, `jti`;
- `sub`: application-user UUID;
- `sid`: authenticated session UUID;
- `preferred_username`: the exact generated `app_s_<32 hex>` PostgreSQL session role;
- `token_use=access` and `scope` containing `pg_appsec`.

The validator must:

1. Verify EdDSA signature against the configured public key/JWKS, with bounded key refresh, TLS verification and rotation handling.
2. Pin exact issuer and audience; validate `exp`, `nbf`, `iat`, token type, client identity and required database scope.
3. Parse `sid` and require `preferred_username == app_s_<sid without hyphens>`; compare that exact value to PostgreSQL's requested `role` argument.
4. Set `result->authorized=true` and `result->authn_id` to a palloc'd copy of that exact session-role name only after all checks pass.
5. Never log raw tokens, fail closed on key/network/parse errors, bound token and claim sizes, and remain interruptible during network I/O.

The validator does not need to trust a client-provided user ID or resolve arbitrary role claims. PostgreSQL's `session_user` becomes the generated session role; `appsec.uid()` then resolves it through `appsec.session_principals` and checks user status, session expiry/revocation and role LOGIN/VALID UNTIL state on every protected statement. A revoked session can therefore no longer access protected data even if a previously issued access token has not yet expired.

External OIDC or Better Auth tokens should be exchanged by a trusted identity adapter: resolve `(issuer, subject)` through `appsec.identities`, apply account-linking policy, create a pg_appsec session, then issue this internal token. Do not treat a Better Auth cookie or generic ID token as a PostgreSQL access token.

## Build

Build the C module against the exact PostgreSQL 18 server headers and install it in PostgreSQL's library directory:

```sh
make PG_CONFIG=/path/to/pg18/bin/pg_config
make PG_CONFIG=/path/to/pg18/bin/pg_config install
```

Configure `oauth_validator_libraries = 'pg_appsec_oauth'` and an `oauth` HBA rule with issuer, scope and validator options. The included C module is intentionally fail-closed and rejects every token until the callback is implemented and independently reviewed.

PostgreSQL warns that a faulty validator can authorize unauthorized database connections. Its OAuth validator API and the exact callback contract are documented in the PostgreSQL 18 manual. Treat the module as security-critical server code.
