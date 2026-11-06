# Build and verification status

- Migrations `001`–`008`: roles, schema, Domino ACL, identity/sessions, schema lockdown, custom RLS DSL, gateway/audit/defaults, SECURITY DEFINER audit + pool lockdown.
- OAuth validator: EdDSA/RS256/ES256, connect-time session-state file, jti denylist + in-process replay cache, kid JWKS rotation, role binding.
- CI: Rust/TS; SQL adversarial + custom RLS regression + SECURITY DEFINER audit + hardening regression; PgBouncer forced-user ban; OAuth Docker E2E matrix (valid, replay, badsig, expired, aud/iss/role, alg none, kid, revoked sid).
- Honest limits: independent crypto review still required; session-state file must be synced by the auth service (validator does not query SQL at connect); gateway HMAC key management is operationally critical; hash chain does not stop a superuser.
