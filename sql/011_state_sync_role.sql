-- 011: dedicated least-privilege role for the oauth-state-sync worker.
-- appsec_state_sync (NOLOGIN group): USAGE on schema appsec + EXECUTE on the
-- three export/verify functions only. No table privileges, no other roles.
-- LISTEN needs no privilege in PostgreSQL. Create a LOGIN member per host:
--   CREATE ROLE oauth_state_sync LOGIN INHERIT PASSWORD '...' IN ROLE appsec_state_sync;
RESET ROLE;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'appsec_state_sync') THEN
    CREATE ROLE appsec_state_sync NOLOGIN NOINHERIT;
  END IF;
END
$$;
ALTER ROLE appsec_state_sync NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT USAGE ON SCHEMA appsec TO appsec_state_sync;
GRANT EXECUTE ON FUNCTION appsec.export_oauth_session_state(),
                          appsec.export_audit_chain_head(),
                          appsec.verify_audit_chain_against_checkpoint(bigint, text)
  TO appsec_state_sync;
