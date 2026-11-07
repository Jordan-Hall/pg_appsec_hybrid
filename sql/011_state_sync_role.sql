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

-- Fix (found by the live Rust auth-service test): 008 enabled RLS on the
-- control-plane tables with an owner-only policy, which silently hid every
-- row from appsec_provisioner (the auth service), so sign-up/sign-in failed.
-- The provisioner is the trusted control plane; give it an explicit policy.
-- Table GRANTs still decide what it may do; app/session roles get nothing.
DO $ctl$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'audit_events','security_audit_chain','sessions','session_principals',
    'pool_credentials','refresh_tokens','gateway_assertions','oauth_jti_denylist',
    'tenants','users','groups','group_members','user_roles','database_acl_entries',
    'jsonb_field_acl','identities','credentials','database_acl_caps','email_verifications'
  ] LOOP
    IF EXISTS (
      SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='appsec' AND c.relname=t AND c.relkind='r' AND c.relrowsecurity
    ) THEN
      EXECUTE format('DROP POLICY IF EXISTS %I ON appsec.%I', t || '_provisioner_all', t);
      EXECUTE format(
        'CREATE POLICY %I ON appsec.%I FOR ALL TO appsec_provisioner USING (true) WITH CHECK (true)',
        t || '_provisioner_all', t);
    END IF;
  END LOOP;
END
$ctl$;
