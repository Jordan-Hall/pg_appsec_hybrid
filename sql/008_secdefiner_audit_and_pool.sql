\set ON_ERROR_STOP on
-- Harden SECURITY DEFINER search_path; revoke PUBLIC execute; pool lookup lock-down.
-- FORCE RLS on application data tables. Control-plane tables used by DEFINER
-- writers ENABLE RLS with owner policies but NO FORCE (owner must write).

DO $fix$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT n.nspname, p.proname, pg_get_function_identity_arguments(p.oid) AS args
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'appsec'
      AND p.prosecdef
      AND (p.proconfig IS NULL OR NOT EXISTS (
            SELECT 1 FROM unnest(p.proconfig) c WHERE c LIKE 'search_path=%'))
  LOOP
    EXECUTE format(
      'ALTER FUNCTION %I.%I(%s) SET search_path = pg_catalog, appsec, pg_temp',
      r.nspname, r.proname, r.args);
  END LOOP;
END
$fix$;

DO $rev$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT p.oid::regprocedure AS reg
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'appsec' AND p.prosecdef
  LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', r.reg);
  END LOOP;
END
$rev$;

REVOKE ALL ON FUNCTION appsec.pgbouncer_lookup(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION appsec.pgbouncer_lookup(text) FROM appsec_app_base, appsec_operator_base, appsec_gateway;
GRANT EXECUTE ON FUNCTION appsec.pgbouncer_lookup(text) TO appsec_pool_auth;

-- Application data: FORCE RLS on documents (app roles never own these rows' table).
-- document_acl: ENABLE RLS + owner policy, but NO FORCE so SECURITY DEFINER owner
-- helpers (can_read_document) can still evaluate ACL rows.
ALTER TABLE appsec.documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE appsec.documents FORCE ROW LEVEL SECURITY;
ALTER TABLE appsec.document_acl ENABLE ROW LEVEL SECURITY;
ALTER TABLE appsec.document_acl NO FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS document_acl_owner_all ON appsec.document_acl;
CREATE POLICY document_acl_owner_all ON appsec.document_acl FOR ALL TO appsec_owner USING (true) WITH CHECK (true);

-- Control-plane: ENABLE RLS, NO FORCE, owner full policy (app roles still need explicit grants).
DO $ctl$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'audit_events','security_audit_chain','sessions','session_principals',
    'pool_credentials','refresh_tokens','gateway_assertions','oauth_jti_denylist',
    'tenants','users','groups','group_members','user_roles','database_acl_entries',
    'jsonb_field_acl','identities','credentials','database_acl_caps'
  ] LOOP
    IF EXISTS (
      SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='appsec' AND c.relname=t AND c.relkind='r'
    ) THEN
      EXECUTE format('ALTER TABLE appsec.%I ENABLE ROW LEVEL SECURITY', t);
      EXECUTE format('ALTER TABLE appsec.%I NO FORCE ROW LEVEL SECURITY', t);
      EXECUTE format('DROP POLICY IF EXISTS %I ON appsec.%I', t || '_owner_all', t);
      EXECUTE format(
        'CREATE POLICY %I ON appsec.%I FOR ALL TO appsec_owner USING (true) WITH CHECK (true)',
        t || '_owner_all', t);
    END IF;
  END LOOP;
END
$ctl$;
