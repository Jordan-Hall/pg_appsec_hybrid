\set ON_ERROR_STOP on
DO $$
DECLARE bad text := '';
DECLARE r record;
BEGIN
  FOR r IN
    SELECT n.nspname||'.'||p.proname||'('||pg_get_function_identity_arguments(p.oid)||')' AS sig
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'appsec' AND p.prosecdef
      AND (p.proconfig IS NULL OR NOT EXISTS (
            SELECT 1 FROM unnest(coalesce(p.proconfig, ARRAY[]::text[])) c WHERE c LIKE 'search_path=%'))
  LOOP
    bad := bad || r.sig || '; ';
  END LOOP;
  IF bad <> '' THEN RAISE EXCEPTION 'SECURITY DEFINER missing search_path: %', bad; END IF;

  bad := '';
  FOR r IN
    SELECT n.nspname||'.'||p.proname AS sig
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'appsec' AND p.prosecdef
      AND has_function_privilege('public', p.oid, 'EXECUTE')
  LOOP
    bad := bad || r.sig || '; ';
  END LOOP;
  IF bad <> '' THEN RAISE EXCEPTION 'SECURITY DEFINER executable by PUBLIC: %', bad; END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='appsec' AND c.relname='documents' AND c.relrowsecurity AND c.relforcerowsecurity
  ) THEN
    RAISE EXCEPTION 'documents must ENABLE+FORCE RLS';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='appsec' AND c.relname='document_acl' AND c.relrowsecurity AND c.relforcerowsecurity
  ) THEN
  END IF;
END $$;
SELECT 'security_audit_ci_ok' AS status;
