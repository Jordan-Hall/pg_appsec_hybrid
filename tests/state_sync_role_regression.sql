\set ON_ERROR_STOP on
-- Requires 001-011. oauth-state-sync role: export only, no table access, no escalation.
DO $$ BEGIN
  CREATE ROLE oauth_state_sync_reg LOGIN INHERIT IN ROLE appsec_state_sync;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Catalog-level: attributes, memberships, zero table privileges.
DO $$
DECLARE bad text;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN ('appsec_state_sync','oauth_state_sync_reg')
             AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls)) THEN
    RAISE EXCEPTION 'state-sync role has elevated attributes';
  END IF;
  IF (SELECT rolcanlogin FROM pg_roles WHERE rolname = 'appsec_state_sync') THEN
    RAISE EXCEPTION 'appsec_state_sync must be NOLOGIN';
  END IF;
  SELECT string_agg(r.rolname, ',') INTO bad
  FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid
  WHERE m.member = 'appsec_state_sync'::regrole;
  IF bad IS NOT NULL THEN RAISE EXCEPTION 'appsec_state_sync is a member of: %', bad; END IF;
  SELECT string_agg(c.oid::regclass::text, ',') INTO bad
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname IN ('appsec','public') AND c.relkind IN ('r','v','m','p','f')
    AND (has_table_privilege('oauth_state_sync_reg', c.oid, 'SELECT')
      OR has_table_privilege('oauth_state_sync_reg', c.oid, 'INSERT')
      OR has_table_privilege('oauth_state_sync_reg', c.oid, 'UPDATE')
      OR has_table_privilege('oauth_state_sync_reg', c.oid, 'DELETE'));
  IF bad IS NOT NULL THEN RAISE EXCEPTION 'state-sync role has table privileges on: %', bad; END IF;
  SELECT string_agg(p.oid::regprocedure::text, ', ') INTO bad
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'appsec' AND p.prosecdef
    AND has_function_privilege('oauth_state_sync_reg', p.oid, 'EXECUTE')
    AND p.oid NOT IN ('appsec.export_oauth_session_state()'::regprocedure,
                      'appsec.export_audit_chain_head()'::regprocedure,
                      'appsec.verify_audit_chain_against_checkpoint(bigint,text)'::regprocedure);
  IF bad IS NOT NULL THEN RAISE EXCEPTION 'state-sync role can execute extra SECURITY DEFINER: %', bad; END IF;
END $$;

SET SESSION AUTHORIZATION oauth_state_sync_reg;
-- Allowed: the exports it needs.
SELECT jsonb_typeof(appsec.export_oauth_session_state()) = 'object' AS export_ok \gset
\if :export_ok
\else
  SELECT 1/0;
\endif
SELECT count(*) >= 0 AS head_ok FROM (SELECT appsec.export_audit_chain_head()) s \gset
LISTEN appsec_oauth_state;
UNLISTEN *;

-- Denied: every probe must fail with permission denied (42501) and that message.
DO $$
DECLARE
  stmt text;
  n int := 0;
BEGIN
  FOREACH stmt IN ARRAY ARRAY[
    'SELECT * FROM appsec.sessions',
    'SELECT * FROM appsec.users',
    'SELECT * FROM appsec.credentials',
    'SELECT * FROM appsec.pool_credentials',
    'SELECT * FROM appsec.refresh_tokens',
    'SELECT * FROM appsec.security_audit_chain',
    'SELECT * FROM appsec.documents',
    'UPDATE appsec.sessions SET revoked_at = NULL',
    'DELETE FROM appsec.security_audit_chain',
    'SET ROLE appsec_owner',
    'SET ROLE appsec_provisioner',
    'SET ROLE appsec_role_admin',
    'SET ROLE postgres',
    'SELECT appsec.create_session_role(''app_s_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'', NULL, now() + interval ''1 hour'', 2)',
    'SELECT appsec.harden_session_role(''app_s_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'', now() + interval ''1 hour'', 2)',
    'SELECT appsec.grant_session_role_to_gateway(''app_s_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'')',
    'SELECT appsec.audit_event(''x'', NULL, ''{}''::jsonb)',
    'SELECT appsec.pgbouncer_lookup(''postgres'')',
    'SELECT appsec.verify_security_audit_chain()',
    'CREATE TABLE appsec.ci_sync_pwn(x int)',
    'CREATE TABLE public.ci_sync_pwn(x int)',
    'CREATE TEMP TABLE ci_sync_tmp(x int)',
    'CREATE ROLE ci_sync_pwn',
    'ALTER ROLE oauth_state_sync_reg BYPASSRLS',
    'GRANT appsec_owner TO oauth_state_sync_reg'
  ] LOOP
    BEGIN
      EXECUTE stmt;
      RAISE EXCEPTION 'state-sync role was ALLOWED: %', stmt USING ERRCODE = 'P0001';
    EXCEPTION
      WHEN insufficient_privilege THEN
        IF SQLERRM !~* '(permission denied|must have|only roles with)' THEN
          RAISE EXCEPTION 'unexpected denial text for %: %', stmt, SQLERRM;
        END IF;
        RAISE NOTICE 'DENIED % -> %', stmt, SQLERRM;
        n := n + 1;
    END;
  END LOOP;
  RAISE NOTICE 'state-sync denials: %', n;
END $$;
RESET SESSION AUTHORIZATION;
SELECT 'state_sync_role_regression_ok' AS status;
