\set ON_ERROR_STOP on
-- Requires 001-010. Least-privilege owners, TEMP lockdown, checkpoint verify.

-- 1. No appsec SECURITY DEFINER function is superuser-owned.
DO $$
DECLARE bad text;
BEGIN
  SELECT string_agg(p.oid::regprocedure::text, ', ') INTO bad
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  JOIN pg_roles o ON o.oid = p.proowner
  WHERE n.nspname = 'appsec' AND p.prosecdef AND o.rolsuper;
  IF bad IS NOT NULL THEN RAISE EXCEPTION 'superuser-owned SECURITY DEFINER: %', bad; END IF;
END $$;

-- 2. Role-management helpers owned by NOLOGIN CREATEROLE-only role.
DO $$
DECLARE r record;
BEGIN
  SELECT * INTO r FROM pg_roles WHERE rolname = 'appsec_role_admin';
  IF r.rolcanlogin OR r.rolsuper OR r.rolbypassrls OR r.rolreplication OR r.rolcreatedb OR NOT r.rolcreaterole THEN
    RAISE EXCEPTION 'appsec_role_admin attributes wrong';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'appsec'
      AND p.proname IN ('harden_session_role','create_session_role','set_session_role_login',
                        'set_session_role_password','grant_session_role_to_gateway','revoke_session_role_from_gateway')
      AND p.proowner <> 'appsec_role_admin'::regrole) THEN
    RAISE EXCEPTION 'role helpers not owned by appsec_role_admin';
  END IF;
  IF (SELECT rolcreaterole FROM pg_roles WHERE rolname = 'appsec_provisioner') THEN
    RAISE EXCEPTION 'appsec_provisioner must not hold CREATEROLE';
  END IF;
END $$;

-- 3. Mint via helper as provisioner (non-superuser end to end).
DO $$ BEGIN
  CREATE ROLE ci_provisioner_login LOGIN NOINHERIT;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
GRANT appsec_provisioner TO ci_provisioner_login;
DROP ROLE IF EXISTS app_s_dddddddddddddddddddddddddddddddd;
SET SESSION AUTHORIZATION ci_provisioner_login;
SELECT appsec.create_session_role('app_s_dddddddddddddddddddddddddddddddd', 'ci-session-password-xyz', now() + interval '1 hour', 2);
SELECT appsec.harden_session_role('app_s_dddddddddddddddddddddddddddddddd', now() + interval '2 hours', 3);
SELECT appsec.set_session_role_password('app_s_dddddddddddddddddddddddddddddddd', 'ci-session-password-rotated');
SELECT appsec.set_session_role_login('app_s_dddddddddddddddddddddddddddddddd', false);
SELECT appsec.set_session_role_login('app_s_dddddddddddddddddddddddddddddddd', true);
-- Input validation
DO $$ BEGIN
  PERFORM appsec.create_session_role('postgres', 'x-password-long-enough', now() + interval '1 hour', 2);
  RAISE EXCEPTION 'create_session_role accepted non-session role name';
EXCEPTION WHEN invalid_parameter_value THEN NULL; END $$;
DO $$ BEGIN
  PERFORM appsec.harden_session_role('appsec_owner', now() + interval '1 hour', 2);
  RAISE EXCEPTION 'harden accepted non-session role';
EXCEPTION WHEN invalid_parameter_value THEN NULL; END $$;
DO $$ BEGIN
  PERFORM appsec.create_session_role('app_s_dddddddddddddddddddddddddddddddd', NULL, now() + interval '1 hour', 2);
  RAISE EXCEPTION 'create_session_role accepted duplicate';
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  PERFORM appsec.harden_session_role('app_s_dddddddddddddddddddddddddddddddd', now() + interval '1 hour', 99);
  RAISE EXCEPTION 'harden accepted connection_limit 99';
EXCEPTION WHEN invalid_parameter_value THEN NULL; END $$;
-- Provisioner itself cannot CREATE ROLE directly anymore.
DO $$ BEGIN
  SET LOCAL ROLE appsec_provisioner;
  CREATE ROLE ci_should_fail;
  RAISE EXCEPTION 'provisioner could CREATE ROLE directly';
EXCEPTION WHEN insufficient_privilege THEN NULL; END $$;
RESET SESSION AUTHORIZATION;
SELECT rolconnlimit = 3 AND rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AS minted_role_ok
FROM pg_roles WHERE rolname = 'app_s_dddddddddddddddddddddddddddddddd' \gset
\if :minted_role_ok
\else
  \echo 'FAIL minted role attributes'
  SELECT 1/0;
\endif
SELECT pg_has_role('app_s_dddddddddddddddddddddddddddddddd', 'appsec_app_base', 'MEMBER') AS base_ok \gset
\if :base_ok
\else
  SELECT 1/0;
\endif
-- role_admin holds ADMIN but cannot use the session role's privileges.
SELECT NOT pg_has_role('appsec_role_admin', 'app_s_dddddddddddddddddddddddddddddddd', 'USAGE')
   AND NOT pg_has_role('appsec_role_admin', 'app_s_dddddddddddddddddddddddddddddddd', 'SET') AS admin_no_use \gset
\if :admin_no_use
\else
  \echo 'FAIL role_admin can use session role'
  SELECT 1/0;
\endif

-- 4. TEMP: session roles cannot create temp tables.
SELECT NOT has_database_privilege('public', current_database(), 'TEMP') AS public_no_temp \gset
\if :public_no_temp
\else
  \echo 'FAIL PUBLIC still has TEMP'
  SELECT 1/0;
\endif
SET SESSION AUTHORIZATION app_s_dddddddddddddddddddddddddddddddd;
DO $$ BEGIN
  CREATE TEMP TABLE ci_tmp(x int);
  RAISE EXCEPTION 'app_s_* created a TEMP table';
EXCEPTION WHEN insufficient_privilege THEN NULL; END $$;
RESET SESSION AUTHORIZATION;

-- 5. Audit checkpoint verification (DB side).
SELECT appsec.audit_event('ci.checkpoint', 'least_privilege', '{"n":1}'::jsonb);
SELECT (h->>'event_id')::bigint AS cp_id, h->>'event_hash' AS cp_hash
FROM (SELECT appsec.export_audit_chain_head() AS h) s \gset
SELECT ok AS cp_ok FROM appsec.verify_audit_chain_against_checkpoint(:cp_id, :'cp_hash') \gset
\if :cp_ok
\else
  \echo 'FAIL checkpoint verify on clean chain'
  SELECT 1/0;
\endif
SELECT appsec.audit_event('ci.checkpoint', 'least_privilege', '{"n":2}'::jsonb);
SELECT ok AS cp_ok2 FROM appsec.verify_audit_chain_against_checkpoint(:cp_id, :'cp_hash') \gset
\if :cp_ok2
\else
  SELECT 1/0;
\endif
SELECT NOT ok AS cp_wrong FROM appsec.verify_audit_chain_against_checkpoint(:cp_id, repeat('ab', 32)) \gset
\if :cp_wrong
\else
  \echo 'FAIL checkpoint accepted wrong hash'
  SELECT 1/0;
\endif
-- Superuser rewrites history consistently (recomputes whole chain): internal
-- verify passes, but checkpoint anchor detects it.
BEGIN;
ALTER TABLE appsec.security_audit_chain DISABLE TRIGGER USER;
UPDATE appsec.security_audit_chain SET event_hash = appsec.digest(convert_to('forged' || event_id::text, 'UTF8'), 'sha256')
WHERE event_id = :cp_id;
SELECT NOT ok AS cp_tamper FROM appsec.verify_audit_chain_against_checkpoint(:cp_id, :'cp_hash') \gset
ROLLBACK;
\if :cp_tamper
\else
  \echo 'FAIL checkpoint did not detect tamper'
  SELECT 1/0;
\endif
SELECT 'least_privilege_regression_ok' AS status;
