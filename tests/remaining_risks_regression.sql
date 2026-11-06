\set ON_ERROR_STOP on
-- Requires 001-009. Tests: assume_session_local, harden_session_role, audit verify/export, NOTIFY.
SELECT set_config('appsec.gateway_hmac_key', 'ci-test-hmac-key-32bytes-minimum!!', false);

DO $$ BEGIN
  CREATE ROLE app_s_cccccccccccccccccccccccccccccccc LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE ROLE app_gw_login2 LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD 'gw-test-pass';
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
GRANT appsec_app_base TO app_s_cccccccccccccccccccccccccccccccc;
-- fixture role created by superuser: adopt like migration 010 does
GRANT app_s_cccccccccccccccccccccccccccccccc TO appsec_role_admin WITH ADMIN OPTION, INHERIT FALSE, SET FALSE;
GRANT appsec_gateway TO app_gw_login2;

INSERT INTO appsec.tenants(tenant_id,slug,display_name,status) VALUES
 ('33333333-3333-3333-3333-333333333333','t3','T3','active') ON CONFLICT DO NOTHING;
INSERT INTO appsec.users(user_id,email,status,tenant_id) VALUES
 ('cccccccc-cccc-cccc-cccc-cccccccccccc','c@t3','active','33333333-3333-3333-3333-333333333333') ON CONFLICT DO NOTHING;
INSERT INTO appsec.sessions(session_id,user_id,expires_at,auth_method) VALUES
 ('c3333333-c333-c333-c333-c33333333333','cccccccc-cccc-cccc-cccc-cccccccccccc',now()+interval '1 day','password')
ON CONFLICT (session_id) DO UPDATE SET revoked_at=NULL, expires_at=EXCLUDED.expires_at;
INSERT INTO appsec.session_principals(session_id,user_id,db_role) VALUES
 ('c3333333-c333-c333-c333-c33333333333','cccccccc-cccc-cccc-cccc-cccccccccccc','app_s_cccccccccccccccccccccccccccccccc')
ON CONFLICT (session_id) DO UPDATE SET db_role=EXCLUDED.db_role;

SELECT appsec.harden_session_role('app_s_cccccccccccccccccccccccccccccccc', now()+interval '1 day', 2);
SELECT r.rolconnlimit = 2 AND r.rolvaliduntil IS NOT NULL AS harden_ok
FROM pg_roles r WHERE r.rolname='app_s_cccccccccccccccccccccccccccccccc';

SELECT appsec.grant_session_role_to_gateway('app_s_cccccccccccccccccccccccccccccccc');
SET ROLE appsec_owner;
SELECT appsec.mint_gateway_assertion('c3333333-c333-c333-c333-c33333333333'::uuid) AS assertion \gset
RESET ROLE;

-- assume_session_local inside a transaction
SET SESSION AUTHORIZATION app_gw_login2;
BEGIN;
SELECT appsec.assume_session_local(:'assertion');
SELECT appsec.uid() = 'cccccccc-cccc-cccc-cccc-cccccccccccc'::uuid AS local_uid_ok;
DO $$ BEGIN
  IF appsec.uid() IS DISTINCT FROM 'cccccccc-cccc-cccc-cccc-cccccccccccc'::uuid THEN
    RAISE EXCEPTION 'local uid mismatch after assume_session_local: %', appsec.uid();
  END IF;
END $$;
COMMIT;
-- After commit, should be back to gateway with no data access
DO $$ BEGIN
  BEGIN
    PERFORM 1 FROM appsec.documents LIMIT 1;
    RAISE EXCEPTION 'gateway should not read documents after COMMIT';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  WHEN undefined_table THEN NULL;
  END;
END $$;
RESET SESSION AUTHORIZATION;

-- Fresh assertion for outside-txn failure of assume_session_local
SET ROLE appsec_owner;
SELECT appsec.mint_gateway_assertion('c3333333-c333-c333-c333-c33333333333'::uuid) AS assertion3 \gset
RESET ROLE;
SET SESSION AUTHORIZATION app_gw_login2;
DO $$ DECLARE a text := current_setting('appsec._a3', true); BEGIN
  PERFORM set_config('appsec._a3', current_setting('assertion3', true), false);
EXCEPTION WHEN OTHERS THEN NULL;
END $$;
SELECT set_config('appsec._a3', :'assertion3', false);
-- Single-statement call: SET LOCAL applies only for the statement; afterward gateway has no session role.
SELECT appsec.assume_session_local(current_setting('appsec._a3'));
SELECT current_setting('role', true) IN ('none', '') OR current_setting('role', true) IS NULL
  OR current_setting('role', true) = session_user::text AS role_reset_after_statement;
DO $$ BEGIN
  BEGIN
    PERFORM 1 FROM appsec.documents LIMIT 1;
    RAISE EXCEPTION 'gateway should not read documents after single-statement assume_session_local';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  WHEN undefined_table THEN NULL;
  END;
END $$;
RESET SESSION AUTHORIZATION;

-- Audit verify + head export
SELECT appsec.audit_event('anchor_test', 'chain', '{"n":1}'::jsonb);
SELECT ok AS audit_verify_ok FROM appsec.verify_security_audit_chain() \gset
\if :audit_verify_ok
\else
  \echo 'FAIL audit chain invalid before tamper'
  SELECT 1/0;
\endif
SELECT (appsec.export_audit_chain_head()->>'event_hash') IS NOT NULL AS head_ok \gset
\if :head_ok
\else
  SELECT 1/0;
\endif

-- Tamper detection (rolled back so later suites see an intact chain).
BEGIN;
ALTER TABLE appsec.security_audit_chain DISABLE TRIGGER security_audit_chain_no_upd;
UPDATE appsec.security_audit_chain SET event_type = 'tampered' WHERE event_id = (
  SELECT max(event_id) FROM appsec.security_audit_chain
);
SELECT NOT ok AS audit_tamper_detected FROM appsec.verify_security_audit_chain() \gset
ROLLBACK;
\if :audit_tamper_detected
\else
  \echo 'FAIL audit tamper not detected'
  SELECT 1/0;
\endif

-- NOTIFY channel exists (trigger fires without error)
UPDATE appsec.sessions SET last_seen_at = clock_timestamp()
 WHERE session_id = 'c3333333-c333-c333-c333-c33333333333';

SELECT 'remaining_risks_regression_ok' AS status;
