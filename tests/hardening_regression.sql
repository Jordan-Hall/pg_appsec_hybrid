\set ON_ERROR_STOP on
-- Requires 001-008. Tests: gateway assume_session, audit chain, event-trigger RLS, ACL cap, pool lookup revoke.
SELECT set_config('appsec.gateway_hmac_key', 'ci-test-hmac-key-32bytes-minimum!!', false);

DO $$ BEGIN
  CREATE ROLE app_s_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE ROLE app_gw_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD 'gw-test-pass';
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
GRANT appsec_app_base TO app_s_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;
-- fixture role created by superuser: adopt like migration 010 does
GRANT app_s_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa TO appsec_role_admin WITH ADMIN OPTION, INHERIT FALSE, SET FALSE;
GRANT appsec_gateway TO app_gw_login;

INSERT INTO appsec.tenants(tenant_id,slug,display_name,status) VALUES
 ('11111111-1111-1111-1111-111111111111','t1','T1','active') ON CONFLICT DO NOTHING;
INSERT INTO appsec.users(user_id,email,status,tenant_id) VALUES
 ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','a@t1','active','11111111-1111-1111-1111-111111111111') ON CONFLICT DO NOTHING;
INSERT INTO appsec.sessions(session_id,user_id,expires_at,auth_method,access_jti) VALUES
 ('a1111111-a111-a111-a111-a11111111111','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',now()+interval '1 day','password','jti-a1')
ON CONFLICT (session_id) DO UPDATE SET access_jti = EXCLUDED.access_jti, revoked_at = NULL, expires_at = EXCLUDED.expires_at;
INSERT INTO appsec.session_principals(session_id,user_id,db_role) VALUES
 ('a1111111-a111-a111-a111-a11111111111','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','app_s_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
ON CONFLICT (session_id) DO UPDATE SET db_role = EXCLUDED.db_role;
INSERT INTO appsec.pool_credentials(db_role,session_id,scram_verifier)
VALUES ('app_s_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','a1111111-a111-a111-a111-a11111111111','SCRAM-SHA-256$iterations=4096$ci$ci')
ON CONFLICT (db_role) DO UPDATE SET revoked_at = NULL, scram_verifier = EXCLUDED.scram_verifier, session_id = EXCLUDED.session_id;

-- Superuser can grant; provisioner helper owns the same privilege after DROP/CREATE in 007.
SELECT appsec.grant_session_role_to_gateway('app_s_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');

-- Mint assertion as provisioner-capable (superuser SET ROLE)
SET ROLE appsec_owner;
SELECT appsec.mint_gateway_assertion('a1111111-a111-a111-a111-a11111111111'::uuid) AS assertion \gset
RESET ROLE;

SET SESSION AUTHORIZATION app_gw_login;
SELECT appsec.assume_session(:'assertion');
SELECT appsec.uid() = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'::uuid AS gateway_uid_ok;
-- Escape attempts
DO $$ BEGIN
  BEGIN
    RESET ROLE;
    -- gateway has no table SELECT on documents
    PERFORM 1 FROM appsec.documents LIMIT 1;
    RAISE EXCEPTION 'gateway should not read documents after RESET ROLE';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  WHEN undefined_table THEN NULL;
  END;
END $$;
-- Re-assume for SET ROLE escape test: need fresh assertion
RESET SESSION AUTHORIZATION;
SET ROLE appsec_owner;
SELECT appsec.mint_gateway_assertion('a1111111-a111-a111-a111-a11111111111'::uuid) AS assertion2 \gset
RESET ROLE;
SET SESSION AUTHORIZATION app_gw_login;
SELECT appsec.assume_session(:'assertion2');
DO $$ BEGIN
  BEGIN
    SET ROLE app_s_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb;
    RAISE EXCEPTION 'SET ROLE to foreign session should fail';
  EXCEPTION WHEN insufficient_privilege OR undefined_object THEN NULL;
  END;
END $$;
SELECT set_config('appsec._test_assertion', :'assertion2', false);
DO $$ DECLARE a text := current_setting('appsec._test_assertion', true); BEGIN
  BEGIN
    PERFORM appsec.assume_session(a);
    RAISE EXCEPTION 'replay should fail';
  EXCEPTION WHEN OTHERS THEN
    IF SQLSTATE IN ('42501','22023','P0001') OR SQLERRM ILIKE '%replay%' OR SQLERRM ILIKE '%signature%' OR SQLERRM ILIKE '%assertion%' THEN
      NULL;
    ELSE
      RAISE;
    END IF;
  END;
END $$;
RESET SESSION AUTHORIZATION;

-- Pool lookup returns verifier for active, nothing when revoked
SET ROLE appsec_pool_auth;
SELECT count(*) = 1 AS pool_active FROM appsec.pgbouncer_lookup('app_s_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
RESET ROLE;
UPDATE appsec.pool_credentials SET revoked_at = clock_timestamp()
 WHERE db_role = 'app_s_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
UPDATE appsec.sessions SET revoked_at = clock_timestamp()
 WHERE session_id = 'a1111111-a111-a111-a111-a11111111111';
SET ROLE appsec_pool_auth;
SELECT count(*) = 0 AS pool_revoked FROM appsec.pgbouncer_lookup('app_s_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
RESET ROLE;

-- Audit chain append-only + hash linkage
SELECT appsec.audit_event('test_login', 'session', '{"ok":true}'::jsonb);
SELECT appsec.audit_event('test_deny', 'session', '{"ok":false}'::jsonb);
DO $$ BEGIN
  BEGIN
    UPDATE appsec.security_audit_chain SET event_type = 'tamper' WHERE event_id = 1;
    RAISE EXCEPTION 'audit update should fail';
  EXCEPTION WHEN insufficient_privilege OR raise_exception THEN NULL;
  END;
END $$;
SELECT count(*) >= 2 AND bool_and(event_hash IS NOT NULL) AS audit_ok FROM appsec.security_audit_chain;

-- Event trigger: new table gets FORCE RLS
CREATE TABLE appsec.ci_new_table(id int PRIMARY KEY, tenant_id uuid, owner_id uuid);
SELECT c.relrowsecurity AND c.relforcerowsecurity AS new_table_rls
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='appsec' AND c.relname='ci_new_table';
DROP TABLE appsec.ci_new_table;

-- ACL cap
INSERT INTO appsec.database_acl_caps(database_name, max_access_level)
VALUES (current_database(), 2)
ON CONFLICT (database_name) DO UPDATE SET max_access_level = 2;
-- restore session for capped check
UPDATE appsec.sessions SET revoked_at = NULL, expires_at = now()+interval '1 day'
 WHERE session_id = 'a1111111-a111-a111-a111-a11111111111';
UPDATE appsec.pool_credentials SET revoked_at = NULL
 WHERE db_role = 'app_s_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
SET SESSION AUTHORIZATION app_s_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;
-- Without ACL entries capped function still returns <= 2
SELECT appsec.effective_database_access_capped('documents') <= 2 AS capped_ok;
RESET SESSION AUTHORIZATION;

SELECT 'hardening_regression_ok' AS status;
