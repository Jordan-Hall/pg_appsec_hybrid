\set ON_ERROR_STOP on
-- Run as a PostgreSQL superuser against a disposable database after migrations 001-005.
BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='app_s_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb') THEN
    CREATE ROLE app_s_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb LOGIN INHERIT NOBYPASSRLS;
  END IF;
END $$;
GRANT appsec_app_base TO app_s_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb;

INSERT INTO appsec.tenants(tenant_id,slug,display_name,status)
VALUES ('cccccccc-cccc-cccc-cccc-cccccccccccc','test-tenant','Test Tenant','active')
ON CONFLICT (tenant_id) DO UPDATE SET status='active';
INSERT INTO appsec.tenants(tenant_id,slug,display_name,status)
VALUES ('eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee','other-tenant','Other Tenant','active')
ON CONFLICT (tenant_id) DO UPDATE SET status='active';
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='app_s_cccccccccccccccccccccccccccccccc') THEN
    CREATE ROLE app_s_cccccccccccccccccccccccccccccccc LOGIN INHERIT NOBYPASSRLS;
  END IF;
END $$;
GRANT appsec_app_base TO app_s_cccccccccccccccccccccccccccccccc;
INSERT INTO appsec.users(user_id,email,status,tenant_id)
VALUES ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','bob@example.test','active','eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee')
ON CONFLICT (user_id) DO UPDATE SET status='active';
INSERT INTO appsec.sessions(session_id,user_id,expires_at,auth_method)
VALUES ('ffffffff-ffff-ffff-ffff-ffffffffffff','bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',clock_timestamp()+interval '1 day','password')
ON CONFLICT (session_id) DO UPDATE SET revoked_at=NULL,expires_at=EXCLUDED.expires_at;
INSERT INTO appsec.session_principals(session_id,user_id,db_role)
VALUES ('ffffffff-ffff-ffff-ffff-ffffffffffff','bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','app_s_cccccccccccccccccccccccccccccccc')
ON CONFLICT (session_id) DO UPDATE SET db_role=EXCLUDED.db_role;
INSERT INTO appsec.pool_credentials(db_role,session_id,scram_verifier)
VALUES ('app_s_cccccccccccccccccccccccccccccccc','ffffffff-ffff-ffff-ffff-ffffffffffff','SCRAM-SHA-256$4096:YWJj$ZGVm:Z2hp')
ON CONFLICT (db_role) DO UPDATE SET revoked_at=NULL;
INSERT INTO appsec.database_acl_entries(database_name,resource_name,principal_kind,principal_id,access_level)
VALUES (current_database(),'documents','user','bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',4)
ON CONFLICT (database_name,resource_name,principal_kind,principal_id) DO UPDATE SET access_level=4;
INSERT INTO appsec.users(user_id,email,status,tenant_id)
VALUES ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','alice@example.test','active','cccccccc-cccc-cccc-cccc-cccccccccccc')
ON CONFLICT (user_id) DO UPDATE SET status='active';
INSERT INTO appsec.sessions(session_id,user_id,expires_at,auth_method)
VALUES ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',clock_timestamp()+interval '1 day','password')
ON CONFLICT (session_id) DO UPDATE SET revoked_at=NULL,expires_at=EXCLUDED.expires_at;
INSERT INTO appsec.session_principals(session_id,user_id,db_role)
VALUES ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','app_s_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb')
ON CONFLICT (session_id) DO UPDATE SET db_role=EXCLUDED.db_role;
INSERT INTO appsec.pool_credentials(db_role,session_id,scram_verifier)
VALUES ('app_s_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','SCRAM-SHA-256$4096:YWJj$ZGVm:Z2hp')
ON CONFLICT (db_role) DO UPDATE SET revoked_at=NULL;
INSERT INTO appsec.user_roles(user_id,role_name,tenant_id,granted_by)
VALUES ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','documents.user','cccccccc-cccc-cccc-cccc-cccccccccccc','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa')
ON CONFLICT DO NOTHING;
INSERT INTO appsec.database_acl_entries(database_name,resource_name,principal_kind,principal_id,access_level)
VALUES (current_database(),'documents','user','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',4)
ON CONFLICT (database_name,resource_name,principal_kind,principal_id) DO UPDATE SET access_level=4;
INSERT INTO appsec.jsonb_field_acl(resource,json_path,read_roles,write_roles)
VALUES ('documents.body',ARRAY['title'],ARRAY['documents.user'],ARRAY['documents.user']),
       ('documents.body',ARRAY['secret'],ARRAY['documents.secret_reader'],ARRAY['documents.secret_writer'])
ON CONFLICT (resource,json_path) DO UPDATE SET read_roles=EXCLUDED.read_roles,write_roles=EXCLUDED.write_roles;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM appsec.pgbouncer_lookup('app_s_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb')) THEN
    RAISE EXCEPTION 'active per-session pool credential was not found';
  END IF;
END $$;

-- Seed a document with a secret field as the database owner. The application
-- role must only receive the explicitly authorized JSON path.
INSERT INTO appsec.documents(document_id,tenant_id,owner_id,body)
VALUES ('dddddddd-dddd-dddd-dddd-dddddddddddd','cccccccc-cccc-cccc-cccc-cccccccccccc',
        'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','{"title":"visible","secret":"never-visible-to-alice"}'::jsonb);
INSERT INTO appsec.document_acl(document_id,tenant_id,readers,authors)
VALUES ('dddddddd-dddd-dddd-dddd-dddddddddddd','cccccccc-cccc-cccc-cccc-cccccccccccc',
        ARRAY['aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa']::uuid[],ARRAY['aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa']::uuid[])
ON CONFLICT (document_id) DO UPDATE SET readers=EXCLUDED.readers,authors=EXCLUDED.authors;
INSERT INTO appsec.documents(document_id,tenant_id,owner_id,body)
VALUES ('eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee','eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee',
        'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','{"title":"bob-only"}'::jsonb);
INSERT INTO appsec.document_acl(document_id,tenant_id,readers,authors)
VALUES ('eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee','eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee',
        ARRAY['bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb']::uuid[],ARRAY['bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb']::uuid[]);

SET SESSION AUTHORIZATION app_s_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb;
DO $$
DECLARE projected jsonb;
BEGIN
  IF appsec.uid() <> 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'::uuid THEN
    RAISE EXCEPTION 'session_user principal mapping failed';
  END IF;
  PERFORM set_config('appsec.user_id','bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',true);
  IF appsec.uid() <> 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'::uuid THEN
    RAISE EXCEPTION 'caller-controlled GUC changed authenticated identity';
  END IF;
  SELECT body INTO projected FROM appsec.get_document('dddddddd-dddd-dddd-dddd-dddddddddddd');
  IF projected->>'title' <> 'visible' THEN RAISE EXCEPTION 'authorized JSON field missing'; END IF;
  IF projected ? 'secret' THEN RAISE EXCEPTION 'unauthorized JSON field leaked'; END IF;
  IF EXISTS (SELECT 1 FROM appsec.get_document('eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee')) THEN
    RAISE EXCEPTION 'cross-tenant document was visible';
  END IF;
  IF appsec.effective_database_access('documents') <> 4 THEN RAISE EXCEPTION 'unexpected database ACL level'; END IF;
  IF appsec.jsonb_all_leaf_paths_writable('documents.body','{"unconfigured":true}'::jsonb) THEN
    RAISE EXCEPTION 'unconfigured JSONB path was writable';
  END IF;
  BEGIN
    PERFORM body FROM appsec.documents WHERE document_id='dddddddd-dddd-dddd-dddd-dddddddddddd';
    RAISE EXCEPTION 'raw JSONB column was directly readable';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END $$;
RESET SESSION AUTHORIZATION;
UPDATE appsec.sessions SET revoked_at=clock_timestamp() WHERE session_id='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
UPDATE appsec.pool_credentials SET revoked_at=clock_timestamp() WHERE session_id='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
SET SESSION AUTHORIZATION app_s_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb;
DO $$ BEGIN
  IF appsec.uid() IS NOT NULL THEN RAISE EXCEPTION 'revoked session retained application identity'; END IF;
END $$;
RESET SESSION AUTHORIZATION;
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM appsec.pgbouncer_lookup('app_s_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb')) THEN
    RAISE EXCEPTION 'revoked session retained pool authentication';
  END IF;
END $$;
UPDATE appsec.sessions SET revoked_at=NULL,expires_at=clock_timestamp()+interval '1 day' WHERE session_id='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
UPDATE appsec.pool_credentials SET revoked_at=NULL WHERE session_id='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
SET SESSION AUTHORIZATION app_s_cccccccccccccccccccccccccccccccc;
DO $$ BEGIN
  IF appsec.uid() <> 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'::uuid THEN RAISE EXCEPTION 'second tenant principal resolution failed'; END IF;
  IF NOT EXISTS (SELECT 1 FROM appsec.get_document('eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee')) THEN RAISE EXCEPTION 'tenant owner could not read own document'; END IF;
  IF EXISTS (SELECT 1 FROM appsec.get_document('dddddddd-dddd-dddd-dddd-dddddddddddd')) THEN RAISE EXCEPTION 'second tenant could read first tenant document'; END IF;
END $$;
RESET SESSION AUTHORIZATION;
UPDATE appsec.tenants SET status='suspended' WHERE tenant_id='eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee';
SET SESSION AUTHORIZATION app_s_cccccccccccccccccccccccccccccccc;
DO $$ BEGIN
  IF appsec.uid() IS NOT NULL THEN RAISE EXCEPTION 'suspended tenant retained database identity'; END IF;
END $$;
RESET SESSION AUTHORIZATION;
UPDATE appsec.tenants SET status='active' WHERE tenant_id='eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee';
UPDATE appsec.sessions SET revoked_at=NULL,expires_at=clock_timestamp()+interval '1 day' WHERE session_id='ffffffff-ffff-ffff-ffff-ffffffffffff';
UPDATE appsec.pool_credentials SET revoked_at=NULL WHERE session_id='ffffffff-ffff-ffff-ffff-ffffffffffff';

-- A user-specific No Access entry overrides a public Reader grant.
INSERT INTO appsec.database_acl_entries(database_name,resource_name,principal_kind,principal_id,access_level)
VALUES (current_database(),'documents','public','*',2)
ON CONFLICT (database_name,resource_name,principal_kind,principal_id) DO UPDATE SET access_level=2;
INSERT INTO appsec.database_acl_entries(database_name,resource_name,principal_kind,principal_id,access_level)
VALUES (current_database(),'documents','user','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',0)
ON CONFLICT (database_name,resource_name,principal_kind,principal_id) DO UPDATE SET access_level=0;
SET SESSION AUTHORIZATION app_s_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb;
DO $$
BEGIN
  IF appsec.effective_database_access('documents') <> 0 THEN
    RAISE EXCEPTION 'specific No Access did not override public Reader';
  END IF;
  IF EXISTS (SELECT 1 FROM appsec.get_document('dddddddd-dddd-dddd-dddd-dddddddddddd')) THEN
    RAISE EXCEPTION 'No Access principal could still read document';
  END IF;
END $$;
RESET SESSION AUTHORIZATION;
ROLLBACK;
