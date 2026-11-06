\set ON_ERROR_STOP on
-- Expect migrations 001-006 already applied. Run as superuser; switches to LOGIN roles.
BEGIN;
DO $$ BEGIN
  CREATE ROLE app_s_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE ROLE app_s_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
GRANT appsec_app_base TO app_s_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, app_s_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb;

INSERT INTO appsec.tenants(tenant_id,slug,display_name,status) VALUES
 ('11111111-1111-1111-1111-111111111111','t1','T1','active')
ON CONFLICT DO NOTHING;
INSERT INTO appsec.users(user_id,email,status,tenant_id) VALUES
 ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','a@t1','active','11111111-1111-1111-1111-111111111111'),
 ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','b@t1','active','11111111-1111-1111-1111-111111111111')
ON CONFLICT DO NOTHING;
INSERT INTO appsec.sessions(session_id,user_id,expires_at,auth_method) VALUES
 ('a1111111-a111-a111-a111-a11111111111','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',now()+interval '1 day','password'),
 ('b2222222-b222-b222-b222-b22222222222','bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',now()+interval '1 day','password')
ON CONFLICT DO NOTHING;
INSERT INTO appsec.session_principals(session_id,user_id,db_role,auth_claims) VALUES
 ('a1111111-a111-a111-a111-a11111111111','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','app_s_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','{"oauth_sub":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}'::jsonb),
 ('b2222222-b222-b222-b222-b22222222222','bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','app_s_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','{}'::jsonb)
ON CONFLICT (session_id) DO UPDATE SET auth_claims = EXCLUDED.auth_claims, db_role = EXCLUDED.db_role, user_id = EXCLUDED.user_id;
INSERT INTO appsec.database_acl_entries(database_name,resource_name,principal_kind,principal_id,access_level)
VALUES (current_database(),'documents','user','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',4),
       (current_database(),'documents','user','bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',2)
ON CONFLICT DO NOTHING;
INSERT INTO appsec.user_roles(user_id,role_name,tenant_id,granted_by) VALUES
 ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','documents.user','11111111-1111-1111-1111-111111111111','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa')
ON CONFLICT DO NOTHING;
INSERT INTO appsec.jsonb_field_acl(resource,json_path,read_roles,write_roles) VALUES
 ('documents.body',ARRAY['title'],ARRAY['documents.user'],ARRAY['documents.user'])
ON CONFLICT DO NOTHING;
COMMIT;

-- create_document works and sets readers_restricted (verify as superuser)
SET SESSION AUTHORIZATION app_s_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;
SELECT appsec.create_document('{"title":"priv"}'::jsonb) AS doc_id \gset
RESET SESSION AUTHORIZATION;
SELECT readers_restricted AS readers_restricted_ok FROM appsec.document_acl WHERE document_id = :'doc_id';

-- Bob cannot read Alice private doc
SET SESSION AUTHORIZATION app_s_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb;
SELECT count(*) AS bob_sees FROM appsec.get_document(:'doc_id'::uuid);
RESET SESSION AUTHORIZATION;

-- public ACL must NOT grant roles via has_role
INSERT INTO appsec.database_acl_entries(database_name,resource_name,principal_kind,principal_id,access_level,assigned_roles)
VALUES (current_database(),'documents','public','*',2,ARRAY['documents.secret_reader'])
ON CONFLICT (database_name,resource_name,principal_kind,principal_id)
DO UPDATE SET assigned_roles=EXCLUDED.assigned_roles, access_level=2;
SET SESSION AUTHORIZATION app_s_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb;
SELECT appsec.has_role('documents.secret_reader') AS public_role_leak;
RESET SESSION AUTHORIZATION;
UPDATE appsec.database_acl_entries SET assigned_roles='{}' WHERE principal_kind='public';

-- GUC spoof must not affect helpers
SET SESSION AUTHORIZATION app_s_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;
SELECT set_config('appsec.user_id','bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',false);
SELECT set_config('appsec.tenant_id','00000000-0000-0000-0000-000000000000',false);
SELECT appsec.uid() = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'::uuid AS uid_stable;
SELECT appsec.session_id() IS NOT NULL AS has_session;
SELECT appsec.auth()->>'user_id' = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' AS auth_uid_ok;
SELECT appsec.auth()->'claims' ? 'oauth_sub' AS auth_claims_ok;
DO $$ BEGIN
  BEGIN
    PERFORM appsec.create_group('nope');
    RAISE EXCEPTION 'create_group should fail';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END $$;
RESET SESSION AUTHORIZATION;

-- Hand-written RLS using helpers (Surreal $auth style)
DROP TABLE IF EXISTS appsec.notes CASCADE;
CREATE TABLE appsec.notes (
  note_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  owner_id uuid NOT NULL,
  body text NOT NULL,
  secret text
);
ALTER TABLE appsec.notes OWNER TO appsec_owner;
SET ROLE appsec_owner;
ALTER TABLE appsec.notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE appsec.notes FORCE ROW LEVEL SECURITY;
CREATE POLICY notes_owner ON appsec.notes FOR ALL
  USING (owner_id = appsec.uid() AND tenant_id = appsec.tenant_id())
  WITH CHECK (owner_id = appsec.uid() AND tenant_id = appsec.tenant_id());
GRANT SELECT, INSERT, UPDATE, DELETE ON appsec.notes TO appsec_app_base;
RESET ROLE;

SET SESSION AUTHORIZATION app_s_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;
INSERT INTO appsec.notes(tenant_id,owner_id,body,secret)
VALUES (appsec.tenant_id(), appsec.uid(), 'alice-note', 'top-secret');
RESET SESSION AUTHORIZATION;
SET SESSION AUTHORIZATION app_s_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb;
SELECT count(*) AS bob_notes FROM appsec.notes;
RESET SESSION AUTHORIZATION;

-- DSL table + field permissions (admin/owner)
SET ROLE appsec_owner;
SELECT appsec.drop_table_permissions('appsec.notes'::regclass);
SELECT appsec.define_table_permissions(
  'appsec.notes'::regclass,
  'owner_id = appsec.uid()',
  'owner_id = appsec.uid()',
  'owner_id = appsec.uid()',
  'owner_id = appsec.uid()',
  'tenant_id');
SELECT appsec.define_field_permissions(
  'appsec.notes'::regclass, 'secret',
  'owner_id = appsec.uid()',
  'owner_id = appsec.uid()');
RESET ROLE;

SET SESSION AUTHORIZATION app_s_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;
SELECT secret IS NOT NULL AS alice_sees_secret FROM appsec.notes_secured WHERE body = 'alice-note';
RESET SESSION AUTHORIZATION;
SET SESSION AUTHORIZATION app_s_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb;
SELECT count(*) AS bob_dsl_notes FROM appsec.notes;
SELECT count(*) AS bob_secured_rows FROM appsec.notes_secured;
RESET SESSION AUTHORIZATION;

-- Combined with ACL documents still works for Alice
SET SESSION AUTHORIZATION app_s_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;
SELECT count(*) AS alice_docs FROM appsec.get_document(:'doc_id'::uuid);
RESET SESSION AUTHORIZATION;

SELECT 'security_regression_ok' AS status;
