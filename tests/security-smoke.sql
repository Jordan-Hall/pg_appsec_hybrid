\set ON_ERROR_STOP on
-- Run as superuser in a disposable database after migrations 001-005.
BEGIN;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='app_s_10000000000000000000000000000001') THEN
    CREATE ROLE app_s_10000000000000000000000000000001 LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    GRANT appsec_app_base TO app_s_10000000000000000000000000000001;
  END IF;
END $$;
GRANT appsec_app_base TO app_s_10000000000000000000000000000001;
INSERT INTO appsec.tenants(tenant_id,slug,display_name,status)
VALUES ('20000000-0000-0000-0000-000000000001','smoke-tenant','Smoke Tenant','active')
ON CONFLICT (tenant_id) DO UPDATE SET status='active';
INSERT INTO appsec.users(user_id,email,status,tenant_id)
VALUES ('10000000-0000-0000-0000-000000000001','alice@example.test','active','20000000-0000-0000-0000-000000000001')
ON CONFLICT (user_id) DO UPDATE SET status='active';
INSERT INTO appsec.sessions(session_id,user_id,expires_at,auth_method)
VALUES ('10000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000001',clock_timestamp()+interval '1 day','test')
ON CONFLICT (session_id) DO UPDATE SET revoked_at=NULL,expires_at=EXCLUDED.expires_at;
INSERT INTO appsec.session_principals(session_id,user_id,db_role)
VALUES ('10000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000001','app_s_10000000000000000000000000000001')
ON CONFLICT (session_id) DO UPDATE SET db_role=EXCLUDED.db_role;
INSERT INTO appsec.database_acl_entries(database_name,resource_name,principal_kind,principal_id,access_level,assigned_roles)
VALUES (current_database(),'documents','user','10000000-0000-0000-0000-000000000001',4,ARRAY['documents.create'])
ON CONFLICT (database_name,resource_name,principal_kind,principal_id) DO UPDATE SET access_level=4,assigned_roles=EXCLUDED.assigned_roles;
INSERT INTO appsec.jsonb_field_acl(resource,json_path,read_roles,write_roles)
VALUES ('documents.body',ARRAY['title'],ARRAY['documents.writer'],ARRAY['documents.writer'])
ON CONFLICT (resource,json_path) DO UPDATE SET read_roles=EXCLUDED.read_roles,write_roles=EXCLUDED.write_roles;
INSERT INTO appsec.user_roles(user_id,role_name,tenant_id,granted_by)
VALUES ('10000000-0000-0000-0000-000000000001','documents.writer','20000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000001')
ON CONFLICT DO NOTHING;
SET SESSION AUTHORIZATION app_s_10000000000000000000000000000001;
DO $$ BEGIN
  IF appsec.uid() <> '10000000-0000-0000-0000-000000000001'::uuid THEN RAISE EXCEPTION 'session principal resolution failed'; END IF;
  IF appsec.create_document('{"title":"hello"}'::jsonb) IS NULL THEN RAISE EXCEPTION 'document creation failed'; END IF;
END $$;
RESET SESSION AUTHORIZATION;
ROLLBACK;
