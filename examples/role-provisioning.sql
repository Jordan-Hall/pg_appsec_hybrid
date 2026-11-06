-- Illustrative only: production role creation is performed atomically by the
-- trusted Rust AuthService. One login role belongs to one authenticated session.
DO $example$
DECLARE
  app_user uuid := '00000000-0000-0000-0000-000000000001';
  session uuid := '00000000-0000-0000-0000-000000000002';
  generated_role name := 'app_s_00000000000000000000000000000002';
BEGIN
  -- The session row must already exist and the role must be generated from its UUID.
  EXECUTE format('CREATE ROLE %I LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS', generated_role);
  EXECUTE format('GRANT appsec_app_base TO %I', generated_role);
  INSERT INTO appsec.session_principals(session_id,user_id,db_role)
  VALUES (session,app_user,generated_role);
END
$example$;
