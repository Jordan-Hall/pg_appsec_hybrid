-- 010: least-privilege owners for role-management helpers, TEMP lockdown,
-- and audit-chain checkpoint verification. Requires PostgreSQL 16+
-- (CREATEROLE only manages roles the creator holds ADMIN OPTION on).
RESET ROLE;

DO $$
BEGIN
  IF current_setting('server_version_num')::int < 160000 THEN
    RAISE EXCEPTION 'pg_appsec 010 requires PostgreSQL 16+ CREATEROLE semantics';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'appsec_role_admin') THEN
    CREATE ROLE appsec_role_admin NOLOGIN NOINHERIT CREATEROLE;
  END IF;
END
$$;
-- Dedicated NOLOGIN owner: CREATEROLE only (no SUPERUSER/BYPASSRLS/REPLICATION/CREATEDB).
ALTER ROLE appsec_role_admin NOLOGIN NOINHERIT CREATEROLE NOSUPERUSER NOCREATEDB NOREPLICATION NOBYPASSRLS;
-- May grant appsec_app_base to new session roles, but cannot use its privileges.
GRANT appsec_app_base TO appsec_role_admin WITH ADMIN OPTION, INHERIT FALSE, SET FALSE;
-- Needs to resolve its own helper functions in schema appsec (no table access).
GRANT USAGE ON SCHEMA appsec TO appsec_role_admin;

-- Adopt pre-existing session roles (created by superuser/provisioner in older
-- installs) so the non-superuser helpers can manage them.
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT rolname FROM pg_roles WHERE rolname ~ '^app_s_[0-9a-f]{32}$' LOOP
    EXECUTE format('GRANT %I TO appsec_role_admin WITH ADMIN OPTION, INHERIT FALSE, SET FALSE', r.rolname);
  END LOOP;
END
$$;

CREATE OR REPLACE FUNCTION appsec._require_role_provisioner()
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, appsec, pg_temp
AS $$
BEGIN
  IF NOT pg_has_role(session_user, 'appsec_provisioner', 'member')
     AND NOT pg_has_role(session_user, 'appsec_owner', 'member') THEN
    RAISE EXCEPTION 'provisioner required' USING ERRCODE = '42501';
  END IF;
END
$$;
GRANT EXECUTE ON FUNCTION appsec._require_role_provisioner() TO PUBLIC;

CREATE OR REPLACE FUNCTION appsec._assert_session_role_safe(target_role name)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, appsec, pg_temp
AS $$
BEGIN
  IF target_role IS NULL OR target_role::text !~ '^app_s_[0-9a-f]{32}$' THEN
    RAISE EXCEPTION 'invalid session role' USING ERRCODE = '22023';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname = target_role
             AND (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls)) THEN
    RAISE EXCEPTION 'session role % has elevated attributes', target_role USING ERRCODE = '42501';
  END IF;
END
$$;
GRANT EXECUTE ON FUNCTION appsec._assert_session_role_safe(name) TO PUBLIC;

DROP FUNCTION IF EXISTS appsec.harden_session_role(name, timestamptz, integer);
CREATE FUNCTION appsec.harden_session_role(target_role name, valid_until timestamptz, connection_limit integer DEFAULT 2)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, appsec, pg_temp
AS $$
BEGIN
  PERFORM appsec._require_role_provisioner();
  PERFORM appsec._assert_session_role_safe(target_role);
  IF connection_limit IS NULL OR connection_limit < 1 OR connection_limit > 16 THEN
    RAISE EXCEPTION 'connection_limit out of range' USING ERRCODE = '22023';
  END IF;
  IF valid_until IS NULL OR valid_until <= clock_timestamp() THEN
    RAISE EXCEPTION 'valid_until must be in the future' USING ERRCODE = '22023';
  END IF;
  EXECUTE format('ALTER ROLE %I WITH LOGIN INHERIT CONNECTION LIMIT %s VALID UNTIL %L',
                 target_role, connection_limit, valid_until);
  PERFORM appsec._assert_session_role_safe(target_role);
END
$$;

CREATE OR REPLACE FUNCTION appsec.create_session_role(target_role name, password text,
  valid_until timestamptz, connection_limit integer DEFAULT 2)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, appsec, pg_temp
AS $$
BEGIN
  PERFORM appsec._require_role_provisioner();
  IF target_role IS NULL OR target_role::text !~ '^app_s_[0-9a-f]{32}$' THEN
    RAISE EXCEPTION 'invalid session role' USING ERRCODE = '22023';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = target_role) THEN
    RAISE EXCEPTION 'session role already exists' USING ERRCODE = '42710';
  END IF;
  IF connection_limit IS NULL OR connection_limit < 1 OR connection_limit > 16 THEN
    RAISE EXCEPTION 'connection_limit out of range' USING ERRCODE = '22023';
  END IF;
  IF valid_until IS NULL OR valid_until <= clock_timestamp() THEN
    RAISE EXCEPTION 'valid_until must be in the future' USING ERRCODE = '22023';
  END IF;
  IF password IS NULL THEN
    EXECUTE format('CREATE ROLE %I LOGIN INHERIT CONNECTION LIMIT %s VALID UNTIL %L',
                   target_role, connection_limit, valid_until);
  ELSE
    EXECUTE format('CREATE ROLE %I LOGIN INHERIT CONNECTION LIMIT %s VALID UNTIL %L PASSWORD %L',
                   target_role, connection_limit, valid_until, password);
  END IF;
  EXECUTE format('GRANT appsec_app_base TO %I', target_role);
  PERFORM appsec._assert_session_role_safe(target_role);
END
$$;

CREATE OR REPLACE FUNCTION appsec.set_session_role_login(target_role name, enabled boolean)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, appsec, pg_temp
AS $$
BEGIN
  PERFORM appsec._require_role_provisioner();
  PERFORM appsec._assert_session_role_safe(target_role);
  EXECUTE format('ALTER ROLE %I %s', target_role, CASE WHEN enabled THEN 'LOGIN' ELSE 'NOLOGIN' END);
END
$$;

CREATE OR REPLACE FUNCTION appsec.set_session_role_password(target_role name, password text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, appsec, pg_temp
AS $$
BEGIN
  PERFORM appsec._require_role_provisioner();
  PERFORM appsec._assert_session_role_safe(target_role);
  IF password IS NULL OR length(password) < 16 THEN
    RAISE EXCEPTION 'password/verifier too short' USING ERRCODE = '22023';
  END IF;
  EXECUTE format('ALTER ROLE %I PASSWORD %L', target_role, password);
END
$$;

DROP FUNCTION IF EXISTS appsec.grant_session_role_to_gateway(name);
DROP FUNCTION IF EXISTS appsec.revoke_session_role_from_gateway(name);
CREATE FUNCTION appsec.grant_session_role_to_gateway(target_role name)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, appsec, pg_temp
AS $$
BEGIN
  PERFORM appsec._require_role_provisioner();
  PERFORM appsec._assert_session_role_safe(target_role);
  EXECUTE format('GRANT %I TO appsec_gateway WITH INHERIT FALSE, SET TRUE', target_role);
END
$$;

CREATE FUNCTION appsec.revoke_session_role_from_gateway(target_role name)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, appsec, pg_temp
AS $$
BEGIN
  PERFORM appsec._require_role_provisioner();
  IF target_role IS NULL OR target_role::text !~ '^app_s_[0-9a-f]{32}$' THEN
    RAISE EXCEPTION 'invalid session role' USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = target_role) THEN
    RETURN;
  END IF;
  EXECUTE format('REVOKE %I FROM appsec_gateway', target_role);
  IF pg_has_role('appsec_gateway', target_role, 'MEMBER') THEN
    RAISE EXCEPTION 'gateway still holds % (granted by another grantor)', target_role USING ERRCODE = '42501';
  END IF;
END
$$;

DO $$
DECLARE f text;
BEGIN
  FOREACH f IN ARRAY ARRAY[
    'appsec.harden_session_role(name, timestamptz, integer)',
    'appsec.create_session_role(name, text, timestamptz, integer)',
    'appsec.set_session_role_login(name, boolean)',
    'appsec.set_session_role_password(name, text)',
    'appsec.grant_session_role_to_gateway(name)',
    'appsec.revoke_session_role_from_gateway(name)'] LOOP
    EXECUTE format('ALTER FUNCTION %s OWNER TO appsec_role_admin', f);
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO appsec_provisioner', f);
  END LOOP;
END
$$;

-- Provisioner no longer needs CREATEROLE: all role DDL goes through the helpers.
ALTER ROLE appsec_provisioner NOCREATEROLE;

-- Event trigger function runs as the DDL issuer (who owns the new table).
ALTER FUNCTION appsec.tg_enforce_rls_on_create() SECURITY INVOKER;

-- Every remaining superuser-owned appsec SECURITY DEFINER function -> appsec_owner.
DO $$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT p.oid::regprocedure AS sig
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    JOIN pg_roles o ON o.oid = p.proowner
    WHERE n.nspname = 'appsec' AND p.prosecdef AND o.rolsuper
  LOOP
    EXECUTE format('ALTER FUNCTION %s OWNER TO appsec_owner', r.sig);
  END LOOP;
END
$$;

-- TEMP: no PUBLIC temp tables in this database (session roles inherit PUBLIC).
DO $$
BEGIN
  EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC', current_database());
END
$$;

-- ---------------------------------------------------------------------------
-- Audit checkpoint verification (signature checked externally by
-- oauth-state-sync --verify-checkpoint; DB side checks hash + chain).
-- ---------------------------------------------------------------------------
SET ROLE appsec_owner;
CREATE OR REPLACE FUNCTION appsec.verify_audit_chain_against_checkpoint(checkpoint_event_id bigint, checkpoint_event_hash text)
RETURNS TABLE(ok boolean, detail text)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, appsec, pg_temp
AS $$
DECLARE
  v record;
  h bytea;
BEGIN
  SELECT * INTO v FROM appsec.verify_security_audit_chain() LIMIT 1;
  IF NOT coalesce(v.ok, false) THEN
    ok := false; detail := 'chain invalid: ' || coalesce(v.detail, 'unknown'); RETURN NEXT; RETURN;
  END IF;
  IF checkpoint_event_hash IS NULL OR checkpoint_event_hash !~ '^[0-9a-f]{64}$' THEN
    ok := false; detail := 'malformed checkpoint hash'; RETURN NEXT; RETURN;
  END IF;
  SELECT c.event_hash INTO h FROM appsec.security_audit_chain c WHERE c.event_id = checkpoint_event_id;
  IF h IS NULL THEN
    ok := false; detail := 'checkpoint event missing (truncated?)'; RETURN NEXT; RETURN;
  END IF;
  IF encode(h, 'hex') <> checkpoint_event_hash THEN
    ok := false; detail := 'checkpoint hash mismatch (rewritten history)'; RETURN NEXT; RETURN;
  END IF;
  ok := true; detail := 'chain valid and matches checkpoint'; RETURN NEXT;
END
$$;
REVOKE ALL ON FUNCTION appsec.verify_audit_chain_against_checkpoint(bigint, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION appsec.verify_audit_chain_against_checkpoint(bigint, text)
  TO appsec_operator_base, appsec_provisioner;
RESET ROLE;

-- Bound the exported state: only revoked sessions that have not yet expired
-- (expired/unknown sessions are denied anyway because they are not active).
SET ROLE appsec_owner;
CREATE OR REPLACE FUNCTION appsec.export_oauth_session_state()
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, appsec, pg_temp
AS $$
  SELECT jsonb_build_object(
    'generated_at', to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
    'active_sessions', coalesce((
      SELECT jsonb_agg(jsonb_build_object(
        'sid', s.session_id,
        'role', sp.db_role,
        'user_id', s.user_id,
        'tenant_id', u.tenant_id,
        'expires_at', to_char(s.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
        'jti', s.access_jti
      ))
      FROM appsec.sessions s
      JOIN appsec.session_principals sp ON sp.session_id = s.session_id
      JOIN appsec.users u ON u.user_id = s.user_id AND u.status = 'active'
      JOIN appsec.tenants t ON t.tenant_id = u.tenant_id AND t.status = 'active'
      WHERE s.revoked_at IS NULL AND s.expires_at > statement_timestamp()
    ), '[]'::jsonb),
    'revoked_sids', coalesce((
      SELECT jsonb_agg(s.session_id)
      FROM appsec.sessions s
      WHERE s.revoked_at IS NOT NULL AND s.expires_at > statement_timestamp()
    ), '[]'::jsonb),
    'denied_jtis', coalesce((
      SELECT jsonb_agg(jti) FROM appsec.oauth_jti_denylist WHERE expires_at > clock_timestamp()
    ), '[]'::jsonb)
  )
$$;
REVOKE ALL ON FUNCTION appsec.export_oauth_session_state() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION appsec.export_oauth_session_state() TO appsec_provisioner, appsec_operator_base;
RESET ROLE;
