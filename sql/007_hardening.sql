\set ON_ERROR_STOP on
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA appsec;

-- ---------------------------------------------------------------------------
-- Opt-in application gateway role (superuser create)
-- ---------------------------------------------------------------------------
DO $gw$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'appsec_gateway') THEN
    CREATE ROLE appsec_gateway NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
      NOINHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
END
$gw$;

-- Remaining objects created as appsec_owner where possible.
SET ROLE appsec_owner;

REVOKE ALL ON SCHEMA appsec FROM appsec_gateway;
GRANT USAGE ON SCHEMA appsec TO appsec_gateway;
-- Explicitly no table DML grants. Gateway may only EXECUTE assume_session / helpers below.

CREATE TABLE IF NOT EXISTS appsec.gateway_assertions (
  jti uuid PRIMARY KEY,
  session_id uuid NOT NULL REFERENCES appsec.sessions(session_id) ON DELETE CASCADE,
  db_role name NOT NULL,
  audience text NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS gateway_assertions_session_idx ON appsec.gateway_assertions(session_id);

-- HMAC-SHA256 over canonical payload using a server secret stored only for owner/provisioner.
-- Production: set via ALTER DATABASE … SET appsec.gateway_hmac_key FROM FILE / vault — never GUCs from clients.
CREATE OR REPLACE FUNCTION appsec._gateway_hmac_key()
RETURNS bytea
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, appsec, pg_temp
AS $$
DECLARE k text;
BEGIN
  k := current_setting('appsec.gateway_hmac_key', true);
  IF k IS NULL OR length(k) < 32 THEN
    RAISE EXCEPTION 'gateway hmac key not configured' USING ERRCODE = 'P0001';
  END IF;
  RETURN convert_to(k, 'UTF8');
END
$$;

CREATE OR REPLACE FUNCTION appsec.mint_gateway_assertion(target_session uuid, audience text DEFAULT 'appsec.gateway', ttl_seconds integer DEFAULT 60)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, appsec, pg_temp
AS $$
DECLARE
  sid uuid; role name; jti uuid := gen_random_uuid(); exp timestamptz; payload text; sig text;
BEGIN
  IF NOT pg_has_role(session_user, 'appsec_provisioner', 'member')
     AND NOT pg_has_role(session_user, 'appsec_owner', 'member')
     AND NOT pg_has_role(session_user, 'appsec_operator_base', 'member') THEN
    RAISE EXCEPTION 'provisioner privilege required to mint gateway assertions' USING ERRCODE = '42501';
  END IF;
  IF audience IS NULL OR length(audience) < 3 OR length(audience) > 200 THEN
    RAISE EXCEPTION 'invalid audience' USING ERRCODE = '22023';
  END IF;
  IF ttl_seconds IS NULL OR ttl_seconds < 5 OR ttl_seconds > 300 THEN
    RAISE EXCEPTION 'ttl_seconds out of range' USING ERRCODE = '22023';
  END IF;
  SELECT s.session_id, sp.db_role INTO sid, role
  FROM appsec.sessions s
  JOIN appsec.session_principals sp ON sp.session_id = s.session_id
  JOIN appsec.users u ON u.user_id = s.user_id AND u.status = 'active'
  WHERE s.session_id = target_session AND s.revoked_at IS NULL AND s.expires_at > statement_timestamp();
  IF sid IS NULL THEN RAISE EXCEPTION 'active session required' USING ERRCODE = '22023'; END IF;
  exp := clock_timestamp() + make_interval(secs => ttl_seconds);
  INSERT INTO appsec.gateway_assertions(jti, session_id, db_role, audience, expires_at)
  VALUES (jti, sid, role, audience, exp);
  payload := jti::text || '|' || sid::text || '|' || role::text || '|' || audience || '|' || floor(extract(epoch from exp))::bigint::text;
  sig := encode(appsec.hmac(convert_to(payload, 'UTF8'), appsec._gateway_hmac_key(), 'sha256'), 'hex');
  RETURN encode(convert_to(payload || '|' || sig, 'UTF8'), 'base64');
END
$$;

-- SECURITY DEFINER verifier (no SET ROLE — forbidden inside definer functions).
CREATE OR REPLACE FUNCTION appsec.verify_gateway_assertion(assertion text)
RETURNS name
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, appsec, pg_temp
AS $$
DECLARE
  raw text; parts text[]; v_jti uuid; v_sid uuid; v_role name; v_aud text; exp_epoch bigint; sig text; expect text;
BEGIN
  IF session_user::text <> 'appsec_gateway'
     AND NOT pg_has_role(session_user, 'appsec_gateway', 'member') THEN
    RAISE EXCEPTION 'assume_session is only callable by appsec_gateway' USING ERRCODE = '42501';
  END IF;
  IF assertion IS NULL OR length(assertion) > 4096 THEN
    RAISE EXCEPTION 'invalid assertion' USING ERRCODE = '22023';
  END IF;
  raw := convert_from(decode(assertion, 'base64'), 'UTF8');
  parts := string_to_array(raw, '|');
  IF cardinality(parts) <> 6 THEN RAISE EXCEPTION 'invalid assertion format' USING ERRCODE = '22023'; END IF;
  v_jti := parts[1]::uuid;
  v_sid := parts[2]::uuid;
  v_role := parts[3]::name;
  v_aud := parts[4];
  exp_epoch := parts[5]::bigint;
  sig := parts[6];
  expect := encode(appsec.hmac(convert_to(parts[1]||'|'||parts[2]||'|'||parts[3]||'|'||parts[4]||'|'||parts[5], 'UTF8'), appsec._gateway_hmac_key(), 'sha256'), 'hex');
  IF sig IS DISTINCT FROM expect THEN
    RAISE EXCEPTION 'assertion signature invalid' USING ERRCODE = '42501';
  END IF;
  IF v_aud <> 'appsec.gateway' THEN
    RAISE EXCEPTION 'assertion audience mismatch' USING ERRCODE = '42501';
  END IF;
  IF exp_epoch < floor(extract(epoch from clock_timestamp())) THEN
    RAISE EXCEPTION 'assertion expired' USING ERRCODE = '42501';
  END IF;
  UPDATE appsec.gateway_assertions ga
     SET consumed_at = clock_timestamp()
   WHERE ga.jti = v_jti
     AND ga.consumed_at IS NULL
     AND ga.expires_at > clock_timestamp()
     AND ga.session_id = v_sid
     AND ga.db_role = v_role
     AND ga.audience = v_aud
     AND EXISTS (
       SELECT 1 FROM appsec.sessions s
       JOIN appsec.users u ON u.user_id = s.user_id AND u.status = 'active'
       WHERE s.session_id = v_sid AND s.revoked_at IS NULL AND s.expires_at > statement_timestamp()
     );
  IF NOT FOUND THEN
    RAISE EXCEPTION 'assertion replayed, revoked, or unknown' USING ERRCODE = '42501';
  END IF;
  RETURN v_role;
END
$$;

-- INVOKER wrapper performs SET ROLE (allowed outside SECURITY DEFINER).
CREATE OR REPLACE FUNCTION appsec.assume_session(assertion text)
RETURNS void
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, appsec, pg_temp
AS $$
DECLARE v_role name;
BEGIN
  v_role := appsec.verify_gateway_assertion(assertion);
  EXECUTE format('SET ROLE %I', v_role);
END
$$;

REVOKE ALL ON FUNCTION appsec._gateway_hmac_key(), appsec.mint_gateway_assertion(uuid,text,integer), appsec.verify_gateway_assertion(text), appsec.assume_session(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION appsec.mint_gateway_assertion(uuid,text,integer) TO appsec_provisioner, appsec_operator_base;
GRANT EXECUTE ON FUNCTION appsec.verify_gateway_assertion(text), appsec.assume_session(text) TO appsec_gateway;
GRANT SELECT, INSERT, UPDATE ON appsec.gateway_assertions TO appsec_owner;
-- Definer functions own the table access; revoke direct DML from app roles.
REVOKE ALL ON TABLE appsec.gateway_assertions FROM PUBLIC, appsec_app_base, appsec_gateway;


-- Auth/provisioner calls this at session mint when gateway mode is enabled.
CREATE OR REPLACE FUNCTION appsec.grant_session_role_to_gateway(target_role name)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, appsec, pg_temp
AS $$
BEGIN
  IF NOT pg_has_role(session_user, 'appsec_provisioner', 'member')
     AND NOT pg_has_role(session_user, 'appsec_owner', 'member') THEN
    RAISE EXCEPTION 'provisioner required' USING ERRCODE = '42501';
  END IF;
  IF target_role::text !~ '^app_s_[0-9a-f]{32}$' THEN
    RAISE EXCEPTION 'invalid session role' USING ERRCODE = '22023';
  END IF;
  EXECUTE format('GRANT %I TO appsec_gateway', target_role);
END
$$;

CREATE OR REPLACE FUNCTION appsec.revoke_session_role_from_gateway(target_role name)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, appsec, pg_temp
AS $$
BEGIN
  IF NOT pg_has_role(session_user, 'appsec_provisioner', 'member')
     AND NOT pg_has_role(session_user, 'appsec_owner', 'member') THEN
    RAISE EXCEPTION 'provisioner required' USING ERRCODE = '42501';
  END IF;
  EXECUTE format('REVOKE %I FROM appsec_gateway', target_role);
EXCEPTION WHEN undefined_object THEN NULL;
END
$$;

REVOKE ALL ON FUNCTION appsec.grant_session_role_to_gateway(name), appsec.revoke_session_role_from_gateway(name) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION appsec.grant_session_role_to_gateway(name), appsec.revoke_session_role_from_gateway(name)
  TO appsec_provisioner, appsec_operator_base;

-- ---------------------------------------------------------------------------
-- Tamper-evident audit hash chain
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS appsec.security_audit_chain (
  event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  actor_user_id uuid,
  actor_role name,
  event_type text NOT NULL,
  resource text,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  prev_hash bytea NOT NULL,
  event_hash bytea NOT NULL
);

CREATE OR REPLACE FUNCTION appsec._audit_append()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, appsec, pg_temp
AS $$
DECLARE prev bytea; payload text; h bytea;
BEGIN
  SELECT event_hash INTO prev FROM appsec.security_audit_chain ORDER BY event_id DESC LIMIT 1;
  IF prev IS NULL THEN prev := decode(repeat('00', 32), 'hex'); END IF;
  NEW.prev_hash := prev;
  payload := coalesce(NEW.occurred_at::text,'') || '|' || coalesce(NEW.actor_user_id::text,'') || '|' ||
             coalesce(NEW.actor_role::text,'') || '|' || coalesce(NEW.event_type,'') || '|' ||
             coalesce(NEW.resource,'') || '|' || coalesce(NEW.detail::text,'{}') || '|' || encode(prev, 'hex');
  h := appsec.digest(convert_to(payload, 'UTF8'), 'sha256');
  NEW.event_hash := h;
  RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS security_audit_chain_hash ON appsec.security_audit_chain;
CREATE TRIGGER security_audit_chain_hash
  BEFORE INSERT ON appsec.security_audit_chain
  FOR EACH ROW EXECUTE FUNCTION appsec._audit_append();

-- Block UPDATE/DELETE on the chain (append-only).
CREATE OR REPLACE FUNCTION appsec._audit_immutable()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  RAISE EXCEPTION 'security_audit_chain is append-only' USING ERRCODE = '42501';
END $$;
DROP TRIGGER IF EXISTS security_audit_chain_no_upd ON appsec.security_audit_chain;
CREATE TRIGGER security_audit_chain_no_upd BEFORE UPDATE OR DELETE ON appsec.security_audit_chain
  FOR EACH ROW EXECUTE FUNCTION appsec._audit_immutable();

CREATE OR REPLACE FUNCTION appsec.audit_event(event_type text, resource text DEFAULT NULL, detail jsonb DEFAULT '{}'::jsonb)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, appsec, pg_temp
AS $$
DECLARE id bigint;
BEGIN
  INSERT INTO appsec.security_audit_chain(actor_user_id, actor_role, event_type, resource, detail)
  VALUES (appsec.uid(), session_user::name, event_type, resource, coalesce(detail, '{}'::jsonb))
  RETURNING event_id INTO id;
  RETURN id;
END
$$;

REVOKE ALL ON FUNCTION appsec.audit_event(text,text,jsonb), appsec._audit_append(), appsec._audit_immutable() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION appsec.audit_event(text,text,jsonb) TO appsec_app_base, appsec_operator_base, appsec_gateway, appsec_provisioner;
REVOKE ALL ON TABLE appsec.security_audit_chain FROM PUBLIC;
GRANT SELECT ON TABLE appsec.security_audit_chain TO appsec_operator_base;

-- ---------------------------------------------------------------------------
-- Per-database ACL max-level caps
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS appsec.database_acl_caps (
  database_name name PRIMARY KEY,
  max_access_level smallint NOT NULL CHECK (max_access_level BETWEEN 0 AND 6),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE OR REPLACE FUNCTION appsec.effective_database_access_capped(resource text)
RETURNS smallint
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, appsec, pg_temp
AS $$
  SELECT LEAST(
    appsec.effective_database_access(resource),
    coalesce((SELECT max_access_level FROM appsec.database_acl_caps WHERE database_name = current_database()), 6::smallint)
  )::smallint
$$;

REVOKE ALL ON FUNCTION appsec.effective_database_access_capped(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION appsec.effective_database_access_capped(text) TO appsec_app_base, appsec_operator_base;

-- ---------------------------------------------------------------------------
-- Enforce consistent ACL: event trigger FORCE RLS on new tables in appsec
-- ---------------------------------------------------------------------------
-- tg_enforce_rls_on_create defined as superuser below

DROP EVENT TRIGGER IF EXISTS appsec_enforce_rls;
-- Event triggers must be created by superuser; install script runs as superuser after RESET.
RESET ROLE;

CREATE OR REPLACE FUNCTION appsec.tg_enforce_rls_on_create()
RETURNS event_trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, appsec, pg_temp
AS $$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT c.oid::regclass AS rel
    FROM pg_event_trigger_ddl_commands() e
    JOIN pg_class c ON c.oid = e.objid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE e.command_tag = 'CREATE TABLE' AND c.relkind = 'r' AND n.nspname = 'appsec'
  LOOP
    BEGIN
      EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', r.rel);
      EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', r.rel);
    EXCEPTION WHEN insufficient_privilege THEN
      RAISE NOTICE 'appsec enforce RLS skipped for % (not owner)', r.rel;
    END;
  END LOOP;
END
$$;

CREATE EVENT TRIGGER appsec_enforce_rls
  ON ddl_command_end
  WHEN TAG IN ('CREATE TABLE')
  EXECUTE FUNCTION appsec.tg_enforce_rls_on_create();

SET ROLE appsec_owner;

-- ---------------------------------------------------------------------------
-- Defaults: public schema lockdown + app role timeouts / connection hints
-- ---------------------------------------------------------------------------
RESET ROLE;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO PUBLIC;
-- TEMP revoke is database-level; apply best-effort for current DB.
DO $$ BEGIN
  EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC', current_database());
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

ALTER ROLE appsec_app_base SET statement_timeout = '30s';
ALTER ROLE appsec_app_base SET idle_in_transaction_session_timeout = '60s';
ALTER ROLE appsec_app_base SET lock_timeout = '10s';
-- Per-session roles inherit from appsec_app_base settings when SET ROLE / membership applies;
-- auth service should also ALTER ROLE app_s_* SET connection_limit = 2 at mint.

SET ROLE appsec_owner;

CREATE TABLE IF NOT EXISTS appsec.oauth_jti_denylist (
  jti text PRIMARY KEY,
  reason text,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- access_jti on sessions for replay binding (optional column)
ALTER TABLE appsec.sessions ADD COLUMN IF NOT EXISTS access_jti text;

-- Export OAuth connect-time session state (auth service / cron writes this to a file the validator reads).
CREATE OR REPLACE FUNCTION appsec.export_oauth_session_state()
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, appsec, pg_temp
AS $$
  SELECT jsonb_build_object(
    'generated_at', clock_timestamp(),
    'active_sessions', coalesce((
      SELECT jsonb_agg(jsonb_build_object(
        'sid', s.session_id,
        'role', sp.db_role,
        'user_id', s.user_id,
        'tenant_id', u.tenant_id,
        'expires_at', s.expires_at,
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
      WHERE s.revoked_at IS NOT NULL OR s.expires_at <= statement_timestamp()
    ), '[]'::jsonb),
    'denied_jtis', coalesce((
      SELECT jsonb_agg(jti) FROM appsec.oauth_jti_denylist WHERE expires_at > clock_timestamp()
    ), '[]'::jsonb)
  )
$$;

REVOKE ALL ON FUNCTION appsec.export_oauth_session_state() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION appsec.export_oauth_session_state() TO appsec_provisioner, appsec_operator_base;
GRANT EXECUTE ON FUNCTION appsec.uid(), appsec.session_id() TO appsec_app_base, appsec_operator_base, appsec_gateway;


RESET ROLE;


-- Gateway mode: after SET ROLE app_s_*, session_user remains gateway.
-- Resolve identity from current_user when it is a session role.
CREATE OR REPLACE FUNCTION appsec.uid()
RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, appsec, pg_temp
AS $$
  SELECT u.user_id
  FROM appsec.users u
  WHERE u.status='active'
    AND EXISTS (SELECT 1 FROM appsec.tenants t WHERE t.tenant_id=u.tenant_id AND t.status='active')
    AND EXISTS (
      SELECT 1 FROM appsec.session_principals sp
      JOIN appsec.sessions s ON s.session_id=sp.session_id
      JOIN pg_catalog.pg_roles r ON r.rolname=sp.db_role AND r.rolcanlogin
        AND (r.rolvaliduntil IS NULL OR r.rolvaliduntil>statement_timestamp())
      WHERE sp.user_id=u.user_id
        AND s.user_id=u.user_id AND s.revoked_at IS NULL AND s.expires_at>statement_timestamp()
        AND sp.db_role = CASE
          WHEN current_user::text ~ '^app_s_[0-9a-f]{32}$' THEN current_user::name
          ELSE session_user::name
        END
    )
  LIMIT 1
$$;

CREATE OR REPLACE FUNCTION appsec.session_id()
RETURNS uuid
LANGUAGE sql STABLE PARALLEL SAFE SECURITY DEFINER
SET search_path = pg_catalog, appsec, pg_temp
AS $$
  SELECT sp.session_id
  FROM appsec.session_principals sp
  JOIN appsec.sessions s ON s.session_id = sp.session_id
  JOIN appsec.users u ON u.user_id = sp.user_id AND u.status = 'active'
  JOIN appsec.tenants t ON t.tenant_id = u.tenant_id AND t.status = 'active'
  JOIN pg_catalog.pg_roles r ON r.rolname = sp.db_role AND r.rolcanlogin
    AND (r.rolvaliduntil IS NULL OR r.rolvaliduntil > statement_timestamp())
  WHERE sp.db_role = CASE
      WHEN current_user::text ~ '^app_s_[0-9a-f]{32}$' THEN current_user::name
      ELSE session_user::name
    END
    AND s.revoked_at IS NULL
    AND s.expires_at > statement_timestamp()
  LIMIT 1
$$;

-- Superuser-owned GRANT helpers (must be able to GRANT session roles to gateway).
DROP FUNCTION IF EXISTS appsec.grant_session_role_to_gateway(name);
DROP FUNCTION IF EXISTS appsec.revoke_session_role_from_gateway(name);
CREATE OR REPLACE FUNCTION appsec.grant_session_role_to_gateway(target_role name)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, appsec, pg_temp
AS $$
BEGIN
  IF NOT pg_has_role(session_user, 'appsec_provisioner', 'member')
     AND NOT pg_has_role(session_user, 'appsec_owner', 'member')
     AND session_user::text <> 'postgres' THEN
    RAISE EXCEPTION 'provisioner required' USING ERRCODE = '42501';
  END IF;
  IF target_role::text !~ '^app_s_[0-9a-f]{32}$' THEN
    RAISE EXCEPTION 'invalid session role' USING ERRCODE = '22023';
  END IF;
  EXECUTE format('GRANT %I TO appsec_gateway', target_role);
END
$$;

CREATE OR REPLACE FUNCTION appsec.revoke_session_role_from_gateway(target_role name)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, appsec, pg_temp
AS $$
BEGIN
  IF NOT pg_has_role(session_user, 'appsec_provisioner', 'member')
     AND NOT pg_has_role(session_user, 'appsec_owner', 'member')
     AND session_user::text <> 'postgres' THEN
    RAISE EXCEPTION 'provisioner required' USING ERRCODE = '42501';
  END IF;
  EXECUTE format('REVOKE %I FROM appsec_gateway', target_role);
EXCEPTION WHEN undefined_object THEN NULL;
END
$$;

REVOKE ALL ON FUNCTION appsec.grant_session_role_to_gateway(name), appsec.revoke_session_role_from_gateway(name) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION appsec.grant_session_role_to_gateway(name), appsec.revoke_session_role_from_gateway(name)
  TO appsec_provisioner, appsec_operator_base;
