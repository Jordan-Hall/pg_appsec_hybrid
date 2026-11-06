\set ON_ERROR_STOP on
-- Close remaining Domino/Surreal risks: NOTIFY for oauth sync, gateway SET LOCAL,
-- session-role mint hardening, audit chain verify + head export.

SET ROLE appsec_owner;

-- ---------------------------------------------------------------------------
-- Gateway: transaction-scoped SET LOCAL ROLE helper (preferred when in a txn)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION appsec.assume_session_local(assertion text)
RETURNS void
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, appsec, pg_temp
AS $$
DECLARE v_role name;
BEGIN
  -- SET LOCAL ROLE requires an open transaction block (PostgreSQL error 25001 otherwise).
  v_role := appsec.verify_gateway_assertion(assertion);
  EXECUTE format('SET LOCAL ROLE %I', v_role);
END
$$;

COMMENT ON FUNCTION appsec.assume_session(text) IS
  'Gateway helper: SET ROLE to the session role for the rest of the session (or until RESET ROLE). '
  'Use when clients run autocommit statements. Prefer assume_session_local inside an explicit transaction '
  'so the role ends at COMMIT/ROLLBACK. Outside an assumed session, appsec_gateway has zero table privileges.';

COMMENT ON FUNCTION appsec.assume_session_local(text) IS
  'Preferred gateway helper inside an explicit transaction: SET LOCAL ROLE so the assumed session '
  'cannot outlive the transaction. Fails outside a transaction block.';

REVOKE ALL ON FUNCTION appsec.assume_session_local(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION appsec.assume_session_local(text) TO appsec_gateway;

-- ---------------------------------------------------------------------------
-- Per-session role mint hardening (called by auth service after CREATE ROLE)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION appsec.harden_session_role(target_role name, valid_until timestamptz, connection_limit integer DEFAULT 2)
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
  IF connection_limit IS NULL OR connection_limit < 1 OR connection_limit > 16 THEN
    RAISE EXCEPTION 'connection_limit out of range' USING ERRCODE = '22023';
  END IF;
  IF valid_until IS NULL OR valid_until <= clock_timestamp() THEN
    RAISE EXCEPTION 'valid_until must be in the future' USING ERRCODE = '22023';
  END IF;
  -- CONNECTION LIMIT + VALID UNTIL only (NOSUPERUSER/NOCREATEDB/... already set at CREATE ROLE;
  -- restating them here requires superuser and fails when this DEFINER is appsec_owner).
  -- Keep INHERIT so GRANT appsec_app_base TO app_s_* confers privileges.
  EXECUTE format(
    'ALTER ROLE %I WITH CONNECTION LIMIT %s VALID UNTIL %L',
    target_role, connection_limit, valid_until
  );
  BEGIN
    EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM %I', current_database(), target_role);
  EXCEPTION WHEN OTHERS THEN
    NULL; -- best-effort; some hosts disallow non-owner TEMP revoke
  END;
END
$$;

REVOKE ALL ON FUNCTION appsec.harden_session_role(name, timestamptz, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION appsec.harden_session_role(name, timestamptz, integer)
  TO appsec_provisioner, appsec_operator_base;

-- ---------------------------------------------------------------------------
-- Audit: verify chain integrity + export head hash for external WORM anchoring
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION appsec.verify_security_audit_chain()
RETURNS TABLE(ok boolean, checked_events bigint, first_bad_event_id bigint, detail text)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, appsec, pg_temp
AS $$
DECLARE
  r record;
  prev bytea := decode(repeat('00', 32), 'hex');
  payload text;
  expect bytea;
  n bigint := 0;
BEGIN
  FOR r IN
    SELECT c.event_id, c.occurred_at, c.actor_user_id, c.actor_role, c.event_type,
           c.resource, c.detail AS event_detail, c.prev_hash, c.event_hash
    FROM appsec.security_audit_chain c
    ORDER BY c.event_id
  LOOP
    n := n + 1;
    IF r.prev_hash IS DISTINCT FROM prev THEN
      ok := false; checked_events := n; first_bad_event_id := r.event_id;
      detail := 'prev_hash mismatch';
      RETURN NEXT; RETURN;
    END IF;
    payload := coalesce(r.occurred_at::text,'') || '|' || coalesce(r.actor_user_id::text,'') || '|' ||
               coalesce(r.actor_role::text,'') || '|' || coalesce(r.event_type,'') || '|' ||
               coalesce(r.resource,'') || '|' || coalesce(r.event_detail::text,'{}') || '|' || encode(prev, 'hex');
    expect := appsec.digest(convert_to(payload, 'UTF8'), 'sha256');
    IF r.event_hash IS DISTINCT FROM expect THEN
      ok := false; checked_events := n; first_bad_event_id := r.event_id;
      detail := 'event_hash mismatch';
      RETURN NEXT; RETURN;
    END IF;
    prev := r.event_hash;
  END LOOP;
  ok := true; checked_events := n; first_bad_event_id := NULL; detail := 'ok';
  RETURN NEXT;
END
$$;

CREATE OR REPLACE FUNCTION appsec.export_audit_chain_head()
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, appsec, pg_temp
AS $$
  SELECT jsonb_build_object(
    'exported_at', clock_timestamp(),
    'database', current_database(),
    'event_id', c.event_id,
    'occurred_at', c.occurred_at,
    'event_type', c.event_type,
    'event_hash', encode(c.event_hash, 'hex'),
    'prev_hash', encode(c.prev_hash, 'hex')
  )
  FROM appsec.security_audit_chain c
  ORDER BY c.event_id DESC
  LIMIT 1
$$;

REVOKE ALL ON FUNCTION appsec.verify_security_audit_chain(), appsec.export_audit_chain_head() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION appsec.verify_security_audit_chain(), appsec.export_audit_chain_head()
  TO appsec_operator_base, appsec_provisioner;

-- ---------------------------------------------------------------------------
-- LISTEN/NOTIFY: session/credential changes for oauth-state-sync worker
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION appsec.notify_oauth_state_changed()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, appsec, pg_temp
AS $$
BEGIN
  PERFORM pg_notify('appsec_oauth_state', TG_TABLE_NAME || ':' || TG_OP);
  RETURN COALESCE(NEW, OLD);
END
$$;

DROP TRIGGER IF EXISTS sessions_oauth_state_notify ON appsec.sessions;
CREATE TRIGGER sessions_oauth_state_notify
  AFTER INSERT OR UPDATE OR DELETE ON appsec.sessions
  FOR EACH ROW EXECUTE FUNCTION appsec.notify_oauth_state_changed();

DROP TRIGGER IF EXISTS pool_credentials_oauth_state_notify ON appsec.pool_credentials;
CREATE TRIGGER pool_credentials_oauth_state_notify
  AFTER INSERT OR UPDATE OR DELETE ON appsec.pool_credentials
  FOR EACH ROW EXECUTE FUNCTION appsec.notify_oauth_state_changed();

DROP TRIGGER IF EXISTS oauth_jti_denylist_notify ON appsec.oauth_jti_denylist;
CREATE TRIGGER oauth_jti_denylist_notify
  AFTER INSERT OR UPDATE OR DELETE ON appsec.oauth_jti_denylist
  FOR EACH ROW EXECUTE FUNCTION appsec.notify_oauth_state_changed();

DROP TRIGGER IF EXISTS users_oauth_state_notify ON appsec.users;
CREATE TRIGGER users_oauth_state_notify
  AFTER UPDATE OF status ON appsec.users
  FOR EACH ROW EXECUTE FUNCTION appsec.notify_oauth_state_changed();

REVOKE ALL ON FUNCTION appsec.notify_oauth_state_changed() FROM PUBLIC;

RESET ROLE;


-- Superuser-owned harden helper (must ALTER arbitrary app_s_* roles).
RESET ROLE;
DROP FUNCTION IF EXISTS appsec.harden_session_role(name, timestamptz, integer);
CREATE OR REPLACE FUNCTION appsec.harden_session_role(target_role name, valid_until timestamptz, connection_limit integer DEFAULT 2)
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
  IF connection_limit IS NULL OR connection_limit < 1 OR connection_limit > 16 THEN
    RAISE EXCEPTION 'connection_limit out of range' USING ERRCODE = '22023';
  END IF;
  IF valid_until IS NULL OR valid_until <= clock_timestamp() THEN
    RAISE EXCEPTION 'valid_until must be in the future' USING ERRCODE = '22023';
  END IF;
  EXECUTE format(
    'ALTER ROLE %I WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT CONNECTION LIMIT %s VALID UNTIL %L',
    target_role, connection_limit, valid_until
  );
  BEGIN
    EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM %I', current_database(), target_role);
  EXCEPTION WHEN OTHERS THEN
    NULL;
  END;
END
$$;
REVOKE ALL ON FUNCTION appsec.harden_session_role(name, timestamptz, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION appsec.harden_session_role(name, timestamptz, integer)
  TO appsec_provisioner, appsec_operator_base;


-- ---------------------------------------------------------------------------
-- Gateway-aware identity: inside SECURITY DEFINER, current_user is the owner.
-- Prefer the SET ROLE / SET LOCAL ROLE target from GUC "role" when it is app_s_*.
-- ---------------------------------------------------------------------------
RESET ROLE;
CREATE OR REPLACE FUNCTION appsec._effective_session_role()
RETURNS name
LANGUAGE sql
STABLE
PARALLEL SAFE
AS $$
  SELECT CASE
    WHEN current_setting('role', true) ~ '^app_s_[0-9a-f]{32}$'
      THEN current_setting('role', true)::name
    WHEN current_user::text ~ '^app_s_[0-9a-f]{32}$'
      THEN current_user::name
    WHEN session_user::text ~ '^app_s_[0-9a-f]{32}$'
      THEN session_user::name
    ELSE session_user::name
  END
$$;

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
        AND sp.db_role = appsec._effective_session_role()
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
  WHERE sp.db_role = appsec._effective_session_role()
    AND s.revoked_at IS NULL
    AND s.expires_at > statement_timestamp()
  LIMIT 1
$$;

-- Safe: only resolves role name from GUCs; must be callable from triggers/policies.
GRANT EXECUTE ON FUNCTION appsec._effective_session_role() TO PUBLIC;
GRANT EXECUTE ON FUNCTION appsec.uid(), appsec.session_id()
  TO appsec_app_base, appsec_operator_base, appsec_gateway;
