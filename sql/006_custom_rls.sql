\set ON_ERROR_STOP on
SET ROLE appsec_owner;

-- Domino Readers migration: a populated Readers field means restricted.
UPDATE appsec.document_acl
   SET readers_restricted = true
 WHERE readers_restricted = false
   AND (cardinality(readers) > 0 OR cardinality(reader_groups) > 0 OR cardinality(reader_roles) > 0);

-- Optional claims stored at session mint (auth service / OAuth adapter).
ALTER TABLE appsec.session_principals
  ADD COLUMN IF NOT EXISTS auth_claims jsonb NOT NULL DEFAULT '{}'::jsonb;

CREATE OR REPLACE FUNCTION appsec.session_id()
RETURNS uuid
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
  SELECT sp.session_id
  FROM appsec.session_principals sp
  JOIN appsec.sessions s ON s.session_id = sp.session_id
  JOIN appsec.users u ON u.user_id = sp.user_id AND u.status = 'active'
  JOIN appsec.tenants t ON t.tenant_id = u.tenant_id AND t.status = 'active'
  JOIN pg_catalog.pg_roles r ON r.rolname = sp.db_role AND r.rolcanlogin
    AND (r.rolvaliduntil IS NULL OR r.rolvaliduntil > statement_timestamp())
  WHERE sp.db_role = session_user::name
    AND s.revoked_at IS NULL
    AND s.expires_at > statement_timestamp()
  LIMIT 1
$$;

-- SurrealDB $auth analogue: principal derived only from session_user.
CREATE OR REPLACE FUNCTION appsec.auth()
RETURNS jsonb
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
  SELECT CASE WHEN appsec.uid() IS NULL THEN NULL ELSE
    jsonb_strip_nulls(jsonb_build_object(
      'user_id', appsec.uid(),
      'tenant_id', appsec.tenant_id(),
      'session_id', appsec.session_id(),
      'db_role', session_user::text,
      'auth_method', (SELECT s.auth_method FROM appsec.sessions s WHERE s.session_id = appsec.session_id()),
      'claims', coalesce((
        SELECT sp.auth_claims FROM appsec.session_principals sp
        WHERE sp.db_role = session_user::name AND sp.session_id = appsec.session_id()
      ), '{}'::jsonb)
    ))
  END
$$;

-- Validate a policy expression: only allowlist identifiers/operators (no semicolons/comments).
CREATE OR REPLACE FUNCTION appsec._validate_policy_expr(expr text)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $$
DECLARE cleaned text := btrim(expr);
BEGIN
  IF cleaned IS NULL OR length(cleaned) = 0 OR length(cleaned) > 4000 THEN
    RAISE EXCEPTION 'policy expression empty or too long' USING ERRCODE = '22023';
  END IF;
  IF cleaned ~* '(;|--|/\*|\*/|\\)' THEN
    RAISE EXCEPTION 'policy expression contains forbidden tokens' USING ERRCODE = '22023';
  END IF;
  -- Allow SQL-ish predicates referencing columns, appsec helpers, literals, AND/OR/NOT, comparisons.
  IF cleaned !~* '^[a-zA-Z0-9_ $"''.()=<>!+\-*/%,:\[\]{}]+$' THEN
    RAISE EXCEPTION 'policy expression contains unsupported characters' USING ERRCODE = '22023';
  END IF;
  IF cleaned ~* '\y(pg_|current_setting|set_config|lo_|dblink|copy|execute|alter|drop|create|grant|revoke|security\s+definer)\y' THEN
    RAISE EXCEPTION 'policy expression references a forbidden identifier' USING ERRCODE = '22023';
  END IF;
  RETURN cleaned;
END
$$;

CREATE OR REPLACE FUNCTION appsec._require_schema_admin(target regclass)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
BEGIN
  IF NOT pg_has_role(session_user, 'appsec_operator_base', 'member')
     AND NOT pg_has_role(session_user, 'appsec_owner', 'member')
     AND appsec.effective_database_access('*') < 6 THEN
    -- Table owner may manage their own table's policies.
    IF NOT EXISTS (
      SELECT 1 FROM pg_class c
      WHERE c.oid = target AND pg_has_role(session_user, c.relowner, 'member')
    ) THEN
      RAISE EXCEPTION 'schema administration privilege required' USING ERRCODE = '42501';
    END IF;
  END IF;
END
$$;

CREATE TABLE IF NOT EXISTS appsec.table_permission_defs (
  table_oid oid PRIMARY KEY,
  select_expr text,
  create_expr text,
  update_expr text,
  delete_expr text,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS appsec.field_permission_defs (
  table_oid oid NOT NULL,
  column_name name NOT NULL,
  select_expr text,
  update_expr text,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (table_oid, column_name)
);

CREATE OR REPLACE FUNCTION appsec.define_table_permissions(
  target_table regclass,
  select_expr text DEFAULT NULL,
  create_expr text DEFAULT NULL,
  update_expr text DEFAULT NULL,
  delete_expr text DEFAULT NULL,
  tenant_column name DEFAULT NULL
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
DECLARE
  rel text := target_table::text;
  sel text; cre text; upd text; del text;
  tenant_pred text := 'true';
BEGIN
  PERFORM appsec._require_schema_admin(target_table);
  IF select_expr IS NOT NULL THEN sel := appsec._validate_policy_expr(select_expr); END IF;
  IF create_expr IS NOT NULL THEN cre := appsec._validate_policy_expr(create_expr); END IF;
  IF update_expr IS NOT NULL THEN upd := appsec._validate_policy_expr(update_expr); END IF;
  IF delete_expr IS NOT NULL THEN del := appsec._validate_policy_expr(delete_expr); END IF;
  IF tenant_column IS NOT NULL THEN
    tenant_pred := format('(%I = appsec.tenant_id() OR pg_has_role(session_user, ''appsec_operator_base'', ''member''))', tenant_column);
  END IF;

  EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', rel);
  EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', rel);

  -- RESTRICTIVE tenant isolation when requested (always AND'd with permissive policies).
  EXECUTE format('DROP POLICY IF EXISTS appsec_tenant_restrictive ON %s', rel);
  IF tenant_column IS NOT NULL THEN
    EXECUTE format(
      'CREATE POLICY appsec_tenant_restrictive ON %s AS RESTRICTIVE FOR ALL USING (%s) WITH CHECK (%s)',
      rel, tenant_pred, tenant_pred);
  END IF;

  EXECUTE format('DROP POLICY IF EXISTS appsec_dsl_select ON %s', rel);
  EXECUTE format('DROP POLICY IF EXISTS appsec_dsl_insert ON %s', rel);
  EXECUTE format('DROP POLICY IF EXISTS appsec_dsl_update ON %s', rel);
  EXECUTE format('DROP POLICY IF EXISTS appsec_dsl_delete ON %s', rel);

  IF sel IS NOT NULL THEN
    EXECUTE format('CREATE POLICY appsec_dsl_select ON %s FOR SELECT USING ((%s) AND appsec.uid() IS NOT NULL)', rel, sel);
  END IF;
  IF cre IS NOT NULL THEN
    EXECUTE format('CREATE POLICY appsec_dsl_insert ON %s FOR INSERT WITH CHECK ((%s) AND appsec.uid() IS NOT NULL)', rel, cre);
  END IF;
  IF upd IS NOT NULL THEN
    EXECUTE format('CREATE POLICY appsec_dsl_update ON %s FOR UPDATE USING ((%s) AND appsec.uid() IS NOT NULL) WITH CHECK ((%s) AND appsec.uid() IS NOT NULL)', rel, upd, upd);
  END IF;
  IF del IS NOT NULL THEN
    EXECUTE format('CREATE POLICY appsec_dsl_delete ON %s FOR DELETE USING ((%s) AND appsec.uid() IS NOT NULL)', rel, del);
  END IF;

  INSERT INTO appsec.table_permission_defs(table_oid, select_expr, create_expr, update_expr, delete_expr)
  VALUES (target_table, sel, cre, upd, del)
  ON CONFLICT (table_oid) DO UPDATE SET
    select_expr = EXCLUDED.select_expr, create_expr = EXCLUDED.create_expr,
    update_expr = EXCLUDED.update_expr, delete_expr = EXCLUDED.delete_expr,
    updated_at = clock_timestamp();
END
$$;

CREATE OR REPLACE FUNCTION appsec.drop_table_permissions(target_table regclass)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
DECLARE rel text := target_table::text;
BEGIN
  PERFORM appsec._require_schema_admin(target_table);
  EXECUTE format('DROP POLICY IF EXISTS appsec_tenant_restrictive ON %s', rel);
  EXECUTE format('DROP POLICY IF EXISTS appsec_dsl_select ON %s', rel);
  EXECUTE format('DROP POLICY IF EXISTS appsec_dsl_insert ON %s', rel);
  EXECUTE format('DROP POLICY IF EXISTS appsec_dsl_update ON %s', rel);
  EXECUTE format('DROP POLICY IF EXISTS appsec_dsl_delete ON %s', rel);
  DELETE FROM appsec.table_permission_defs WHERE table_oid = target_table;
  DELETE FROM appsec.field_permission_defs WHERE table_oid = target_table;
END
$$;

-- Field permissions: defs + generic BEFORE UPDATE OF trigger + readability helper.

DROP FUNCTION IF EXISTS appsec.field_readable(regclass, name);
DROP FUNCTION IF EXISTS appsec.define_field_permissions(regclass, name, text, text);
DROP FUNCTION IF EXISTS appsec.drop_field_permissions(regclass, name);
DROP FUNCTION IF EXISTS appsec._rebuild_field_view(regclass);

CREATE OR REPLACE FUNCTION appsec.field_readable(target_table regclass, target_column name)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
DECLARE expr text;
BEGIN
  SELECT select_expr INTO expr FROM appsec.field_permission_defs
   WHERE table_oid = target_table AND column_name = target_column;
  IF expr IS NULL THEN
    RETURN true; -- no field policy => column visibility left to table grants/RLS
  END IF;
  RETURN (SELECT result FROM appsec._eval_bool_expr(expr) AS result);
END
$$;

-- Evaluate a previously validated boolean expression in a locked-down search_path.
CREATE OR REPLACE FUNCTION appsec._eval_bool_expr(expr text)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
DECLARE ok boolean;
BEGIN
  EXECUTE format('SELECT (%s)::boolean', appsec._validate_policy_expr(expr)) INTO ok;
  RETURN coalesce(ok, false);
EXCEPTION WHEN OTHERS THEN
  RETURN false;
END
$$;

CREATE OR REPLACE FUNCTION appsec._field_update_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
DECLARE rec record;
  old_val text; new_val text;
BEGIN
  FOR rec IN
    SELECT column_name, update_expr FROM appsec.field_permission_defs WHERE table_oid = TG_RELID
  LOOP
    EXECUTE format('SELECT ($1).%I::text, ($2).%I::text', rec.column_name, rec.column_name)
      INTO old_val, new_val USING OLD, NEW;
    IF old_val IS DISTINCT FROM new_val THEN
      IF rec.update_expr IS NULL OR NOT appsec._eval_bool_expr(rec.update_expr) THEN
        RAISE EXCEPTION 'not authorized to update column %', rec.column_name USING ERRCODE = '42501';
      END IF;
    END IF;
  END LOOP;
  RETURN NEW;
END
$$;


-- Rebuild schema.table_secured view: columns with select_expr are masked unless predicate holds.
CREATE OR REPLACE FUNCTION appsec._rebuild_field_view(target_table regclass)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
DECLARE
  nsp name; rel name; view_name text; col record; parts text[] := ARRAY[]::text[];
  sel text; sql text;
BEGIN
  SELECT c.relnamespace::regnamespace::name, c.relname INTO nsp, rel
  FROM pg_class c WHERE c.oid = target_table;
  view_name := format('%I.%I', nsp, rel || '_secured');
  FOR col IN
    SELECT a.attname
    FROM pg_attribute a
    WHERE a.attrelid = target_table AND a.attnum > 0 AND NOT a.attisdropped
    ORDER BY a.attnum
  LOOP
    SELECT select_expr INTO sel FROM appsec.field_permission_defs
     WHERE table_oid = target_table AND column_name = col.attname;
    IF sel IS NULL THEN
      parts := parts || format('%I', col.attname);
    ELSE
      parts := parts || format('CASE WHEN (%s) THEN %I ELSE NULL END AS %I', sel, col.attname, col.attname);
    END IF;
  END LOOP;
  IF cardinality(parts) = 0 THEN
    EXECUTE format('DROP VIEW IF EXISTS %s', view_name);
    RETURN;
  END IF;
  sql := format('CREATE OR REPLACE VIEW %s WITH (security_barrier=true) AS SELECT %s FROM %s',
                view_name, array_to_string(parts, ', '), target_table::text);
  EXECUTE sql;
  EXECUTE format('ALTER VIEW %s OWNER TO appsec_owner', view_name);
  EXECUTE format('REVOKE ALL ON %s FROM PUBLIC', view_name);
  EXECUTE format('GRANT SELECT ON %s TO appsec_app_base, appsec_operator_base', view_name);
END
$$;

CREATE OR REPLACE FUNCTION appsec.define_field_permissions(
  target_table regclass,
  target_column name,
  select_expr text DEFAULT NULL,
  update_expr text DEFAULT NULL
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
DECLARE
  rel text := target_table::text;
  sel text; upd text;
BEGIN
  PERFORM appsec._require_schema_admin(target_table);
  IF NOT EXISTS (
    SELECT 1 FROM pg_attribute a
    WHERE a.attrelid = target_table AND a.attname = target_column AND a.attnum > 0 AND NOT a.attisdropped
  ) THEN
    RAISE EXCEPTION 'column % does not exist on %', target_column, rel USING ERRCODE = '42703';
  END IF;
  IF select_expr IS NOT NULL THEN sel := appsec._validate_policy_expr(select_expr); END IF;
  IF update_expr IS NOT NULL THEN upd := appsec._validate_policy_expr(update_expr); END IF;

  INSERT INTO appsec.field_permission_defs(table_oid, column_name, select_expr, update_expr)
  VALUES (target_table, target_column, sel, upd)
  ON CONFLICT ON CONSTRAINT field_permission_defs_pkey DO UPDATE SET
    select_expr = EXCLUDED.select_expr, update_expr = EXCLUDED.update_expr,
    updated_at = clock_timestamp();

  -- Column grants: mask SELECT via security_barrier view when select_expr set; UPDATE guarded by trigger.
  IF sel IS NOT NULL THEN
    EXECUTE format('REVOKE SELECT (%I) ON TABLE %s FROM appsec_app_base', target_column, rel);
  ELSE
    EXECUTE format('GRANT SELECT (%I) ON TABLE %s TO appsec_app_base', target_column, rel);
  END IF;
  IF upd IS NOT NULL THEN
    EXECUTE format('GRANT UPDATE (%I) ON TABLE %s TO appsec_app_base', target_column, rel);
  END IF;

  EXECUTE format('DROP TRIGGER IF EXISTS appsec_field_update_guard ON %s', rel);
  EXECUTE format(
    'CREATE TRIGGER appsec_field_update_guard BEFORE UPDATE ON %s FOR EACH ROW EXECUTE FUNCTION appsec._field_update_guard()',
    rel);

  PERFORM appsec._rebuild_field_view(target_table);
END
$$;

CREATE OR REPLACE FUNCTION appsec.drop_field_permissions(target_table regclass, target_column name)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
BEGIN
  PERFORM appsec._require_schema_admin(target_table);
  DELETE FROM appsec.field_permission_defs WHERE table_oid = target_table AND column_name = target_column;
  IF NOT EXISTS (SELECT 1 FROM appsec.field_permission_defs WHERE table_oid = target_table) THEN
    EXECUTE format('DROP TRIGGER IF EXISTS appsec_field_update_guard ON %s', target_table::text);
  END IF;
  PERFORM appsec._rebuild_field_view(target_table);
END
$$;

REVOKE ALL ON FUNCTION appsec.session_id(), appsec.auth(), appsec.field_readable(regclass,name),
  appsec.define_table_permissions(regclass,text,text,text,text,name),
  appsec.drop_table_permissions(regclass),
  appsec.define_field_permissions(regclass,name,text,text),
  appsec.drop_field_permissions(regclass,name),
  appsec._validate_policy_expr(text),
  appsec._require_schema_admin(regclass),
  appsec._eval_bool_expr(text),
  appsec._field_update_guard(),
  appsec._rebuild_field_view(regclass)
FROM PUBLIC;

GRANT EXECUTE ON FUNCTION appsec.session_id(), appsec.auth(), appsec.field_readable(regclass,name)
  TO appsec_app_base, appsec_operator_base;

GRANT EXECUTE ON FUNCTION
  appsec.define_table_permissions(regclass,text,text,text,text,name),
  appsec.drop_table_permissions(regclass),
  appsec.define_field_permissions(regclass,name,text,text),
  appsec.drop_field_permissions(regclass,name)
  TO appsec_operator_base;

GRANT EXECUTE ON FUNCTION appsec.uid(), appsec.tenant_id(), appsec.has_role(text)
  TO appsec_app_base, appsec_operator_base;

RESET ROLE;

-- LEAKPROOF requires installing superuser. Safe: helpers reveal nothing beyond return value.
DO $leak$
BEGIN
  ALTER FUNCTION appsec.uid() LEAKPROOF;
  ALTER FUNCTION appsec.tenant_id() LEAKPROOF;
  ALTER FUNCTION appsec.session_id() LEAKPROOF;
  ALTER FUNCTION appsec.auth() LEAKPROOF;
  ALTER FUNCTION appsec.has_role(text) LEAKPROOF;
  ALTER FUNCTION appsec.has_nonpublic_role(text) LEAKPROOF;
EXCEPTION WHEN insufficient_privilege THEN
  RAISE NOTICE 'LEAKPROOF skipped (installer is not superuser)';
WHEN undefined_function THEN
  RAISE NOTICE 'LEAKPROOF skipped (function missing)';
END
$leak$;
