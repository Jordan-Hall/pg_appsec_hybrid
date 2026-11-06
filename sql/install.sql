-- BEGIN 001_roles.sql

DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'appsec_owner') THEN
    CREATE ROLE appsec_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'appsec_provisioner') THEN
    CREATE ROLE appsec_provisioner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'appsec_app_base') THEN
    CREATE ROLE appsec_app_base NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'appsec_operator_base') THEN
    CREATE ROLE appsec_operator_base NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'appsec_pool_auth') THEN
    CREATE ROLE appsec_pool_auth NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
END
$roles$;

CREATE SCHEMA IF NOT EXISTS appsec AUTHORIZATION appsec_owner;
REVOKE ALL ON SCHEMA appsec FROM PUBLIC;
GRANT USAGE ON SCHEMA appsec TO appsec_app_base, appsec_operator_base, appsec_pool_auth;
GRANT USAGE, CREATE ON SCHEMA appsec TO appsec_owner;
GRANT appsec_app_base TO appsec_operator_base;

ALTER DEFAULT PRIVILEGES FOR ROLE appsec_owner IN SCHEMA appsec REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE appsec_owner IN SCHEMA appsec REVOKE ALL ON TABLES FROM PUBLIC;

-- This is a non-login control-plane role. Grant it only to a dedicated
-- provisioning service identity, never to the application runtime role.
ALTER ROLE appsec_provisioner CREATEROLE;
GRANT appsec_app_base TO appsec_provisioner WITH ADMIN OPTION;
-- END 001_roles.sql

-- BEGIN 002_schema.sql
SET ROLE appsec_owner;

CREATE TABLE IF NOT EXISTS appsec.tenants (
  tenant_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug text NOT NULL UNIQUE CHECK (length(slug) BETWEEN 1 AND 128),
  display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 256),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','deleted')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS appsec.users (
  user_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text,
  username text,
  display_name text,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','locked','disabled','deleted')),
  tenant_id uuid NOT NULL REFERENCES appsec.tenants(tenant_id),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (email IS NULL OR length(email) <= 320),
  CHECK (username IS NULL OR length(username) BETWEEN 1 AND 128)
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_uq ON appsec.users (tenant_id, lower(email)) WHERE email IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_uq ON appsec.users (tenant_id, lower(username)) WHERE username IS NOT NULL;

CREATE TABLE IF NOT EXISTS appsec.identities (
  identity_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES appsec.users(user_id) ON DELETE CASCADE,
  provider text NOT NULL,
  provider_subject text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(provider, provider_subject),
  UNIQUE(user_id, provider)
);

CREATE TABLE IF NOT EXISTS appsec.principals (
  user_id uuid PRIMARY KEY REFERENCES appsec.users(user_id) ON DELETE CASCADE,
  db_role name NOT NULL UNIQUE,
  principal_kind text NOT NULL DEFAULT 'application' CHECK (principal_kind IN ('application','operator','service')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS appsec.groups (
  group_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES appsec.tenants(tenant_id),
  name text NOT NULL,
  UNIQUE(tenant_id, name)
);
CREATE TABLE IF NOT EXISTS appsec.user_roles (
  user_id uuid NOT NULL REFERENCES appsec.users(user_id) ON DELETE CASCADE,
  role_name text NOT NULL CHECK (length(role_name) BETWEEN 1 AND 128),
  tenant_id uuid NOT NULL REFERENCES appsec.tenants(tenant_id),
  granted_by uuid NOT NULL REFERENCES appsec.users(user_id),
  granted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(user_id, role_name)
);
CREATE INDEX IF NOT EXISTS user_roles_tenant_role_idx ON appsec.user_roles(tenant_id, role_name);

CREATE TABLE IF NOT EXISTS appsec.group_members (
  group_id uuid NOT NULL REFERENCES appsec.groups(group_id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES appsec.users(user_id) ON DELETE CASCADE,
  PRIMARY KEY(group_id, user_id)
);

CREATE TABLE IF NOT EXISTS appsec.database_acl_entries (
  acl_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  database_name text NOT NULL DEFAULT current_database(),
  resource_name text NOT NULL DEFAULT '*',
  principal_kind text NOT NULL CHECK (principal_kind IN ('user','group','role','public')),
  principal_id text NOT NULL,
  access_level smallint NOT NULL CHECK (access_level BETWEEN 0 AND 6),
  assigned_roles text[] NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(database_name,resource_name,principal_kind,principal_id)
);
CREATE INDEX IF NOT EXISTS database_acl_lookup_idx ON appsec.database_acl_entries(database_name,resource_name,principal_kind,principal_id);

CREATE TABLE IF NOT EXISTS appsec.document_acl (
  document_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES appsec.tenants(tenant_id),
  readers uuid[] NOT NULL DEFAULT '{}',
  authors uuid[] NOT NULL DEFAULT '{}',
  reader_groups uuid[] NOT NULL DEFAULT '{}',
  author_groups uuid[] NOT NULL DEFAULT '{}',
  reader_roles text[] NOT NULL DEFAULT '{}',
  author_roles text[] NOT NULL DEFAULT '{}',
  readers_restricted boolean NOT NULL DEFAULT false,
  is_public boolean NOT NULL DEFAULT false,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS appsec.jsonb_field_acl (
  resource text NOT NULL,
  json_path text[] NOT NULL,
  read_roles text[] NOT NULL DEFAULT '{}',
  write_roles text[] NOT NULL DEFAULT '{}',
  read_groups uuid[] NOT NULL DEFAULT '{}',
  write_groups uuid[] NOT NULL DEFAULT '{}',
  PRIMARY KEY(resource, json_path)
);

CREATE TABLE IF NOT EXISTS appsec.audit_events (
  event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  actor_role name NOT NULL DEFAULT session_user,
  actor_user_id uuid,
  event_type text NOT NULL,
  resource text,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb
);

REVOKE ALL ON ALL TABLES IN SCHEMA appsec FROM PUBLIC, appsec_app_base, appsec_operator_base;
GRANT SELECT ON appsec.tenants, appsec.users, appsec.groups, appsec.group_members, appsec.document_acl, appsec.audit_events TO appsec_operator_base;

RESET ROLE;
-- END 002_schema.sql

-- BEGIN 003_policies.sql
SET ROLE appsec_owner;

CREATE OR REPLACE FUNCTION appsec.uid()
RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
  SELECT p.user_id
  FROM appsec.principals AS p
  JOIN appsec.users AS u USING (user_id)
  WHERE p.db_role = session_user::name
    AND u.status = 'active'
$$;

CREATE OR REPLACE FUNCTION appsec.tenant_id()
RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
  SELECT u.tenant_id FROM appsec.users AS u WHERE u.user_id = appsec.uid()
$$;

CREATE OR REPLACE FUNCTION appsec.has_role(requested_role text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
 SELECT EXISTS (SELECT 1 FROM appsec.user_roles r WHERE r.user_id=appsec.uid()
   AND r.tenant_id=appsec.tenant_id() AND r.role_name=requested_role)
 OR EXISTS (
   SELECT 1 FROM appsec.database_acl_entries a
   WHERE a.database_name=current_database()
     AND requested_role = ANY(a.assigned_roles)
     AND ((a.principal_kind='user' AND a.principal_id=appsec.uid()::text)
       OR (a.principal_kind='group' AND EXISTS (
         SELECT 1 FROM appsec.group_members gm WHERE gm.user_id=appsec.uid() AND gm.group_id::text=a.principal_id)))
 )
$$;

CREATE OR REPLACE FUNCTION appsec.effective_database_access(target_resource text DEFAULT '*')
RETURNS smallint LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
  SELECT CASE
    WHEN pg_has_role(session_user, 'appsec_operator_base', 'member') THEN 6::smallint
    ELSE coalesce((
      SELECT a.access_level
      FROM appsec.database_acl_entries a
      WHERE a.database_name = current_database()
        AND a.resource_name IN ('*', target_resource)
        AND (
          (a.principal_kind = 'public' AND a.principal_id = '*')
          OR (a.principal_kind = 'user' AND a.principal_id = appsec.uid()::text)
          OR (a.principal_kind = 'group' AND EXISTS (
            SELECT 1 FROM appsec.group_members gm
            WHERE gm.user_id = appsec.uid() AND gm.group_id::text = a.principal_id))
          OR (a.principal_kind = 'role' AND appsec.has_role(a.principal_id))
        )
      ORDER BY (a.resource_name = target_resource) DESC,
        CASE a.principal_kind WHEN 'user' THEN 4 WHEN 'group' THEN 3 WHEN 'role' THEN 2 ELSE 1 END DESC,
        a.access_level DESC
      LIMIT 1
    ), 0)::smallint
  END
$$;

CREATE OR REPLACE FUNCTION appsec.is_member_of_any(group_ids uuid[])
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
  SELECT EXISTS (
    SELECT 1 FROM appsec.group_members gm
    WHERE gm.user_id = appsec.uid() AND gm.group_id = ANY(group_ids)
  )
$$;

CREATE OR REPLACE FUNCTION appsec.can_read_document(doc_id uuid)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
  SELECT EXISTS (
    SELECT 1 FROM appsec.document_acl a
    WHERE a.document_id = doc_id
      AND (a.tenant_id = appsec.tenant_id() OR pg_has_role(session_user, 'appsec_operator_base', 'member'))
      AND (
        ((appsec.effective_database_access('documents') >= 2 AND (
          NOT a.readers_restricted
          OR appsec.uid() = ANY(a.readers)
          OR appsec.uid() = ANY(a.authors)
          OR appsec.is_member_of_any(a.reader_groups)
          OR appsec.is_member_of_any(a.author_groups)
          OR EXISTS (SELECT 1 FROM unnest(a.reader_roles || a.author_roles) r WHERE appsec.has_role(r))
          OR pg_has_role(session_user, 'appsec_operator_base', 'member')
        )) OR (a.is_public AND appsec.has_role('documents.read_public')))
      )
  )
$$;

CREATE OR REPLACE FUNCTION appsec.can_write_document(doc_id uuid)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
  SELECT EXISTS (
    SELECT 1 FROM appsec.document_acl a
    WHERE a.document_id = doc_id
      AND (a.tenant_id = appsec.tenant_id() OR pg_has_role(session_user, 'appsec_operator_base', 'member'))
      AND (
        (NOT a.readers_restricted
          OR appsec.uid() = ANY(a.readers) OR appsec.uid() = ANY(a.authors)
          OR appsec.is_member_of_any(a.reader_groups) OR appsec.is_member_of_any(a.author_groups)
          OR EXISTS (SELECT 1 FROM unnest(a.reader_roles || a.author_roles) r WHERE appsec.has_role(r))
          OR pg_has_role(session_user, 'appsec_operator_base', 'member')
          OR (a.is_public AND appsec.has_role('documents.write_public')))
        AND (
          (appsec.effective_database_access('documents') >= 3 AND (appsec.uid() = ANY(a.authors) OR appsec.is_member_of_any(a.author_groups)
            OR EXISTS (SELECT 1 FROM unnest(a.author_roles) r WHERE appsec.has_role(r))))
          OR appsec.effective_database_access('documents') >= 4
          OR (a.is_public AND appsec.has_role('documents.write_public'))
          OR pg_has_role(session_user, 'appsec_operator_base', 'member')
        )
      )
  )
$$;

CREATE TABLE IF NOT EXISTS appsec.documents (
  document_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES appsec.tenants(tenant_id),
  owner_id uuid NOT NULL REFERENCES appsec.users(user_id),
  body jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='document_acl_document_fk' AND conrelid='appsec.document_acl'::regclass) THEN
    ALTER TABLE appsec.document_acl ADD CONSTRAINT document_acl_document_fk
      FOREIGN KEY (document_id) REFERENCES appsec.documents(document_id) ON DELETE CASCADE;
  END IF;
END $$;

ALTER TABLE appsec.documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE appsec.documents FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS documents_select ON appsec.documents;
DROP POLICY IF EXISTS documents_insert ON appsec.documents;
DROP POLICY IF EXISTS documents_update ON appsec.documents;
DROP POLICY IF EXISTS documents_delete ON appsec.documents;
CREATE POLICY documents_select ON appsec.documents FOR SELECT
  USING ((tenant_id = appsec.tenant_id() OR pg_has_role(session_user, 'appsec_operator_base', 'member')) AND appsec.can_read_document(document_id));
CREATE POLICY documents_insert ON appsec.documents FOR INSERT
  WITH CHECK (tenant_id = appsec.tenant_id() AND owner_id = appsec.uid());
CREATE POLICY documents_update ON appsec.documents FOR UPDATE
  USING ((tenant_id = appsec.tenant_id() OR pg_has_role(session_user, 'appsec_operator_base', 'member')) AND appsec.can_write_document(document_id))
  WITH CHECK ((tenant_id = appsec.tenant_id() OR pg_has_role(session_user, 'appsec_operator_base', 'member')) AND appsec.can_write_document(document_id));
CREATE POLICY documents_delete ON appsec.documents FOR DELETE
  USING ((tenant_id = appsec.tenant_id() OR pg_has_role(session_user, 'appsec_operator_base', 'member')) AND appsec.can_write_document(document_id));

REVOKE ALL ON appsec.documents FROM PUBLIC, appsec_app_base;
GRANT SELECT (document_id, tenant_id, owner_id, created_at, updated_at), DELETE ON appsec.documents TO appsec_app_base;

CREATE OR REPLACE FUNCTION appsec.jsonb_set_deep(target jsonb, path text[], value jsonb)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE STRICT
SET search_path = pg_catalog
AS $$
DECLARE child jsonb;
BEGIN
  IF cardinality(path) = 0 THEN RETURN value; END IF;
  IF cardinality(path) = 1 THEN
    RETURN jsonb_set(coalesce(target, '{}'::jsonb), path, value, true);
  END IF;
  child := target -> path[1];
  IF child IS NULL THEN child := '{}'::jsonb; END IF;
  child := appsec.jsonb_set_deep(child, path[2:cardinality(path)], value);
  RETURN jsonb_set(coalesce(target, '{}'::jsonb), ARRAY[path[1]], child, true);
END
$$;

CREATE OR REPLACE FUNCTION appsec.jsonb_project(resource_name text, input_doc jsonb)
RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
DECLARE
  result jsonb := '{}'::jsonb;
  policy record;
  value jsonb;
BEGIN
  IF jsonb_typeof(input_doc) <> 'object' THEN
    RAISE EXCEPTION 'JSON document must be an object' USING ERRCODE = '22023';
  END IF;
  FOR policy IN
    SELECT json_path, read_roles, read_groups
    FROM appsec.jsonb_field_acl f
    WHERE resource = resource_name
      AND NOT EXISTS (
        SELECT 1 FROM appsec.jsonb_field_acl child
        WHERE child.resource = f.resource
          AND cardinality(child.json_path) > cardinality(f.json_path)
          AND child.json_path[1:cardinality(f.json_path)] = f.json_path
      )
  LOOP
    IF (cardinality(policy.read_roles) > 0 OR cardinality(policy.read_groups) > 0)
       AND (EXISTS (SELECT 1 FROM unnest(policy.read_roles) rr WHERE appsec.has_role(rr::text)) OR appsec.is_member_of_any(policy.read_groups)) THEN
      value := input_doc #> policy.json_path;
      IF value IS NOT NULL THEN
        result := appsec.jsonb_set_deep(result, policy.json_path, value);
      END IF;
    END IF;
  END LOOP;
  RETURN result;
END
$$;

CREATE OR REPLACE FUNCTION appsec.jsonb_path_write_allowed(resource_name text, path text[])
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
  SELECT EXISTS (
    SELECT 1 FROM appsec.jsonb_field_acl f
    WHERE f.resource = resource_name
      AND f.json_path = path
      AND (cardinality(f.write_roles) > 0 OR cardinality(f.write_groups) > 0)
      AND (EXISTS (SELECT 1 FROM unnest(f.write_roles) rr WHERE appsec.has_role(rr::text)) OR appsec.is_member_of_any(f.write_groups))
  )
$$;


CREATE OR REPLACE FUNCTION appsec.jsonb_all_leaf_paths_writable(resource_name text, node jsonb, prefix text[] DEFAULT '{}')
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
DECLARE item record;
BEGIN
  IF jsonb_typeof(node) = 'object' THEN
    FOR item IN SELECT key, value FROM jsonb_each(node) LOOP
      IF NOT appsec.jsonb_all_leaf_paths_writable(resource_name, item.value, prefix || item.key) THEN
        RETURN false;
      END IF;
    END LOOP;
    RETURN true;
  END IF;
  RETURN cardinality(prefix) > 0 AND appsec.jsonb_path_write_allowed(resource_name, prefix);
END
$$;

CREATE OR REPLACE FUNCTION appsec.create_document(input_body jsonb)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
DECLARE
  new_id uuid;
  actor uuid := appsec.uid();
  tenant uuid := appsec.tenant_id();
BEGIN
  IF actor IS NULL OR tenant IS NULL OR NOT (
    appsec.effective_database_access('documents') = 1
    OR appsec.effective_database_access('documents') >= 4
    OR (appsec.effective_database_access('documents') = 3 AND appsec.has_role('documents.create'))
    OR (input_body ->> '$PublicAccess' = '1' AND appsec.has_role('documents.write_public'))
  ) THEN
    RAISE EXCEPTION 'database ACL does not grant document creation' USING ERRCODE = '42501';
  END IF;
  IF jsonb_typeof(input_body) <> 'object' THEN
    RAISE EXCEPTION 'document body must be a JSON object' USING ERRCODE = '22023';
  END IF;
  IF NOT appsec.jsonb_all_leaf_paths_writable('documents.body', input_body) THEN
    RAISE EXCEPTION 'document contains an unconfigured or unauthorized JSON field' USING ERRCODE = '42501';
  END IF;
  -- Allocate id first and avoid INSERT…RETURNING: under FORCE RLS the SELECT
  -- policy (can_read_document) would fail before document_acl exists.
  new_id := gen_random_uuid();
  INSERT INTO appsec.documents(document_id, tenant_id, owner_id, body)
  VALUES (new_id, tenant, actor, input_body);
  INSERT INTO appsec.document_acl(document_id, tenant_id, readers, authors, readers_restricted, is_public)
  VALUES (new_id, tenant, ARRAY[actor], ARRAY[actor], true, coalesce(input_body ->> '$PublicAccess' = '1', false));
  RETURN new_id;
END
$$;

CREATE OR REPLACE FUNCTION appsec.set_jsonb_path(doc_id uuid, path text[], new_value jsonb)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
DECLARE changed integer;
BEGIN
  IF path IS NULL OR cardinality(path) = 0 OR array_position(path, '') IS NOT NULL THEN
    RAISE EXCEPTION 'invalid JSON path' USING ERRCODE = '22023';
  END IF;
  IF EXISTS (
    SELECT 1 FROM appsec.jsonb_field_acl child
    WHERE child.resource = 'documents.body'
      AND cardinality(child.json_path) > cardinality(path)
      AND child.json_path[1:cardinality(path)] = path
  ) THEN
    RAISE EXCEPTION 'cannot replace a JSON path containing separately secured descendants' USING ERRCODE = '42501';
  END IF;
  IF NOT appsec.can_write_document(doc_id) OR NOT appsec.jsonb_path_write_allowed('documents.body', path) THEN
    RAISE EXCEPTION 'not authorized to write JSON path' USING ERRCODE = '42501';
  END IF;
  UPDATE appsec.documents
     SET body = appsec.jsonb_set_deep(body, path, new_value), updated_at = clock_timestamp()
   WHERE document_id = doc_id;
  GET DIAGNOSTICS changed = ROW_COUNT;
  RETURN changed = 1;
END
$$;

CREATE OR REPLACE FUNCTION appsec.get_document(doc_id uuid)
RETURNS TABLE(document_id uuid, tenant_id uuid, owner_id uuid, body jsonb, created_at timestamptz, updated_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
  SELECT d.document_id, d.tenant_id, d.owner_id,
         appsec.jsonb_project('documents.body', d.body), d.created_at, d.updated_at
  FROM appsec.documents d
  WHERE d.document_id = doc_id
    AND appsec.can_read_document(d.document_id)
$$;

REVOKE ALL ON FUNCTION appsec.create_document(jsonb), appsec.set_jsonb_path(uuid,text[],jsonb), appsec.get_document(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION appsec.create_document(jsonb), appsec.set_jsonb_path(uuid,text[],jsonb), appsec.get_document(uuid) TO appsec_app_base, appsec_operator_base;

REVOKE ALL ON FUNCTION appsec.uid(), appsec.tenant_id(), appsec.has_role(text), appsec.is_member_of_any(uuid[]), appsec.can_read_document(uuid), appsec.can_write_document(uuid), appsec.jsonb_project(text,jsonb), appsec.jsonb_path_write_allowed(text,text[]), appsec.jsonb_all_leaf_paths_writable(text,jsonb,text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION appsec.uid(), appsec.tenant_id(), appsec.has_role(text), appsec.is_member_of_any(uuid[]), appsec.can_read_document(uuid), appsec.can_write_document(uuid), appsec.jsonb_project(text,jsonb), appsec.jsonb_path_write_allowed(text,text[]), appsec.jsonb_all_leaf_paths_writable(text,jsonb,text[]) TO appsec_app_base, appsec_operator_base;

RESET ROLE;
-- END 003_policies.sql

-- BEGIN 004_identity_sessions_acl.sql
SET ROLE appsec_owner;

ALTER TABLE appsec.groups ADD COLUMN IF NOT EXISTS created_by uuid REFERENCES appsec.users(user_id);

CREATE TABLE IF NOT EXISTS appsec.user_roles (
  user_id uuid NOT NULL REFERENCES appsec.users(user_id) ON DELETE CASCADE,
  role_name text NOT NULL CHECK (length(role_name) BETWEEN 1 AND 128),
  tenant_id uuid NOT NULL,
  granted_by uuid NOT NULL REFERENCES appsec.users(user_id),
  granted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(user_id, role_name),
  FOREIGN KEY(user_id) REFERENCES appsec.users(user_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS user_roles_tenant_role_idx ON appsec.user_roles(tenant_id, role_name);

CREATE TABLE IF NOT EXISTS appsec.credentials (
  user_id uuid PRIMARY KEY REFERENCES appsec.users(user_id) ON DELETE CASCADE,
  password_phc text NOT NULL,
  password_changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  failed_attempts integer NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
  locked_until timestamptz,
  require_password_change boolean NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS appsec.sessions (
  session_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES appsec.users(user_id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  ip inet,
  user_agent text,
  auth_method text NOT NULL CHECK (auth_method IN ('password','oidc','oauth','better_auth','operator')),
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata) = 'object')
);
CREATE INDEX IF NOT EXISTS sessions_user_active_idx ON appsec.sessions(user_id, expires_at) WHERE revoked_at IS NULL;

-- Each authenticated application session gets its own PostgreSQL login role.
-- This keeps session identity distinct through both session and transaction pooling.
CREATE TABLE IF NOT EXISTS appsec.session_principals (
  session_id uuid PRIMARY KEY REFERENCES appsec.sessions(session_id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES appsec.users(user_id) ON DELETE CASCADE,
  db_role name NOT NULL UNIQUE CHECK (db_role::text ~ '^app_s_[0-9a-f]{32}$'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(session_id,user_id)
);

-- Contains only PostgreSQL SCRAM verifiers, never the cleartext pool password.
-- PgBouncer's auth_query reads active verifiers through a narrowly granted function.
CREATE TABLE IF NOT EXISTS appsec.pool_credentials (
  db_role name PRIMARY KEY CHECK (db_role::text ~ '^app_s_[0-9a-f]{32}$'),
  session_id uuid NOT NULL UNIQUE REFERENCES appsec.sessions(session_id) ON DELETE CASCADE,
  scram_verifier text NOT NULL CHECK (scram_verifier LIKE 'SCRAM-SHA-256$%'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  rotated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  revoked_at timestamptz
);

CREATE TABLE IF NOT EXISTS appsec.refresh_tokens (
  token_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id uuid NOT NULL REFERENCES appsec.sessions(session_id) ON DELETE CASCADE,
  token_hash bytea NOT NULL UNIQUE,
  issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  replaced_by uuid REFERENCES appsec.refresh_tokens(token_id),
  revoked_at timestamptz
);
CREATE INDEX IF NOT EXISTS refresh_tokens_session_idx ON appsec.refresh_tokens(session_id);

CREATE TABLE IF NOT EXISTS appsec.email_verifications (
  verification_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES appsec.users(user_id) ON DELETE CASCADE,
  token_hash bytea NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS appsec.password_resets (
  reset_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES appsec.users(user_id) ON DELETE CASCADE,
  token_hash bytea NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE OR REPLACE FUNCTION appsec.uid()
RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
  SELECT u.user_id
  FROM appsec.users u
  WHERE u.status='active'
    AND EXISTS (SELECT 1 FROM appsec.tenants t WHERE t.tenant_id=u.tenant_id AND t.status='active')
    AND (
      EXISTS (
        SELECT 1 FROM appsec.session_principals sp
        JOIN appsec.sessions s ON s.session_id=sp.session_id
        JOIN pg_catalog.pg_roles r ON r.rolname=sp.db_role AND r.rolcanlogin
          AND (r.rolvaliduntil IS NULL OR r.rolvaliduntil>statement_timestamp())
        WHERE sp.db_role=session_user::name AND sp.user_id=u.user_id
          AND s.user_id=u.user_id AND s.revoked_at IS NULL AND s.expires_at>statement_timestamp()
      )
      OR EXISTS (
        SELECT 1 FROM appsec.principals p
        JOIN pg_catalog.pg_roles r ON r.rolname=p.db_role AND r.rolcanlogin
          AND (r.rolvaliduntil IS NULL OR r.rolvaliduntil>statement_timestamp())
        WHERE p.db_role=session_user::name AND p.user_id=u.user_id
          AND p.principal_kind IN ('operator','service')
      )
    )
  LIMIT 1
$$;

CREATE OR REPLACE FUNCTION appsec.has_nonpublic_role(requested_role text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
 SELECT EXISTS (SELECT 1 FROM appsec.user_roles r WHERE r.user_id=appsec.uid()
   AND r.tenant_id=appsec.tenant_id() AND r.role_name=requested_role)
 OR EXISTS (SELECT 1 FROM appsec.database_acl_entries a
   WHERE a.database_name=current_database() AND requested_role=ANY(a.assigned_roles)
     AND ((a.principal_kind='user' AND a.principal_id=appsec.uid()::text)
       OR (a.principal_kind='group' AND EXISTS (
         SELECT 1 FROM appsec.group_members gm WHERE gm.user_id=appsec.uid() AND gm.group_id::text=a.principal_id))))
$$;

CREATE OR REPLACE FUNCTION appsec.audit_security_change()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
DECLARE actor uuid; old_data jsonb; new_data jsonb; resource_key text;
BEGIN
  actor := appsec.uid();
  IF TG_OP <> 'INSERT' THEN old_data := to_jsonb(OLD); END IF;
  IF TG_OP <> 'DELETE' THEN new_data := to_jsonb(NEW); END IF;
  resource_key := coalesce(new_data->>'document_id', old_data->>'document_id',
    new_data->>'tenant_id', old_data->>'tenant_id', new_data->>'user_id', old_data->>'user_id',
    new_data->>'group_id', old_data->>'group_id', new_data->>'resource_name', old_data->>'resource_name', new_data->>'resource', old_data->>'resource');
  IF TG_TABLE_NAME='sessions' THEN
    old_data := CASE WHEN old_data IS NULL THEN NULL ELSE jsonb_build_object('session_id',old_data->>'session_id','revoked_at',old_data->>'revoked_at') END;
    new_data := CASE WHEN new_data IS NULL THEN NULL ELSE jsonb_build_object('session_id',new_data->>'session_id','revoked_at',new_data->>'revoked_at') END;
  ELSIF TG_TABLE_NAME='users' THEN
    old_data := CASE WHEN old_data IS NULL THEN NULL ELSE jsonb_build_object('user_id',old_data->>'user_id','status',old_data->>'status') END;
    new_data := CASE WHEN new_data IS NULL THEN NULL ELSE jsonb_build_object('user_id',new_data->>'user_id','status',new_data->>'status') END;
  END IF;
  INSERT INTO appsec.audit_events(actor_user_id,event_type,resource,detail)
  VALUES(actor,'security.'||TG_TABLE_NAME||'.'||lower(TG_OP),resource_key,
    jsonb_build_object('old',old_data,'new',new_data));
  IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END $$;

CREATE OR REPLACE FUNCTION appsec.pgbouncer_lookup(requested_user text)
RETURNS TABLE(username text, password text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
  SELECT pc.db_role::text, pc.scram_verifier
  FROM appsec.pool_credentials pc
  JOIN appsec.sessions s ON s.session_id=pc.session_id
  JOIN appsec.users u ON u.user_id=s.user_id
  JOIN appsec.tenants ten ON ten.tenant_id=u.tenant_id AND ten.status='active'
  JOIN pg_catalog.pg_roles r ON r.rolname=pc.db_role AND r.rolcanlogin
    AND (r.rolvaliduntil IS NULL OR r.rolvaliduntil>statement_timestamp())
  WHERE pc.db_role::text=requested_user
    AND pc.revoked_at IS NULL AND s.revoked_at IS NULL
    AND s.expires_at>statement_timestamp() AND u.status='active'
$$;

CREATE OR REPLACE FUNCTION appsec.current_user_status()
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$ SELECT u.status FROM appsec.users u WHERE u.user_id = appsec.uid() $$;

CREATE OR REPLACE FUNCTION appsec.revoke_session(target_session uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
DECLARE n integer;
BEGIN
  UPDATE appsec.sessions s SET revoked_at = clock_timestamp()
   WHERE s.session_id = target_session
     AND (s.user_id = appsec.uid() OR pg_has_role(session_user, 'appsec_operator_base', 'member'))
     AND s.revoked_at IS NULL;
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n = 1 THEN
    UPDATE appsec.refresh_tokens SET revoked_at = clock_timestamp()
     WHERE session_id = target_session AND revoked_at IS NULL;
    UPDATE appsec.pool_credentials SET revoked_at=clock_timestamp()
     WHERE session_id=target_session AND revoked_at IS NULL;
  END IF;
  RETURN n = 1;
END $$;

CREATE OR REPLACE FUNCTION appsec.revoke_all_sessions()
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
DECLARE n integer;
BEGIN
  UPDATE appsec.sessions SET revoked_at = clock_timestamp()
   WHERE user_id = appsec.uid() AND revoked_at IS NULL;
  GET DIAGNOSTICS n = ROW_COUNT;
  UPDATE appsec.refresh_tokens t SET revoked_at = clock_timestamp()
   FROM appsec.sessions s WHERE s.session_id = t.session_id AND s.user_id = appsec.uid() AND t.revoked_at IS NULL;
  UPDATE appsec.pool_credentials pc SET revoked_at=clock_timestamp()
   FROM appsec.sessions s WHERE s.session_id=pc.session_id AND s.user_id=appsec.uid() AND pc.revoked_at IS NULL;
  RETURN n;
END $$;

CREATE OR REPLACE FUNCTION appsec.set_document_acl(
  target_document uuid, new_readers uuid[], new_authors uuid[],
  new_reader_groups uuid[], new_author_groups uuid[], make_public boolean DEFAULT false
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
DECLARE d appsec.documents%ROWTYPE;
BEGIN
  SELECT * INTO d FROM appsec.documents WHERE document_id = target_document FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'document not found' USING ERRCODE = 'P0002'; END IF;
  IF d.owner_id <> appsec.uid()
     AND NOT pg_has_role(session_user, 'appsec_operator_base', 'member')
     AND appsec.effective_database_access('documents') < 6 AND appsec.effective_database_access('*') < 6 THEN
    RAISE EXCEPTION 'only the document owner or an authorized operator may change its ACL' USING ERRCODE = '42501';
  END IF;
  IF d.tenant_id <> appsec.tenant_id() AND NOT pg_has_role(session_user,'appsec_operator_base','member') THEN
    RAISE EXCEPTION 'tenant mismatch' USING ERRCODE = '42501';
  END IF;
  IF EXISTS (
    SELECT 1 FROM unnest(coalesce(new_readers,'{}'::uuid[]) || coalesce(new_authors,'{}'::uuid[])) x
    LEFT JOIN appsec.users u ON u.user_id = x
    WHERE u.user_id IS NULL OR u.tenant_id IS DISTINCT FROM d.tenant_id OR u.status <> 'active'
  ) THEN RAISE EXCEPTION 'ACL contains an invalid, inactive or cross-tenant user' USING ERRCODE = '22023'; END IF;
  IF EXISTS (
    SELECT 1 FROM unnest(coalesce(new_reader_groups,'{}'::uuid[]) || coalesce(new_author_groups,'{}'::uuid[])) x
    LEFT JOIN appsec.groups g ON g.group_id = x
    WHERE g.group_id IS NULL OR g.tenant_id IS DISTINCT FROM d.tenant_id
  ) THEN RAISE EXCEPTION 'ACL contains an invalid or cross-tenant group' USING ERRCODE = '22023'; END IF;
  INSERT INTO appsec.document_acl(document_id, tenant_id, readers, authors, reader_groups, author_groups, readers_restricted, is_public, updated_at)
  VALUES (target_document, d.tenant_id,
          array_append(array_remove(coalesce(new_readers,'{}'::uuid[]),d.owner_id),d.owner_id),
          array_append(array_remove(coalesce(new_authors,'{}'::uuid[]),d.owner_id),d.owner_id),
          coalesce(new_reader_groups,'{}'), coalesce(new_author_groups,'{}'),
          (cardinality(coalesce(new_readers,'{}'::uuid[]))>0 OR cardinality(coalesce(new_reader_groups,'{}'::uuid[]))>0),
          make_public, clock_timestamp())
  ON CONFLICT (document_id) DO UPDATE SET
    readers = EXCLUDED.readers, authors = EXCLUDED.authors,
    reader_groups = EXCLUDED.reader_groups, author_groups = EXCLUDED.author_groups,
    readers_restricted = EXCLUDED.readers_restricted, is_public = EXCLUDED.is_public, updated_at = EXCLUDED.updated_at;
END $$;

CREATE OR REPLACE FUNCTION appsec.add_document_reader(target_document uuid, target_user uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
DECLARE d appsec.documents%ROWTYPE;
BEGIN
  SELECT * INTO d FROM appsec.documents WHERE document_id = target_document FOR UPDATE;
  IF NOT FOUND OR (d.owner_id <> appsec.uid() AND NOT pg_has_role(session_user,'appsec_operator_base','member')
      AND appsec.effective_database_access('documents') < 6 AND appsec.effective_database_access('*') < 6) THEN
    RAISE EXCEPTION 'not authorized to share document' USING ERRCODE = '42501';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM appsec.users WHERE user_id=target_user AND tenant_id=d.tenant_id AND status='active') THEN
    RAISE EXCEPTION 'reader must be an active user in the same tenant' USING ERRCODE = '22023';
  END IF;
  UPDATE appsec.document_acl SET readers = array_append(array_remove(readers,target_user),target_user),
    readers_restricted=true, updated_at=clock_timestamp()
   WHERE document_id=target_document AND tenant_id=d.tenant_id;
END $$;

CREATE OR REPLACE FUNCTION appsec.add_document_author(target_document uuid, target_user uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
DECLARE d appsec.documents%ROWTYPE;
BEGIN
  SELECT * INTO d FROM appsec.documents WHERE document_id = target_document FOR UPDATE;
  IF NOT FOUND OR (d.owner_id <> appsec.uid() AND NOT pg_has_role(session_user,'appsec_operator_base','member')
      AND appsec.effective_database_access('documents') < 6 AND appsec.effective_database_access('*') < 6) THEN
    RAISE EXCEPTION 'not authorized to delegate document authorship' USING ERRCODE = '42501';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM appsec.users WHERE user_id=target_user AND tenant_id=d.tenant_id AND status='active') THEN
    RAISE EXCEPTION 'author must be an active user in the same tenant' USING ERRCODE = '22023';
  END IF;
  UPDATE appsec.document_acl SET authors = array_append(array_remove(authors,target_user),target_user), updated_at=clock_timestamp()
   WHERE document_id=target_document AND tenant_id=d.tenant_id;
END $$;

CREATE OR REPLACE FUNCTION appsec.set_document_acl_full(
  target_document uuid, new_readers uuid[], new_authors uuid[],
  new_reader_groups uuid[], new_author_groups uuid[],
  new_reader_roles text[], new_author_roles text[], make_public boolean DEFAULT false,
  restrict_readers boolean DEFAULT true
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM unnest(coalesce(new_reader_roles,'{}') || coalesce(new_author_roles,'{}')) AS roles(role_name)
             WHERE length(trim(roles.role_name)) NOT BETWEEN 1 AND 128) THEN
    RAISE EXCEPTION 'invalid Domino role name' USING ERRCODE='22023';
  END IF;
  PERFORM appsec.set_document_acl(target_document,new_readers,new_authors,new_reader_groups,new_author_groups,make_public);
  UPDATE appsec.document_acl SET reader_roles=coalesce(new_reader_roles,'{}'),
    author_roles=coalesce(new_author_roles,'{}'), readers_restricted=restrict_readers, updated_at=clock_timestamp()
  WHERE document_id=target_document AND (tenant_id=appsec.tenant_id() OR pg_has_role(session_user,'appsec_operator_base','member'));
END $$;

CREATE OR REPLACE FUNCTION appsec.create_tenant(tenant_slug text, tenant_display_name text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
DECLARE new_tenant uuid;
BEGIN
  IF NOT pg_has_role(session_user,'appsec_operator_base','member') AND NOT appsec.has_nonpublic_role('tenants.create') THEN
    RAISE EXCEPTION 'tenant administration privilege required' USING ERRCODE='42501';
  END IF;
  IF length(trim(tenant_slug)) NOT BETWEEN 1 AND 128 OR length(trim(tenant_display_name)) NOT BETWEEN 1 AND 256 THEN
    RAISE EXCEPTION 'invalid tenant name' USING ERRCODE='22023';
  END IF;
  INSERT INTO appsec.tenants(slug,display_name) VALUES(lower(trim(tenant_slug)),trim(tenant_display_name))
  RETURNING tenant_id INTO new_tenant;
  RETURN new_tenant;
END $$;

CREATE OR REPLACE FUNCTION appsec.set_tenant_status(target_tenant uuid, new_status text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
DECLARE changed integer;
BEGIN
  IF NOT pg_has_role(session_user,'appsec_operator_base','member') AND NOT appsec.has_nonpublic_role('tenants.manage') THEN
    RAISE EXCEPTION 'tenant administration privilege required' USING ERRCODE='42501';
  END IF;
  IF new_status NOT IN ('active','suspended','deleted') THEN
    RAISE EXCEPTION 'invalid tenant status' USING ERRCODE='22023';
  END IF;
  UPDATE appsec.tenants SET status=new_status,updated_at=clock_timestamp() WHERE tenant_id=target_tenant;
  GET DIAGNOSTICS changed=ROW_COUNT;
  IF changed=1 AND new_status<>'active' THEN
    UPDATE appsec.sessions s SET revoked_at=clock_timestamp()
      FROM appsec.users u WHERE s.user_id=u.user_id AND u.tenant_id=target_tenant AND s.revoked_at IS NULL;
    UPDATE appsec.refresh_tokens r SET revoked_at=clock_timestamp()
      FROM appsec.sessions s JOIN appsec.users u ON u.user_id=s.user_id
      WHERE r.session_id=s.session_id AND u.tenant_id=target_tenant AND r.revoked_at IS NULL;
    UPDATE appsec.pool_credentials pc SET revoked_at=clock_timestamp()
      FROM appsec.sessions s JOIN appsec.users u ON u.user_id=s.user_id
      WHERE pc.session_id=s.session_id AND u.tenant_id=target_tenant AND pc.revoked_at IS NULL;
  END IF;
  RETURN changed=1;
END $$;

CREATE OR REPLACE FUNCTION appsec.create_group(group_name text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
DECLARE gid uuid;
BEGIN
  IF length(trim(group_name)) NOT BETWEEN 1 AND 128 THEN RAISE EXCEPTION 'invalid group name' USING ERRCODE='22023'; END IF;
  IF appsec.uid() IS NULL OR appsec.tenant_id() IS NULL THEN RAISE EXCEPTION 'active tenant principal required' USING ERRCODE='42501'; END IF;
  IF NOT pg_has_role(session_user,'appsec_operator_base','member')
     AND appsec.effective_database_access('*') < 6
     AND appsec.effective_database_access('documents') < 6
     AND NOT appsec.has_nonpublic_role('groups.create') THEN
    RAISE EXCEPTION 'group administration privilege required' USING ERRCODE='42501';
  END IF;
  INSERT INTO appsec.groups(tenant_id,name,created_by) VALUES(appsec.tenant_id(),group_name,appsec.uid()) RETURNING group_id INTO gid;
  RETURN gid;
END $$;

CREATE OR REPLACE FUNCTION appsec.add_group_member(target_group uuid, target_user uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM appsec.groups WHERE group_id=target_group AND tenant_id=appsec.tenant_id()
                 AND (created_by=appsec.uid() OR pg_has_role(session_user,'appsec_operator_base','member') OR (appsec.effective_database_access('documents') >= 6 OR appsec.effective_database_access('*') >= 6))) THEN
    RAISE EXCEPTION 'group not found or not authorized' USING ERRCODE='42501';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM appsec.users WHERE user_id=target_user AND tenant_id=appsec.tenant_id() AND status='active') THEN
    RAISE EXCEPTION 'user not found, inactive or cross-tenant' USING ERRCODE='22023';
  END IF;
  INSERT INTO appsec.group_members(group_id,user_id) VALUES(target_group,target_user) ON CONFLICT DO NOTHING;
END $$;

CREATE OR REPLACE FUNCTION appsec.remove_group_member(target_group uuid, target_user uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
DECLARE n integer;
BEGIN
  DELETE FROM appsec.group_members gm USING appsec.groups g
   WHERE gm.group_id=target_group AND gm.user_id=target_user AND g.group_id=gm.group_id AND g.tenant_id=appsec.tenant_id()
     AND (g.created_by=appsec.uid() OR pg_has_role(session_user,'appsec_operator_base','member') OR appsec.effective_database_access('documents') >= 6 OR appsec.effective_database_access('*') >= 6);
  GET DIAGNOSTICS n=ROW_COUNT;
  RETURN n=1;
END $$;

CREATE OR REPLACE FUNCTION appsec.has_role(requested_role text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
 SELECT EXISTS (SELECT 1 FROM appsec.user_roles r WHERE r.user_id=appsec.uid()
   AND r.tenant_id=appsec.tenant_id() AND r.role_name=requested_role)
 OR EXISTS (
   SELECT 1 FROM appsec.database_acl_entries a
   WHERE a.database_name=current_database()
     AND requested_role = ANY(a.assigned_roles)
     AND ((a.principal_kind='user' AND a.principal_id=appsec.uid()::text)
       OR (a.principal_kind='group' AND EXISTS (
         SELECT 1 FROM appsec.group_members gm WHERE gm.user_id=appsec.uid() AND gm.group_id::text=a.principal_id)))
 )
$$;

CREATE OR REPLACE FUNCTION appsec.grant_role(target_user uuid, requested_role text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
BEGIN
  IF NOT pg_has_role(session_user,'appsec_operator_base','member') AND appsec.effective_database_access('*') < 6 THEN
    RAISE EXCEPTION 'database Manager privilege required' USING ERRCODE='42501';
  END IF;
  IF length(trim(requested_role)) NOT BETWEEN 1 AND 128 THEN RAISE EXCEPTION 'invalid role name' USING ERRCODE='22023'; END IF;
  IF NOT EXISTS (SELECT 1 FROM appsec.users WHERE user_id=target_user AND status='active') THEN
    RAISE EXCEPTION 'active user required' USING ERRCODE='22023';
  END IF;
  INSERT INTO appsec.user_roles(user_id,role_name,tenant_id,granted_by)
  SELECT target_user,requested_role,tenant_id,appsec.uid() FROM appsec.users WHERE user_id=target_user
  ON CONFLICT(user_id,role_name) DO NOTHING;
END $$;

CREATE OR REPLACE FUNCTION appsec.revoke_role(target_user uuid, requested_role text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
DECLARE n integer;
BEGIN
  IF NOT pg_has_role(session_user,'appsec_operator_base','member') AND appsec.effective_database_access('*') < 6 THEN
    RAISE EXCEPTION 'database Manager privilege required' USING ERRCODE='42501';
  END IF;
  DELETE FROM appsec.user_roles WHERE user_id=target_user AND role_name=requested_role;
  GET DIAGNOSTICS n=ROW_COUNT; RETURN n=1;
END $$;

CREATE OR REPLACE FUNCTION appsec.set_jsonb_field_policy(
  resource_name text, path text[], allowed_read_roles text[], allowed_write_roles text[],
  allowed_read_groups uuid[] DEFAULT '{}', allowed_write_groups uuid[] DEFAULT '{}'
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
BEGIN
  IF NOT pg_has_role(session_user,'appsec_operator_base','member') AND appsec.effective_database_access(resource_name) < 6 AND appsec.effective_database_access('*') < 6 THEN
    RAISE EXCEPTION 'database Manager privilege required' USING ERRCODE='42501';
  END IF;
  IF resource_name IS NULL OR length(resource_name)>256 OR path IS NULL OR cardinality(path)=0
     OR array_position(path,'') IS NOT NULL THEN RAISE EXCEPTION 'invalid resource or JSON path' USING ERRCODE='22023'; END IF;
  INSERT INTO appsec.jsonb_field_acl(resource,json_path,read_roles,write_roles,read_groups,write_groups)
  VALUES(resource_name,path,coalesce(allowed_read_roles,'{}'),coalesce(allowed_write_roles,'{}'),
         coalesce(allowed_read_groups,'{}'),coalesce(allowed_write_groups,'{}'))
  ON CONFLICT(resource,json_path) DO UPDATE SET read_roles=EXCLUDED.read_roles, write_roles=EXCLUDED.write_roles,
    read_groups=EXCLUDED.read_groups, write_groups=EXCLUDED.write_groups;
END $$;

CREATE OR REPLACE FUNCTION appsec.list_my_sessions()
RETURNS TABLE(session_id uuid, created_at timestamptz, last_seen_at timestamptz, expires_at timestamptz, revoked_at timestamptz, auth_method text, user_agent text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
 SELECT s.session_id,s.created_at,s.last_seen_at,s.expires_at,s.revoked_at,s.auth_method,s.user_agent
 FROM appsec.sessions s WHERE s.user_id=appsec.uid() ORDER BY s.created_at DESC
$$;

REVOKE ALL ON ALL TABLES IN SCHEMA appsec FROM PUBLIC;
DROP TRIGGER IF EXISTS appsec_audit_acl ON appsec.database_acl_entries;
CREATE TRIGGER appsec_audit_acl AFTER INSERT OR UPDATE OR DELETE ON appsec.database_acl_entries
  FOR EACH ROW EXECUTE FUNCTION appsec.audit_security_change();
DROP TRIGGER IF EXISTS appsec_audit_document_acl ON appsec.document_acl;
CREATE TRIGGER appsec_audit_document_acl AFTER INSERT OR UPDATE OR DELETE ON appsec.document_acl
  FOR EACH ROW EXECUTE FUNCTION appsec.audit_security_change();
DROP TRIGGER IF EXISTS appsec_audit_user_roles ON appsec.user_roles;
CREATE TRIGGER appsec_audit_user_roles AFTER INSERT OR UPDATE OR DELETE ON appsec.user_roles
  FOR EACH ROW EXECUTE FUNCTION appsec.audit_security_change();
DROP TRIGGER IF EXISTS appsec_audit_group_members ON appsec.group_members;
CREATE TRIGGER appsec_audit_group_members AFTER INSERT OR UPDATE OR DELETE ON appsec.group_members
  FOR EACH ROW EXECUTE FUNCTION appsec.audit_security_change();
DROP TRIGGER IF EXISTS appsec_audit_jsonb_field_acl ON appsec.jsonb_field_acl;
CREATE TRIGGER appsec_audit_jsonb_field_acl AFTER INSERT OR UPDATE OR DELETE ON appsec.jsonb_field_acl
  FOR EACH ROW EXECUTE FUNCTION appsec.audit_security_change();
DROP TRIGGER IF EXISTS appsec_audit_tenants ON appsec.tenants;
CREATE TRIGGER appsec_audit_tenants BEFORE UPDATE OF status ON appsec.tenants
  FOR EACH ROW EXECUTE FUNCTION appsec.audit_security_change();
DROP TRIGGER IF EXISTS appsec_audit_tenant_create ON appsec.tenants;
CREATE TRIGGER appsec_audit_tenant_create AFTER INSERT ON appsec.tenants
  FOR EACH ROW EXECUTE FUNCTION appsec.audit_security_change();
DROP TRIGGER IF EXISTS appsec_audit_users ON appsec.users;
CREATE TRIGGER appsec_audit_users BEFORE UPDATE OF status ON appsec.users
  FOR EACH ROW EXECUTE FUNCTION appsec.audit_security_change();
DROP TRIGGER IF EXISTS appsec_audit_sessions ON appsec.sessions;
CREATE TRIGGER appsec_audit_sessions BEFORE INSERT OR UPDATE OF revoked_at ON appsec.sessions
  FOR EACH ROW EXECUTE FUNCTION appsec.audit_security_change();
DROP TRIGGER IF EXISTS appsec_audit_groups ON appsec.groups;
CREATE TRIGGER appsec_audit_groups AFTER INSERT OR UPDATE OR DELETE ON appsec.groups
  FOR EACH ROW EXECUTE FUNCTION appsec.audit_security_change();

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA appsec FROM PUBLIC;
GRANT EXECUTE ON FUNCTION appsec.current_user_status(), appsec.revoke_session(uuid), appsec.revoke_all_sessions(),
 appsec.set_document_acl(uuid,uuid[],uuid[],uuid[],uuid[],boolean),
 appsec.set_document_acl_full(uuid,uuid[],uuid[],uuid[],uuid[],text[],text[],boolean,boolean), appsec.add_document_reader(uuid,uuid),
 appsec.add_document_author(uuid,uuid), appsec.create_group(text), appsec.add_group_member(uuid,uuid),
 appsec.remove_group_member(uuid,uuid), appsec.has_role(text), appsec.has_nonpublic_role(text), appsec.grant_role(uuid,text),
 appsec.revoke_role(uuid,text), appsec.set_jsonb_field_policy(text,text[],text[],text[],uuid[],uuid[]), appsec.list_my_sessions(),
 appsec.uid(), appsec.tenant_id(), appsec.is_member_of_any(uuid[]), appsec.can_read_document(uuid),
 appsec.can_write_document(uuid), appsec.jsonb_project(text,jsonb), appsec.jsonb_path_write_allowed(text,text[]),
 appsec.jsonb_set_deep(jsonb,text[],jsonb), appsec.jsonb_all_leaf_paths_writable(text,jsonb,text[]),
 appsec.create_document(jsonb), appsec.set_jsonb_path(uuid,text[],jsonb), appsec.get_document(uuid),
 appsec.effective_database_access(text)
 TO appsec_app_base, appsec_operator_base;
GRANT EXECUTE ON FUNCTION appsec.pgbouncer_lookup(text) TO appsec_pool_auth;
GRANT EXECUTE ON FUNCTION appsec.create_tenant(text,text), appsec.set_tenant_status(uuid,text) TO appsec_operator_base, appsec_app_base;

-- Privileges for the isolated authentication/provisioning service connection.
GRANT USAGE ON SCHEMA appsec TO appsec_provisioner;
GRANT SELECT, INSERT, UPDATE ON appsec.users, appsec.credentials,
  appsec.email_verifications, appsec.sessions, appsec.refresh_tokens,
  appsec.session_principals, appsec.pool_credentials TO appsec_provisioner;
GRANT SELECT ON appsec.tenants, appsec.user_roles, appsec.database_acl_entries, appsec.group_members TO appsec_provisioner;
GRANT INSERT ON appsec.audit_events TO appsec_provisioner;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA appsec TO appsec_provisioner;

CREATE OR REPLACE FUNCTION appsec.effective_database_access(target_resource text DEFAULT '*')
RETURNS smallint LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
  SELECT CASE WHEN pg_has_role(session_user,'appsec_operator_base','member') THEN 6::smallint
    ELSE coalesce((
      SELECT a.access_level FROM appsec.database_acl_entries a
      WHERE a.database_name=current_database() AND a.resource_name IN ('*',target_resource)
        AND ((a.principal_kind='public' AND a.principal_id='*')
          OR (a.principal_kind='user' AND a.principal_id=appsec.uid()::text)
          OR (a.principal_kind='group' AND EXISTS (SELECT 1 FROM appsec.group_members gm WHERE gm.user_id=appsec.uid() AND gm.group_id::text=a.principal_id))
          OR (a.principal_kind='role' AND appsec.has_role(a.principal_id)))
      ORDER BY (a.resource_name=target_resource) DESC,
        CASE a.principal_kind WHEN 'user' THEN 4 WHEN 'group' THEN 3 WHEN 'role' THEN 2 ELSE 1 END DESC,
        a.access_level DESC LIMIT 1
    ),0)::smallint END
$$;

CREATE OR REPLACE FUNCTION appsec.set_database_acl(
  target_resource text, target_kind text, target_principal text,
  target_level smallint, target_roles text[] DEFAULT '{}'
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
BEGIN
  IF NOT pg_has_role(session_user,'appsec_operator_base','member') AND appsec.effective_database_access(target_resource) < 6 AND appsec.effective_database_access('*') < 6 THEN
    RAISE EXCEPTION 'database Manager privilege required' USING ERRCODE='42501';
  END IF;
  IF target_resource IS NULL OR length(target_resource)>256 OR target_kind IS NULL OR target_kind NOT IN ('user','group','role','public')
     OR target_principal IS NULL OR length(target_principal)>256 OR target_level NOT BETWEEN 0 AND 6 THEN
    RAISE EXCEPTION 'invalid database ACL entry' USING ERRCODE='22023';
  END IF;
  IF target_kind='user' AND NOT EXISTS (SELECT 1 FROM appsec.users WHERE user_id=target_principal::uuid) THEN
    RAISE EXCEPTION 'ACL user does not exist' USING ERRCODE='22023';
  END IF;
  IF target_kind='group' AND NOT EXISTS (SELECT 1 FROM appsec.groups WHERE group_id=target_principal::uuid) THEN
    RAISE EXCEPTION 'ACL group does not exist' USING ERRCODE='22023';
  END IF;
  IF target_kind='public' AND target_principal<>'*' THEN
    RAISE EXCEPTION 'public principal must be *' USING ERRCODE='22023';
  END IF;
  INSERT INTO appsec.database_acl_entries(database_name,resource_name,principal_kind,principal_id,access_level,assigned_roles)
  VALUES(current_database(),target_resource,target_kind,target_principal,target_level,coalesce(target_roles,'{}'))
  ON CONFLICT(database_name,resource_name,principal_kind,principal_id) DO UPDATE
    SET access_level=EXCLUDED.access_level,assigned_roles=EXCLUDED.assigned_roles;
END $$;

CREATE OR REPLACE FUNCTION appsec.remove_database_acl(target_resource text, target_kind text, target_principal text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
DECLARE n integer;
BEGIN
  IF NOT pg_has_role(session_user,'appsec_operator_base','member') AND appsec.effective_database_access(target_resource) < 6 AND appsec.effective_database_access('*') < 6 THEN
    RAISE EXCEPTION 'database Manager privilege required' USING ERRCODE='42501';
  END IF;
  DELETE FROM appsec.database_acl_entries WHERE database_name=current_database()
    AND resource_name=target_resource AND principal_kind=target_kind AND principal_id=target_principal;
  GET DIAGNOSTICS n=ROW_COUNT; RETURN n=1;
END $$;

CREATE OR REPLACE FUNCTION appsec.can_delete_document(doc_id uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, appsec
AS $$
 SELECT appsec.can_read_document(doc_id) AND (
   appsec.effective_database_access('documents') >= 4
   OR (appsec.effective_database_access('documents') = 3 AND appsec.has_role('documents.delete') AND appsec.can_write_document(doc_id))
 )
$$;

DROP POLICY IF EXISTS documents_delete ON appsec.documents;
CREATE POLICY documents_delete ON appsec.documents FOR DELETE
  USING ((tenant_id=appsec.tenant_id() OR pg_has_role(session_user,'appsec_operator_base','member')) AND appsec.can_delete_document(document_id));

REVOKE ALL ON FUNCTION appsec.set_database_acl(text,text,text,smallint,text[]),
  appsec.remove_database_acl(text,text,text), appsec.can_delete_document(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION appsec.set_database_acl(text,text,text,smallint,text[]),
  appsec.remove_database_acl(text,text,text), appsec.can_delete_document(uuid)
  TO appsec_app_base, appsec_operator_base;

REVOKE ALL ON FUNCTION appsec.effective_database_access(text), appsec.set_database_acl(text,text,text,smallint,text[]),
 appsec.remove_database_acl(text,text,text), appsec.can_delete_document(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION appsec.effective_database_access(text), appsec.set_database_acl(text,text,text,smallint,text[]),
 appsec.remove_database_acl(text,text,text), appsec.can_delete_document(uuid) TO appsec_app_base, appsec_operator_base;

RESET ROLE;
-- END 004_identity_sessions_acl.sql

-- BEGIN 005_schema_security.sql
SET ROLE appsec_owner;

-- Applies tenant isolation and owner-based defaults to an application-owned table.
-- The caller must own the target table; this function does not elevate privileges.
CREATE OR REPLACE FUNCTION appsec.protect_tenant_owned_table(
  target_table regclass,
  tenant_column name,
  owner_column name,
  read_all_role text DEFAULT NULL,
  write_all_role text DEFAULT NULL
) RETURNS void
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, appsec
AS $$
DECLARE
  relation_kind "char";
  tenant_type oid;
  owner_type oid;
  table_sql text := target_table::text;
  read_predicate text;
  write_predicate text;
BEGIN
  SELECT c.relkind INTO relation_kind
  FROM pg_class c WHERE c.oid = target_table;
  IF relation_kind IS DISTINCT FROM 'r' AND relation_kind IS DISTINCT FROM 'p' THEN
    RAISE EXCEPTION 'target must be an ordinary or partitioned table' USING ERRCODE = '22023';
  END IF;

  SELECT a.atttypid INTO tenant_type FROM pg_attribute a
   WHERE a.attrelid = target_table AND a.attname = tenant_column AND a.attnum > 0 AND NOT a.attisdropped;
  SELECT a.atttypid INTO owner_type FROM pg_attribute a
   WHERE a.attrelid = target_table AND a.attname = owner_column AND a.attnum > 0 AND NOT a.attisdropped;
  IF tenant_type IS DISTINCT FROM 'uuid'::regtype::oid OR owner_type IS DISTINCT FROM 'uuid'::regtype::oid THEN
    RAISE EXCEPTION 'tenant and owner columns must both exist and have type uuid' USING ERRCODE = '22023';
  END IF;

  read_predicate := format('(%I = appsec.uid() OR %s OR pg_has_role(session_user, ''appsec_operator_base'', ''member''))', owner_column,
    CASE WHEN read_all_role IS NULL THEN 'false' ELSE format('appsec.has_role(%L)', read_all_role) END);
  write_predicate := format('(%I = appsec.uid() OR %s OR pg_has_role(session_user, ''appsec_operator_base'', ''member''))', owner_column,
    CASE WHEN write_all_role IS NULL THEN 'false' ELSE format('appsec.has_role(%L)', write_all_role) END);

  EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', table_sql);
  EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', table_sql);
  EXECUTE format('DROP POLICY IF EXISTS appsec_tenant_select ON %s', table_sql);
  EXECUTE format('DROP POLICY IF EXISTS appsec_tenant_insert ON %s', table_sql);
  EXECUTE format('DROP POLICY IF EXISTS appsec_tenant_update ON %s', table_sql);
  EXECUTE format('DROP POLICY IF EXISTS appsec_tenant_delete ON %s', table_sql);
  EXECUTE format('CREATE POLICY appsec_tenant_select ON %s FOR SELECT USING ((%I = appsec.tenant_id() OR pg_has_role(session_user, ''appsec_operator_base'', ''member'')) AND %s)', table_sql, tenant_column, read_predicate);
  EXECUTE format('CREATE POLICY appsec_tenant_insert ON %s FOR INSERT WITH CHECK ((%I = appsec.tenant_id() OR pg_has_role(session_user, ''appsec_operator_base'', ''member'')) AND %I = appsec.uid())', table_sql, tenant_column, owner_column);
  EXECUTE format('CREATE POLICY appsec_tenant_update ON %s FOR UPDATE USING ((%I = appsec.tenant_id() OR pg_has_role(session_user, ''appsec_operator_base'', ''member'')) AND %s) WITH CHECK ((%I = appsec.tenant_id() OR pg_has_role(session_user, ''appsec_operator_base'', ''member'')) AND %s)', table_sql, tenant_column, write_predicate, tenant_column, write_predicate);
  EXECUTE format('CREATE POLICY appsec_tenant_delete ON %s FOR DELETE USING ((%I = appsec.tenant_id() OR pg_has_role(session_user, ''appsec_operator_base'', ''member'')) AND %s)', table_sql, tenant_column, write_predicate);
END
$$;

-- Applies column grants for the shared application base role. Existing grants
-- to other roles must be audited separately; PostgreSQL privileges are additive.
CREATE OR REPLACE FUNCTION appsec.configure_column_access(
  target_table regclass,
  readable_columns name[] DEFAULT '{}',
  insertable_columns name[] DEFAULT '{}',
  updatable_columns name[] DEFAULT '{}'
) RETURNS void
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, appsec
AS $$
DECLARE
  table_sql text := target_table::text;
  col_list text;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_class WHERE oid=target_table AND relkind IN ('r','p')) THEN
    RAISE EXCEPTION 'target must be an ordinary or partitioned table' USING ERRCODE='22023';
  END IF;
  IF EXISTS (
    SELECT 1 FROM unnest(coalesce(readable_columns,'{}'::name[]) || coalesce(insertable_columns,'{}'::name[]) || coalesce(updatable_columns,'{}'::name[])) AS cols(col)
    WHERE NOT EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid=target_table AND a.attname=cols.col AND a.attnum>0 AND NOT a.attisdropped)
  ) THEN RAISE EXCEPTION 'one or more requested columns do not exist' USING ERRCODE='22023'; END IF;

  EXECUTE format('REVOKE ALL ON TABLE %s FROM PUBLIC, appsec_app_base, appsec_operator_base', table_sql);
  IF cardinality(readable_columns) > 0 THEN
    SELECT string_agg(format('%I', n), ',') INTO col_list FROM unnest(readable_columns) n;
    EXECUTE format('GRANT SELECT (%s) ON TABLE %s TO appsec_app_base', col_list, table_sql);
  END IF;
  IF cardinality(insertable_columns) > 0 THEN
    SELECT string_agg(format('%I', n), ',') INTO col_list FROM unnest(insertable_columns) n;
    EXECUTE format('GRANT INSERT (%s) ON TABLE %s TO appsec_app_base', col_list, table_sql);
  END IF;
  IF cardinality(updatable_columns) > 0 THEN
    SELECT string_agg(format('%I', n), ',') INTO col_list FROM unnest(updatable_columns) n;
    EXECUTE format('GRANT UPDATE (%s) ON TABLE %s TO appsec_app_base', col_list, table_sql);
  END IF;
END
$$;

REVOKE ALL ON FUNCTION appsec.protect_tenant_owned_table(regclass,name,name,text,text),
  appsec.configure_column_access(regclass,name[],name[],name[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION appsec.protect_tenant_owned_table(regclass,name,name,text,text),
  appsec.configure_column_access(regclass,name[],name[],name[]) TO appsec_operator_base;

RESET ROLE;
-- END 005_schema_security.sql

-- BEGIN 006_custom_rls.sql
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
-- END 006_custom_rls.sql

-- BEGIN 007_hardening.sql
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
-- END 007_hardening.sql

-- BEGIN 008_secdefiner_audit_and_pool.sql
-- Harden SECURITY DEFINER search_path; revoke PUBLIC execute; pool lookup lock-down.
-- FORCE RLS on application data tables. Control-plane tables used by DEFINER
-- writers ENABLE RLS with owner policies but NO FORCE (owner must write).

DO $fix$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT n.nspname, p.proname, pg_get_function_identity_arguments(p.oid) AS args
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'appsec'
      AND p.prosecdef
      AND (p.proconfig IS NULL OR NOT EXISTS (
            SELECT 1 FROM unnest(p.proconfig) c WHERE c LIKE 'search_path=%'))
  LOOP
    EXECUTE format(
      'ALTER FUNCTION %I.%I(%s) SET search_path = pg_catalog, appsec, pg_temp',
      r.nspname, r.proname, r.args);
  END LOOP;
END
$fix$;

DO $rev$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT p.oid::regprocedure AS reg
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'appsec' AND p.prosecdef
  LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', r.reg);
  END LOOP;
END
$rev$;

REVOKE ALL ON FUNCTION appsec.pgbouncer_lookup(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION appsec.pgbouncer_lookup(text) FROM appsec_app_base, appsec_operator_base, appsec_gateway;
GRANT EXECUTE ON FUNCTION appsec.pgbouncer_lookup(text) TO appsec_pool_auth;

-- Application data: FORCE RLS on documents (app roles never own these rows' table).
-- document_acl: ENABLE RLS + owner policy, but NO FORCE so SECURITY DEFINER owner
-- helpers (can_read_document) can still evaluate ACL rows.
ALTER TABLE appsec.documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE appsec.documents FORCE ROW LEVEL SECURITY;
ALTER TABLE appsec.document_acl ENABLE ROW LEVEL SECURITY;
ALTER TABLE appsec.document_acl NO FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS document_acl_owner_all ON appsec.document_acl;
CREATE POLICY document_acl_owner_all ON appsec.document_acl FOR ALL TO appsec_owner USING (true) WITH CHECK (true);

-- Control-plane: ENABLE RLS, NO FORCE, owner full policy (app roles still need explicit grants).
DO $ctl$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'audit_events','security_audit_chain','sessions','session_principals',
    'pool_credentials','refresh_tokens','gateway_assertions','oauth_jti_denylist',
    'tenants','users','groups','group_members','user_roles','database_acl_entries',
    'jsonb_field_acl','identities','credentials','database_acl_caps'
  ] LOOP
    IF EXISTS (
      SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='appsec' AND c.relname=t AND c.relkind='r'
    ) THEN
      EXECUTE format('ALTER TABLE appsec.%I ENABLE ROW LEVEL SECURITY', t);
      EXECUTE format('ALTER TABLE appsec.%I NO FORCE ROW LEVEL SECURITY', t);
      EXECUTE format('DROP POLICY IF EXISTS %I ON appsec.%I', t || '_owner_all', t);
      EXECUTE format(
        'CREATE POLICY %I ON appsec.%I FOR ALL TO appsec_owner USING (true) WITH CHECK (true)',
        t || '_owner_all', t);
    END IF;
  END LOOP;
END
$ctl$;
-- END 008_secdefiner_audit_and_pool.sql

-- BEGIN 009_close_remaining_risks.sql
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
-- END 009_close_remaining_risks.sql

-- BEGIN 010_least_privilege_owners.sql
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
-- END 010_least_privilege_owners.sql

-- Restrict the Rust-exposed password helpers to application principals.
REVOKE ALL ON FUNCTION appsec.hash_password(text), appsec.verify_password(text,text), appsec.version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION appsec.hash_password(text), appsec.verify_password(text,text), appsec.version() TO appsec_app_base, appsec_operator_base;
