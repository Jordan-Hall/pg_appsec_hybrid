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
         SELECT 1 FROM appsec.group_members gm WHERE gm.user_id=appsec.uid() AND gm.group_id::text=a.principal_id))
       OR (a.principal_kind='public' AND a.principal_id='*'))
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
  INSERT INTO appsec.documents(tenant_id, owner_id, body)
  VALUES (tenant, actor, input_body)
  RETURNING document_id INTO new_id;
  INSERT INTO appsec.document_acl(document_id, tenant_id, readers, authors, is_public)
  VALUES (new_id, tenant, ARRAY[actor], ARRAY[actor], input_body ->> '$PublicAccess' = '1');
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
  FROM appsec.documents d WHERE d.document_id = doc_id
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
         SELECT 1 FROM appsec.group_members gm WHERE gm.user_id=appsec.uid() AND gm.group_id::text=a.principal_id))
       OR (a.principal_kind='public' AND a.principal_id='*'))
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

-- Restrict the Rust-exposed password helpers to application principals.
REVOKE ALL ON FUNCTION appsec.hash_password(text), appsec.verify_password(text,text), appsec.version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION appsec.hash_password(text), appsec.verify_password(text,text), appsec.version() TO appsec_app_base, appsec_operator_base;
