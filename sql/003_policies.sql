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
