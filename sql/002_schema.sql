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
