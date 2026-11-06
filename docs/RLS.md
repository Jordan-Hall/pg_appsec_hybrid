# Custom RLS helpers and SurrealDB-style permissions

Application principals authenticate as per-session roles `app_s_<32hex>`. Identity helpers resolve **only** from `session_user` (never from caller-set GUCs). Use them in plain `CREATE POLICY` or through the permission DSL.

## Identity helpers (Surreal `$auth`)

| SurrealDB | PostgreSQL (`appsec`) | Notes |
|---|---|---|
| `$auth.id` / `$auth` | `appsec.uid()` / `appsec.auth()` | `auth()` returns jsonb: `user_id`, `tenant_id`, `session_id`, `db_role`, `auth_method`, `claims` |
| `$auth.tenant` (app convention) | `appsec.tenant_id()` | Active tenant of the mapped user |
| session id | `appsec.session_id()` | Active unrevoked session for `session_user` |
| role check | `appsec.has_role(text)` | User roles + non-public ACL `assigned_roles` only (never `public`) |

All helpers are `STABLE`, `SECURITY DEFINER` with pinned `search_path`, and marked `LEAKPROOF` when installed by a superuser. Grant: `appsec_app_base`, `appsec_operator_base`.

```sql
-- Spoof attempt: ignored
SELECT set_config('appsec.user_id', 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', false);
SELECT appsec.uid();           -- still Alice
SELECT appsec.auth()->'claims'; -- OAuth/adapter claims stored at mint time
```

## Hand-written policies (any table)

```sql
-- SurrealDB
-- DEFINE TABLE notes PERMISSIONS
--   FOR select, create, update, delete WHERE owner = $auth.id;

-- PostgreSQL
ALTER TABLE appsec.notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE appsec.notes FORCE ROW LEVEL SECURITY;
CREATE POLICY notes_owner ON appsec.notes FOR ALL
  USING (owner_id = appsec.uid() AND tenant_id = appsec.tenant_id())
  WITH CHECK (owner_id = appsec.uid() AND tenant_id = appsec.tenant_id());
```

## Permission DSL

Callable by `appsec_owner` / `appsec_operator_base` / table owner (not app sessions).

```sql
-- SurrealDB
-- DEFINE TABLE notes SCHEMAFULL
--   PERMISSIONS FOR select WHERE owner = $auth.id
--   PERMISSIONS FOR create, update, delete WHERE owner = $auth.id;
-- DEFINE FIELD secret ON notes
--   PERMISSIONS FOR select, update WHERE owner = $auth.id;

-- PostgreSQL DSL
SELECT appsec.define_table_permissions(
  'appsec.notes'::regclass,
  'owner_id = appsec.uid()',  -- select
  'owner_id = appsec.uid()',  -- create/insert
  'owner_id = appsec.uid()',  -- update
  'owner_id = appsec.uid()',  -- delete
  'tenant_id'                 -- optional RESTRICTIVE tenant column
);

SELECT appsec.define_field_permissions(
  'appsec.notes'::regclass, 'secret',
  'owner_id = appsec.uid()',  -- select (masked via security_barrier view)
  'owner_id = appsec.uid()'   -- update (BEFORE UPDATE trigger)
);

-- Read masked columns through the generated view:
SELECT * FROM appsec.notes_secured;

SELECT appsec.drop_field_permissions('appsec.notes'::regclass, 'secret');
SELECT appsec.drop_table_permissions('appsec.notes'::regclass);
```

Expressions are validated (no `;`, comments, `set_config`, DDL, `SECURITY DEFINER`, etc.), identifiers are `%I`-quoted, policies are idempotent (`DROP POLICY IF EXISTS` then recreate), and `FORCE ROW LEVEL SECURITY` is always enabled.

## Composing with Domino ACL

| Layer | Policy kind | Combination |
|---|---|---|
| Tenant isolation (`tenant_column` arg) | **RESTRICTIVE** | Always AND'd — must pass even if a permissive policy allows |
| DSL `appsec_dsl_*` / hand-written | PERMISSIVE (default) | OR'd with other permissive policies on the same command |
| Domino `document_acl` / `can_read_document` | Used inside document policies & SECURITY DEFINER APIs | Independent; keep using `get_document` / ACL helpers |

Example: a table can have RESTRICTIVE tenant isolation **and** permissive owner DSL policies **and** still call `appsec.has_role` inside expressions. Domino ACL tables remain optional: leave them unused for plain Surreal-style apps, or AND/OR them explicitly in your expressions / document policies.

## Threat notes

- Helpers never read `current_setting('appsec.*')` for identity.
- Field `select_expr` masking is enforced through `*_secured` security-barrier views (column SELECT revoked on base table). Direct `SELECT secret FROM notes` is denied for app roles when a field select policy exists.
- Field `update_expr` is enforced by `appsec_field_update_guard` (cannot be bypassed by column UPDATE grants alone under FORCE RLS + trigger).
- Independent review still required before production (especially OAuth crypto and SECURITY DEFINER surface).


## Application gateway mode (opt-in)

Default is still per-session DB roles end-to-end. Gateway mode is explicit:

1. Provisioner grants `app_s_<sid>` to `appsec_gateway` (`grant_session_role_to_gateway`).
2. Edge process logs in as a member of `appsec_gateway` (no table privileges).
3. `SELECT appsec.assume_session(minted_assertion);` verifies HMAC + audience + expiry + one-time jti, then `SET ROLE` to the session role.
4. `appsec.uid()` resolves via `current_user` when it is `app_s_*` (because `session_user` remains the gateway).
5. `RESET ROLE` returns to gateway — data access denied.

Assertions are minted only by provisioner/operator with `appsec.gateway_hmac_key` configured server-side.


## Gateway session assumption

- Prefer `appsec.assume_session_local(assertion)` inside an explicit `BEGIN`…`COMMIT` (`SET LOCAL ROLE`; ends with the transaction).
- `appsec.assume_session(assertion)` uses session-scoped `SET ROLE` for autocommit clients; after `RESET ROLE` the gateway login has **zero** table privileges (CI covers spoof/replay/escape).
- Outside an assumed session, `appsec_gateway` must remain without DML/SELECT on protected tables.
