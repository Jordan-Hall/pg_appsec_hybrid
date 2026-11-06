# Developer experience design

The public API should make the secure path the shortest path. `AuthTransport` is an application-owned HTTP adapter; this repository does not ship an HTTP server yet. Tenant context is resolved by trusted server-side routing/invitation state.

```ts
const authTransport: AuthTransport = createYourServerAuthTransport();
const auth = new PgAppSec(databaseClient, authTransport);

const signup = await auth.signUp({ email, password, displayName });
await auth.verifyEmail(signup.verificationToken);

const session = await auth.signIn({ email, password, tenantId });
const poolCredentials = PgAppSec.poolCredentials(session);
const userPool = createPgPool({
  host: "pgbouncer.internal",
  database: "appdb",
  user: poolCredentials.user,
  password: poolCredentials.password,
});

const db = new PgAppSec(userPool);
const documentId = await db.createDocument({ title: "hello", private: { notes: "..." } });
await db.setDocumentAcl({ documentId, readers: [colleagueId], readersRestricted: true });
const document = await db.getDocument(documentId);
```

For direct PostgreSQL OAuth, connect as `session.user.databaseRole` and use `session.accessToken` as the bearer token; do not use `databasePassword` for OAuth. For PgBouncer SCRAM, use `PgAppSec.poolCredentials(session)`. Refresh returns a rotated database password; replace the credentials used for new pooler connections. Existing backend connections remain bound to the same session role and are revoked by the session lookup.

The SDK must never accept a user ID as an authorization context. The database obtains identity from the authenticated PostgreSQL principal (`session_user`) and resolves it through `appsec.session_principals` (or a separately provisioned operator/service principal). An explicit `asUser(userId)` API is prohibited.

## SQL-first schema declarations

The intended future declaration DSL is migration-backed SQL, not runtime policy callbacks:

```sql
SELECT appsec.enable_document_security('public.documents',
  identity_column => 'owner_id', tenant_column => 'tenant_id',
  readers_column => 'readers', authors_column => 'authors');
SELECT appsec.protect_jsonb_path('public.documents', 'body', '{billing,bank_account}',
  read_roles => ARRAY['billing_reader'], write_roles => ARRAY['billing_admin']);
```

These helpers must generate ordinary PostgreSQL policies/views/grants and be inspectable using `appsec.describe_security(resource)` before they are advertised as stable.

## Error model

- Authentication errors are deliberately non-enumerating.
- Authorization failures use SQLSTATE `42501`.
- Missing records return no rows or `P0002` according to the API contract; they must not disclose cross-tenant existence.
- Validation errors use `22023` or constraint SQLSTATEs.
- Every SDK method accepts a transaction-bound client when the caller needs multi-step atomic work.

## Protect an application-owned table

Run migrations through `005_schema_security.sql`, then have the table owner execute:

```sql
SELECT appsec.protect_tenant_owned_table(
  'public.projects'::regclass, 'tenant_id', 'owner_id',
  'projects.read_all', 'projects.write_all'
);

SELECT appsec.configure_column_access(
  'public.projects'::regclass,
  ARRAY['id','tenant_id','owner_id','name']::name[],
  ARRAY['tenant_id','owner_id','name']::name[],
  ARRAY['name']::name[]
);
```

The first helper enables and forces RLS with tenant isolation and owner defaults. The second removes table-level grants to `PUBLIC` and `appsec_app_base`, then grants only the requested columns to the application base role. PostgreSQL grants are additive: audit grants to every other role and inherited role before relying on column restrictions. Keep secrets in separate tables or expose them through narrowly scoped views/functions whenever possible.

JSONB field policies are deny-by-default for document creation: every scalar/array leaf must have an explicit writable path policy. Nested object paths are projected recursively. Array elements are currently treated as one secured value; per-element JSON array ACLs are not implemented.
