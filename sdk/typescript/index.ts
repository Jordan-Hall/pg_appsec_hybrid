export type UUID = string;
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

export interface Queryable {
  query<T = Record<string, unknown>>(sql: string, params?: readonly unknown[]): Promise<{ rows: T[] }>;
}

export interface AuthTransport {
  post<T>(path: string, body: Record<string, unknown>): Promise<T>;
}

export interface ApplicationUser {
  userId: UUID;
  email: string | null;
  tenantId: UUID;
  databaseRole: string;
}

export interface AuthResult {
  accessToken: string;
  refreshToken: string;
  accessExpiresIn: number;
  databasePassword: string;
  sessionId: UUID;
  user: ApplicationUser;
}

export interface PgConnectionCredentials {
  user: string;
  password: string;
}

export interface DocumentRecord {
  document_id: UUID;
  tenant_id: UUID;
  owner_id: UUID;
  body: Json;
  created_at: string;
  updated_at: string;
}

export class PgAppSec {
  constructor(private readonly db: Queryable, private readonly auth?: AuthTransport) {}

  static poolCredentials(auth: AuthResult): PgConnectionCredentials {
    if (!auth.user.databaseRole || !auth.databasePassword) throw new Error("Authentication result has no pool credentials");
    return { user: auth.user.databaseRole, password: auth.databasePassword };
  }

  private authApi(): AuthTransport {
    if (!this.auth) throw new Error("Configure an AuthTransport to use authentication methods");
    return this.auth;
  }

  signUp(input: { email: string; password: string; displayName?: string }): Promise<{ userId: UUID; verificationToken: string }> {
    return this.authApi().post("/v1/signup", input);
  }

  verifyEmail(token: string): Promise<{ verified: boolean }> {
    return this.authApi().post("/v1/verify-email", { token });
  }

  signIn(input: { email: string; password: string; tenantId: UUID; userAgent?: string }): Promise<AuthResult> {
    return this.authApi().post("/v1/signin", input);
  }

  refresh(refreshToken: string): Promise<AuthResult> {
    return this.authApi().post("/v1/refresh", { refreshToken });
  }

  signOut(): Promise<{ revoked: boolean }> {
    return this.authApi().post("/v1/signout", {});
  }

  async createTenant(slug: string, displayName: string): Promise<UUID> {
    const { rows } = await this.db.query<{ tenant_id: UUID }>(
      "select appsec.create_tenant($1,$2) as tenant_id", [slug, displayName],
    );
    if (!rows[0]) throw new Error("tenant creation returned no identifier");
    return rows[0].tenant_id;
  }

  async setTenantStatus(tenantId: UUID, status: "active" | "suspended" | "deleted"): Promise<boolean> {
    const { rows } = await this.db.query<{ changed: boolean }>(
      "select appsec.set_tenant_status($1::uuid,$2) as changed", [tenantId, status],
    );
    return rows[0]?.changed ?? false;
  }

  async createGroup(name: string): Promise<UUID> {
    const { rows } = await this.db.query<{ group_id: UUID }>(
      "select appsec.create_group($1) as group_id", [name],
    );
    if (!rows[0]) throw new Error("group creation returned no identifier");
    return rows[0].group_id;
  }

  async addGroupMember(groupId: UUID, userId: UUID): Promise<void> {
    await this.db.query("select appsec.add_group_member($1::uuid,$2::uuid)", [groupId, userId]);
  }

  async removeGroupMember(groupId: UUID, userId: UUID): Promise<boolean> {
    const { rows } = await this.db.query<{ removed: boolean }>(
      "select appsec.remove_group_member($1::uuid,$2::uuid) as removed", [groupId, userId],
    );
    return rows[0]?.removed ?? false;
  }

  async grantRole(userId: UUID, role: string): Promise<void> {
    await this.db.query("select appsec.grant_role($1::uuid,$2)", [userId, role]);
  }

  async revokeRole(userId: UUID, role: string): Promise<boolean> {
    const { rows } = await this.db.query<{ revoked: boolean }>(
      "select appsec.revoke_role($1::uuid,$2) as revoked", [userId, role],
    );
    return rows[0]?.revoked ?? false;
  }

  async setDatabaseAcl(input: {
    resource: string;
    principalKind: "user" | "group" | "role" | "public";
    principalId: string;
    accessLevel: 0 | 1 | 2 | 3 | 4 | 5 | 6;
    assignedRoles?: readonly string[];
  }): Promise<void> {
    await this.db.query(
      "select appsec.set_database_acl($1,$2,$3,$4::smallint,$5::text[])",
      [input.resource, input.principalKind, input.principalId, input.accessLevel, input.assignedRoles ?? []],
    );
  }

  async removeDatabaseAcl(resource: string, principalKind: "user" | "group" | "role" | "public", principalId: string): Promise<boolean> {
    const { rows } = await this.db.query<{ removed: boolean }>(
      "select appsec.remove_database_acl($1,$2,$3) as removed", [resource, principalKind, principalId],
    );
    return rows[0]?.removed ?? false;
  }

  async setJsonbFieldPolicy(input: {
    resource: string;
    path: readonly string[];
    readRoles: readonly string[];
    writeRoles: readonly string[];
    readGroups?: readonly UUID[];
    writeGroups?: readonly UUID[];
  }): Promise<void> {
    await this.db.query(
      "select appsec.set_jsonb_field_policy($1,$2::text[],$3::text[],$4::text[],$5::uuid[],$6::uuid[])",
      [input.resource, input.path, input.readRoles, input.writeRoles, input.readGroups ?? [], input.writeGroups ?? []],
    );
  }

  async createDocument(body: Json): Promise<UUID> {
    const { rows } = await this.db.query<{ id: UUID }>(
      "select appsec.create_document($1::jsonb) as id", [JSON.stringify(body)],
    );
    if (!rows[0]) throw new Error("document creation returned no identifier");
    return rows[0].id;
  }

  async getDocument(id: UUID): Promise<DocumentRecord | null> {
    const { rows } = await this.db.query<DocumentRecord>(
      "select * from appsec.get_document($1::uuid)", [id],
    );
    return rows[0] ?? null;
  }

  async setJsonPath(id: UUID, path: readonly string[], value: Json): Promise<boolean> {
    const { rows } = await this.db.query<{ changed: boolean }>(
      "select appsec.set_jsonb_path($1::uuid,$2::text[],$3::jsonb) as changed",
      [id, path, JSON.stringify(value)],
    );
    return rows[0]?.changed ?? false;
  }

  async setDocumentAcl(input: {
    documentId: UUID;
    readers?: readonly UUID[];
    authors?: readonly UUID[];
    readerGroups?: readonly UUID[];
    authorGroups?: readonly UUID[];
    readerRoles?: readonly string[];
    authorRoles?: readonly string[];
    readersRestricted?: boolean;
    isPublic?: boolean;
  }): Promise<void> {
    await this.db.query(
      "select appsec.set_document_acl_full($1,$2::uuid[],$3::uuid[],$4::uuid[],$5::uuid[],$6::text[],$7::text[],$8,$9)",
      [input.documentId, input.readers ?? [], input.authors ?? [], input.readerGroups ?? [], input.authorGroups ?? [], input.readerRoles ?? [], input.authorRoles ?? [], input.isPublic ?? false, input.readersRestricted ?? Boolean((input.readers?.length ?? 0) || (input.readerGroups?.length ?? 0) || (input.readerRoles?.length ?? 0))],
    );
  }

  async listSessions(): Promise<Array<{
    session_id: UUID; created_at: string; last_seen_at: string; expires_at: string;
    revoked_at: string | null; auth_method: string; user_agent: string | null;
  }>> {
    const { rows } = await this.db.query<{
      session_id: UUID; created_at: string; last_seen_at: string; expires_at: string;
      revoked_at: string | null; auth_method: string; user_agent: string | null;
    }>("select * from appsec.list_my_sessions()");
    return rows;
  }

  async revokeSession(id: UUID): Promise<boolean> {
    const { rows } = await this.db.query<{ revoked: boolean }>(
      "select appsec.revoke_session($1::uuid) as revoked", [id],
    );
    return rows[0]?.revoked ?? false;
  }

  async revokeAllSessions(): Promise<number> {
    const { rows } = await this.db.query<{ count: number }>(
      "select appsec.revoke_all_sessions() as count",
    );
    return Number(rows[0]?.count ?? 0);
  }
}
