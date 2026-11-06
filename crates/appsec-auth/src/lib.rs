use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use jsonwebtoken::{
    decode, encode, Algorithm as JwtAlgorithm, DecodingKey, EncodingKey, Header, Validation,
};
use pbkdf2::pbkdf2_hmac;
use rand::{rngs::OsRng as RandomOsRng, RngCore};
use sha2::{Digest, Sha256};
type HmacSha256 = Hmac<Sha256>;
use sqlx::{PgPool, Row};
use thiserror::Error;
use uuid::Uuid;

const PASSWORD_MIN_BYTES: usize = 12;
const PASSWORD_MAX_BYTES: usize = 1024;
const ACCESS_TTL_SECONDS: i64 = 900;
const REFRESH_TTL_DAYS: i64 = 30;
const MAX_FAILED_ATTEMPTS: i32 = 10;
const DUMMY_PASSWORD_PHC: &str = "$argon2id$v=19$m=65536,t=3,p=1$L0GZGwOEtbXcbgv7cT+4/w$7JLHevR9weywJuV8TB5K1Qh+Em0oZN/L4P/AgvknWkE";

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("account requires email verification or is disabled")]
    AccountUnavailable,
    #[error("invalid or expired verification token")]
    InvalidVerification,
    #[error("invalid or expired refresh token")]
    InvalidRefresh,
    #[error("password must contain between 12 and 1024 UTF-8 bytes")]
    InvalidPassword,
    #[error("authentication signing key is invalid")]
    SigningKey,
    #[error("invalid or expired access token")]
    InvalidAccessToken,
    #[error("database operation failed: {0}")]
    Database(#[from] sqlx::Error),
    #[error("password operation failed")]
    Password,
    #[error("token operation failed")]
    Token,
}

#[derive(Clone)]
pub struct AuthConfig {
    pub issuer: String,
    pub audience: String,
    pub access_ttl_seconds: i64,
    pub refresh_ttl_days: i64,
    pub ed25519_private_key_pem: Vec<u8>,
    pub ed25519_public_key_pem: Vec<u8>,
}

impl AuthConfig {
    pub fn production(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        private_pem: Vec<u8>,
        public_pem: Vec<u8>,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            access_ttl_seconds: ACCESS_TTL_SECONDS,
            refresh_ttl_days: REFRESH_TTL_DAYS,
            ed25519_private_key_pem: private_pem,
            ed25519_public_key_pem: public_pem,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthUser {
    pub user_id: Uuid,
    #[serde(rename = "databaseRole")]
    pub db_role: String,
    pub email: Option<String>,
    pub tenant_id: Uuid,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthTokens {
    pub session_id: Uuid,
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_in: i64,
    pub database_password: Option<String>,
    pub user: AuthUser,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct AccessClaims {
    iss: String,
    aud: String,
    sub: String,
    preferred_username: String,
    token_use: String,
    scope: String,
    iat: i64,
    nbf: i64,
    exp: i64,
    jti: String,
    sid: String,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedSession {
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub database_role: String,
}

pub struct AuthService {
    pool: PgPool,
    config: AuthConfig,
}

impl AuthService {
    pub fn new(pool: PgPool, config: AuthConfig) -> Self {
        Self { pool, config }
    }

    pub fn authenticate_access_token(
        &self,
        token: &str,
    ) -> Result<AuthenticatedSession, AuthError> {
        let key = DecodingKey::from_ed_pem(&self.config.ed25519_public_key_pem)
            .map_err(|_| AuthError::SigningKey)?;
        let mut validation = Validation::new(JwtAlgorithm::EdDSA);
        validation.set_issuer(std::slice::from_ref(&self.config.issuer));
        validation.set_audience(std::slice::from_ref(&self.config.audience));
        validation.validate_exp = true;
        validation.validate_nbf = true;
        let data = decode::<AccessClaims>(token, &key, &validation)
            .map_err(|_| AuthError::InvalidAccessToken)?;
        let claims = data.claims;
        let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AuthError::InvalidAccessToken)?;
        let session_id = Uuid::parse_str(&claims.sid).map_err(|_| AuthError::InvalidAccessToken)?;
        let now = Utc::now().timestamp();
        if claims.token_use != "access"
            || !claims
                .scope
                .split_whitespace()
                .any(|scope| scope == "pg_appsec")
            || claims.preferred_username != role_for_session(session_id)
            || claims.iat > now + 30
            || now.saturating_sub(claims.iat) > self.config.access_ttl_seconds + 60
            || claims.jti.is_empty()
        {
            return Err(AuthError::InvalidAccessToken);
        }
        Ok(AuthenticatedSession {
            user_id,
            session_id,
            database_role: claims.preferred_username,
        })
    }

    pub async fn sign_out_access_token(&self, token: &str) -> Result<bool, AuthError> {
        let principal = self.authenticate_access_token(token)?;
        self.sign_out_session(principal.user_id, principal.session_id)
            .await
    }

    pub async fn revoke_session_access_token(
        &self,
        token: &str,
        target_session: Uuid,
    ) -> Result<bool, AuthError> {
        let principal = self.authenticate_access_token(token)?;
        self.sign_out_session(principal.user_id, target_session)
            .await
    }

    pub async fn change_password_access_token(
        &self,
        token: &str,
        new_password: &str,
    ) -> Result<(), AuthError> {
        let principal = self.authenticate_access_token(token)?;
        self.change_password_for_user(principal.user_id, Some(principal.session_id), new_password)
            .await
    }

    pub async fn disable_user_access_token(
        &self,
        token: &str,
        target_user: Uuid,
    ) -> Result<(), AuthError> {
        let actor = self.authenticate_access_token(token)?;
        self.disable_user_for_admin(&actor, target_user).await
    }

    pub async fn enable_user_access_token(
        &self,
        token: &str,
        target_user: Uuid,
    ) -> Result<(), AuthError> {
        let actor = self.authenticate_access_token(token)?;
        self.enable_user_for_admin(&actor, target_user).await
    }

    async fn admin_allowed_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        actor: &AuthenticatedSession,
    ) -> Result<bool, AuthError> {
        let active: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM appsec.sessions s JOIN appsec.users u USING(user_id) JOIN appsec.tenants ten USING(tenant_id) WHERE s.session_id=$1 AND s.user_id=$2 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND u.status='active' AND ten.status='active')")
            .bind(actor.session_id).bind(actor.user_id).fetch_one(&mut **tx).await?;
        if !active {
            return Ok(false);
        }
        let allowed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM appsec.user_roles WHERE user_id=$1 AND role_name='appsec.admin') OR EXISTS(SELECT 1 FROM appsec.database_acl_entries a WHERE a.database_name=current_database() AND 'appsec.admin'=ANY(a.assigned_roles) AND ((a.principal_kind='user' AND a.principal_id=$1::text) OR (a.principal_kind='group' AND EXISTS(SELECT 1 FROM appsec.group_members gm WHERE gm.user_id=$1 AND gm.group_id::text=a.principal_id))))")
            .bind(actor.user_id).fetch_one(&mut **tx).await?;
        Ok(allowed)
    }

    pub async fn sign_up(
        &self,
        email: &str,
        password: &str,
        tenant_id: Uuid,
        display_name: Option<&str>,
    ) -> Result<(Uuid, String), AuthError> {
        validate_password(password)?;
        let normalized_email = email.trim().to_lowercase();
        if normalized_email.is_empty()
            || normalized_email.len() > 320
            || !normalized_email.contains('@')
        {
            return Err(AuthError::InvalidCredentials);
        }
        let password_phc = hash_password(password)?;
        let user_id = Uuid::new_v4();
        let verification = random_token();
        let verification_hash = sha256(verification.as_bytes());
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE appsec_provisioner")
            .execute(&mut *tx)
            .await?;
        let tenant_active: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM appsec.tenants WHERE tenant_id=$1 AND status='active')",
        )
        .bind(tenant_id)
        .fetch_one(&mut *tx)
        .await?;
        if !tenant_active {
            return Err(AuthError::AccountUnavailable);
        }

        sqlx::query("INSERT INTO appsec.users(user_id,email,display_name,status,tenant_id) VALUES($1,$2,$3,'pending',$4)")
            .bind(user_id).bind(&normalized_email).bind(display_name).bind(tenant_id).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO appsec.credentials(user_id,password_phc) VALUES($1,$2)")
            .bind(user_id)
            .bind(password_phc)
            .execute(&mut *tx)
            .await?;

        sqlx::query("INSERT INTO appsec.email_verifications(user_id,token_hash,expires_at) VALUES($1,$2,clock_timestamp()+interval '24 hours')")
            .bind(user_id).bind(verification_hash.to_vec()).execute(&mut *tx).await?;
        Self::write_audit(
            &mut tx,
            None,
            "auth.signup_requested",
            Some(user_id.to_string()),
            serde_json::json!({"tenant_id": tenant_id}),
        )
        .await?;
        tx.commit().await?;
        Ok((user_id, verification))
    }

    pub async fn verify_email(&self, raw_token: &str) -> Result<(), AuthError> {
        let token_hash = sha256(raw_token.as_bytes());
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE appsec_provisioner")
            .execute(&mut *tx)
            .await?;
        let row = sqlx::query("SELECT verification_id,user_id FROM appsec.email_verifications WHERE token_hash=$1 AND consumed_at IS NULL AND expires_at>clock_timestamp() FOR UPDATE")
            .bind(token_hash.to_vec()).fetch_optional(&mut *tx).await?;
        let Some(row) = row else {
            return Err(AuthError::InvalidVerification);
        };
        let verification_id: Uuid = row.try_get("verification_id")?;
        let user_id: Uuid = row.try_get("user_id")?;
        sqlx::query("UPDATE appsec.email_verifications SET consumed_at=clock_timestamp() WHERE verification_id=$1")
            .bind(verification_id).execute(&mut *tx).await?;
        sqlx::query("UPDATE appsec.users SET status='active',updated_at=clock_timestamp() WHERE user_id=$1 AND status='pending'")
            .bind(user_id).execute(&mut *tx).await?;
        Self::write_audit(
            &mut tx,
            Some(user_id),
            "auth.email_verified",
            Some(user_id.to_string()),
            serde_json::json!({}),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn sign_in(
        &self,
        email: &str,
        password: &str,
        tenant_id: Uuid,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<AuthTokens, AuthError> {
        let normalized_email = email.trim().to_lowercase();
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE appsec_provisioner")
            .execute(&mut *tx)
            .await?;
        let row = sqlx::query(concat!(
            "SELECT u.user_id,u.email,u.tenant_id,u.status,t.status AS tenant_status,c.password_phc,c.failed_attempts,c.locked_until ",
            "FROM appsec.users u JOIN appsec.tenants t USING(tenant_id) JOIN appsec.credentials c USING(user_id) ",
            "WHERE lower(u.email)=lower($1) AND u.tenant_id=$2 FOR UPDATE OF u,c,t"
        )).bind(&normalized_email).bind(tenant_id).fetch_optional(&mut *tx).await?;
        let Some(row) = row else {
            let _ = verify_password(password, DUMMY_PASSWORD_PHC).unwrap_or(false);
            Self::write_audit(
                &mut tx,
                None,
                "auth.signin_failed",
                None,
                serde_json::json!({"tenant_id": tenant_id, "reason": "unknown_account", "ip": ip}),
            )
            .await?;
            tx.commit().await?;
            return Err(AuthError::InvalidCredentials);
        };
        let user_id: Uuid = row.try_get("user_id")?;
        let status: String = row.try_get("status")?;
        let tenant_status: String = row.try_get("tenant_status")?;
        let locked_until: Option<chrono::DateTime<Utc>> = row.try_get("locked_until")?;
        let phc: String = row.try_get("password_phc")?;
        let valid = verify_password(password, &phc).unwrap_or(false);
        if !valid {
            let attempts: i32 = row.try_get("failed_attempts")?;
            let next = attempts.saturating_add(1);
            sqlx::query("UPDATE appsec.credentials SET failed_attempts=$2,locked_until=CASE WHEN $2 >= $3 THEN clock_timestamp()+interval '15 minutes' ELSE locked_until END WHERE user_id=$1")
                .bind(user_id).bind(next).bind(MAX_FAILED_ATTEMPTS)
                .execute(&mut *tx).await?;
            Self::write_audit(
                &mut tx,
                Some(user_id),
                "auth.signin_failed",
                Some(user_id.to_string()),
                serde_json::json!({"tenant_id": tenant_id, "reason": "bad_password", "ip": ip}),
            )
            .await?;
            tx.commit().await?;
            return Err(AuthError::InvalidCredentials);
        }
        if status != "active"
            || tenant_status != "active"
            || locked_until.is_some_and(|until| until > Utc::now())
        {
            Self::write_audit(&mut tx, Some(user_id), "auth.signin_failed", Some(user_id.to_string()), serde_json::json!({"tenant_id": tenant_id, "reason": "account_unavailable", "ip": ip})).await?;
            tx.commit().await?;
            return Err(AuthError::InvalidCredentials);
        }
        sqlx::query(
            "UPDATE appsec.credentials SET failed_attempts=0,locked_until=NULL WHERE user_id=$1",
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
        let session_id = Uuid::new_v4();
        let role = role_for_session(session_id);
        let refresh_expires = Utc::now() + Duration::days(self.config.refresh_ttl_days);
        let (database_password, verifier) = postgres_scram_credential()?;
        sqlx::query("SET LOCAL password_encryption='scram-sha-256'")
            .execute(&mut *tx)
            .await?;
        // Role DDL goes through appsec_role_admin-owned helpers (PG16+ CREATEROLE
        // + ADMIN OPTION); the provisioner itself holds no CREATEROLE.
        sqlx::query("SELECT appsec.create_session_role($1::name, $2, $3::timestamptz, 2)")
            .bind(&role)
            .bind(&verifier)
            .bind(refresh_expires)
            .execute(&mut *tx)
            .await?;
        let user = AuthUser {
            user_id,
            db_role: role.clone(),
            email: row.try_get("email")?,
            tenant_id: row.try_get("tenant_id")?,
        };
        let refresh = random_token();
        let refresh_hash = sha256(refresh.as_bytes());
        sqlx::query("INSERT INTO appsec.sessions(session_id,user_id,expires_at,ip,user_agent,auth_method) VALUES($1,$2,$3,$4::inet,$5,'password')")
            .bind(session_id).bind(user.user_id).bind(refresh_expires).bind(ip).bind(user_agent).execute(&mut *tx).await?;
        sqlx::query(
            "INSERT INTO appsec.session_principals(session_id,user_id,db_role) VALUES($1,$2,$3)",
        )
        .bind(session_id)
        .bind(user.user_id)
        .bind(&role)
        .execute(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO appsec.pool_credentials(db_role,session_id,scram_verifier) VALUES($1,$2,$3)")
            .bind(&role).bind(session_id).bind(&verifier).execute(&mut *tx).await?;
        sqlx::query(
            "INSERT INTO appsec.refresh_tokens(session_id,token_hash,expires_at) VALUES($1,$2,$3)",
        )
        .bind(session_id)
        .bind(refresh_hash.to_vec())
        .bind(refresh_expires)
        .execute(&mut *tx)
        .await?;
        let access_token = self.issue_access_token(&user, session_id)?;
        Self::write_audit(
            &mut tx,
            Some(user_id),
            "auth.signin_succeeded",
            Some(session_id.to_string()),
            serde_json::json!({"tenant_id": tenant_id, "session_id": session_id, "ip": ip}),
        )
        .await?;
        tx.commit().await?;
        Ok(AuthTokens {
            session_id,
            access_token,
            refresh_token: refresh,
            access_expires_in: self.config.access_ttl_seconds,
            database_password: Some(database_password),
            user,
        })
    }

    async fn sign_out_session(&self, user_id: Uuid, session_id: Uuid) -> Result<bool, AuthError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE appsec_provisioner")
            .execute(&mut *tx)
            .await?;
        let role: Option<String> = sqlx::query_scalar("SELECT db_role::text FROM appsec.session_principals WHERE session_id=$1 AND user_id=$2")
            .bind(session_id).bind(user_id).fetch_optional(&mut *tx).await?;
        let result = sqlx::query("UPDATE appsec.sessions SET revoked_at=clock_timestamp() WHERE session_id=$1 AND user_id=$2 AND revoked_at IS NULL")
            .bind(session_id).bind(user_id).execute(&mut *tx).await?;
        if result.rows_affected() == 1 {
            sqlx::query("UPDATE appsec.refresh_tokens SET revoked_at=clock_timestamp() WHERE session_id=$1 AND revoked_at IS NULL")
                .bind(session_id).execute(&mut *tx).await?;
            sqlx::query("UPDATE appsec.pool_credentials SET revoked_at=clock_timestamp() WHERE session_id=$1 AND revoked_at IS NULL")
                .bind(session_id).execute(&mut *tx).await?;
            if let Some(role) = role {
                alter_role_login(&mut tx, &role, false).await?;
            }
            Self::write_audit(
                &mut tx,
                Some(user_id),
                "auth.session_revoked",
                Some(session_id.to_string()),
                serde_json::json!({}),
            )
            .await?;
        }
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    async fn change_password_for_user(
        &self,
        user_id: Uuid,
        required_session: Option<Uuid>,
        new_password: &str,
    ) -> Result<(), AuthError> {
        let phc = hash_password(new_password)?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE appsec_provisioner")
            .execute(&mut *tx)
            .await?;
        if let Some(session_id) = required_session {
            let active = sqlx::query("SELECT s.session_id FROM appsec.sessions s JOIN appsec.users u USING(user_id) JOIN appsec.tenants ten USING(tenant_id) WHERE s.session_id=$1 AND s.user_id=$2 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND u.status='active' AND ten.status='active' FOR UPDATE OF s,u")
                .bind(session_id).bind(user_id).fetch_optional(&mut *tx).await?;
            if active.is_none() {
                return Err(AuthError::InvalidAccessToken);
            }
        }
        sqlx::query("UPDATE appsec.credentials SET password_phc=$2,password_changed_at=clock_timestamp(),failed_attempts=0,locked_until=NULL WHERE user_id=$1")
            .bind(user_id).bind(phc).execute(&mut *tx).await?;
        sqlx::query("UPDATE appsec.sessions SET revoked_at=clock_timestamp() WHERE user_id=$1 AND revoked_at IS NULL")
            .bind(user_id).execute(&mut *tx).await?;
        sqlx::query("UPDATE appsec.refresh_tokens t SET revoked_at=clock_timestamp() FROM appsec.sessions s WHERE s.session_id=t.session_id AND s.user_id=$1 AND t.revoked_at IS NULL")
            .bind(user_id).execute(&mut *tx).await?;
        sqlx::query("UPDATE appsec.pool_credentials pc SET revoked_at=clock_timestamp() FROM appsec.sessions s WHERE s.session_id=pc.session_id AND s.user_id=$1 AND pc.revoked_at IS NULL")
            .bind(user_id).execute(&mut *tx).await?;
        let roles =
            sqlx::query("SELECT db_role::text FROM appsec.session_principals WHERE user_id=$1")
                .bind(user_id)
                .fetch_all(&mut *tx)
                .await?;
        for row in roles {
            let role: String = row.try_get("db_role")?;
            alter_role_login(&mut tx, &role, false).await?;
        }
        Self::write_audit(
            &mut tx,
            Some(user_id),
            "auth.password_changed",
            Some(user_id.to_string()),
            serde_json::json!({}),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn disable_user_for_admin(
        &self,
        actor: &AuthenticatedSession,
        user_id: Uuid,
    ) -> Result<(), AuthError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE appsec_provisioner")
            .execute(&mut *tx)
            .await?;
        if !Self::admin_allowed_in_tx(&mut tx, actor).await? {
            return Err(AuthError::AccountUnavailable);
        }
        let changed = sqlx::query("UPDATE appsec.users SET status='disabled',updated_at=clock_timestamp() WHERE user_id=$1 AND status <> 'deleted'")
            .bind(user_id).execute(&mut *tx).await?;
        if changed.rows_affected() != 1 {
            return Err(AuthError::AccountUnavailable);
        }
        sqlx::query("UPDATE appsec.sessions SET revoked_at=clock_timestamp() WHERE user_id=$1 AND revoked_at IS NULL")
            .bind(user_id).execute(&mut *tx).await?;
        sqlx::query("UPDATE appsec.refresh_tokens t SET revoked_at=clock_timestamp() FROM appsec.sessions s WHERE s.session_id=t.session_id AND s.user_id=$1 AND t.revoked_at IS NULL")
            .bind(user_id).execute(&mut *tx).await?;
        sqlx::query("UPDATE appsec.pool_credentials pc SET revoked_at=clock_timestamp() FROM appsec.sessions s WHERE s.session_id=pc.session_id AND s.user_id=$1 AND pc.revoked_at IS NULL")
            .bind(user_id).execute(&mut *tx).await?;
        let roles =
            sqlx::query("SELECT db_role::text FROM appsec.session_principals WHERE user_id=$1")
                .bind(user_id)
                .fetch_all(&mut *tx)
                .await?;
        for row in roles {
            let role: String = row.try_get("db_role")?;
            alter_role_login(&mut tx, &role, false).await?;
        }
        Self::write_audit(
            &mut tx,
            Some(actor.user_id),
            "admin.user_disabled",
            Some(user_id.to_string()),
            serde_json::json!({"target_user_id": user_id}),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn enable_user_for_admin(
        &self,
        actor: &AuthenticatedSession,
        user_id: Uuid,
    ) -> Result<(), AuthError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE appsec_provisioner")
            .execute(&mut *tx)
            .await?;
        if !Self::admin_allowed_in_tx(&mut tx, actor).await? {
            return Err(AuthError::AccountUnavailable);
        }
        let changed = sqlx::query("UPDATE appsec.users SET status='active',updated_at=clock_timestamp() WHERE user_id=$1 AND status='disabled'")
            .bind(user_id).execute(&mut *tx).await?;
        if changed.rows_affected() != 1 {
            return Err(AuthError::AccountUnavailable);
        }
        Self::write_audit(
            &mut tx,
            Some(actor.user_id),
            "admin.user_enabled",
            Some(user_id.to_string()),
            serde_json::json!({"target_user_id": user_id}),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn reap_expired_sessions(&self) -> Result<u64, AuthError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE appsec_provisioner")
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE appsec.sessions SET revoked_at=clock_timestamp() WHERE revoked_at IS NULL AND expires_at<=clock_timestamp()")
            .execute(&mut *tx).await?;
        sqlx::query("UPDATE appsec.refresh_tokens t SET revoked_at=clock_timestamp() FROM appsec.sessions s WHERE s.session_id=t.session_id AND (s.revoked_at IS NOT NULL OR s.expires_at<=clock_timestamp()) AND t.revoked_at IS NULL")
            .execute(&mut *tx).await?;
        sqlx::query("UPDATE appsec.pool_credentials pc SET revoked_at=clock_timestamp() FROM appsec.sessions s WHERE s.session_id=pc.session_id AND (s.revoked_at IS NOT NULL OR s.expires_at<=clock_timestamp()) AND pc.revoked_at IS NULL")
            .execute(&mut *tx).await?;
        let roles = sqlx::query("SELECT sp.db_role::text FROM appsec.session_principals sp JOIN appsec.sessions s USING(session_id) WHERE (s.revoked_at IS NOT NULL OR s.expires_at<=clock_timestamp())")
            .fetch_all(&mut *tx).await?;
        for row in &roles {
            let role: String = row.try_get("db_role")?;
            alter_role_login(&mut tx, &role, false).await?;
        }
        Self::write_audit(
            &mut tx,
            None,
            "auth.expired_sessions_reaped",
            None,
            serde_json::json!({"count": roles.len()}),
        )
        .await?;
        tx.commit().await?;
        Ok(roles.len() as u64)
    }

    pub async fn refresh(&self, raw_refresh: &str) -> Result<AuthTokens, AuthError> {
        let old_hash = sha256(raw_refresh.as_bytes());
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE appsec_provisioner")
            .execute(&mut *tx)
            .await?;
        let row = sqlx::query(concat!(
            "SELECT t.token_id,t.session_id,t.consumed_at,t.revoked_at,t.expires_at,s.user_id,s.revoked_at AS session_revoked,s.expires_at AS session_expires,u.email,u.tenant_id,u.status,ten.status AS tenant_status,sp.db_role ",
            "FROM appsec.refresh_tokens t JOIN appsec.sessions s USING(session_id) JOIN appsec.users u USING(user_id) ",
            "JOIN appsec.tenants ten USING(tenant_id) JOIN appsec.session_principals sp USING(session_id,user_id) WHERE t.token_hash=$1 FOR UPDATE OF t,s,u,ten"
        )).bind(old_hash.to_vec()).fetch_optional(&mut *tx).await?;
        let Some(row) = row else {
            return Err(AuthError::InvalidRefresh);
        };
        let token_id: Uuid = row.try_get("token_id")?;
        let session_id: Uuid = row.try_get("session_id")?;
        let consumed: Option<chrono::DateTime<Utc>> = row.try_get("consumed_at")?;
        let revoked: Option<chrono::DateTime<Utc>> = row.try_get("revoked_at")?;
        let session_revoked: Option<chrono::DateTime<Utc>> = row.try_get("session_revoked")?;
        let token_exp: chrono::DateTime<Utc> = row.try_get("expires_at")?;
        let session_exp: chrono::DateTime<Utc> = row.try_get("session_expires")?;
        let status: String = row.try_get("status")?;
        let tenant_status: String = row.try_get("tenant_status")?;
        if consumed.is_some() {
            let user_id: Uuid = row.try_get("user_id")?;
            sqlx::query(
                "UPDATE appsec.sessions SET revoked_at=clock_timestamp() WHERE session_id=$1",
            )
            .bind(session_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query("UPDATE appsec.refresh_tokens SET revoked_at=clock_timestamp() WHERE session_id=$1 AND revoked_at IS NULL")
                .bind(session_id).execute(&mut *tx).await?;
            sqlx::query("UPDATE appsec.pool_credentials SET revoked_at=clock_timestamp() WHERE session_id=$1 AND revoked_at IS NULL")
                .bind(session_id).execute(&mut *tx).await?;
            let role: String = row.try_get("db_role")?;
            alter_role_login(&mut tx, &role, false).await?;
            Self::write_audit(
                &mut tx,
                Some(user_id),
                "auth.refresh_reuse_detected",
                Some(session_id.to_string()),
                serde_json::json!({}),
            )
            .await?;
            tx.commit().await?;
            return Err(AuthError::InvalidRefresh);
        }
        if revoked.is_some()
            || session_revoked.is_some()
            || token_exp <= Utc::now()
            || session_exp <= Utc::now()
            || status != "active"
            || tenant_status != "active"
        {
            tx.rollback().await?;
            return Err(AuthError::InvalidRefresh);
        }
        let user = user_from_row(&row)?;
        let (database_password, verifier) = postgres_scram_credential()?;
        sqlx::query("SET LOCAL password_encryption='scram-sha-256'")
            .execute(&mut *tx)
            .await?;
        alter_role_password(&mut tx, &user.db_role, &verifier).await?;
        let next_exp = Utc::now() + Duration::days(self.config.refresh_ttl_days);
        alter_role_valid_until(&mut tx, &user.db_role, next_exp).await?;
        sqlx::query("SELECT appsec.harden_session_role($1::name, $2::timestamptz, 2)")
            .bind(&user.db_role)
            .bind(next_exp)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE appsec.pool_credentials SET scram_verifier=$2,rotated_at=clock_timestamp(),revoked_at=NULL WHERE session_id=$1")
            .bind(session_id).bind(&verifier).execute(&mut *tx).await?;
        let next_refresh = random_token();
        let next_hash = sha256(next_refresh.as_bytes());
        let next_id = Uuid::new_v4();
        sqlx::query("INSERT INTO appsec.refresh_tokens(token_id,session_id,token_hash,expires_at) VALUES($1,$2,$3,$4)")
            .bind(next_id).bind(session_id).bind(next_hash.to_vec()).bind(next_exp).execute(&mut *tx).await?;
        sqlx::query("UPDATE appsec.refresh_tokens SET consumed_at=clock_timestamp(),replaced_by=$2 WHERE token_id=$1")
            .bind(token_id).bind(next_id).execute(&mut *tx).await?;
        sqlx::query("UPDATE appsec.sessions SET last_seen_at=clock_timestamp(),expires_at=$2 WHERE session_id=$1")
            .bind(session_id).bind(next_exp).execute(&mut *tx).await?;
        let access_token = self.issue_access_token(&user, session_id)?;
        Self::write_audit(
            &mut tx,
            Some(user.user_id),
            "auth.refresh_succeeded",
            Some(session_id.to_string()),
            serde_json::json!({}),
        )
        .await?;
        tx.commit().await?;
        Ok(AuthTokens {
            session_id,
            access_token,
            refresh_token: next_refresh,
            access_expires_in: self.config.access_ttl_seconds,
            database_password: Some(database_password),
            user,
        })
    }

    async fn write_audit(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        actor_user_id: Option<Uuid>,
        event_type: &str,
        resource: Option<String>,
        detail: serde_json::Value,
    ) -> Result<(), AuthError> {
        let detail = serde_json::to_string(&detail).map_err(|_| AuthError::Token)?;
        sqlx::query("INSERT INTO appsec.audit_events(actor_role,actor_user_id,event_type,resource,detail) VALUES(current_user,$1,$2,$3,$4::jsonb)")
            .bind(actor_user_id).bind(event_type).bind(resource).bind(detail).execute(&mut **tx).await?;
        Ok(())
    }

    fn issue_access_token(&self, user: &AuthUser, session_id: Uuid) -> Result<String, AuthError> {
        let now = Utc::now().timestamp();
        let claims = AccessClaims {
            iss: self.config.issuer.clone(),
            aud: self.config.audience.clone(),
            sub: user.user_id.to_string(),
            preferred_username: user.db_role.clone(),
            token_use: "access".into(),
            scope: "pg_appsec".into(),
            iat: now,
            nbf: now,
            exp: now + self.config.access_ttl_seconds,
            jti: Uuid::new_v4().to_string(),
            sid: session_id.to_string(),
        };
        let key = EncodingKey::from_ed_pem(&self.config.ed25519_private_key_pem)
            .map_err(|_| AuthError::SigningKey)?;
        encode(&Header::new(JwtAlgorithm::EdDSA), &claims, &key).map_err(|_| AuthError::Token)
    }
}

fn user_from_row(row: &sqlx::postgres::PgRow) -> Result<AuthUser, AuthError> {
    Ok(AuthUser {
        user_id: row.try_get("user_id")?,
        db_role: row.try_get("db_role")?,
        email: row.try_get("email")?,
        tenant_id: row.try_get("tenant_id")?,
    })
}

fn role_for_session(id: Uuid) -> String {
    format!("app_s_{}", id.simple())
}

fn is_generated_role(role: &str) -> bool {
    role.strip_prefix("app_s_")
        .is_some_and(|suffix| suffix.len() == 32 && suffix.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn postgres_scram_credential() -> Result<(String, String), AuthError> {
    let password = random_token();
    let mut salt = [0u8; 16];
    RandomOsRng.fill_bytes(&mut salt);
    let iterations = 4096u32;
    let mut salted_password = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, iterations, &mut salted_password);
    let mut client_mac =
        HmacSha256::new_from_slice(&salted_password).map_err(|_| AuthError::Password)?;
    client_mac.update(b"Client Key");
    let client_key = client_mac.finalize().into_bytes();
    let stored_key = Sha256::digest(client_key);
    let mut server_mac =
        HmacSha256::new_from_slice(&salted_password).map_err(|_| AuthError::Password)?;
    server_mac.update(b"Server Key");
    let server_key = server_mac.finalize().into_bytes();
    let verifier = format!(
        "SCRAM-SHA-256${iterations}:{}${}:{}",
        STANDARD.encode(salt),
        STANDARD.encode(stored_key),
        STANDARD.encode(server_key)
    );
    Ok((password, verifier))
}

async fn alter_role_login(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    role: &str,
    enabled: bool,
) -> Result<(), AuthError> {
    if !is_generated_role(role) {
        return Err(AuthError::AccountUnavailable);
    }
    sqlx::query("SELECT appsec.set_session_role_login($1::name, $2)")
        .bind(role)
        .bind(enabled)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn alter_role_valid_until(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    role: &str,
    expires: chrono::DateTime<Utc>,
) -> Result<(), AuthError> {
    if !is_generated_role(role) {
        return Err(AuthError::AccountUnavailable);
    }
    sqlx::query("SELECT appsec.harden_session_role($1::name, $2::timestamptz, 2)")
        .bind(role)
        .bind(expires)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn alter_role_password(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    role: &str,
    verifier: &str,
) -> Result<(), AuthError> {
    if !is_generated_role(role) {
        return Err(AuthError::AccountUnavailable);
    }
    sqlx::query("SELECT appsec.set_session_role_password($1::name, $2)")
        .bind(role)
        .bind(verifier)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

fn validate_password(password: &str) -> Result<(), AuthError> {
    if !(PASSWORD_MIN_BYTES..=PASSWORD_MAX_BYTES).contains(&password.len()) {
        return Err(AuthError::InvalidPassword);
    }
    Ok(())
}

fn argon2id() -> Result<Argon2<'static>, AuthError> {
    let params = Params::new(65_536, 3, 1, None).map_err(|_| AuthError::Password)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn hash_password(password: &str) -> Result<String, AuthError> {
    validate_password(password)?;
    let salt = SaltString::generate(&mut OsRng);
    argon2id()?
        .hash_password(password.as_bytes(), &salt)
        .map(|v| v.to_string())
        .map_err(|_| AuthError::Password)
}

fn verify_password(password: &str, phc: &str) -> Result<bool, AuthError> {
    if password.len() > PASSWORD_MAX_BYTES {
        return Ok(false);
    }
    let parsed = match PasswordHash::new(phc) {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    Ok(argon2id()?
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

fn random_token() -> String {
    let mut bytes = [0u8; 48];
    RandomOsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_names_are_deterministic_and_safe() {
        let id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        assert_eq!(
            role_for_session(id),
            "app_s_00000000000000000000000000000001"
        );
    }

    #[test]
    fn dummy_hash_is_valid_argon2id() {
        assert!(verify_password("not-a-real-user-password-constant", DUMMY_PASSWORD_PHC).unwrap());
        assert!(!verify_password("wrong-password", DUMMY_PASSWORD_PHC).unwrap());
    }

    #[test]
    fn postgres_scram_verifier_has_expected_shape() {
        let (password, verifier) = postgres_scram_credential().unwrap();
        assert!(password.len() >= 60);
        assert!(verifier.starts_with("SCRAM-SHA-256$4096:"));
        assert_eq!(verifier.matches('$').count(), 2);
        assert_eq!(verifier.split(':').count(), 3);
    }

    #[test]
    fn refresh_hash_is_fixed_length() {
        assert_eq!(sha256(b"token").len(), 32);
    }

    #[test]
    fn random_refresh_tokens_are_unpadded_url_safe() {
        let token = random_token();
        assert!(!token.contains('='));
        assert_eq!(URL_SAFE_NO_PAD.decode(token).unwrap().len(), 48);
    }
}
