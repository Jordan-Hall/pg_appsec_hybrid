//! Live PG18 test of the auth service's role lifecycle through the
//! appsec_role_admin-owned helpers (create_session_role,
//! set_session_role_password, set_session_role_login, harden_session_role).
//!
//! Skips unless APPSEC_LIVE_SERVICE_URL / APPSEC_LIVE_ADMIN_URL /
//! APPSEC_LIVE_DB_HOST / APPSEC_LIVE_DB_PORT / APPSEC_LIVE_DB_NAME and the
//! Ed25519 PEM paths are set (CI sets them).
use pg_appsec_auth::{AuthConfig, AuthService};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Connection, PgConnection, Row};
use uuid::Uuid;

struct Env {
    service_url: String,
    admin_url: String,
    host: String,
    port: u16,
    db: String,
    priv_pem: Vec<u8>,
    pub_pem: Vec<u8>,
}

fn env() -> Option<Env> {
    let g = |k: &str| std::env::var(k).ok();
    Some(Env {
        service_url: g("APPSEC_LIVE_SERVICE_URL")?,
        admin_url: g("APPSEC_LIVE_ADMIN_URL")?,
        host: g("APPSEC_LIVE_DB_HOST")?,
        port: g("APPSEC_LIVE_DB_PORT")?.parse().ok()?,
        db: g("APPSEC_LIVE_DB_NAME")?,
        priv_pem: std::fs::read(g("APPSEC_LIVE_ED25519_PRIVATE_PEM")?).ok()?,
        pub_pem: std::fs::read(g("APPSEC_LIVE_ED25519_PUBLIC_PEM")?).ok()?,
    })
}

async fn connect_as(e: &Env, role: &str, password: &str) -> Result<PgConnection, sqlx::Error> {
    let opts = PgConnectOptions::new()
        .host(&e.host)
        .port(e.port)
        .database(&e.db)
        .username(role)
        .password(password);
    PgConnection::connect_with(&opts).await
}

/// Login must be refused, and the server's stated reason must match.
async fn expect_login_denied(e: &Env, role: &str, password: &str, reason: &str, case: &str) {
    match connect_as(e, role, password).await {
        Ok(_) => panic!("{case}: login unexpectedly succeeded for {role}"),
        Err(err) => {
            let msg = err.to_string();
            assert!(
                msg.contains(reason),
                "{case}: denied for the wrong reason: {msg} (want '{reason}')"
            );
            println!("PASS {case} (denied: {msg})");
        }
    }
}

async fn expect_sql_denied(conn: &mut PgConnection, sql: &str, case: &str) {
    match sqlx::query(sql).execute(&mut *conn).await {
        Ok(_) => panic!("{case}: statement unexpectedly allowed: {sql}"),
        Err(sqlx::Error::Database(d)) => {
            assert_eq!(
                d.code().as_deref(),
                Some("42501"),
                "{case}: wrong SQLSTATE for {sql}: {}",
                d.message()
            );
            assert!(
                d.message().contains("permission denied"),
                "{case}: wrong reason: {}",
                d.message()
            );
            println!("PASS {case} (denied: {})", d.message());
        }
        Err(other) => panic!("{case}: unexpected error {other}"),
    }
}

#[tokio::test]
async fn live_session_role_lifecycle() {
    let Some(e) = env() else {
        eprintln!("SKIP live_pg: APPSEC_LIVE_* not set");
        return;
    };
    let admin = PgPoolOptions::new()
        .max_connections(2)
        .connect(&e.admin_url)
        .await
        .unwrap();
    let tenant = Uuid::new_v4();
    let other_tenant = Uuid::new_v4();
    for (t, slug) in [(tenant, "live-a"), (other_tenant, "live-b")] {
        sqlx::query("INSERT INTO appsec.tenants(tenant_id,slug,display_name,status) VALUES($1,$2,$2,'active')")
            .bind(t)
            .bind(format!("{slug}-{}", &t.to_string()[..8]))
            .execute(&admin)
            .await
            .unwrap();
    }
    // The service pool is a non-superuser member of appsec_provisioner only.
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&e.service_url)
        .await
        .unwrap();
    let svc = AuthService::new(
        pool,
        AuthConfig::production(
            "https://pg-appsec.test",
            "pg_appsec",
            e.priv_pem.clone(),
            e.pub_pem.clone(),
        ),
    );

    // sign up + verify + sign in => create_session_role (+ harden)
    let email = format!("live-{}@example.test", Uuid::new_v4());
    let password = "correct horse battery staple";
    let (user_id, verification) = svc.sign_up(&email, password, tenant, None).await.unwrap();
    svc.verify_email(&verification).await.unwrap();
    let t1 = svc
        .sign_in(
            &email,
            password,
            tenant,
            Some("127.0.0.1"),
            Some("live-test"),
        )
        .await
        .unwrap();
    let role = t1.user.db_role.clone();
    let pw1 = t1.database_password.clone().expect("database password");
    assert!(role.starts_with("app_s_"));

    // Role attributes / ownership as created by appsec_role_admin.
    let r = sqlx::query(
        "SELECT r.rolcanlogin, r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolbypassrls, r.rolreplication,
                r.rolconnlimit, r.rolvaliduntil IS NOT NULL AS has_until,
                EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.roleid = r.oid
                        AND m.member = 'appsec_role_admin'::regrole AND m.admin_option
                        AND NOT m.inherit_option AND NOT m.set_option) AS admin_only,
                pg_has_role(r.rolname, 'appsec_app_base', 'MEMBER') AS base
         FROM pg_roles r WHERE r.rolname = $1",
    )
    .bind(&role)
    .fetch_one(&admin)
    .await
    .unwrap();
    assert!(r.get::<bool, _>("rolcanlogin"));
    for k in [
        "rolsuper",
        "rolcreaterole",
        "rolcreatedb",
        "rolbypassrls",
        "rolreplication",
    ] {
        assert!(!r.get::<bool, _>(k), "session role has {k}");
    }
    assert_eq!(r.get::<i32, _>("rolconnlimit"), 2);
    assert!(r.get::<bool, _>("has_until"));
    assert!(
        r.get::<bool, _>("admin_only"),
        "appsec_role_admin must hold ADMIN only"
    );
    assert!(r.get::<bool, _>("base"));
    println!("PASS minted_role_attributes ({role})");

    // Log in as the session role and check scoping.
    let mut c = connect_as(&e, &role, &pw1).await.expect("session login");
    let (uid, who): (Option<Uuid>, String) =
        sqlx::query_as("SELECT appsec.uid(), session_user::text")
            .fetch_one(&mut c)
            .await
            .unwrap();
    assert_eq!(uid, Some(user_id));
    assert_eq!(who, role);
    println!("PASS session_login_uid_scoped");
    expect_sql_denied(
        &mut c,
        "SELECT * FROM appsec.credentials",
        "session_no_credentials",
    )
    .await;
    expect_sql_denied(
        &mut c,
        "SELECT * FROM appsec.sessions",
        "session_no_sessions_table",
    )
    .await;
    expect_sql_denied(
        &mut c,
        "SET ROLE appsec_provisioner",
        "session_no_set_role_provisioner",
    )
    .await;
    expect_sql_denied(
        &mut c,
        "CREATE TEMP TABLE live_tmp(x int)",
        "session_no_temp",
    )
    .await;
    expect_sql_denied(
        &mut c,
        "SELECT appsec.create_session_role('app_s_ffffffffffffffffffffffffffffffff', NULL, now() + interval '1 hour', 2)",
        "session_cannot_mint_roles",
    )
    .await;
    c.close().await.ok();

    // refresh => set_session_role_password (+ harden): old password dead, new works.
    let t2 = svc.refresh(&t1.refresh_token).await.unwrap();
    let pw2 = t2.database_password.clone().expect("rotated password");
    assert_ne!(pw1, pw2);
    expect_login_denied(
        &e,
        &role,
        &pw1,
        "password authentication failed",
        "old_password_after_rotation",
    )
    .await;
    connect_as(&e, &role, &pw2)
        .await
        .expect("rotated password login")
        .close()
        .await
        .ok();
    println!("PASS rotated_password_login");

    // sign out => set_session_role_login(false)
    assert!(svc.sign_out_access_token(&t2.access_token).await.unwrap());
    let canlogin: bool = sqlx::query_scalar("SELECT rolcanlogin FROM pg_roles WHERE rolname=$1")
        .bind(&role)
        .fetch_one(&admin)
        .await
        .unwrap();
    assert!(!canlogin);
    expect_login_denied(
        &e,
        &role,
        &pw2,
        "is not permitted to log in",
        "revoked_session_login",
    )
    .await;

    // Expired session: keep a live connection, expire it, check uid() goes NULL,
    // then the reaper disables login.
    let t3 = svc
        .sign_in(&email, password, tenant, None, None)
        .await
        .unwrap();
    let role3 = t3.user.db_role.clone();
    let pw3 = t3.database_password.clone().unwrap();
    let mut c3 = connect_as(&e, &role3, &pw3)
        .await
        .expect("second session login");
    sqlx::query("UPDATE appsec.sessions SET expires_at = clock_timestamp() - interval '1 second' WHERE session_id = $1")
        .bind(t3.session_id)
        .execute(&admin)
        .await
        .unwrap();
    let uid3: Option<Uuid> = sqlx::query_scalar("SELECT appsec.uid()")
        .fetch_one(&mut c3)
        .await
        .unwrap();
    assert_eq!(uid3, None, "expired session must resolve to no user");
    println!("PASS expired_session_uid_null");
    c3.close().await.ok();
    assert!(svc.reap_expired_sessions().await.unwrap() >= 1);
    expect_login_denied(
        &e,
        &role3,
        &pw3,
        "is not permitted to log in",
        "expired_session_login",
    )
    .await;

    // Role whose VALID UNTIL has passed cannot log in even if LOGIN is set.
    let t4 = svc
        .sign_in(&email, password, tenant, None, None)
        .await
        .unwrap();
    let role4 = t4.user.db_role.clone();
    let pw4 = t4.database_password.clone().unwrap();
    sqlx::query(&format!("ALTER ROLE {role4} VALID UNTIL '2000-01-01'"))
        .execute(&admin)
        .await
        .unwrap();
    expect_login_denied(
        &e,
        &role4,
        &pw4,
        "password authentication failed",
        "valid_until_passed_login",
    )
    .await;
    println!("live_pg_ok");
}
