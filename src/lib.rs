use pgrx::prelude::*;

pgrx::pg_module_magic!();

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use thiserror::Error;
use zeroize::Zeroize;

const MEMORY_KIB: u32 = 65_536;
const ITERATIONS: u32 = 3;
const LANES: u32 = 1;

#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("password must contain between 12 and 1024 UTF-8 bytes")]
    InvalidLength,
    #[error("password hash is malformed")]
    InvalidHash,
    #[error("password hashing failed")]
    Hashing,
}

fn argon2id() -> Result<Argon2<'static>, PasswordError> {
    let params =
        Params::new(MEMORY_KIB, ITERATIONS, LANES, None).map_err(|_| PasswordError::Hashing)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

pub fn hash_password(password: &str) -> Result<String, PasswordError> {
    if !(12..=1024).contains(&password.as_bytes().len()) {
        return Err(PasswordError::InvalidLength);
    }
    let salt = SaltString::generate(&mut OsRng);
    argon2id()?
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| PasswordError::Hashing)
}

pub fn verify_password(password: &str, encoded_hash: &str) -> Result<bool, PasswordError> {
    if password.len() > 1024 {
        return Ok(false);
    }
    let parsed = PasswordHash::new(encoded_hash).map_err(|_| PasswordError::InvalidHash)?;
    Ok(argon2id()?
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

#[pg_extern(name = "hash_password")]
fn pg_hash_password(password: String) -> String {
    hash_password(&password).unwrap_or_else(|_| pgrx::error!("password hashing failed"))
}

#[pg_extern(name = "verify_password")]
fn pg_verify_password(password: String, encoded_hash: String) -> bool {
    verify_password(&password, &encoded_hash)
        .unwrap_or_else(|_| pgrx::error!("password verification failed"))
}

#[pg_extern(name = "version")]
fn pg_appsec_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

pgrx::extension_sql_file!("../sql/install.sql", name = "install", finalize);

pub struct SecretString(String);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2id_round_trip() {
        let password = "correct horse battery staple";
        let hash = hash_password(password).expect("hash");
        assert!(verify_password(password, &hash).expect("verify"));
        assert!(!verify_password("incorrect password", &hash).expect("verify"));
    }

    #[test]
    fn rejects_short_passwords() {
        assert!(matches!(
            hash_password("short"),
            Err(PasswordError::InvalidLength)
        ));
    }
}
