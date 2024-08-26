use openssl::rand::rand_bytes;
use serde::{Deserialize, Serialize};

use crate::CryptError;

/// Stores the AES key
#[derive(Debug, Serialize, Deserialize)]
pub struct AesKey {
    key: [u8; 32],
}
impl AesKey {
    pub fn new() -> Result<Self, CryptError> {
        Ok(Self {
            key: Self::generate_key_32bytes()?,
        })
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { key: bytes }
    }

    pub fn get_key(&self) -> [u8; 32] {
        self.key
    }

    /// Generate a 32 byte random key.
    fn generate_key_32bytes() -> Result<[u8; 32], CryptError> {
        let mut key = [0; 32];
        rand_bytes(&mut key).map_err(|e| CryptError::RandError(e))?;

        Ok(key)
    }
}
