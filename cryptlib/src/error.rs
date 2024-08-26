use std::fmt::Display;

use openssl::error::ErrorStack;

#[derive(Debug)]
pub enum CryptError {
    RsaError(ErrorStack),
    AesError(ErrorStack),
    SignError(ErrorStack),
    PublicKey(ErrorStack),
    RandError(ErrorStack),
}

impl Display for CryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptError::RsaError(e) => write!(f, "Rsa Error: {}", e),
            CryptError::AesError(e) => write!(f, "Aes Error: {}", e),
            CryptError::SignError(e) => write!(f, "Sign Error: {}", e),
            CryptError::PublicKey(e) => write!(f, "Public Key Error: {}", e),
            CryptError::RandError(e) => write!(f, "Rand Error: {}", e),
        }
    }
}
