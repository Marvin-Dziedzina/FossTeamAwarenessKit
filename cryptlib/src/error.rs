use std::{error::Error, fmt::Display};

use openssl::error::ErrorStack;

#[derive(Debug)]
pub enum CryptError {
    RsaError(ErrorStack),
    AesError(ErrorStack),
    SignError(ErrorStack),
    PublicKey(ErrorStack),
    RandError(ErrorStack),
    AesKeyError(String),
}

impl Display for CryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptError::RsaError(e) => write!(f, "RSA Error: {}", e),
            CryptError::AesError(e) => write!(f, "AES Error: {}", e),
            CryptError::SignError(e) => write!(f, "Sign Error: {}", e),
            CryptError::PublicKey(e) => write!(f, "Public Key Error: {}", e),
            CryptError::RandError(e) => write!(f, "Rand Error: {}", e),
            CryptError::AesKeyError(e) => write!(f, "AES Kez Lenght Error: {}", e),
        }
    }
}

impl Error for CryptError {}
