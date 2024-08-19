mod aes;
mod rsa;

use crate::CryptError;
pub use aes::AES;
pub use rsa::{PublicKey, RSA};

pub struct Cryptography {
    rsa: RSA,
    aes: AES,
}
impl Cryptography {
    /// Create new Cryptogrphy instance.
    pub fn new() -> Result<Self, CryptError> {
        Ok(Self {
            rsa: RSA::new(2048)?,
            aes: AES::new(),
        })
    }

    pub fn from_bytes(bits: u32) -> Result<Self, CryptError> {
        Ok(Self {
            rsa: RSA::new(bits)?,
            aes: AES::new(),
        })
    }
}
