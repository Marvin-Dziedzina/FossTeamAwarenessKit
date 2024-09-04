use serde::{Deserialize, Serialize};

use crate::{aes::AesCiphertext, rsa::RsaCiphertext};

/// `rsa_ciphertext` holds the encrypted aes key. `aes_ciphertext` holds the aes encrypted data.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CiphertextData {
    rsa_ciphertext: RsaCiphertext,
    aes_ciphertext: AesCiphertext,
}
impl CiphertextData {
    pub fn new(rsa_ciphertext: RsaCiphertext, aes_ciphertext: AesCiphertext) -> Self {
        Self {
            rsa_ciphertext,
            aes_ciphertext,
        }
    }

    pub fn get_components(self) -> (RsaCiphertext, AesCiphertext) {
        (self.rsa_ciphertext, self.aes_ciphertext)
    }
}
