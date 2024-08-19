use openssl::{
    self,
    rand::rand_bytes,
    symm::{decrypt_aead, encrypt_aead, Cipher},
};

use crate::CryptError;

mod encrypted;

pub use encrypted::AesCiphertext;

pub struct AES {
    key: [u8; 32],
    cipher: Cipher,
}
impl AES {
    pub fn new() -> Self {
        // Generate AES key
        let key = Self::generate_key_32bytes();
        let cipher = Cipher::aes_256_gcm();

        Self { key, cipher }
    }

    /// Encrypt data
    /// aad is additional data that is not encrypted but is protected against tampering.
    pub fn encrypt(&self, data: &[u8], aad: Vec<u8>) -> Result<AesCiphertext, CryptError> {
        let iv = Self::generate_iv_16bytes();
        let mut tag = [0; 16];
        let ciphertext = match encrypt_aead(self.cipher, &self.key, Some(&iv), &aad, data, &mut tag)
        {
            Ok(ciphertext) => ciphertext,
            Err(e) => return Err(CryptError::AesError(e)),
        };

        Ok(AesCiphertext::new(ciphertext, iv, aad, tag))
    }

    pub fn decrypt(&self, ciphertext: AesCiphertext) -> Result<Vec<u8>, CryptError> {
        let (ciphertext, iv, aad, tag) = ciphertext.get_components();
        match decrypt_aead(self.cipher, &self.key, Some(&iv), &aad, &ciphertext, &tag) {
            Ok(data) => Ok(data),
            Err(e) => Err(CryptError::AesError(e)),
        }
    }

    fn generate_key_32bytes() -> [u8; 32] {
        let mut key = [0; 32];
        rand_bytes(&mut key);

        key
    }

    fn generate_iv_16bytes() -> [u8; 16] {
        let mut key: [u8; 16] = [0; 16];
        rand_bytes(&mut key);

        key
    }
}
