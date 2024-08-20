use openssl::{
    self,
    rand::rand_bytes,
    symm::{decrypt_aead, encrypt_aead, Cipher},
};

use crate::CryptError;

mod aes_decrypt;
mod encrypted;

pub use aes_decrypt::AesDecrypted;
pub use encrypted::AesCiphertext;

pub struct AES {
    key: [u8; 32],
    cipher: Cipher,
}
impl AES {
    /// Create new `AES` instance.
    pub fn new() -> Result<Self, CryptError> {
        // Generate `AES` key
        let key = Self::generate_key_32bytes()?;

        let cipher = Cipher::aes_256_gcm();

        Ok(Self { key, cipher })
    }

    /// Encrypt data.
    /// `aad` is additional data that is not encrypted but is protected against tampering.
    /// `aad` has no size limit.
    pub fn encrypt(&self, data: &[u8], aad: Vec<u8>) -> Result<AesCiphertext, CryptError> {
        let iv = Self::generate_iv_16bytes()?;
        let mut tag = [0; 16];

        // Encrypt
        let ciphertext = encrypt_aead(self.cipher, &self.key, Some(&iv), &aad, data, &mut tag)
            .map_err(|e| CryptError::AesError(e))?;

        Ok(AesCiphertext::new(ciphertext, iv, aad, tag))
    }

    /// Decript data.
    pub fn decrypt(&self, ciphertext: AesCiphertext) -> Result<AesDecrypted, CryptError> {
        let (ciphertext, iv, aad, tag) = ciphertext.get_components();

        // Decrypt
        let data = decrypt_aead(self.cipher, &self.key, Some(&iv), &aad, &ciphertext, &tag)
            .map_err(|e| CryptError::AesError(e))?;

        Ok(AesDecrypted::new(data, aad))
    }

    /// Generate a 32 byte random key.
    fn generate_key_32bytes() -> Result<[u8; 32], CryptError> {
        let mut key = [0; 32];
        rand_bytes(&mut key).map_err(|e| CryptError::Rand(e))?;

        Ok(key)
    }

    /// Generate a 16 byte random iv.
    fn generate_iv_16bytes() -> Result<[u8; 16], CryptError> {
        let mut key: [u8; 16] = [0; 16];
        rand_bytes(&mut key).map_err(|e| CryptError::Rand(e))?;

        Ok(key)
    }
}