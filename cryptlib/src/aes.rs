use std::fmt::Debug;

use openssl::{
    self,
    rand::rand_bytes,
    symm::{decrypt_aead, encrypt_aead, Cipher},
};
use serde::{
    de::{self, Visitor},
    ser::SerializeStruct,
    Deserialize, Serialize,
};

use crate::CryptError;

mod aes_decrypt;
mod encrypted;
mod key;
pub use aes_decrypt::AesDecrypted;
pub use encrypted::AesCiphertext;
pub use key::{AesKey, EncryptedAesKey};

pub struct AES {
    key: AesKey,
    cipher: Cipher,
}
impl AES {
    /// Create new `AES` instance.
    pub fn new() -> Result<Self, CryptError> {
        // Generate `AES` key
        let key = AesKey::new()?;

        Ok(Self {
            key,
            cipher: Self::get_cipher(),
        })
    }

    /// Create `AES` instance from `AesKey`.
    pub fn from_key(key: AesKey) -> Self {
        Self {
            key,
            cipher: Self::get_cipher(),
        }
    }

    /// Create instance of `AES` from aes key bytes.
    pub fn from_key_bytes(bytes: [u8; 32]) -> Self {
        Self {
            key: AesKey::from_bytes(bytes),
            cipher: Self::get_cipher(),
        }
    }

    /// Get AES key
    pub fn get_key(&self) -> AesKey {
        self.key.clone()
    }

    /// Set AES key
    pub fn set_key(&mut self, key: AesKey) {
        self.key = key;
    }

    /// Encrypt data.
    /// `aad` is additional data that is not encrypted but is protected against tampering.
    /// `aad` has no size limit.
    pub fn encrypt(&self, data: &[u8], aad: Vec<u8>) -> Result<AesCiphertext, CryptError> {
        self.encrypt_from_key(data, aad, &self.get_key())
    }

    pub fn encrypt_from_key(
        &self,
        data: &[u8],
        aad: Vec<u8>,
        key: &AesKey,
    ) -> Result<AesCiphertext, CryptError> {
        let iv = Self::generate_iv_16bytes()?;
        let mut tag = [0; 16];

        // Encrypt
        let ciphertext = encrypt_aead(
            self.cipher,
            &key.get_bytes(),
            Some(&iv),
            &aad,
            data,
            &mut tag,
        )
        .map_err(|e| CryptError::AesError(e))?;

        Ok(AesCiphertext::new(ciphertext, iv, aad, tag))
    }

    /// Decript data.
    pub fn decrypt(&self, ciphertext: AesCiphertext) -> Result<AesDecrypted, CryptError> {
        self.decrypt_from_key(ciphertext, &self.get_key())
    }

    pub fn decrypt_from_key(
        &self,
        ciphertext: AesCiphertext,
        key: &AesKey,
    ) -> Result<AesDecrypted, CryptError> {
        let (ciphertext, iv, aad, tag) = ciphertext.get_components();

        // Decrypt
        let data = decrypt_aead(
            self.cipher,
            &key.get_bytes(),
            Some(&iv),
            &aad,
            &ciphertext,
            &tag,
        )
        .map_err(|e| CryptError::AesError(e))?;

        Ok(AesDecrypted::new(data, aad))
    }

    /// Generate a 16 byte random iv.
    fn generate_iv_16bytes() -> Result<[u8; 16], CryptError> {
        let mut key: [u8; 16] = [0; 16];
        rand_bytes(&mut key).map_err(|e| CryptError::RandError(e))?;

        Ok(key)
    }

    /// Return aes_256_gcm cipher.
    fn get_cipher() -> Cipher {
        Cipher::aes_256_gcm()
    }
}

impl Debug for AES {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AES").field("key", &self.key).finish()
    }
}

impl Serialize for AES {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("AES", 1)?;

        state.serialize_field("key", &self.key.get_bytes())?;

        state.end()
    }
}

impl<'de> Deserialize<'de> for AES {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct AESVisitor;

        impl<'de> Visitor<'de> for AESVisitor {
            type Value = AES;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("an aes key in byte form with a lenght of 32 bytes")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut raw_key: Option<Vec<u8>> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "key" => {
                            if raw_key.is_some() {
                                return Err(de::Error::duplicate_field("key"));
                            };

                            raw_key = Some(map.next_value()?)
                        }
                        _ => return Err(de::Error::unknown_field(&key, &["key"])),
                    }
                }

                let raw_key = raw_key.ok_or_else(|| {
                    de::Error::custom(format!("Could not unwrap aes key from Option!"))
                })?;

                if raw_key.len() != 32 {
                    return Err(de::Error::custom(format!(
                        "Expected key length is 32 bytes, the key given has {} bytes!",
                        raw_key.len()
                    )));
                }

                Ok(AES::from_key_bytes(raw_key.try_into().map_err(|_| {
                    de::Error::custom(format!("Could not convert bytes to AES key!"))
                })?))
            }
        }

        deserializer.deserialize_struct("AES", &["key"], AESVisitor)
    }
}

#[cfg(test)]
mod aes_tests {
    use crate::*;

    #[test]
    fn aes() {
        let data = b"AES is a symmetric encryption.";
        let aad = b"This will be visible but can not be changed or the decription will fail";

        let aes = AES::new().unwrap();

        // Encrypt
        let ciphertext = aes.encrypt(data, aad.to_vec()).unwrap();

        // Decrypt
        let out = aes.decrypt(ciphertext).unwrap();

        assert_eq!(data.to_vec(), out.data);

        assert_eq!(aad.to_vec(), out.aad);
    }

    #[test]
    fn aes_serde() {
        let aes = AES::new().unwrap();

        let json = serde_json::to_string(&aes).unwrap();

        let _: AES = serde_json::from_str(&json).unwrap();
    }
}
