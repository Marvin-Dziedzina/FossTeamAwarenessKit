pub mod aes;
mod error;
mod responses;
pub mod rsa;

use aes::{AesDecrypted, AesKey, AES};
pub use error::CryptError;
use openssl::sha::Sha256;
pub use responses::CiphertextData;
use rsa::{PublicKey, Signature, RSA};
use serde::{Deserialize, Serialize};

pub type Sha256Hash = [u8; 32];

#[derive(Debug, Serialize, Deserialize)]
pub struct CryptLib {
    rsa: RSA,
    aes: AES,
}
impl CryptLib {
    pub fn new(bits: u32) -> Result<Self, CryptError> {
        Ok(Self {
            rsa: RSA::new(bits)?,
            aes: AES::new()?,
        })
    }

    /// Create instance from aes key
    pub fn from_aes_key(bits: u32, aes_key: AesKey) -> Result<Self, CryptError> {
        Ok(Self {
            rsa: RSA::new(bits)?,
            aes: AES::from_key(aes_key),
        })
    }

    pub fn get_public_keys(&self) -> Result<PublicKey, CryptError> {
        self.rsa.get_public_keys()
    }

    /// Encrypt `data`. `aad` are additional bytes that are **NOT** encrypted but cant be altered.
    pub fn encrypt(
        &self,
        receiver_public_key: &PublicKey,
        data: &[u8],
        aad: Vec<u8>,
    ) -> Result<CiphertextData, CryptError> {
        let aes_ciphertext = self.aes.encrypt(data, aad)?;
        let aes_key = self
            .rsa
            .encrypt(receiver_public_key, &self.aes.get_key().get_bytes())?;

        Ok(CiphertextData::new(aes_key, aes_ciphertext))
    }

    /// Decrypt `CiphertextData`.
    pub fn decrypt(&self, ciphertext: CiphertextData) -> Result<AesDecrypted, CryptError> {
        let (rsa_ciphertext, aes_ciphertext) = ciphertext.get_components();

        let aes_key = AesKey::from_vec(&self.rsa.decrypt(rsa_ciphertext)?)?;

        self.aes.decrypt_from_key(aes_ciphertext, &aes_key)
    }

    /// Sign data
    pub fn sign(&self, data: &[u8]) -> Result<Signature, CryptError> {
        self.rsa.sign(data)
    }

    /// Verify data
    pub fn verify(
        &self,
        public_key: &PublicKey,
        data: &[u8],
        signature: Signature,
    ) -> Result<bool, CryptError> {
        self.rsa.verify(public_key, data, signature)
    }

    pub fn sha256(buf: &[u8]) -> Sha256Hash {
        let mut hasher = Sha256::new();

        hasher.update(buf);

        hasher.finish()
    }
}

#[cfg(test)]
mod crypt_lib_tests {
    use super::*;

    #[test]
    fn crypt_lib_encryption() {
        let crypt_lib = CryptLib::new(2048).unwrap();

        let data = "Encrypted data!".as_bytes();
        let aad = "AAD data".as_bytes().to_vec();

        let ciphertext = crypt_lib
            .encrypt(&crypt_lib.get_public_keys().unwrap(), data, aad.clone())
            .unwrap();

        let decrypted = crypt_lib.decrypt(ciphertext).unwrap();

        let (data_dec, aad_dec) = decrypted.get_components();

        assert_eq!(data, data_dec);
        assert_eq!(aad, aad_dec);
    }

    #[test]
    fn crypt_lib_signing() {
        let crypt_lib = CryptLib::new(2048).unwrap();

        let data = "Test".as_bytes();

        let signature = crypt_lib.sign(data).unwrap();

        let result = crypt_lib
            .verify(&crypt_lib.get_public_keys().unwrap(), data, signature)
            .unwrap();

        assert_eq!(true, result);
    }

    #[test]
    fn crypt_lib_serde() {
        let crypt_lib = CryptLib::new(2048).unwrap();

        let json = serde_json::to_string(&crypt_lib).unwrap();

        let _: CryptLib = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn sha256_test() {
        let buf = b"Sha256 Test";

        let hash = CryptLib::sha256(buf);

        assert_eq!(
            hash,
            [
                // This array represents the sha256 hash of "Sha256 Test"
                166, 60, 82, 147, 46, 231, 78, 240, 20, 236, 61, 240, 28, 106, 175, 103, 46, 102,
                174, 38, 19, 220, 90, 2, 210, 253, 126, 140, 69, 27, 30, 112
            ]
        );
    }
}
