pub mod aes;
mod error;
mod responses;
pub mod rsa;

use aes::{AesDecrypted, AesKey, AES};
pub use error::CryptError;
pub use responses::CiphertextData;
use rsa::{PublicKey, Signature, RSA};
use serde::{Deserialize, Serialize};

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

    /// Decrypt `EncryptedData`.
    pub fn decrypt(&mut self, ciphertext: CiphertextData) -> Result<AesDecrypted, CryptError> {
        let (rsa_ciphertext, aes_ciphertext) = ciphertext.get_components();

        let aes_key = AesKey::from_vec(&self.rsa.decrypt(rsa_ciphertext)?)?;

        self.aes.set_key(aes_key);
        self.aes.decrypt(aes_ciphertext)
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
}

#[cfg(test)]
mod tests {
    use super::*;

    use aes::AES;
    use rsa::RSA;

    #[test]
    fn crypt_lib_encryption() {
        let mut crypt_lib = CryptLib::new(2048).unwrap();

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
    fn rsa() {
        let data = b"Unit test goes brrrrrrr";

        let rsa = RSA::new(2048).unwrap();
        let pub_key = rsa.get_public_keys().unwrap();

        // Encrypt
        let ciphertext = rsa.encrypt(&pub_key, data).unwrap();

        // Decrypt
        let out = rsa.decrypt(ciphertext).unwrap();

        assert_eq!(data.to_vec(), out);
    }

    #[test]
    fn signing() {
        let data = b"My precious data!";

        let rsa = RSA::new(2048).unwrap();
        let pub_key = rsa.get_public_keys().unwrap();

        // Sign
        let signature = rsa.sign(data).unwrap();

        // Verify
        let is_valid = rsa.verify(&pub_key, data, signature).unwrap();

        assert_eq!(true, is_valid);
    }

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
    fn rsa_serde() {
        let rsa = RSA::new(2048).unwrap();

        let json = serde_json::to_string(&rsa).unwrap();

        let _: RSA = serde_json::from_str(&json).unwrap();

        assert_eq!(true, true);
    }

    #[test]
    fn aes_serde() {
        let aes = AES::new().unwrap();

        let json = serde_json::to_string(&aes).unwrap();

        let _: AES = serde_json::from_str(&json).unwrap();

        assert_eq!(true, true);
    }

    #[test]
    fn rsa_public_key_serde() {
        let rsa_public_key = RSA::new(2048).unwrap().get_public_keys().unwrap();

        let json = serde_json::to_string(&rsa_public_key).unwrap();

        let _: PublicKey = serde_json::from_str(&json).unwrap();

        assert_eq!(true, true);
    }

    #[test]
    fn sign_public_key_serde() {
        let sign_public_key = RSA::new(2048).unwrap().get_public_keys().unwrap();

        let json = serde_json::to_string(&sign_public_key).unwrap();

        let _: PublicKey = serde_json::from_str(&json).unwrap();

        assert_eq!(true, true);
    }
}
