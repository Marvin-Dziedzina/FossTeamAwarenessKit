use openssl::{
    self,
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
    rsa::{Padding, Rsa},
    sign::{Signer, Verifier},
};

mod encrypted;
mod public_key;
mod signature;

use crate::CryptError;
pub use encrypted::RsaCiphertext;
pub use public_key::{KeyFormat, PublicKey};
pub use signature::Signature;

pub struct RSA {
    keys: Rsa<Private>,
    sign_keys: PKey<Private>,
}
impl RSA {
    /// Create a new instance of `RSA`. Use 2048 bits for default.
    pub fn new(bits: u32) -> Result<Self, CryptError> {
        // Generate private and public RSA key
        let keys = Rsa::generate(bits).map_err(|e| CryptError::RsaError(e))?;

        // Generate signing keys
        let rsa_keys = Rsa::generate(bits).map_err(|e| CryptError::RsaError(e))?;
        let sign_keys = PKey::from_rsa(rsa_keys).map_err(|e| CryptError::RsaError(e))?;

        Ok(Self { keys, sign_keys })
    }

    pub fn get_public_rsa_key(&self) -> Result<PublicKey<Rsa<Public>>, CryptError> {
        // Get public rsa key from keys
        let der = self
            .keys
            .public_key_to_der()
            .map_err(|e| CryptError::RsaError(e))?;

        // Create `PublicKey` instance
        Ok(PublicKey::new_rsa(&der, KeyFormat::DER)?)
    }

    pub fn get_public_sign_key(&self) -> Result<PublicKey<PKey<Public>>, CryptError> {
        // Get public sign key from sign_keys
        let der = self
            .sign_keys
            .public_key_to_der()
            .map_err(|e| CryptError::SignError(e))?;

        // Create `PublicKey` instance
        Ok(PublicKey::new_pkey(&der, KeyFormat::DER)?)
    }

    /// Encrypt data
    pub fn encrypt(
        &self,
        receiver_public_key: &PublicKey<Rsa<Public>>,
        data: &[u8],
    ) -> Result<RsaCiphertext, CryptError> {
        // Ciphertext buffer
        let mut ciphertext = vec![0; self.keys.size() as usize];

        // Encrypt
        receiver_public_key
            .get_key()
            .public_encrypt(data, &mut ciphertext, Padding::PKCS1_OAEP)
            .map_err(|e| CryptError::RsaError(e))?;

        // Create `RsaCiphertext` instance
        Ok(RsaCiphertext::new(ciphertext))
    }

    /// Decrypt data
    pub fn decrypt(&self, rsa_ciphertext: RsaCiphertext) -> Result<Vec<u8>, CryptError> {
        let ciphertext = rsa_ciphertext.get_components();

        // Data buffer
        let mut data = vec![0; self.keys.size() as usize];

        // Decrypt ciphertext
        let count = &self
            .keys
            .private_decrypt(&ciphertext, &mut data, Padding::PKCS1_OAEP)
            .map_err(|e| CryptError::RsaError(e))?;

        // Slice decripted data to count of bytes decrypted
        Ok(data[0..count.to_owned()].to_vec())
    }

    /// Sign data
    pub fn sign(&self, data: &[u8]) -> Result<Signature, CryptError> {
        // Create `signer`
        let mut signer = Signer::new(MessageDigest::sha512(), &self.sign_keys)
            .map_err(|e| CryptError::SignError(e))?;

        // Add data to be signed
        signer.update(data).map_err(|e| CryptError::SignError(e))?;

        // Sign
        let signature = signer.sign_to_vec().map_err(|e| CryptError::SignError(e))?;

        Ok(Signature::new(signature))
    }

    /// Verify data
    pub fn verify(
        &self,
        public_key: PublicKey<PKey<Public>>,
        data: &[u8],
        signature: Signature,
    ) -> Result<bool, CryptError> {
        // Create `verifier`
        let mut verifier = Verifier::new(MessageDigest::sha512(), public_key.get_key())
            .map_err(|e| CryptError::SignError(e))?;

        // Add data to be verified
        verifier
            .update(data)
            .map_err(|e| CryptError::SignError(e))?;

        // Verify data with signature
        Ok(verifier
            .verify(&signature.get_signature())
            .map_err(|e| CryptError::SignError(e))?)
    }
}
