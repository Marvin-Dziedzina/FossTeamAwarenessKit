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
    sign_key: PKey<Private>,
}
impl RSA {
    /// Create a new instance of RSA. Use 2048 bits for default.
    pub fn new(bits: u32) -> Result<Self, CryptError> {
        // Generate private and public RSA key
        let keys = match Rsa::generate(bits) {
            Ok(keys) => keys,
            Err(e) => return Err(CryptError::RsaError(e)),
        };

        // Generate signing keys
        let rsa_key = match Rsa::generate(bits) {
            Ok(rsa_key) => rsa_key,
            Err(e) => return Err(CryptError::RsaError(e)),
        };
        let sign_key = match PKey::from_rsa(rsa_key) {
            Ok(sign_key) => sign_key,
            Err(e) => return Err(CryptError::RsaError(e)),
        };

        Ok(Self { keys, sign_key })
    }

    pub fn get_public_rsa_key(&self) -> Result<PublicKey<Rsa<Public>>, CryptError> {
        let der = match self.keys.public_key_to_der() {
            Ok(der) => der,
            Err(e) => return Err(CryptError::RsaError(e)),
        };

        Ok(PublicKey::new_rsa(&der, KeyFormat::DER)?)
    }

    pub fn get_public_sign_key(&self) -> Result<PublicKey<PKey<Public>>, CryptError> {
        let der = match self.sign_key.public_key_to_der() {
            Ok(der) => der,
            Err(e) => return Err(CryptError::SignError(e)),
        };

        Ok(PublicKey::new_pkey(&der, KeyFormat::DER)?)
    }

    /// Encrypt data
    pub fn encrypt(
        &self,
        receiver_public_key: &PublicKey<Rsa<Public>>,
        data: &[u8],
    ) -> Result<RsaCiphertext, CryptError> {
        let mut ciphertext = vec![0; self.keys.size() as usize];
        match receiver_public_key.get_key().public_encrypt(
            data,
            &mut ciphertext,
            Padding::PKCS1_OAEP,
        ) {
            Ok(_) => Ok(RsaCiphertext::new(ciphertext)),
            Err(e) => Err(CryptError::RsaError(e)),
        }
    }

    /// Decrypt data
    pub fn decrypt(&self, rsa_ciphertext: RsaCiphertext) -> Result<Vec<u8>, CryptError> {
        let ciphertext = rsa_ciphertext.get_components();

        let mut data = vec![0; self.keys.size() as usize];
        let count = match &self
            .keys
            .private_decrypt(&ciphertext, &mut data, Padding::PKCS1_OAEP)
        {
            Ok(count) => *count,
            Err(e) => return Err(CryptError::RsaError(e.to_owned())),
        };

        let mut out = Vec::new();
        out.extend(&data[0..count]);
        Ok(out)
    }

    /// Sign data
    pub fn sign(&self, data: &[u8]) -> Result<Signature, CryptError> {
        let mut signer = match Signer::new(MessageDigest::sha512(), &self.sign_key) {
            Ok(signer) => signer,
            Err(e) => return Err(CryptError::SignError(e)),
        };

        // Add data to be signed
        match signer.update(data) {
            Ok(_) => (),
            Err(e) => return Err(CryptError::SignError(e)),
        };

        let signature = match signer.sign_to_vec() {
            Ok(signature) => signature,
            Err(e) => return Err(CryptError::SignError(e)),
        };

        Ok(Signature::new(signature))
    }

    /// Verify data
    pub fn verify(
        &self,
        public_key: PublicKey<PKey<Public>>,
        data: &[u8],
        signature: Signature,
    ) -> Result<bool, CryptError> {
        let mut verifier = match Verifier::new(MessageDigest::sha512(), public_key.get_key()) {
            Ok(verifier) => verifier,
            Err(e) => return Err(CryptError::SignError(e)),
        };

        // Add data to be verified
        match verifier.update(data) {
            Ok(_) => (),
            Err(e) => return Err(CryptError::SignError(e)),
        };

        // Verify data with signature
        match verifier.verify(&signature.get_signature()) {
            Ok(is_valid) => Ok(is_valid),
            Err(e) => Err(CryptError::SignError(e)),
        }
    }
}
