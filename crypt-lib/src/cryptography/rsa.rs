use openssl::{
    self,
    pkey::Private,
    rsa::{Padding, Rsa},
};

mod encrypted;
mod public_key;

use crate::CryptError;
pub use encrypted::RsaCiphertext;
pub use public_key::PublicKey;

pub struct RSA {
    keys: Rsa<Private>,
    signing_key: u8,
    verifying_key: u8,
}
impl RSA {
    /// Create a new instance of RSA. Use 2048 bits for default.
    pub fn new(bits: u32) -> Result<Self, CryptError> {
        // Generate private and public RSA key with default of 2048 bits
        let keys = Rsa::generate(bits).unwrap();

        // Signing
        let signing_key = 0;
        let verifying_key = 0;

        Ok(Self {
            keys,
            signing_key,
            verifying_key,
        })
    }

    pub fn get_public_key(&self) -> Result<Vec<u8>, CryptError> {
        match self.keys.public_key_to_pem() {
            Ok(public_key_pem) => Ok(public_key_pem),
            Err(e) => Err(CryptError::RsaError(e)),
        }
    }

    pub fn encrypt(
        &self,
        receiver_public_key: &PublicKey,
        data: &[u8],
    ) -> Result<RsaCiphertext, CryptError> {
        let mut ciphertext = vec![0; self.keys.size() as usize];
        match receiver_public_key.get_keys().public_encrypt(
            data,
            &mut ciphertext,
            Padding::PKCS1_OAEP,
        ) {
            Ok(_) => Ok(RsaCiphertext::new(ciphertext)),
            Err(e) => Err(CryptError::RsaError(e)),
        }
    }

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

    // TODO: Implement signing
    // pub fn sign(&mut self, data: &[u8]) {
    //     self.signing_key.
    // }
}
