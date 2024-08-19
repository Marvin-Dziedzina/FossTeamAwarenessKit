use openssl::{pkey::Public, rsa::Rsa};

use crate::CryptError;

pub struct PublicKey {
    public_key: Rsa<Public>,
}
impl PublicKey {
    pub fn from_pem(pem: &[u8]) -> Result<Self, CryptError> {
        let public_key = match Rsa::public_key_from_pem(pem) {
            Ok(public_key) => public_key,
            Err(e) => return Err(CryptError::RsaError(e)),
        };

        Ok(Self { public_key })
    }

    pub fn get_keys(&self) -> &Rsa<Public> {
        &self.public_key
    }
}
