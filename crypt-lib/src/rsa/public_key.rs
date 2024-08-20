use openssl::{
    pkey::{PKey, Public},
    rsa::Rsa,
};

use crate::CryptError;

pub struct PublicKey<T> {
    public_key: T,
}
impl<T> PublicKey<T> {
    pub fn get_key(&self) -> &T {
        &self.public_key
    }
}

impl PublicKey<Rsa<Public>> {
    pub fn new_rsa(public_key: &[u8], key_format: KeyFormat) -> Result<Self, CryptError> {
        let key = match key_format {
            KeyFormat::DER => {
                Rsa::public_key_from_der(public_key).map_err(|e| CryptError::PublicKey(e))?
            }
            KeyFormat::PEM => {
                Rsa::public_key_from_pem(public_key).map_err(|e| CryptError::PublicKey(e))?
            }
        };

        Ok(Self { public_key: key })
    }
}

impl PublicKey<PKey<Public>> {
    pub fn new_pkey(public_key: &[u8], key_format: KeyFormat) -> Result<Self, CryptError> {
        let key = match key_format {
            KeyFormat::DER => {
                PKey::public_key_from_der(public_key).map_err(|e| CryptError::PublicKey(e))?
            }
            KeyFormat::PEM => {
                PKey::public_key_from_pem(public_key).map_err(|e| CryptError::PublicKey(e))?
            }
        };

        Ok(Self { public_key: key })
    }
}

pub enum KeyFormat {
    PEM,
    DER,
}
