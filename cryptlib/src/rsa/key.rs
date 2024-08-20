use openssl::{
    pkey::{PKey, Public},
    rsa::Rsa,
};

use crate::CryptError;

mod traits;

pub use traits::PublicKey;

/// Stores the public key of Rsa.
pub struct RsaPublicKey {
    key: Rsa<Public>,
}
impl PublicKey<Rsa<Public>> for RsaPublicKey {
    fn new(public_key: &[u8], key_format: KeyFormat) -> Result<Self, CryptError> {
        let key = match key_format {
            KeyFormat::DER => Rsa::public_key_from_der(public_key),
            KeyFormat::PEM => Rsa::public_key_from_der(public_key),
        }
        .map_err(|e| CryptError::PublicKey(e))?;

        Ok(Self { key })
    }

    fn get_key(&self) -> &Rsa<Public> {
        &self.key
    }
}

/// Stores the PKey.
pub struct SignPublicKey {
    key: PKey<Public>,
}
impl PublicKey<PKey<Public>> for SignPublicKey {
    fn new(public_key: &[u8], key_format: KeyFormat) -> Result<Self, CryptError>
    where
        Self: Sized,
    {
        let key = match key_format {
            KeyFormat::DER => PKey::public_key_from_der(public_key),
            KeyFormat::PEM => PKey::public_key_from_der(public_key),
        }
        .map_err(|e| CryptError::PublicKey(e))?;

        Ok(Self { key })
    }

    fn get_key(&self) -> &PKey<Public> {
        &self.key
    }
}

/// Common supported key formats
pub enum KeyFormat {
    PEM,
    DER,
}
