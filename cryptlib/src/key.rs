use openssl::{
    pkey::{PKey, Public},
    rsa::Rsa,
};

use crate::CryptError;

/// Stores the public key of eighter Rsa or PKey.
///
/// Example:
/// ``` rust
/// PublicKey<Rsa<Public>>
///
/// PublicKey<PKey<Public>>
/// ```
pub struct PublicKey<T> {
    public_key: T,
}
impl<T> PublicKey<T> {
    pub fn get_key(&self) -> &T {
        &self.public_key
    }
}

impl PublicKey<Rsa<Public>> {
    /// Store `Rsa` key
    pub fn new_rsa(public_key: &[u8], key_format: KeyFormat) -> Result<Self, CryptError> {
        // Instance `Rsa` depending on the key format
        let key = match key_format {
            KeyFormat::DER => Rsa::public_key_from_der(public_key),
            KeyFormat::PEM => Rsa::public_key_from_pem(public_key),
        }
        .map_err(|e| CryptError::PublicKey(e))?;

        Ok(Self { public_key: key })
    }
}

impl PublicKey<PKey<Public>> {
    /// Store `PKey`
    pub fn new_pkey(public_key: &[u8], key_format: KeyFormat) -> Result<Self, CryptError> {
        // Instance `PKey` depending on the key format
        let key = match key_format {
            KeyFormat::DER => PKey::public_key_from_der(public_key),
            KeyFormat::PEM => PKey::public_key_from_pem(public_key),
        }
        .map_err(|e| CryptError::PublicKey(e))?;

        Ok(Self { public_key: key })
    }
}

/// Common supported key formats
pub enum KeyFormat {
    PEM,
    DER,
}
