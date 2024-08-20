use super::KeyFormat;
use crate::CryptError;

pub trait PublicKey<T> {
    fn new(public_key: &[u8], key_format: KeyFormat) -> Result<Self, CryptError>
    where
        Self: Sized;

    fn get_key(&self) -> &T;
}
