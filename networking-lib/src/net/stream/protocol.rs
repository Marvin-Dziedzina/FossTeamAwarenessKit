use std::sync::{Arc, Mutex};

use cryptlib::{rsa::PublicKey, CiphertextData, CryptLib};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::{time, NetError};

#[derive(Debug)]
pub struct Protocol {
    timestamp: u128,
    action: Action,
    sender_public_key: PublicKey,
    data: Vec<u8>,
}
impl Protocol {
    pub fn new(crypt_lib: &CryptLib, action: Action, data: Vec<u8>) -> Result<Self, NetError> {
        Ok(Self {
            timestamp: time::get_unix_epoch_timestamp(),
            action,
            sender_public_key: crypt_lib
                .get_public_keys()
                .map_err(|e| NetError::CryptError(e))?,
            data,
        })
    }
}

impl Protocol {
    fn from_bytes(bytes: &[u8], crypt_lib: &CryptLib) -> Result<Self, NetError> {
        let ciphertext_data: CiphertextData =
            bincode::deserialize(bytes).map_err(|e| NetError::BincodeError(e))?;

        let aes_decrypted = crypt_lib
            .decrypt(ciphertext_data)
            .map_err(|e| NetError::CryptError(e))?;
        let (data, aad) = aes_decrypted.get_components();

        let protocol_data: ProtocolData =
            bincode::deserialize(&aad).map_err(|e| NetError::BincodeError(e))?;

        Ok(Self {
            timestamp: protocol_data.timestamp,
            action: protocol_data.action,
            sender_public_key: protocol_data.sender_public_key,
            data,
        })
    }

    fn to_bytes(
        &self,
        crypt_lib: &CryptLib,
        receiver_public_key: &PublicKey,
    ) -> Result<Vec<u8>, NetError> {
        let protocol_data = ProtocolData::new(self);
        let bincode_protocol_data =
            bincode::serialize(&protocol_data).map_err(|e| NetError::BincodeError(e))?;

        let ciphertext_data = crypt_lib
            .encrypt(receiver_public_key, &self.data, bincode_protocol_data)
            .map_err(|e| NetError::CryptError(e))?;

        bincode::serialize(&ciphertext_data).map_err(|e| NetError::BincodeError(e))
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ProtocolData {
    timestamp: u128,
    action: Action,
    sender_public_key: PublicKey,
}
impl ProtocolData {
    pub fn new(protocol: &Protocol) -> Self {
        Self {
            timestamp: protocol.timestamp,
            action: protocol.action.clone(),
            sender_public_key: protocol.sender_public_key.clone(),
        }
    }
}

impl Serde for ProtocolData {
    fn from_bytes(bytes: &[u8]) -> Result<Self, NetError>
    where
        Self: Sized,
    {
        bincode::deserialize(bytes).map_err(|e| NetError::BincodeError(e))
    }

    fn to_bytes(&self) -> Result<Vec<u8>, NetError> {
        bincode::serialize(&self).map_err(|e| NetError::BincodeError(e))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Action {
    Transmit,
    Ping,
    Close,
}

pub trait Serde {
    fn from_bytes(bytes: &[u8]) -> Result<Self, NetError>
    where
        Self: Sized;

    fn to_bytes(&self) -> Result<Vec<u8>, NetError>;
}
