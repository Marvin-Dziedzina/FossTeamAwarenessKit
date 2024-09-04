use serde::{Deserialize, Serialize};

/// Stores `AES` ciphertext
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AesCiphertext {
    ciphertext: Vec<u8>,
    iv: [u8; 16],
    aad: Vec<u8>,
    tag: [u8; 16],
}
impl AesCiphertext {
    pub fn new(ciphertext: Vec<u8>, iv: [u8; 16], aad: Vec<u8>, tag: [u8; 16]) -> Self {
        Self {
            ciphertext,
            iv,
            aad,
            tag,
        }
    }

    /// Get components (ciphertext, iv, aad, tag)
    pub fn get_components(self) -> (Vec<u8>, [u8; 16], Vec<u8>, [u8; 16]) {
        (self.ciphertext, self.iv, self.aad, self.tag)
    }
}
