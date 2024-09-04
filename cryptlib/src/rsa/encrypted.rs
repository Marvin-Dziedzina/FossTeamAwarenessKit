use serde::{Deserialize, Serialize};

/// Stores a ciphertext
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RsaCiphertext {
    ciphertext: Vec<u8>,
}
impl RsaCiphertext {
    /// Create a new instance of `RsaCiphertext`
    pub fn new(ciphertext: Vec<u8>) -> Self {
        Self { ciphertext }
    }

    /// Consumes self and returns the ciphertext
    pub fn get_components(self) -> Vec<u8> {
        self.ciphertext
    }
}
