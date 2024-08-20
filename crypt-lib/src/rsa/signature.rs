/// Stores a signature
pub struct Signature {
    signature: Vec<u8>,
}
impl Signature {
    /// Create a new instance of `Signature`
    pub fn new(signature: Vec<u8>) -> Self {
        Self { signature }
    }

    /// Consumes self and returns the signature
    pub fn get_signature(self) -> Vec<u8> {
        self.signature
    }
}
