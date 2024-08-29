/// Stores `data` and `aad`.
pub struct AesDecrypted {
    pub data: Vec<u8>,
    pub aad: Vec<u8>,
}
impl AesDecrypted {
    pub fn new(data: Vec<u8>, aad: Vec<u8>) -> Self {
        Self { data, aad }
    }

    /// Get components as tuple (data, aad).
    pub fn get_components(self) -> (Vec<u8>, Vec<u8>) {
        (self.data, self.aad)
    }
}
