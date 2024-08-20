pub struct RsaCiphertext {
    ciphertext: Vec<u8>,
}
impl RsaCiphertext {
    pub fn new(ciphertext: Vec<u8>) -> Self {
        Self { ciphertext }
    }

    pub fn get_components(self) -> Vec<u8> {
        self.ciphertext
    }
}
