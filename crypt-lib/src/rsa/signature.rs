pub struct Signature {
    signature: Vec<u8>,
}
impl Signature {
    pub fn new(signature: Vec<u8>) -> Self {
        Self { signature }
    }

    pub fn get_signature(self) -> Vec<u8> {
        self.signature
    }
}
