use crate::{aes::AesCiphertext, rsa::RsaCiphertext};

pub struct CiphertextData {
    rsa_ciphertext: RsaCiphertext,
    aes_ciphertext: AesCiphertext,
}
impl CiphertextData {
    pub fn new(rsa_ciphertext: RsaCiphertext, aes_ciphertext: AesCiphertext) -> Self {
        Self {
            rsa_ciphertext,
            aes_ciphertext,
        }
    }

    pub fn get_components(self) -> (RsaCiphertext, AesCiphertext) {
        (self.rsa_ciphertext, self.aes_ciphertext)
    }
}
