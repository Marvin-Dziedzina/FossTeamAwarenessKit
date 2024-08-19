mod cryptography;
mod error;

pub use cryptography::{Cryptography, PublicKey, AES, RSA};
pub use error::CryptError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa() {
        let rsa = RSA::new(2048).unwrap();
        let pub_key = PublicKey::from_pem(&rsa.get_public_key().unwrap()).unwrap();

        let data = b"Unit test goes brrrrrrr";
        // Encript
        let ciphertext = rsa.encrypt(&pub_key, data).unwrap();

        // Decrypt
        let out = rsa.decrypt(ciphertext).unwrap();

        assert_eq!(data.to_vec(), out);
    }

    #[test]
    fn signing() {}

    #[test]
    fn aes() {
        let aes = AES::new();

        let data = b"AES is a symmetric encryption.";
        let aad = b"This will be visible but can not be changed or the decription will fail";

        // Encrypt
        let ciphertext = aes.encrypt(data, aad.to_vec()).unwrap();

        // Decrypt
        let out = aes.decrypt(ciphertext).unwrap();

        assert_eq!(data.to_vec(), out);
    }
}
