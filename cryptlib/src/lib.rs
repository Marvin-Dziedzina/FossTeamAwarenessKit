pub mod aes;
mod error;
pub mod rsa;

pub use error::CryptError;

#[cfg(test)]
mod tests {
    use std::{fs, io::Write};

    use super::*;

    use aes::AES;
    use rsa::{RsaPublicKey, SignPublicKey, RSA};

    #[test]
    fn rsa() {
        let data = b"Unit test goes brrrrrrr";

        let rsa = RSA::new(2048).unwrap();
        let pub_key = rsa.get_public_rsa_key().unwrap();

        // Encrypt
        let ciphertext = rsa.encrypt(&pub_key, data).unwrap();

        // Decrypt
        let out = rsa.decrypt(ciphertext).unwrap();

        assert_eq!(data.to_vec(), out);
    }

    #[test]
    fn signing() {
        let data = b"My precious data!";

        let rsa = RSA::new(2048).unwrap();
        let pub_key = rsa.get_public_sign_key().unwrap();

        // Sign
        let signature = rsa.sign(data).unwrap();

        // Verify
        let is_valid = rsa.verify(pub_key, data, signature).unwrap();

        assert_eq!(true, is_valid);
    }

    #[test]
    fn aes() {
        let data = b"AES is a symmetric encryption.";
        let aad = b"This will be visible but can not be changed or the decription will fail";

        let aes = AES::new().unwrap();

        // Encrypt
        let ciphertext = aes.encrypt(data, aad.to_vec()).unwrap();

        // Decrypt
        let out = aes.decrypt(ciphertext).unwrap();

        assert_eq!(data.to_vec(), out.data);

        assert_eq!(aad.to_vec(), out.aad);
    }

    #[test]
    fn rsa_serde() {
        let rsa = RSA::new(2048).unwrap();

        let json = serde_json::to_string(&rsa).unwrap();

        let _: RSA = serde_json::from_str(&json).unwrap();

        assert_eq!(true, true);
    }

    #[test]
    fn aes_serde() {
        let aes = AES::new().unwrap();

        let json = serde_json::to_string(&aes).unwrap();

        let _: AES = serde_json::from_str(&json).unwrap();

        assert_eq!(true, true);
    }

    #[test]
    fn rsa_public_key_serde() {
        let rsa_public_key = RSA::new(2048).unwrap().get_public_rsa_key().unwrap();

        let json = serde_json::to_string(&rsa_public_key).unwrap();

        let _: RsaPublicKey = serde_json::from_str(&json).unwrap();

        assert_eq!(true, true);
    }

    #[test]
    fn sign_public_key_serde() {
        let sign_public_key = RSA::new(2048).unwrap().get_public_sign_key().unwrap();

        let json = serde_json::to_string(&sign_public_key).unwrap();

        let _: SignPublicKey = serde_json::from_str(&json).unwrap();

        assert_eq!(true, true);
    }
}
