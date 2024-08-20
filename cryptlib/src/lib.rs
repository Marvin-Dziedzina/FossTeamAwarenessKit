pub mod aes;
mod error;
pub mod rsa;

pub use error::CryptError;

#[cfg(test)]
mod tests {

    use aes::AES;
    use rsa::RSA;

    use super::*;

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
}
