use openssl::error::ErrorStack;

#[derive(Debug)]
pub enum CryptError {
    RsaError(ErrorStack),
    AesError(ErrorStack),
}
