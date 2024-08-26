use serde::{Deserialize, Serialize};

mod rsa_public_key;
mod sign_public_key;
mod traits;

pub use rsa_public_key::RsaPublicKey;
pub use sign_public_key::SignPublicKey;
pub use traits::PublicKey;

/// Common supported key formats
#[derive(Debug, Serialize, Deserialize)]
pub enum KeyFormat {
    PEM,
    DER,
}
