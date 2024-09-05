use std::{fmt::Display, io};

use cryptlib::CryptError;

#[derive(Debug)]
pub enum NetError {
    ListenerError(io::Error),
    CryptError(CryptError),
    BincodeError(bincode::Error),
    IOError(io::Error),
}

impl Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetError::ListenerError(e) => write!(f, "Listener Error: {}", e),
            NetError::CryptError(e) => write!(f, "Crypt Error: {}", e),
            NetError::BincodeError(e) => write!(f, "Bincode Error: {}", e),
            NetError::IOError(e) => write!(f, "IO Error: {}", e),
        }
    }
}
