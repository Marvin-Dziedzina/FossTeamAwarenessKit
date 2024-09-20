use crate::NetError;

pub trait Bytes: Sized {
    /// Constructs `Self` from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self, NetError>;

    /// Destructs `self` to bytes.
    fn to_bytes(&self) -> Result<Vec<u8>, NetError>;
}
