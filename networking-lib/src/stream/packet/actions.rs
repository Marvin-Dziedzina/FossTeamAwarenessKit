use cryptlib::{rsa::PublicKey, Sha256Hash};
use serde::{Deserialize, Serialize};

/// Tha basic action from stream.
#[derive(Debug, Serialize, Deserialize)]
pub enum Action {
    /// A packet
    Transmission,

    /// A previously sent packet was received.
    Received(Sha256Hash),
    /// A previously sent packet needs to be resended.
    Resend(Sha256Hash),

    /// Getting a ping.
    Ping(PublicKey),
    /// Getting a previously sent ping.
    PingResponse(PublicKey),

    /// Closing of stream.
    Close,
}
