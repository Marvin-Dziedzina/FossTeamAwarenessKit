use serde::{Deserialize, Serialize};

mod error;
mod net;
mod time;

pub use error::NetError;

#[derive(Debug, Serialize, Deserialize)]
struct NetLib {}
impl NetLib {
    /* /// Send a message to selected connections or to all when `None` is received.
    pub fn send(connections: Option<Vec<String>>, msg: Vec<u8>) -> Result<(), NetError> {}

    /// Receive message from selected or from all connections when `None` is passed.
    pub fn recv(connections: Option<Vec<String>>) -> Result<Message, NetError> {}

    /// Get all connections that are currently active.
    pub fn get_connections() -> Result<Vec<Connection>, NetError> {} */
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
