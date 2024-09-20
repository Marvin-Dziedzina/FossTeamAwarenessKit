use cryptlib::CryptLib;
use log::info;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;

use crate::NetError;

use super::{packet::Action, Bytes, PacketTrait, Stream, TransmissionPacket};

impl<S: Serialize + for<'a> Deserialize<'a> + PacketTrait + std::marker::Send> Stream<S> {
    /// Writes the bytes to the stream.
    pub async fn write(&self, bytes: &[u8]) -> Result<(), NetError> {
        let is_stream_alive_rlock = self.is_stream_alive.read().await;
        if !*is_stream_alive_rlock {
            info!("Stream can not be written to! Cause it is not alive.");
            return Err(NetError::StreamNotAlive);
        };

        let mut write_half_lock = self.write_half.lock().await;

        write_half_lock
            .write_all(&(bytes.len() as u64).to_le_bytes())
            .await
            .map_err(|e| NetError::IOError(e))?;

        write_half_lock
            .write_all(&bytes)
            .await
            .map_err(|e| NetError::IOError(e))?;

        write_half_lock
            .flush()
            .await
            .map_err(|e| NetError::IOError(e))?;

        let mut written_packets_lock = self.written_packets.lock().await;
        let hash = CryptLib::sha256(&bytes);
        written_packets_lock.insert(hash, bytes.to_vec());

        Ok(())
    }

    /// Ping the connection.
    pub async fn ping(&self) -> Result<(), NetError> {
        let private_key = self
            .crypt_lib
            .read()
            .await
            .get_public_keys()
            .map_err(|e| NetError::CryptError(e))?;
        let packet = TransmissionPacket::new(Action::Ping(private_key), &[0 as u8; 0]);
        self.write(&packet.to_bytes()?).await?;

        Ok(())
    }
}
