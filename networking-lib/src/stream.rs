use std::net::SocketAddr;
use std::{collections::HashMap, sync::Arc};

use cryptlib::rsa::PublicKey;
use cryptlib::{CryptLib, Sha256Hash};
use log::{debug, info};
use serde::{Deserialize, Serialize};
use tokio::io::{BufReader, BufWriter};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;

mod bytes;
mod packet;
mod read_half;
mod write_half;

pub use bytes::Bytes;
pub use packet::{Packet, PacketTrait, TransmissionPacket};

use packet::Action;

use crate::NetError;

#[derive(Debug)]
/// A single tcp stream.
pub struct Stream<
    S: Serialize + for<'a> Deserialize<'a> + PacketTrait + std::marker::Send + 'static,
> {
    is_stream_alive: Arc<RwLock<bool>>,
    peer_address: SocketAddr,

    read_half: Arc<Mutex<BufReader<OwnedReadHalf>>>,
    reader_task: Option<JoinHandle<()>>,
    read_packets: Arc<Mutex<Vec<Packet<S>>>>,

    write_half: Arc<Mutex<BufWriter<OwnedWriteHalf>>>,
    written_packets: Arc<Mutex<HashMap<Sha256Hash, Vec<u8>>>>,

    crypt_lib: Arc<RwLock<CryptLib>>,
    receiver_public_key: Option<PublicKey>,
}
impl<S: Serialize + for<'a> Deserialize<'a> + PacketTrait + std::marker::Send + 'static> Stream<S> {
    /// Creates a new `Stream`.
    pub async fn new(
        stream: TcpStream,
        crypt_lib: Arc<RwLock<CryptLib>>,
    ) -> Result<Arc<RwLock<Self>>, NetError> {
        let is_stream_alive = Arc::new(RwLock::new(true));
        let peer_address = stream.peer_addr().map_err(NetError::StreamError)?;

        let (read_half, write_half) = stream.into_split();
        let read_half = Arc::new(Mutex::new(BufReader::new(read_half)));
        let write_half = Arc::new(Mutex::new(BufWriter::new(write_half)));

        let read_packets = Arc::new(Mutex::new(Vec::new()));
        let written_packets = Arc::new(Mutex::new(HashMap::new()));

        let stream = Arc::new(RwLock::new(Self {
            is_stream_alive,
            peer_address,

            read_half,
            reader_task: None,
            read_packets,

            write_half,
            written_packets,

            crypt_lib,
            receiver_public_key: None,
        }));

        let stream_task = stream.clone();
        let reader_task = tokio::spawn(async { Self::read_handler(stream_task).await });

        let stream_c = stream.clone();
        let mut stream_wlock = stream_c.write().await;
        stream_wlock.reader_task = Some(reader_task);
        stream_wlock.ping().await?;

        debug!("New stream created.");

        Ok(stream)
    }

    /// Closes the stream.
    pub async fn close(&self) -> Result<(), NetError> {
        let packet = TransmissionPacket::new(Action::Close, &[0_u8; 0]);
        let result = match self.write(&packet.to_bytes()?).await.err() {
            Some(e) => match e {
                NetError::StreamNotAlive => Ok(()),
                _ => Err(e),
            },
            None => Ok(()),
        };

        debug!("Wrote close packet.");

        let mut is_stream_alive_wlock = self.is_stream_alive.write().await;
        *is_stream_alive_wlock = false;

        info!("Closed stream.");

        result
    }

    /// Writes data to the stream.
    pub async fn send(&self, data: &[u8]) -> Result<(), NetError> {
        let packet = TransmissionPacket::new(Action::Transmission, data);
        self.write(&packet.to_bytes()?).await
    }

    /// Reads all data that is ready to be read.
    pub async fn read(&self) -> Option<Packet<S>> {
        let mut read_packets_lock = self.read_packets.lock().await;
        if read_packets_lock.len() == 0 {
            return None;
        };

        Some(read_packets_lock.remove(0))
    }

    pub async fn get_receiver_public_key(&self) -> &Option<PublicKey> {
        &self.receiver_public_key
    }

    pub async fn is_stream_alive(&self) -> bool {
        let is_stream_alive_rlock = self.is_stream_alive.read().await;
        *is_stream_alive_rlock
    }

    pub async fn get_peer_ip(&self) -> &std::net::SocketAddr {
        &self.peer_address
    }
}

impl<S: Serialize + for<'a> Deserialize<'a> + PacketTrait + std::marker::Send + 'static> Drop
    for Stream<S>
{
    fn drop(&mut self) {
        if let Ok(rt) = tokio::runtime::Runtime::new() {
            let is_stream_alive_rlock = rt.block_on(async { self.is_stream_alive.read().await });
            if *is_stream_alive_rlock {
                rt.block_on(async { self.close().await }).ok();
                debug!("Closed stream for dropping the stream.");
            };

            if let Some(reader_task) = &self.reader_task {
                reader_task.abort();
                debug!("Reader Task aborted for dropping the stream.");
            };
        } else {
            debug!("Could not drop stream properly.");
        };
    }
}

#[cfg(test)]
mod stream_tests {
    // use super::*;
}
