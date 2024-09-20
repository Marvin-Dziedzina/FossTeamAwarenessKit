use std::{mem, sync::Arc};

use log::warn;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, BufReader},
    net::tcp::OwnedReadHalf,
    sync::{Mutex, RwLock},
    time,
};

use crate::NetError;

use super::{
    packet::{Action, Packet},
    Bytes, PacketTrait, Stream, TransmissionPacket,
};

/// `ReadHalf` implements many useful functions for reading from a tcp stream.
impl<S: Serialize + for<'a> Deserialize<'a> + PacketTrait + std::marker::Send> Stream<S> {
    /// Returns all read packets that have been read until the call of this function.
    pub async fn get_packets(&self) -> Vec<Packet<S>> {
        let mut read_packets_lock = self.read_packets.lock().await;
        mem::take(&mut *read_packets_lock)
    }

    /// This function reads all available packets and writes them into `read_packets`. Needs to be spawned as a tokio task. This functions runs indefinitely until stopped.
    pub async fn read_handler(stream: Arc<RwLock<Stream<S>>>) {
        let stream_rlock = stream.read().await;

        let is_stream_alive = &stream_rlock.is_stream_alive;

        let read_half = &stream_rlock.read_half;
        let read_packets = &stream_rlock.read_packets;

        loop {
            // Check if stream is still alive
            let is_stream_alive_rlock = is_stream_alive.read().await;
            if !*is_stream_alive_rlock {
                drop(is_stream_alive_rlock);

                time::sleep(time::Duration::from_secs(10)).await;
                continue;
            };

            // Read packet lenght and the packet
            let packet_lenght = match Self::read_packet_lenght(read_half).await {
                Ok(packet_lenght) => packet_lenght,
                Err(_) => {
                    Self::detected_eof(is_stream_alive.clone()).await;
                    continue;
                }
            };
            let transmission_packet = match Self::read_packet(read_half, packet_lenght).await {
                Ok(transmission_packet) => transmission_packet,
                Err(_) => {
                    Self::detected_eof(is_stream_alive.clone()).await;
                    continue;
                }
            };

            let packet = match Self::unpack_transmission_packet(transmission_packet, &stream).await
            {
                Some(value) => value,
                None => continue,
            };

            // Write the packet to `read_packets` if is some.
            if let Some(packet) = packet {
                let mut read_packets_lock = read_packets.lock().await;
                read_packets_lock.push(packet);
            };
        }
    }

    async fn unpack_transmission_packet(
        transmission_packet: TransmissionPacket,
        stream: &Arc<RwLock<Stream<S>>>,
    ) -> Option<Option<Packet<S>>> {
        match transmission_packet.action {
            Action::Transmission => match bincode::deserialize(transmission_packet.get_packets()) {
                Ok(packet) => packet,
                Err(_) => None,
            },

            Action::Resend(hash) => {
                let stream_rlock = stream.read().await;
                let written_packets_lock = stream_rlock.written_packets.lock().await;

                if let Some(written_packet) = written_packets_lock.get(&hash) {
                    stream_rlock
                        .write(written_packet)
                        .await
                        .expect("Could not wite a resend request!");
                } else {
                    warn!(
                        "Could not resend {}! It was not found in `written_packets`.",
                        hex::encode(hash)
                    );
                };

                None
            }
            Action::Received(hash) => {
                let stream_rlock = stream.read().await;
                let mut written_packets_lock = stream_rlock.written_packets.lock().await;

                match written_packets_lock.remove(&hash) {
                    Some(_) => (),
                    None => warn!(
                        "Could not remove {}! The packet was received but it could not be found in `written_packets`.",
                        hex::encode(hash)
                    ),
                };

                None
            }

            Action::Ping(public_key) => {
                let mut stream_wlock = stream.write().await;
                stream_wlock.receiver_public_key = Some(public_key);

                let private_key = stream_wlock
                    .crypt_lib
                    .read()
                    .await
                    .get_public_keys()
                    .expect("Could not get `PublicKey`");

                let packet = TransmissionPacket::new(Action::PingResponse(private_key), &[0_u8; 0]);
                let bytes = packet
                    .to_bytes()
                    .expect("Could not serialize with bincode!");
                match stream_wlock.write(&bytes).await {
                    Ok(_) => (),
                    Err(e) => warn!("Could not write `PingResponse` to stream! Error: {}", e),
                };

                None
            }
            Action::PingResponse(public_key) => {
                let mut stream_wlock = stream.write().await;
                stream_wlock.receiver_public_key = Some(public_key);

                None
            }

            Action::Close => {
                let stream_rlock = stream.read().await;
                stream_rlock
                    .close()
                    .await
                    .expect("Could not close connection!");

                None
            }
        }
    }

    /// Set the `is_stream_alive` to false.
    async fn detected_eof(is_stream_alive: Arc<RwLock<bool>>) {
        let mut is_stream_alive_wlock = is_stream_alive.write().await;
        *is_stream_alive_wlock = false;
    }

    /// Returns the lenght of the next packet.
    async fn read_packet_lenght(
        read_half: &Arc<Mutex<BufReader<OwnedReadHalf>>>,
    ) -> Result<u64, NetError> {
        let mut read_half_lock = read_half.lock().await;

        let mut buf = [0; 8];
        read_half_lock
            .read_exact(&mut buf)
            .await
            .map_err(|e| NetError::IOError(e))?;

        let packet_lenght = u64::from_le_bytes(buf);

        Ok(packet_lenght)
    }

    /// Returns the packet. `get_packet_lenght` needs to be called before.
    async fn read_packet(
        read_half: &Arc<Mutex<BufReader<OwnedReadHalf>>>,
        packet_lenght: u64,
    ) -> Result<TransmissionPacket, NetError> {
        let mut read_half_lock = read_half.lock().await;

        let mut packet_bytes: Vec<u8> = Vec::with_capacity(packet_lenght as usize);
        loop {
            let mut buf: [u8; 512] = [0; 512];
            let bytes_read = match read_half_lock.read(&mut buf).await {
                Ok(bytes_read) => bytes_read,
                Err(_) => continue,
            };

            packet_bytes.extend(&buf[0..bytes_read]);

            if packet_bytes.len() as u64 >= packet_lenght {
                break;
            }
        }

        let packet = TransmissionPacket::from_bytes(&packet_bytes)?;

        Ok(packet)
    }
}
