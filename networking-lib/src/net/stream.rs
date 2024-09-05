use std::{mem, sync::Arc};

use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{
    tcp::{OwnedReadHalf, OwnedWriteHalf},
    TcpStream,
};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::NetError;

mod protocol;

use protocol::{Action, Protocol};

#[derive(Debug)]
/// A single tcp stream.
pub struct Stream {
    stream_writer: Arc<Mutex<BufWriter<OwnedWriteHalf>>>,
    reader_task: JoinHandle<Result<(), NetError>>,
    read_buf: Arc<Mutex<Vec<Vec<u8>>>>,
}
impl Stream {
    /// Creates a new `Stream`.
    pub fn new(stream: TcpStream) -> Self {
        let (read_half, write_half) = stream.into_split();

        let stream_writer = Arc::new(Mutex::new(BufWriter::new(write_half)));
        let stream_reader = BufReader::new(read_half);
        let read_buf = Arc::new(Mutex::new(Vec::new()));

        let reader_read_buf = read_buf.clone();
        let reader_task =
            tokio::spawn(async { Self::reader(stream_reader, reader_read_buf).await });

        Self {
            stream_writer,
            reader_task,
            read_buf,
        }
    }

    /// Writes data to the stream.
    pub async fn write(&self, data: &[u8]) -> Result<(), NetError> {
        if data.len() == 0 {
            return Ok(());
        };

        let writer = self.stream_writer.clone();

        Self::writer(writer, data).await?;

        Ok(())
    }

    /// Writes the lenght of buf and buf to the stream.
    async fn writer(
        stream_writer: Arc<Mutex<BufWriter<OwnedWriteHalf>>>,
        buf: &[u8],
    ) -> Result<(), NetError> {
        let mut writer_lock = stream_writer.lock().await;

        // Send message lenght
        writer_lock.write_all(&(buf.len() as u64).to_le_bytes());

        // Send message
        writer_lock
            .write_all(&buf)
            .await
            .map_err(|e| NetError::IOError(e))?;

        writer_lock.flush().await.map_err(|e| NetError::IOError(e));

        Ok(())
    }

    /// Reads all data that is ready to be read.
    pub async fn read(&self) -> Vec<Vec<u8>> {
        // Get `read_buf` data and replace them with an empty `Vec`.
        let mut read_buf_lock = self.read_buf.lock().await;
        let read_buf_contents = mem::take(&mut *read_buf_lock);

        read_buf_contents
    }

    /// Reads all available data to the internal buffer.
    async fn reader(
        mut stream_reader: BufReader<OwnedReadHalf>,
        read_buf: Arc<Mutex<Vec<Vec<u8>>>>,
    ) -> Result<(), NetError> {
        loop {
            // Read data
            let total_lenght = Self::get_data_lenght(&mut stream_reader).await?;
            let data = Self::get_data(&mut stream_reader, total_lenght).await?;

            // Save message into buffer
            let mut read_buf_lock = read_buf.lock().await;
            read_buf_lock.push(data);
        }
    }

    /// Returns the lenght of the next message. Needs to be paired with `get_message`.
    async fn get_data_lenght(
        reader_lock: &mut BufReader<OwnedReadHalf>,
    ) -> Result<usize, NetError> {
        let mut total_lenght_bytes: [u8; 8] = [0; 8];
        reader_lock
            .read_exact(&mut total_lenght_bytes)
            .await
            .map_err(|e| NetError::IOError(e))?;
        let total_lenght = u64::from_le_bytes(total_lenght_bytes) as usize;
        Ok(total_lenght)
    }

    /// Returns all bytes until `total_lenght` is reached.
    async fn get_data(
        reader_lock: &mut BufReader<OwnedReadHalf>,
        total_lenght: usize,
    ) -> Result<Vec<u8>, NetError> {
        let mut data_buf: Vec<u8> = Vec::new();
        loop {
            // Read bytes into `buf`
            let mut buf = [0; 512];
            let read_bytes = reader_lock
                .read(&mut buf)
                .await
                .map_err(|e| NetError::IOError(e))?;

            data_buf.extend(&buf[0..read_bytes]);

            // Check if `data_buf` equals or is bigger than `total_lenght`
            if total_lenght <= data_buf.len() {
                data_buf = (&data_buf[0..total_lenght]).to_vec();

                break;
            };
        }
        Ok(data_buf)
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        todo!()
    }
}

#[cfg(test)]
mod stream_tests {
    use super::*;
}
