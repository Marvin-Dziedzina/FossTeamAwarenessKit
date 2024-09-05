use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

pub mod stream;

use stream::Stream;

use crate::NetError;

struct Net {
    address: SocketAddr,
    listener: Arc<TcpListener>,
    listener_task: Option<JoinHandle<()>>,
    connections: Arc<Mutex<Vec<String>>>,
    streams: Arc<Mutex<HashMap<String, Stream>>>,
    send_buffer: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    recv_buffer: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}
impl Net {
    pub async fn new(address: SocketAddr) -> Result<Self, NetError> {
        let listener = TcpListener::bind(address)
            .await
            .map_err(|e| NetError::ListenerError(e))?;

        Ok(Self {
            address: address,
            listener: Arc::new(listener),
            listener_task: None,
            connections: Arc::new(Mutex::new(Vec::new())),
            streams: Arc::new(Mutex::new(HashMap::new())),
            send_buffer: Arc::new(Mutex::new(HashMap::new())),
            recv_buffer: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn open(&mut self) {
        // Clone all needed fields
        let listener = self.listener.clone();
        let connections = self.connections.clone();
        let streams = self.streams.clone();

        let listener_thread = tokio::spawn(async {
            Self::handle_incoming(listener, connections, streams);
        });

        self.listener_task = Some(listener_thread);
    }

    async fn handle_incoming(
        listener: Arc<TcpListener>,
        connections: Arc<Mutex<Vec<String>>>,
        streams: Arc<Mutex<HashMap<String, Stream>>>,
    ) {
        loop {
            match listener.accept().await {
                Ok((stream, socket_address)) => Self::add_connection(
                    connections.clone(),
                    streams.clone(),
                    socket_address,
                    stream,
                )
                .await
                .unwrap(),
                Err(_) => continue,
            };
        }
    }

    async fn add_connection(
        connections: Arc<Mutex<Vec<String>>>,
        streams: Arc<Mutex<HashMap<String, Stream>>>,
        socket_address: SocketAddr,
        stream: TcpStream,
    ) -> Result<(), NetError> {
        // Lock mutexes
        let mut connection_lock = connections
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut stream_lock = streams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let address = socket_address.ip().to_string();

        connection_lock.push(address.clone());
        stream_lock.insert(address, Stream::new(stream));

        Ok(())
    }

    pub async fn close(&mut self) {}

    pub async fn send(&mut self) {}

    pub async fn recv(&mut self) {}

    pub async fn get_connections(&self) {}
}
