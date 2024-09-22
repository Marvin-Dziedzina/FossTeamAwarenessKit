use std::{collections::HashMap, marker::PhantomData, net::SocketAddr, ops::Deref, sync::Arc};

use cryptlib::CryptLib;
use log::{debug, error, info, trace};
use serde::{
    de::{self, Visitor},
    ser::SerializeStruct,
    Deserialize, Serialize,
};
use tokio::{
    net::{TcpListener, TcpStream, ToSocketAddrs},
    runtime,
    sync::{Mutex, RwLock},
    task::JoinHandle,
};

pub mod stream;

mod error;
mod time;

pub use error::NetError;

use stream::{Packet, PacketTrait, Stream};

pub type Address = String;

#[derive(Debug)]
struct NetLib<S: Serialize + for<'a> Deserialize<'a> + PacketTrait + std::marker::Send + 'static> {
    binding_address: String,
    listener: Arc<TcpListener>,
    listener_task: Option<JoinHandle<()>>,

    connections: Arc<Mutex<Vec<Address>>>,
    streams: Arc<Mutex<HashMap<Address, Arc<RwLock<Stream<S>>>>>>,

    crypt_lib: Arc<RwLock<CryptLib>>,
}
impl<S: Serialize + for<'a> Deserialize<'a> + PacketTrait + std::marker::Send + 'static> NetLib<S> {
    pub async fn new<T: ToSocketAddrs>(
        address: T,
        crypt_lib_bits: cryptlib::Bits,
    ) -> Result<Self, NetError> {
        let listener = TcpListener::bind(address)
            .await
            .map_err(NetError::ListenerError)?;

        let crypt_lib = CryptLib::new(crypt_lib_bits).map_err(NetError::CryptError)?;

        debug!("Create new NetLib.");

        Ok(Self {
            binding_address: listener
                .local_addr()
                .map_err(NetError::ListenerError)?
                .to_string(),
            listener: Arc::new(listener),
            listener_task: None,

            connections: Arc::new(Mutex::new(Vec::new())),
            streams: Arc::new(Mutex::new(HashMap::new())),

            crypt_lib: Arc::new(RwLock::new(crypt_lib)),
        })
    }

    pub async fn from_crypt_lib(address: String, crypt_lib: CryptLib) -> Result<Self, NetError> {
        let listener = TcpListener::bind(&address)
            .await
            .map_err(NetError::ListenerError)?;

        debug!("Create new NetLib.");

        Ok(Self {
            binding_address: address,
            listener: Arc::new(listener),
            listener_task: None,

            connections: Arc::new(Mutex::new(Vec::new())),
            streams: Arc::new(Mutex::new(HashMap::new())),

            crypt_lib: Arc::new(RwLock::new(crypt_lib)),
        })
    }

    pub async fn open(&mut self) {
        // Clone all needed fields
        let listener = self.listener.clone();
        let connections = self.connections.clone();
        let streams = self.streams.clone();
        let crypt_lib = self.crypt_lib.clone();

        let listener_task = tokio::spawn(async {
            Self::handle_incoming(listener, connections, streams, crypt_lib).await;
        });

        trace!("Started listener task.");

        self.listener_task = Some(listener_task);

        debug!("Opened NetLib listener.");
    }

    pub async fn close(&mut self) {
        let mut connections_lock = self.connections.lock().await;
        let mut streams_lock = self.streams.lock().await;
        for (addr, stream) in streams_lock.iter() {
            let stream_rlock = stream.read().await;
            stream_rlock.close().await.expect("Could not close stream!");
        }

        debug!("Closed connections.");

        connections_lock.clear();
        streams_lock.clear();

        debug!("Cleared connections and streams.");

        if let Some(listener_task) = &self.listener_task {
            listener_task.abort();
            self.listener_task = None;

            debug!("Aborted listener task.");
        };
    }

    pub async fn connect<T: ToSocketAddrs>(&self, addr: T) -> Result<(), NetError> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(NetError::StreamError)?;
        let address = stream.peer_addr().map_err(NetError::StreamError)?;
        debug!("Connected to {}.", address.to_string());

        Self::add_connection(
            &self.connections,
            &self.streams,
            address,
            stream,
            &self.crypt_lib,
        )
        .await?;
        debug!("Added connection.");

        info!("Established connection with {}.", address);

        Ok(())
    }

    async fn handle_incoming(
        listener: Arc<TcpListener>,
        connections: Arc<Mutex<Vec<String>>>,
        streams: Arc<Mutex<HashMap<String, Arc<RwLock<Stream<S>>>>>>,
        crypt_lib: Arc<RwLock<CryptLib>>,
    ) {
        loop {
            match listener.accept().await {
                Ok((stream, socket_address)) => {
                    Self::add_connection(
                        &connections,
                        &streams,
                        socket_address,
                        stream,
                        &crypt_lib,
                    )
                    .await
                    .unwrap();

                    info!("Got connection from {}.", socket_address.to_string());
                }
                Err(e) => {
                    error!("Could not get connection! Error: {}", e);
                    continue;
                }
            };
        }
    }

    async fn add_connection(
        connections: &Arc<Mutex<Vec<String>>>,
        streams: &Arc<Mutex<HashMap<String, Arc<RwLock<Stream<S>>>>>>,
        socket_address: SocketAddr,
        stream: TcpStream,
        crypt_lib: &Arc<RwLock<CryptLib>>,
    ) -> Result<(), NetError> {
        // Lock mutexes
        let mut connection_lock = connections.lock().await;
        let mut stream_lock = streams.lock().await;

        let address = socket_address.ip().to_string();
        let stream = Stream::new(stream, crypt_lib.clone()).await?;
        debug!("Created new `Stream` from `TcpStream`.");

        connection_lock.push(address.clone());
        stream_lock.insert(address, stream);
        debug!("Inserted new stream.");

        Ok(())
    }

    pub async fn send<T: Serialize + for<'a> Deserialize<'a>>(
        &self,
        addresses: Option<Vec<Address>>,
        data: &T,
    ) -> Result<(), Vec<NetError>> {
        let bytes = bincode::serialize(data).map_err(|e| vec![NetError::BincodeError(e)])?;

        let mut errors = Vec::new();

        let streams_lock = self.streams.lock().await;
        for (address, stream) in streams_lock.iter() {
            if let Some(addresses) = &addresses {
                if !addresses.contains(address) {
                    debug!("Skip sending on {}.", address);
                    continue;
                };
            };

            let stream_rlock = stream.read().await;
            match stream_rlock.send(&bytes).await {
                Ok(_) => debug!("Sent data to {}.", address),
                Err(e) => {
                    error!(
                        "Got error while sending data to {}! Error: {}",
                        stream_rlock.get_peer_ip().await,
                        e
                    );
                    errors.push(e);
                }
            };
        }

        if errors.is_empty() {
            debug!("No errors while sending.");

            Ok(())
        } else {
            Err(errors)
        }
    }

    pub async fn recv(&self, addresses: Option<Vec<Address>>) -> HashMap<Address, Vec<Packet<S>>> {
        let mut packets = HashMap::new();

        let streams_lock = self.streams.lock().await;
        for (address, stream) in streams_lock.iter() {
            if let Some(addresses) = &addresses {
                if !addresses.contains(address) {
                    debug!("Skip receiving on {}.", address);
                    continue;
                };
            };

            let stream_rlock = stream.read().await;
            packets.insert(address.clone(), stream_rlock.get_packets().await);
            debug!("Received data from {}.", address);
        }

        packets
    }

    /// Get the current connections.
    pub async fn get_connections_snapshot(&self) -> Vec<Address> {
        self.connections.lock().await.clone()
    }

    /// Get connections
    pub async fn get_connections(&self) -> &Arc<Mutex<Vec<Address>>> {
        &self.connections
    }
}

impl<S: Serialize + for<'a> Deserialize<'a> + PacketTrait + std::marker::Send + 'static> Serialize
    for NetLib<S>
{
    fn serialize<SE>(&self, serializer: SE) -> Result<SE::Ok, SE::Error>
    where
        SE: serde::Serializer,
    {
        let rt = tokio::runtime::Runtime::new().expect("Could not create a new runtime!");

        let crypt_lib = rt.block_on(async { self.crypt_lib.read().await });

        let mut state = serializer.serialize_struct("NetLib", 2)?;

        state.serialize_field("binding_address", &self.binding_address)?;
        state.serialize_field("crypt_lib", crypt_lib.deref())?;

        state.end()
    }
}

impl<'de, S: Serialize + for<'a> Deserialize<'a> + PacketTrait + std::marker::Send + 'static>
    Deserialize<'de> for NetLib<S>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct NetLibVisitor<S> {
            marker: PhantomData<S>,
        }

        impl<
                S: Serialize + for<'a> Deserialize<'a> + PacketTrait + std::marker::Send + 'static,
            > Default for NetLibVisitor<S>
        {
            fn default() -> Self {
                Self {
                    marker: Default::default(),
                }
            }
        }

        impl<
                'de,
                S: Serialize + for<'a> Deserialize<'a> + PacketTrait + std::marker::Send + 'static,
            > Visitor<'de> for NetLibVisitor<S>
        {
            type Value = NetLib<S>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a serialized NetLib struct")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut binding_address = None;
                let mut crypt_lib = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        "binding_address" => {
                            if binding_address.is_some() {
                                return Err(de::Error::duplicate_field("binding_address"));
                            };

                            binding_address = Some(map.next_value()?)
                        }
                        "crypt_lib" => {
                            if crypt_lib.is_some() {
                                return Err(de::Error::duplicate_field("crypt_lib"));
                            };

                            crypt_lib = Some(map.next_value()?)
                        }
                        _ => {
                            return Err(de::Error::unknown_field(
                                key,
                                &["binding_address", "crypt_lib"],
                            ))
                        }
                    }
                }

                let binding_address =
                    binding_address.ok_or_else(|| de::Error::missing_field("binding_address"))?;
                let crypt_lib = crypt_lib.ok_or_else(|| de::Error::duplicate_field("crypt_lib"))?;

                let rt = runtime::Runtime::new().map_err(|e| {
                    de::Error::custom(format!("Could not create runtime! Error: {}", e))
                })?;

                let net_lib =
                    rt.block_on(async { NetLib::from_crypt_lib(binding_address, crypt_lib).await });

                net_lib.map_err(|e| {
                    de::Error::custom(format!("Could not deserialize `NetLib`! Error: {}", e))
                })
            }
        }

        deserializer.deserialize_struct(
            "NetLib",
            &["binding_address", "crypt_lib"],
            NetLibVisitor::default(),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Display;

    use log::debug;

    use super::*;

    #[derive(Debug, Serialize, Deserialize)]
    struct Message {
        message: String,
    }
    impl Display for Message {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.message)
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    enum CustomPacket {
        Message,
    }
    impl PacketTrait for CustomPacket {
        fn to_struct(
            &self,
            bytes: &[u8],
        ) -> Result<Box<dyn std::any::Any>, Box<bincode::ErrorKind>> {
            match self {
                CustomPacket::Message => {
                    Ok(Box::new(bincode::deserialize::<Message>(bytes).unwrap()))
                }
            }
        }
    }

    #[tokio::test]
    async fn it_works() {
        env_logger::init();

        let mut net_lib1 = NetLib::<CustomPacket>::new("localhost:8080", cryptlib::Bits::Bits2048)
            .await
            .unwrap();
        let mut net_lib2 = NetLib::<CustomPacket>::new("localhost:8090", cryptlib::Bits::Bits2048)
            .await
            .unwrap();

        net_lib1.open().await;
        net_lib2.open().await;

        debug!("Before connect!");
        net_lib2.connect("localhost:8080").await.unwrap();
        debug!("Afer connect!");

        net_lib1
            .send(
                None,
                &Message {
                    message: String::from("Test"),
                },
            )
            .await
            .unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;

        let streams = net_lib1.streams.clone();

        net_lib1.close().await;
        net_lib2.close().await;

        assert_eq!(true, true);
    }
}
