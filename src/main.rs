use clap::Parser;
use encryption::Session;
use log::{debug, warn};
use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use tokio::task;

mod encryption;

use crate::encryption::KeyPair;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let options = Args::parse();

    let listen_addr: SocketAddr = options.listen_addr.parse()?;

    let keys = KeyPair::generate();
    let mut node = Node::new(keys, listen_addr)?;
    node.bind().await?;

    debug!("public key: {}", hex::encode(&node.keys.public_key));
    debug!("secret key: {}", hex::encode(&node.keys.secret_key[..32]));
    debug!("peer id: {}", node.id());

    let node = Arc::new(node);
    let accept_node = Arc::clone(&node);
    tokio::spawn(async move {
        if let Err(e) = accept_node.run_accept_loop().await {
            eprintln!("Error in accept loop: {:?}", e);
        }
    });

    if options.interactive {
        let interactive_mode = Arc::clone(&node);
        std::thread::spawn(move || {
            if let Err(e) = open_tty(interactive_mode) {
                eprintln!("TTY error: {:?}", e);
            }
        });
    }

    for bootstrap_addr in &options.bootstrap_nodes {
        match bootstrap_addr.parse::<SocketAddr>() {
            Ok(addr) => match node.get_or_create_client(addr).await {
                Ok(_client) => {}
                Err(e) => {
                    warn!("Could not connect to bootstrap node {}: {}", addr, e);
                }
            },
            Err(e) => {
                warn!("Could not parse bootstrap addr {}: {}", bootstrap_addr, e);
            }
        }
    }

    Ok(())
}

fn bootstrap_node_with_peer(node: Node, client: Client) {}

struct Node {
    id: ID,
    socket: TcpListener,
    address: SocketAddr,
    keys: KeyPair,
    table: RoutingTable,
    clients: HashMap<SocketAddr, Arc<Mutex<Client>>>,
    processed_nonces: HashSet<[u8; 16]>,
}

impl Node {
    pub fn new(keys: KeyPair, address: SocketAddr) -> io::Result<Self> {
        let socket = TcpListener::bind(address)?;
        let local_addr = socket.local_addr()?;
        let id = ID::new(keys.public_key.to_bytes(), local_addr);

        Ok(Self {
            id,
            socket,
            address: local_addr,
            keys,
            table: RoutingTable::new(keys.public_key.to_bytes()),
            clients: HashMap::new(),
            processed_nonces: HashSet::new(),
        })
    }

    pub fn run_accept_loop(self: Arc<Mutex<Self>>) -> io::Result<()> {
        let socket = self.lock().unwrap().socket.try_clone()?;
        for stream in socket.incoming() {
            match stream {
                Ok(stream) => {
                    let node_clone = Arc::clone(&self);
                    thread::spawn(move || {
                        if let Err(err) = Node::handle_client(node_clone, stream) {
                            eprintln!("Client handler error: {err}");
                        }
                    });
                }
                Err(e) => {}
            }
        }
    }
}

struct Client {
    socket: TcpListener,
    address: SocketAddr,
    conn: Connection,
    peer_id: Option<ID>,
    keys: KeyPair,
    read_task: Option<tokio::task::JoinHandle<Result<Vec<u8>, anyhow::Error>>>,
    can_read: tokio::sync::Notify,
}

impl Client {
    pub async fn new(
        socket: TcpListener,
        address: SocketAddr,
        node_keys: KeyPair,
    ) -> anyhow::Result<Self> {
        Ok(Client {
            socket,
            address,
            conn: Connection::new(socket.clone(), node_keys),
            peer_id: None,
            keys: KeyPair::generate(),
            read_task: None,
            can_read: tokio::sync::Notify::new(),
        })
    }

    pub fn writer(&mut self) -> Writer {
        self.conn.writer()
    }

    pub async fn flush(&mut self) -> std::io::Result<()> {
        self.conn.flush().await
    }

    pub fn acquire_reader(&mut self) {
        self.can_read = Arc::new(tokio::sync::Notify::new());
    }

    pub fn release_reader(&self) {
        self.can_read.notify_one();
    }

    pub async fn configure_peer(
        &mut self,
        peer_id: ID,
        public_key: [u8; 32],
        nonce: [u8; 32],
        key_type: KeyType,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let shared = self.keys.secret;

        let mut hasher = Hasher::new();
        hasher.update(&shared);
        hasher.update(&nonce);
        let shared_secret = hasher.finalize();

        self.peer_id = Some(peer_id);

        let session = match key_type {
            KeyType::KeyPair => {
                Session::new(encryption::random_id(), shared_secret.as_bytes(), self.keys)
            }
            KeyType::RemoteKey => Session::new_remote(
                encryption::random_id(),
                shared_secret.as_bytes(),
                public_key,
            ),
        };

        self.conn.session = Some(session);
        self.conn.flags |= FLAG_SIGNED |= FLAG_ENCRYPTED;

        Ok(())
    }
}

pub enum KeyType {
    RemoteKey,
    KeyPair,
}

const FLAG_SIGNED: u8 = 0x1;
const FLAG_ENCRYPTED: u8 = 0x2;

struct Connection {
    pub write_buffer: BytesMut,
    pub backend: Backend,
    pub flags: u8,
    pub node_keys: KeyPair,
    pub session: Option<Box<Session>>,
}

impl Connection {
    pub fn new(backend: Backend, node_keys: KeyPair) -> Self {
        Self {
            write_buffer: BytesMut::with_capacity(1024),
            backend,
            flags: 0x0,
            node_keys,
            session: None,
        }
    }

    pub fn writer(&mut self) -> &mut BytesMut {
        &mut self.write_buffer
    }

    pub async fn flush(&mut self) -> io::Result<()> {
        debug!("flushing with flags 0x{:02x}", self.flags);

        let mut data_to_write = self.write_buffer.split().freeze();
        let is_signed = self.flags & FLAG_SIGNED != 0;
        let is_encrypted = self.flags & FLAG_ENCRYPTED != 0;

        let mut encryption_metadata: Option<EncryptionMetadata> = None;

        if is_encrypted {
            let session = self
                .session
                .as_mut()
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Missing session"))?;

            let EncryptedMessage {
                cipher_text,
                dh,
                n,
                pn,
            } = session.encrypt(&data_to_write)?;

            encryption_metadata = Some(EncryptionMetadata { dh, n, pn });
            data_to_write = cipher_text.into();
        }
        let signature_len = if is_signed { Signature::BYTE_SIZE } else { 0 };
        let metadata_len = if is_encrypted {
            EncryptionMetadata::BYTE_SIZE
        } else {
            0
        };

        let packet_len = data_to_write.len() + signature_len + metadata_len;

        let mut output = BytesMut::with_capacity(5 + packet_len);

        PacketHeader {
            flags: self.flags,
            len: packet_len as u16,
        }
        .write(&mut output)?;

        if let Some(meta) = &encryption_metadata {
            meta.write(&mut output)?;
        }

        output.put_slice(&data_to_write);

        if is_signed {
            let msg = &output[5..];
            let sig = self.node_keys.sign(msg);
            output.put_slice(&sig.to_bytes());
        }

        debug_assert_eq!(output.len(), 5 + packet_len);

        match &mut self.backend {
            Backend::Socket(stream) => {
                tokio::io::write_all(stream, output.freeze()).await?;
            }
            Backend::Connection(conn) => {
                conn.writer().put_slice(&output);
            }
        }

        Ok(())
    }
}

pub struct SigningWriter<W: Write> {
    inner: W,
    signer: X25519_dalek::SignerMut<'static>,
    buffer: Vec<u8>,
}

impl<W: Write> SigningWriter<W> {
    pub fn new(inner: W, signing_key: &'static SigningKey) -> Self {
        Self {
            inner,
            signer: signing_key.into(),
            buffer: Vec::new(),
        }
    }

    pub fn sign(mut self) -> io::Result<()> {
        let sign: Signature = self.signer.sign(&self.buffer);
        self.inner.write_all(sig.as_ref())
    }

    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for SigningWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
