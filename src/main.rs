use anyhow::bail;
use blake3::Hasher;
use bytes::{BufMut, BytesMut};
use clap::{Parser, arg};
use ed25519_dalek::ed25519::signature::SignerMut;
use ed25519_dalek::{Signature, SigningKey};
use encryption::{Encrypted, Session, init};
use kademlia::{ID, RoutingTable};
use log::{debug, warn};
use net::frame::{RouteFrame, find_node_frame};
use net::packet::{EncryptionMetadata, Op, Packet, PacketHeader, Tag};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::io::{self, BufRead};
use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

mod encryption;
mod kademlia;
mod net;

use crate::encryption::KeyPair;

#[derive(Parser)]
#[command(name = "rpma")]
struct Args {
    #[arg(long)]
    listen_addr: String,
    #[arg(long)]
    interactive: bool,
    #[arg(trailing_var_arg = true)]
    bootstrap_nodes: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let options = Args::parse();

    let listen_addr: SocketAddr = options.listen_addr.parse()?;

    let keys = KeyPair::generate();
    let mut node = Node::new(keys, listen_addr)?;
    node.bind().await?;

    debug!("public key: {}", hex::encode(&node.keys.public.to_bytes()));
    debug!(
        "secret key: {}",
        hex::encode(&node.keys.secret.to_bytes()[..32])
    );
    debug!("peer id: {}", node.id);

    let node = Arc::new(node);
    let accept_node = Arc::clone(&node);
    tokio::spawn(async move {
        if let Err(e) = accept_node.run_accept_loop().await {
            eprintln!("Error in accept loop: {:?}", e);
        }
    });

    if options.interactive {
        let interactive_node = Arc::clone(&node);
        std::thread::spawn(move || {
            if let Err(e) = open_tty(&mut interactive_node) {
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

fn bootstrap_node_with_peer(node: &mut Node, client: &mut Client) -> anyhow::Result<()> {
    debug!("bootstrapping with node {:?}", client.peer_id);

    client.acquire_reader();

    Packet {
        op: Op::Request,
        tag: Tag::FindNodes,
    }
    .write(&mut client.writer())?;

    find_node_frame::Request {
        public_key: node.id.public_key,
    }
    .write(&mut client.writer())?;

    client.flush();

    let raw_frame = Node::read_frame(client)?;

    let mut cursor = std::io::Cursor::new(raw_frame);
    let packet = Packet::read(&mut cursor)?;
    if packet.op != Op::Response {
        bail!("UnexpectedOp");
    }
    if packet.tag != Tag::FindNodes {
        bail!("UnexpectedTag");
    }

    let frame = find_node_frame::Response::read(&mut cursor)?;

    for peer_id in frame.peer_ids {
        if let Err(err) = node.get_or_create_client(peer_id.address) {
            warn!("could not connect to peer {}: {}", peer_id, err);
            continue;
        }
    }

    Ok(())
}

fn open_tty(node: &mut Node) -> std::io::Result<()> {
    println!("Opening interactive tty...");
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut buffer = String::new();

    loop {
        buffer.clear();
        stdin.lock().read_line(&mut buffer)?;
        let command = buffer.trim_end();

        match command {
            "id" => {
                println!("{}", node.id);
            }
            "help" => {
                println!("Commands");
                println!("\thelp        Shows this menu");
                println!("\tid          Prints the ID of the current node");
                println!("\techo        Echoes a message to the terminal");
                println!("\troute       Routes a packet to the specified node");
                println!("\tpeers       Lists all nodes that the current node is connected to");
                println!("\tbroadcast   Sends a message to all connected nodes");
                println!("\texit        Terminate the current node and exit program");
            }
            cmd if cmd.starts_with("echo ") => {
                let message = &cmd[5..];
                println!("{}", message);
            }
            "peers" => {
                println!("Connected to {} peers", node.clients.len());
                for client in node.clients.values() {
                    println!("Connected to {:?}", client.lock().unwrap().peer_id);
                }
            }
            cmd if cmd.starts_with("route ") => {
                let route_data = &cmd[6..];
                let mut parts = route_data.splitn(2, ' ');
                let id = parts.next().unwrap_or("");
                let msg = parts.next().unwrap_or("");

                if id.len() != 64 {
                    println!("Error: route data must be 32 bytes long");
                    continue;
                }

                let dest_key = match hex::decode(id) {
                    Ok(bytes) if bytes.len() == 32 => {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        arr
                    }
                    _ => {
                        println!("Error: route data must be a valid hex string");
                        continue;
                    }
                };

                let next_hop_id = match Routing::next_hop(node, node.id.public_key, dest_key, &[]) {
                    Some(hop) => hop,
                    None => {
                        println!("Could not route packet to {:?}", hex::decode(dest_key));
                        continue;
                    }
                };

                let next_hop = match node.get_or_create_client(next_hop_id.address) {
                    Ok(c) => c,
                    Err(e) => {
                        println!("Error getting client: {}", e);
                        continue;
                    }
                };

                Packet {
                    op: Op::Command,
                    tag: Tag::Route,
                }
                .write(next_hop.writer())?;
                RouteFrame {
                    src: node.id.public_key,
                    dst: dest_key,
                    hops: vec![],
                }
                .write(next_hop.writer())?;

                let mut dest_conn = Connection::new(&next_hop.conn, node.keys);

                // let key_pair = KeyPair::from(&node.keys)?;
                // let remote_public_key =
                //     PublicKey::from(ed25519_dalek::VerifyingKey::from_bytes(dest_key)?)?;
                // let shared_key = x2

                dest_conn.session = Some(Routing::get_or_create_session(shared_key, key_pair)?);
            }
        }
    }
}

struct Node {
    id: ID,
    socket: Option<TcpStream>,
    address: SocketAddr,
    keys: KeyPair,
    table: RoutingTable,
    clients: HashMap<SocketAddr, Arc<Mutex<Client>>>,
    processed_nonces: HashSet<[u8; 16]>,
}

impl Node {
    pub fn new(keys: KeyPair, address: SocketAddr) -> io::Result<Self> {
        let id = ID {
            public_key: keys.public.to_bytes(),
            address,
        };

        Ok(Self {
            id,
            socket: None,
            address,
            keys: keys.clone(),
            table: RoutingTable::new(keys.public.to_bytes()),
            clients: HashMap::new(),
            processed_nonces: HashSet::new(),
        })
    }

    pub async fn bind(&mut self) -> std::io::Result<()> {
        let listener = tokio::net::TcpListener::bind(self.address);
        let local_addr = listener.await?.local_addr().unwrap();
        self.address = local_addr;
        self.id.address = local_addr;
        self.socket = Some(listener.await.unwrap());
        Ok(())
    }

    pub async fn run_accept_loop(self: Arc<Self>) -> std::io::Result<()> {
        let listener = {
            let node = self.deref();
            node.socket.as_ref().unwrap().clone()
        };

        loop {
            let (stream, addr) = listener.accept()?;
            let node_clone = self.clone();
            tokio::spawn(async move {
                if let Err(e) = node_clone.handle_client(stream, addr).await {
                    eprintln!("Error handling client {}: {:?}", addr, e);
                }
            });
        }
    }

    async fn handle_client(
        self: Arc<Self>,
        mut stream: TcpStream,
        address: SocketAddr,
    ) -> std::io::Result<()> {
        let mut buf = [0u8; 1024];
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                break;
            }

            let packet = Packet::read(&mut &buf[..n])?;
            self.deref()
                .process_packet(packet, address, &mut stream)
                .await?;
        }
        Ok(())
    }

    async fn process_packet(
        &self,
        packet: Packet,
        addr: SocketAddr,
        stream: &mut TcpStream,
    ) -> std::io::Result<()> {
        match packet.op {
            Op::Request => match packet.tag {
                Tag::Hello => {
                    // NOOP
                }
                Tag::FindNodes => {
                    // NOOP
                }
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Unexpected tag",
                    ));
                }
            },

            Op::Command => {
                match packet.tag {
                    Tag::Route => {
                        // NOOP
                    }
                    Tag::Echo => {
                        // NOOP
                    }
                    Tag::Broadcast => {
                        // NOOP
                    }
                    _ => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Unexpected tag",
                        ));
                    }
                }
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Unexpected op",
                ));
            }
        }
        Ok(())
    }

    pub fn get_or_create_client() {}

    pub fn close_client() {}
}

struct Client {
    socket: TcpStream,
    address: SocketAddr,
    conn: Connection,
    peer_id: Option<ID>,
    keys: KeyPair,
    read_task: Option<tokio::task::JoinHandle<Result<Vec<u8>, anyhow::Error>>>,
    can_read: Arc<tokio::sync::Notify>,
}

impl Client {
    pub async fn new(
        socket: TcpStream,
        address: SocketAddr,
        node_keys: KeyPair,
    ) -> anyhow::Result<Self> {
        Ok(Client {
            socket,
            address,
            conn: Connection::new(Backend::Socket(socket), node_keys),
            peer_id: None,
            keys: KeyPair::generate(),
            read_task: None,
            can_read: Arc::new(tokio::sync::Notify::new()),
        })
    }

    pub fn writer(&mut self) -> &mut BytesMut {
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
        let shared = self.keys.secret.as_bytes();

        let mut hasher = Hasher::new();
        hasher.update(shared);
        hasher.update(&nonce);
        let shared_secret = hasher.finalize();

        self.peer_id = Some(peer_id);

        let session = match key_type {
            KeyType::KeyPair(_) => Session::new(
                &encryption::random_id(),
                *shared_secret.as_bytes(),
                self.keys,
            ),
            KeyType::RemoteKey(_) => Session::new(
                &encryption::random_id(),
                *shared_secret.as_bytes(),
                self.keys,
            ),
        };

        self.conn.session = Some(Box::new(session));
        self.conn.flags |= FLAG_SIGNED | FLAG_ENCRYPTED;

        Ok(())
    }
}

pub enum KeyType {
    RemoteKey([u8; 32]),
    KeyPair(KeyPair),
}

const FLAG_SIGNED: u8 = 0x1;
const FLAG_ENCRYPTED: u8 = 0x2;

pub enum Backend {
    Socket(TcpStream),
    Connection(Box<Connection>),
}

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

            let Encrypted {
                cipher_text,
                dh,
                n,
                pn,
            } = session.encrypt((&data_to_write).to_vec());

            encryption_metadata = Some(EncryptionMetadata { dh, n, pn });
            data_to_write = cipher_text.into();
        }
        let signature_len = if is_signed { Signature::BYTE_SIZE } else { 0 };
        let metadata_len = if is_encrypted {
            EncryptionMetadata::SIZE
        } else {
            0
        };

        let packet_len = data_to_write.len() + signature_len + metadata_len;

        let mut output = BytesMut::with_capacity(5 + packet_len);

        PacketHeader {
            flags: self.flags,
            len: packet_len as u32,
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
                stream.write_all(output.freeze()).await?;
            }
            Backend::Connection(conn) => {
                conn.writer().put_slice(&output);
            }
        }

        Ok(())
    }
}

pub struct Routing {
    sessions: Mutex<HashMap<[u8; 32], Arc<Mutex<Session>>>>,
}

impl Routing {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    pub fn next_hop(
        node: &Node,
        src: [u8; 32],
        public_key: [u8; 32],
        prev_hops: &[ID],
    ) -> Option<ID> {
        if let Some(peer_id) = node.table.get(&public_key) {
            return Some(peer_id);
        }

        let mut peer_ids: [ID; 16] = [ID::default(); 16];
        let len = node.table.closest_to(&mut peer_ids, &public_key);

        for i in 0..len {
            let mut ok = true;
            for prev in prev_hops {
                if prev.public_key == src {
                    continue;
                }

                if prev == &peer_ids[i] {
                    ok = false;
                    break;
                }
            }
            if ok {
                return Some(peer_ids[i]);
            }
        }

        None
    }

    pub fn get_or_create_session(
        &self,
        key: [u8; 32],
        key_type: KeyType,
    ) -> anyhow::Result<Arc<Mutex<Session>>> {
        {
            let sessions_guard = self.sessions.lock().unwrap();
            if let Some(existing) = sessions_guard.get(&key) {
                return Ok(existing.clone());
            }
        }

        debug!("creating new session for {}", hex::encode(key));

        let session_obj = match key_type {
            KeyType::KeyPair(kp) => init(&encryption::random_id(), key, kp),
            KeyType::RemoteKey(remote_key) => {
                encryption::init_remote_key(&encryption::random_id(), key, remote_key)
            }
        };

        let arc_session = Arc::new(Mutex::new(session_obj));

        let mut sessions_guard = self.sessions.lock().unwrap();

        if let Some(existing) = sessions_guard.get(&key) {
            return Ok(existing.clone());
        }
        sessions_guard.insert(key, arc_session.clone());
        Ok(arc_session)
    }
}

pub struct SigningWriter<W: Write> {
    underlying_stream: W,
    signer: SigningKey,
    buffer: Vec<u8>,
}

impl<W: Write> SigningWriter<W> {
    pub fn new(underlying_stream: W, signer: SigningKey) -> Self {
        Self {
            underlying_stream,
            signer,
            buffer: Vec::new(),
        }
    }

    pub fn inner_mut(&mut self) -> &mut W {
        &mut self.underlying_stream
    }

    pub fn sign(mut self) -> io::Result<()> {
        let signature: Signature = self.signer.sign(&self.buffer);
        self.underlying_stream.write_all(signature.s_bytes())?;
        Ok(())
    }
}

impl<W: Write> Write for SigningWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        self.underlying_stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.underlying_stream.flush()
    }
}
