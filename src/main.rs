use anyhow::bail;
use blake3::{Hash, Hasher};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use clap::{Parser, arg};
use ed25519_dalek::ed25519::signature::SignerMut;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use encryption::{Encrypted, Session};
use kademlia::{ID, PutResult, RoutingTable};
use log::{debug, info, warn};
use net::frame::{self, RouteFrame, find_node_frame};
use net::packet::{EncryptionMetadata, Op, Packet, PacketHeader, Tag};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::io::{self, BufRead};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

mod encryption;
mod kademlia;
mod net;

use crate::encryption::KeyPair;

#[derive(Parser)]
#[command(name = "rpma", version)]
struct Args {
    #[arg(long)]
    listen_addr: String,
    #[arg(long)]
    interactive: bool,
    #[arg(trailing_var_arg = true)]
    peer: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let args = Args::parse();

    let listen_addr: SocketAddr = args.listen_addr.parse()?;

    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)?;
    let signing = SigningKey::from_bytes(&seed);

    let node = Arc::new(Node::bind(signing, listen_addr).await?);
    {
        let n = node.clone();
        tokio::spawn(async move {
            if let Err(e) = n.run_accept_loop().await {
                eprintln!("Error in accept loop: {:?}", e);
            }
        });
    }

    for p in args.peer {
        if let Ok(addr) = p.parse() {
            if let Err(e) = bootstrap_node_with_peer(node.clone(), addr).await {
                warn!("bootstrap failed: {e:#}");
            }
        }
    }

    if args.interactive {
        open_tty(node.clone()).await?;
    }

    futures::future::pending::<()>().await;
    #[allow(unreachable_code)]
    Ok(())
}

pub struct BytesMutWriter<'a> {
    buf: &'a mut BytesMut,
}

impl<'a> Write for BytesMutWriter<'a> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub async fn bootstrap_node_with_peer(node: Arc<Node>, peer: SocketAddr) -> anyhow::Result<()> {
    let stream = TcpStream::connect(peer).await?;
    let client = node.get_or_create_client(peer, stream.try_clone()?).await?;

    {
        let mut c = client.lock().await;
        Packet {
            op: Op::Request,
            tag: Tag::FindNodes,
        }
        .write(c.writer())?;
        find_node_frame::Request {
            public_key: node.id.public_key,
        }
        .write(c.writer())?;
        c.flush().await?;
    }

    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        bail!("peer closed");
    }

    let mut cur = &buf[..n];
    let pkt = Packet::read(&mut cur)?;
    if pkt.op != Op::Response || pkt.tag != Tag::FindNodes {
        bail!("unexpected response");
    }
    let rsp = find_node_frame::Response::read(&mut cur)?;
    for id in &rsp.peer_ids {
        match node.table.put(*id) {
            PutResult::Full => {}
            PutResult::Updated => info!("bootstrap: updated {}", id.address),
            PutResult::Inserted => info!("bootstrap: added {}", id.address),
        }
    }

    Ok(())
}

async fn open_tty(node: Arc<Node>) -> std::io::Result<()> {
    println!("Opening interactive tty...");
    let mut line = String::new();
    let stdin = io::stdin();
    loop {
        line.clear();
        if stdin.lock().read_line(&mut line).is_err() {
            continue;
        }
        let cmd = line.trim();

        match cmd {
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
                println!("Connected to {} peers", node.clients.lock().await.len());
                for client in node.clients.lock().await.values() {
                    println!("Connected to {:?}", client.lock().await.peer_id);
                }
            }
            cmd if cmd.starts_with("route ") => {
                let dst_hex = cmd.split_whitespace().nth(1).unwrap_or_default();
                if dst_hex.len() != 64 {
                    println!("need 32-byte hex public key");
                    continue;
                }
                let dst = [0u8; 32];
                if let Some(next) = Routing::next_hop(&node, node.id.public_key, dst, &[]) {
                    println!("next hop: {} -> {}", hex::encode(dst), next.address);
                } else {
                    println!("no route");
                }
            }
            _ => {}
        }
    }
}

struct Node {
    id: ID,
    address: SocketAddr,
    listener: TcpListener,
    signer: SigningKey,
    verifier: VerifyingKey,
    table: RoutingTable,
    clients: Mutex<HashMap<SocketAddr, Arc<Mutex<Client>>>>,
    processed_nonces: Mutex<HashSet<[u8; 16]>>,
    routing: Routing,
}

impl Node {
    pub async fn bind(signer: SigningKey, address: SocketAddr) -> std::io::Result<Self> {
        let listener = TcpListener::bind(address).await?;
        let verifier = signer.verifying_key();
        let id = ID {
            public_key: verifier.to_bytes(),
            address,
        };

        Ok(Self {
            id,
            address,
            listener,
            signer,
            verifier,
            table: RoutingTable::new(verifier.to_bytes()),
            clients: Mutex::new(HashMap::new()),
            processed_nonces: Mutex::new(HashSet::new()),
            routing: Routing::new(),
        })
    }

    pub async fn run_accept_loop(self: Arc<Self>) -> std::io::Result<()> {
        loop {
            let (stream, addr) = self.listener.accept().await?;
            let me = self.clone();
            tokio::spawn(async move {
                if let Err(e) = me.run_read_loop(stream, addr).await {
                    warn!("read loop error from {}: {e:?}", addr);
                }
            });
        }
    }

    pub async fn run_read_loop(
        self: Arc<Self>,
        mut stream: TcpStream,
        addr: SocketAddr,
    ) -> io::Result<()> {
        let client_arc = self.get_or_create_client(addr, stream.try_clone()?).await?;

        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let mut cursor = &buf[..n];

            while cursor.remaining() > 0 {
                let pkt = Packet::read(&mut cursor)?;
                self.handle_node_packet(client_arc.clone(), pkt, cursor.chunk(), &mut stream)
                    .await?;
                break;
            }
        }

        Ok(())
    }

    async fn handle_node_packet(
        self: &Arc<Self,
        client_arc: Arc<Mutex<Client>>,
        packet: Packet,
        raw_tail: &[u8],
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

    pub async fn get_or_create_client(
        &mut self,
        addr: SocketAddr,
        stream: TcpStream,
    ) -> io::Result<Arc<Mutex<Client>>> {
        if let Some(c) = self.clients.lock().await.get(&addr) {
            return Ok(c.clone());
        }
        let client = Arc::new(Mutex::new(Client::new(stream, addr, self.signer.clone())));
        self.clients.lock().insert(addr, client.clone());
        Ok(client)
    }
}

struct Client {
    stream: TcpStream,
    address: SocketAddr,
    conn: Connection,
    peer_id: Option<ID>,
    read_notify: Arc<tokio::sync::Notify>,
}

impl Client {
    pub fn new(stream: TcpStream, address: SocketAddr, node_signer: SigningKey) -> Self {
        Self {
            stream,
            address,
            conn: Connection::new_socket(stream.clone(), node_signer),
            peer_id: None,
            read_notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    pub fn writer(&mut self) -> &mut BytesMut {
        self.conn.writer()
    }

    pub async fn flush(&mut self) -> std::io::Result<()> {
        self.conn.flush().await
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
    Connection(*mut Connection),
}

struct Connection {
    pub write_buffer: BytesMut,
    pub backend: Backend,
    pub flags: u8,
    pub node_signer: SigningKey,
    pub session: Option<Arc<Mutex<Session>>>,
}

impl Connection {
    fn new_socket(stream: TcpStream, node_signer: SigningKey) -> Self {
        Self {
            write_buffer: BytesMut::with_capacity(2048),
            backend: Backend::Socket(stream),
            flags: 0,
            node_signer,
            session: None,
        }
    }

    fn new_nested(conn: *mut Connection, node_signer: SigningKey) -> Self {
        Self {
            write_buffer: BytesMut::with_capacity(2048),
            backend: Backend::Connection(conn),
            flags: 0,
            node_signer,
            session: None,
        }
    }

    pub fn writer(&mut self) -> &mut BytesMut {
        &mut self.write_buffer
    }

    fn set_signed(&mut self, v: bool) {
        if v {
            self.flags |= 0x1
        } else {
            self.flags &= !0x1
        }
    }

    fn set_encrypted(&mut self, v: bool) {
        if v {
            self.flags |= 0x2
        } else {
            self.flags &= !0x2
        }
    }

    pub async fn flush(&mut self) -> io::Result<()> {
        debug!("flushing with flags 0x{:02x}", self.flags);

        if self.write_buffer.is_empty() {
            return Ok(());
        }

        let mut payload = self.write_buffer.split().freeze();

        let mut encryption_metadata: Option<EncryptionMetadata> = None;

        if (self.flags & 0x2) != 0 {
            let session = self
                .session
                .as_ref()
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Missing session"))?
                .lock()
                .await;

            let Encrypted {
                cipher_text,
                dh,
                n,
                pn,
            } = session.encrypt(payload.to_vec());

            encryption_metadata = Some(EncryptionMetadata { dh, n, pn });
            payload = Bytes::from(cipher_text);
        }

        let signature_len = if (self.flags & 0x1) != 0 {
            Signature::BYTE_SIZE
        } else {
            0
        };
        let metadata_len = if encryption_metadata.is_some() {
            EncryptionMetadata::SIZE
        } else {
            0
        };
        let packet_len = payload.len() + signature_len + metadata_len;

        let mut out = BytesMut::with_capacity(5 + packet_len);
        PacketHeader {
            flags: self.flags,
            len: packet_len as u32,
        }
        .write(&mut out)?;

        if let Some(meta) = &encryption_metadata {
            meta.write(&mut out)?;
        }

        out.extend_from_slice(&payload);

        if (self.flags & 0x1) != 0 {
            let msg = &out[5..];
            let sig = self.node_signer.sign(msg);
            out.extend_from_slice(&sig.to_bytes());
        }

        debug_assert_eq!(out.len(), 5 + packet_len);

        match &mut self.backend {
            Backend::Socket(stream) => {
                stream.write_all(&out).await?;
            }
            Backend::Connection(conn) => unsafe {
                (**conn).writer().put_slice(&out);
            },
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

    pub fn next_hop(node: &Node, src: [u8; 32], dst: [u8; 32], prev_hops: &[ID]) -> Option<ID> {
        if let Some(peer_id) = node.table.get(&dst) {
            return Some(peer_id);
        }

        let mut candidates: [ID; 16] = [ID::default(); 16];
        let len = node.table.closest_to(&mut candidates, &dst);

        for i in 0..len {
            let mut ok = true;
            for prev in prev_hops {
                if prev.public_key == src {
                    continue;
                }

                if prev == &candidates[i] {
                    ok = false;
                    break;
                }
            }
            if ok {
                return Some(candidates[i]);
            }
        }

        None
    }

    pub async fn get_or_create_session(&self, shared: [u8; 32]) -> Arc<Mutex<Session>> {
        let mut guard = self.sessions.lock().await;
        guard
            .entry(shared)
            .or_insert_with(|| Arc::new(Mutex::new(Session::new(shared))))
            .clone()
    }
}
