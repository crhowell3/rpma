use anyhow::bail;
use blake3::Hasher;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use clap::{Parser, arg};
use ed25519_dalek::ed25519::signature::SignerMut;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use encryption::{Encrypted, Session};
use kademlia::{ID, PutResult, RoutingTable};
use log::{debug, error, info, warn};
use net::frame::{self, find_node_frame};
use net::packet::{EncryptionMetadata, Op, Packet, PacketHeader, Tag};
use rand::RngCore;
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::io::{self, BufRead};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex as AsyncMutex;

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
    rand::thread_rng().fill_bytes(&mut seed);
    let signing = SigningKey::from_bytes(&seed);

    let node = Arc::new(Node::bind(signing, listen_addr).await?);
    {
        let n = node.clone();
        tokio::spawn(async move {
            if let Err(e) = n.run_accept_loop().await {
                eprintln!("Error in accept loop: {e:?}");
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

pub async fn bootstrap_node_with_peer(node: Arc<Node>, peer: SocketAddr) -> anyhow::Result<()> {
    let mut stream = TcpStream::connect(peer).await?;

    let wbuf = bytes::BytesMut::with_capacity(1024);
    Packet {
        op: Op::Request,
        tag: Tag::FindNodes,
    }
    .write(&mut wbuf.clone().writer())?;

    net::frame::find_node_frame::Request {
        public_key: node.id.public_key,
    }
    .write(&mut wbuf.clone().writer())?;
    stream.write_all(&wbuf).await?;

    let mut rbuf = vec![0u8; 16 * 1024];
    let n = stream.read(&mut rbuf).await?;
    if n == 0 {
        bail!("bootstrap: peer {peer} closed the connection");
    }
    let mut cur = &rbuf[..n];

    let pkt = Packet::read(&mut cur)?;
    if pkt.op != Op::Response || pkt.tag != Tag::FindNodes {
        bail!(
            "bootstrap: unexpected response from {peer}: op={:?} tag={:?}",
            pkt.op,
            pkt.tag
        );
    }

    let rsp = find_node_frame::Response::read(&mut cur)?;

    {
        let mut table = node.table.write().unwrap();
        for id in &rsp.peer_ids {
            match table.put(*id) {
                PutResult::Full => {}
                PutResult::Inserted => info!("bootstrap: added {}", id.address),
                PutResult::Updated => info!("bootstrap: updated {}", id.address),
            }
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
                println!("{message}");
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
    keys: Arc<KeyPair>,
    table: RwLock<RoutingTable>,
    clients: AsyncMutex<HashMap<SocketAddr, Arc<AsyncMutex<Client>>>>,
    processed_nonces: AsyncMutex<HashSet<[u8; 16]>>,
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
            keys: Arc::new(KeyPair::generate()),
            table: RwLock::new(RoutingTable::new(verifier.to_bytes())),
            clients: AsyncMutex::new(HashMap::new()),
            processed_nonces: AsyncMutex::new(HashSet::new()),
            routing: Routing::new(),
        })
    }

    pub async fn run_accept_loop(self: Arc<Self>) -> std::io::Result<()> {
        loop {
            let (stream, addr) = self.listener.accept().await?;
            let me = std::sync::Arc::clone(&self);

            tokio::spawn(async move {
                let (reader, writer) = stream.into_split();

                if let Err(e) = me.register_client(addr, writer).await {
                    error!("get_or_create_client error for {addr}: {e:?}");
                    return;
                }

                if let Err(e) = me.run_read_loop(reader, addr).await {
                    warn!("read loop error from {addr}: {e:?}");
                }
            });
        }
    }

    pub async fn run_read_loop(
        self: Arc<Self>,
        mut reader: OwnedReadHalf,
        addr: SocketAddr,
    ) -> io::Result<()> {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let mut cursor = &buf[..n];

            while cursor.has_remaining() {
                let pkt = Packet::read(&mut cursor)?;
                let tail = &buf[(n - cursor.remaining())..n];
                self.handle_node_packet(addr, pkt, tail).await?;
            }
        }

        Ok(())
    }

    async fn configure_peer_after_hello(
        &self,
        client: &mut Client,
        remote_peer: ID,
        remote_ephemeral_pk: [u8; 32],
        local_nonce: [u8; 16],
        remote_nonce: [u8; 16],
    ) -> io::Result<()> {
        let mut hasher = Hasher::new();

        hasher.update(&remote_peer.public_key);
        hasher.update(&self.id.public_key);
        hasher.update(&remote_ephemeral_pk);
        hasher.update(&local_nonce);
        hasher.update(&remote_nonce);
        let digest = hasher.finalize();

        let mut shared_key = [0u8; 32];
        shared_key.copy_from_slice(digest.as_bytes());

        let session = self
            .routing
            .get_or_create_session(shared_key, KeyType::KeyPair((*self.keys).clone()))
            .await;
        client.conn.session = Some(session);
        Ok(())
    }

    async fn handle_node_packet(
        self: &Arc<Self>,
        client_addr: SocketAddr,
        packet: Packet,
        raw_tail: &[u8],
    ) -> io::Result<()> {
        match packet.op {
            Op::Request => match packet.tag {
                Tag::Hello => {
                    let mut rdr = io::Cursor::new(raw_tail);
                    let hello = frame::HelloFrame::read(&mut rdr).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "data incorrect")
                    })?;

                    // Read trailing signature
                    let sig_bytes = {
                        let mut s = [0u8; Signature::BYTE_SIZE];
                        std::io::Read::read_exact(&mut rdr, &mut s)?;
                        s
                    };

                    // Verify signature
                    let sig = Signature::from_bytes(&sig_bytes);
                    let to_verify = &raw_tail[..raw_tail.len() - Signature::BYTE_SIZE];
                    let peer_vk =
                        VerifyingKey::from_bytes(&hello.peer_id.public_key).map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidData, "invalid public key")
                        })?;
                    peer_vk.verify_strict(to_verify, &sig).map_err(|_| {
                        io::Error::new(io::ErrorKind::PermissionDenied, "bad hello signature")
                    })?;

                    {
                        let mut table = self.table.write().unwrap();
                        match table.put(hello.peer_id) {
                            PutResult::Full => info!("hello: table full; peer ignored"),
                            PutResult::Updated => info!("hello: peer updated"),
                            PutResult::Inserted => info!("hello: peer registered"),
                        }
                    }

                    let client_arc = {
                        let map = self.clients.lock().await;
                        map.get(&client_addr).cloned().ok_or_else(|| {
                            io::Error::new(io::ErrorKind::NotFound, "client not found")
                        })?
                    };

                    let mut client = client_arc.lock().await;
                    client.peer_id = Some(hello.peer_id);

                    let mut local_nonce = [0u8; 16];
                    rand::thread_rng().fill_bytes(&mut local_nonce);

                    client.conn.set_signed(true);
                    client.conn.set_encrypted(false);

                    {
                        let mut w = client.writer().writer();
                        Packet {
                            op: Op::Response,
                            tag: Tag::Hello,
                        }
                        .write(&mut w)?;

                        frame::HelloFrame {
                            peer_id: self.id,
                            public_key: self.id.public_key,
                            nonce: local_nonce,
                        }
                        .write(&mut w)?;
                    }

                    client.flush().await?;

                    self.configure_peer_after_hello(
                        &mut client,
                        hello.peer_id,
                        hello.public_key,
                        local_nonce,
                        hello.nonce,
                    )
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                }
                Tag::FindNodes => {
                    let mut rdr = io::Cursor::new(raw_tail);
                    let q = find_node_frame::Request::read(&mut rdr).map_err(|e| {
                        io::Error::new(io::ErrorKind::InvalidData, format!("bad FindNodes: {e}"))
                    })?;

                    let (peers_vec, _n) = {
                        let table = self.table.read().unwrap();
                        let mut peers: [ID; 16] = [ID::default(); 16];
                        let n = table.closest_to(&mut peers, &q.public_key);
                        (peers[..n].to_vec(), n)
                    };

                    let client_arc = {
                        let map = self.clients.lock().await;
                        map.get(&client_addr).cloned().ok_or_else(|| {
                            io::Error::new(io::ErrorKind::NotFound, "client not found")
                        })?
                    };

                    let mut client = client_arc.lock().await;
                    {
                        let mut w = client.writer().writer();
                        Packet {
                            op: Op::Response,
                            tag: Tag::FindNodes,
                        }
                        .write(&mut w)?;
                        find_node_frame::Response {
                            peer_ids: peers_vec,
                        }
                        .write(&mut w)?;
                        let _ = w.into_inner();
                    }
                    client.flush().await?;
                }
                _ => {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "Unexpected tag"));
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

    async fn register_client(&self, addr: SocketAddr, writer: OwnedWriteHalf) -> io::Result<()> {
        let mut map = self.clients.lock().await;
        if !map.contains_key(&addr) {
            let client = Arc::new(AsyncMutex::new(Client::new(
                addr,
                writer,
                self.signer.clone(),
            )));
            map.insert(addr, client);
        }

        Ok(())
    }

    pub async fn get_or_create_client(
        &mut self,
        addr: SocketAddr,
        writer: OwnedWriteHalf,
    ) -> io::Result<Arc<AsyncMutex<Client>>> {
        if let Some(c) = self.clients.lock().await.get(&addr) {
            return Ok(c.clone());
        }
        let client = Arc::new(AsyncMutex::new(Client::new(
            addr,
            writer,
            self.signer.clone(),
        )));
        self.clients.lock().await.insert(addr, client.clone());
        Ok(client)
    }
}

struct Client {
    address: SocketAddr,
    writer: Arc<AsyncMutex<OwnedWriteHalf>>,
    conn: Connection,
    peer_id: Option<ID>,
    read_notify: Arc<tokio::sync::Notify>,
}

impl Client {
    pub fn new(address: SocketAddr, writer: OwnedWriteHalf, node_signer: SigningKey) -> Self {
        let writer = Arc::new(AsyncMutex::new(writer));
        let conn = Connection {
            write_buffer: bytes::BytesMut::with_capacity(2048),
            backend: Backend::Socket(writer.clone()),
            flags: 0,
            node_signer,
            session: None,
        };

        Self {
            address,
            writer,
            conn,
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
    Socket(Arc<AsyncMutex<OwnedWriteHalf>>),
    Buffer(Arc<Mutex<BytesMut>>),
}

struct Connection {
    pub write_buffer: BytesMut,
    pub backend: Backend,
    pub flags: u8,
    pub node_signer: SigningKey,
    pub session: Option<Arc<AsyncMutex<Session>>>,
}

impl Connection {
    fn new_socket(writer: Arc<AsyncMutex<OwnedWriteHalf>>, node_signer: SigningKey) -> Self {
        Self {
            write_buffer: BytesMut::with_capacity(2048),
            backend: Backend::Socket(writer),
            flags: 0,
            node_signer,
            session: None,
        }
    }

    fn new_nested(parent_buf: Arc<Mutex<BytesMut>>, node_signer: SigningKey) -> Self {
        Self {
            write_buffer: BytesMut::with_capacity(2048),
            backend: Backend::Buffer(parent_buf),
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
            let mut session_guard = self
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
            } = session_guard.encrypt(payload.to_vec());

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
        {
            let mut w = out.writer();
            PacketHeader {
                flags: self.flags,
                len: packet_len as u32,
            }
            .write(&mut w)?;

            if let Some(meta) = &encryption_metadata {
                meta.write(&mut w)?;
            }

            std::io::Write::write_all(&mut w, &payload)?;
            out = w.into_inner();
        }

        if (self.flags & 0x1) != 0 {
            let msg = &out[5..];
            let sig = self.node_signer.sign(msg);
            out.extend_from_slice(&sig.to_bytes());
        }

        debug_assert_eq!(out.len(), 5 + packet_len);

        match &mut self.backend {
            Backend::Socket(writer_arc) => {
                let mut writer = writer_arc.lock().await;
                writer.write_all(&out).await?;
            }
            Backend::Buffer(parent) => {
                let mut parent_buf = parent.lock().unwrap();
                parent_buf.put_slice(&out);
            }
        }

        Ok(())
    }
}

pub struct Routing {
    sessions: Mutex<HashMap<[u8; 32], Arc<AsyncMutex<Session>>>>,
}

impl Routing {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    pub fn next_hop(node: &Node, src: [u8; 32], dst: [u8; 32], prev_hops: &[ID]) -> Option<ID> {
        {
            let table = node.table.read().unwrap();
            if let Some(peer_id) = table.get(&dst) {
                return Some(peer_id);
            }
        }

        let mut candidates: [ID; 16] = [ID::default(); 16];
        let len = node.table.read().unwrap().closest_to(&mut candidates, &dst);
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

    pub async fn get_or_create_session(
        &self,
        key: [u8; 32],
        key_type: KeyType,
    ) -> Arc<AsyncMutex<Session>> {
        if let Some(existing) = self.sessions.lock().unwrap().get(&key) {
            return existing.clone();
        }

        let session = match key_type {
            KeyType::KeyPair(kp) => Session::new(&[], key, kp),
            KeyType::RemoteKey(remote_key) => {
                Session::init_remote_key((&[]).to_vec(), key, remote_key)
            }
        };

        let arc = Arc::new(AsyncMutex::new(session));
        self.sessions.lock().unwrap().insert(key, arc.clone());
        arc
    }
}
