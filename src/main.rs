#![warn(unused_extern_crates, unused_imports, unused_variables)]
#![warn(dead_code)]

use blake3::Hasher;
use bytes::{BufMut, Bytes, BytesMut};
use clap::{Parser, arg};
use ed25519_dalek::ed25519::signature::SignerMut;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use encryption::{Encrypted, Session};
use env_logger::Env;
use kademlia::{ID, PutResult, RoutingTable};
use log::{debug, error, info, warn};
use net::frame::{self, find_node_frame};
use net::packet::{EncryptionMetadata, Op, Packet, PacketHeader, Tag};
use rand::RngCore;
use rustyline::{Editor, error::ReadlineError};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::io::{self};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::mpsc;

mod encryption;
mod kademlia;
mod net;

use crate::encryption::KeyPair;
use once_cell::sync::OnceCell;
static LOG_TX: OnceCell<tokio::sync::mpsc::UnboundedSender<String>> = OnceCell::new();

struct ChannelLogger;

impl log::Log for ChannelLogger {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }
    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        // Suppress rustyline debug logs
        if record.level() == log::Level::Debug && record.target().starts_with("rustyline") {
            return;
        }
        if let Some(tx) = LOG_TX.get() {
            let msg = format!("[{}] {}", record.level(), record.args());
            let _ = tx.send(msg);
        }
    }
    fn flush(&self) {}
}

#[derive(Parser)]
#[command(name = "rpma", version)]
struct Args {
    #[arg(long, short('l'))]
    listen_addr: String,
    #[arg(long, short('i'))]
    interactive: bool,
    #[arg(long, short('p'))]
    peers: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
                error!("Error in accept loop: {e:?}");
            }
        });
    }

    for p in args.peers {
        if let Ok(addr) = p.parse() {
            let n = node.clone();
            tokio::spawn(async move {
                if let Err(e) = n.connect_and_register(addr).await {
                    warn!("connect to {addr} failed: {e:?}");
                }
            });
        }
    }

    if args.interactive {
        let (tx, rx) = mpsc::unbounded_channel::<String>();
        LOG_TX.set(tx.clone()).ok();
        log::set_boxed_logger(Box::new(ChannelLogger)).unwrap();
        log::set_max_level(log::LevelFilter::Debug);
        open_tty(node.clone(), tx, rx).await?;
    } else {
        env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();
        let (dummy_tx, dummy_rx) = mpsc::unbounded_channel::<String>();
        open_tty(node.clone(), dummy_tx, dummy_rx).await?;
    }

    futures::future::pending::<()>().await;
    #[allow(unreachable_code)]
    Ok(())
}

async fn open_tty(
    node: Arc<Node>,
    tx: mpsc::UnboundedSender<String>,
    mut rx: mpsc::UnboundedReceiver<String>,
) -> std::io::Result<()> {
    let mut rl = Editor::<(), rustyline::history::MemHistory>::with_history(
        rustyline::Config::default(),
        rustyline::history::MemHistory::new(),
    )
    .unwrap();
    println!("Opening interactive tty...");

    loop {
        // Print any pending output before showing prompt
        while let Ok(msg) = rx.try_recv() {
            println!("\x1b[1;34m[OUT]\x1b[0m {}", msg); // Blue color for output
        }

        let readline = rl.readline("\x1b[1;32m>>> "); // Green prompt
        match readline {
            Ok(line) => {
                let _ = rl.add_history_entry(line.as_str());
                let cmd = line.trim();
                match cmd {
                    "id" | "whoami" => {
                        tx.send(format!("Node ID: {}", node.id)).unwrap();
                    }
                    "help" => {
                        tx.send("Commands".to_string()).unwrap();
                        tx.send("  help        Shows this menu".to_string())
                            .unwrap();
                        tx.send("  whoami      Prints the ID of the current node".to_string())
                            .unwrap();
                        tx.send("  id          Alias for 'whoami'".to_string())
                            .unwrap();
                        tx.send("  echo        Echoes a message to the terminal".to_string())
                            .unwrap();
                        tx.send("  route       Routes a packet to the specified node".to_string())
                            .unwrap();
                        tx.send(
                            "  peers       Lists all nodes that the current node is connected to"
                                .to_string(),
                        )
                        .unwrap();
                        tx.send("  broadcast   Sends a message to all connected nodes".to_string())
                            .unwrap();
                        tx.send(
                            "  exit        Terminate the current node and exit program".to_string(),
                        )
                        .unwrap();
                    }
                    cmd if cmd.starts_with("echo ") => {
                        let message = &cmd[5..];
                        tx.send(message.to_string()).unwrap();
                    }
                    "peers" => {
                        let map = node.clients.lock().await;
                        tx.send(format!("Connected to {} peers", map.len()))
                            .unwrap();
                        for client in map.values() {
                            let c = client.lock().await;
                            tx.send(format!(
                                "  Connected to peer with id {}",
                                c.peer_id.unwrap()
                            ))
                            .unwrap();
                        }
                    }
                    cmd if cmd.starts_with("route ") => {
                        let dst_hex = cmd.split_whitespace().nth(1).unwrap_or_default();
                        if dst_hex.len() != 64 {
                            tx.send("need 32-byte hex public key".to_string()).unwrap();
                            continue;
                        }
                        let dst = [0u8; 32];
                        if let Some(next) = Routing::next_hop(&node, node.id.public_key, dst, &[]) {
                            tx.send(format!(
                                "next hop: {} -> {}",
                                hex::encode(dst),
                                next.address
                            ))
                            .unwrap();
                        } else {
                            tx.send("no route".to_string()).unwrap();
                        }
                    }
                    cmd if cmd.starts_with("broadcast ") => {
                        let message = &cmd.as_bytes()["broadcast ".len()..];
                        node.broadcast_to_connected(message, 4).await;
                        tx.send("broadcast enqueued to connected peers".to_string())
                            .unwrap();
                    }
                    "exit" => {
                        tx.send("Bye!".to_string()).unwrap();
                        std::process::exit(0);
                    }
                    _ => {}
                }
            }
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                tx.send("Bye!".to_string()).unwrap();
                return Ok(());
            }
            Err(err) => {
                tx.send(format!("Error: {:?}", err)).unwrap();
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed",
                ));
            }
        }
    }
}

struct Node {
    id: ID,
    #[allow(dead_code)]
    address: SocketAddr,
    listener: TcpListener,
    signer: SigningKey,
    #[allow(dead_code)]
    verifier: VerifyingKey,
    keys: Arc<KeyPair>,
    table: RwLock<RoutingTable>,
    clients: AsyncMutex<HashMap<SocketAddr, Arc<AsyncMutex<Client>>>>,
    processed_nonces: AsyncMutex<HashSet<[u8; 16]>>,
    routing: Routing,
}

const HEADER_SIZE: usize = PacketHeader::SIZE;

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

    async fn send_hello(&self, client: &mut Client) -> std::io::Result<()> {
        let local_nonce = frame::random_nonce();

        client.conn.set_signed(true);
        client.conn.set_encrypted(false);

        {
            let mut w = client.writer().writer();
            Packet {
                op: Op::Request,
                tag: Tag::Hello,
            }
            .write(&mut w)?;
            frame::HelloFrame {
                peer_id: self.id,
                public_key: self.id.public_key,
                nonce: local_nonce,
            }
            .write(&mut w)?;
            let _ = w.into_inner();
        }

        client.flush().await?;

        Ok(())
    }

    pub async fn run_accept_loop(self: Arc<Self>) -> std::io::Result<()> {
        loop {
            let (stream, addr) = self.listener.accept().await?;
            log::info!("accept: connection from {addr}");
            let me = std::sync::Arc::clone(&self);

            tokio::spawn(async move {
                let (reader, writer) = stream.into_split();

                if let Err(e) = me.register_client(addr, writer).await {
                    error!("register_client error for {addr}: {e:?}");
                    return;
                }

                log::info!("accept: registered {addr}, spawning read loop");

                if let Err(e) = me.run_read_loop(reader, addr).await {
                    warn!("read loop error from {addr}: {e:?}");
                }
            });
        }
    }

    async fn broadcast_to_connected(&self, msg: &[u8], ttl: u8) {
        // make a nonce
        let mut nonce = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        let b = net::frame::BroadcastFrame {
            src: self.id.public_key,
            nonce,
            ts: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i128,
            n: ttl,
        };
        log::debug!(
            "broadcast SEND: nonce={} ttl={} msg_bytes={:?}",
            hex::encode(nonce),
            ttl,
            msg
        );

        let map = self.clients.lock().await;
        for (addr, client_arc) in map.iter() {
            let mut client = client_arc.lock().await;
            client.conn.set_encrypted(false);
            client.conn.set_signed(true);

            let mut w = client.writer().writer();
            if let Err(e) = (|| -> std::io::Result<()> {
                Packet {
                    op: Op::Command,
                    tag: Tag::Broadcast,
                }
                .write(&mut w)?;
                b.write(&mut w)?;
                // Write 2-byte length prefix (big-endian)
                let msg_len = msg.len() as u16;
                w.write_all(&msg_len.to_be_bytes())?;
                w.write_all(msg)?;
                Ok(())
            })() {
                log::debug!("broadcast: build {} failed: {e:?}", addr);
                continue;
            }
            let _ = w.into_inner();

            if let Err(e) = client.flush().await {
                log::debug!("broadcast: flush {} failed: {e:?}", addr);
            }
        }
    }

    pub async fn run_read_loop(
        self: Arc<Self>,
        mut reader: OwnedReadHalf,
        addr: SocketAddr,
    ) -> io::Result<()> {
        let mut buffer = vec![0u8; 16 * 1024];

        loop {
            let n = reader.read(&mut buffer).await?;
            if n == 0 {
                break;
            }

            let mut i = 0;
            while i + HEADER_SIZE <= n {
                let mut header_cursor = io::Cursor::new(&buffer[i..i + HEADER_SIZE]);
                let header = PacketHeader::read(&mut header_cursor).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("bad header: {e}"))
                })?;
                let body_len = header.len as usize;
                let frame_total = HEADER_SIZE + body_len;

                if i + frame_total > n {
                    break;
                }

                let body = &buffer[i + HEADER_SIZE..i + frame_total];

                let mut pkt_cur = io::Cursor::new(body);
                let pkt = Packet::read(&mut pkt_cur).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("bad packet: {e}"))
                })?;

                let tail_start = pkt_cur.position() as usize;
                let raw_tail = &body[tail_start..];

                self.handle_node_packet(addr, pkt, raw_tail).await?;

                i += frame_total;
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
                    let mut cursor = io::Cursor::new(raw_tail);
                    let hello = frame::HelloFrame::read(&mut cursor).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "bad hello frame")
                    })?;

                    let signed_len = cursor.position() as usize;

                    // Read trailing signature
                    let mut sig_bytes = [0u8; Signature::BYTE_SIZE];
                    io::Read::read_exact(&mut cursor, &mut sig_bytes)?;
                    let sig = Signature::from_bytes(&sig_bytes);

                    let mut prefix = Vec::with_capacity(2);
                    Packet {
                        op: packet.op,
                        tag: packet.tag,
                    }
                    .write(&mut prefix)?;

                    let mut to_verify_buffer = Vec::with_capacity(2 + signed_len);
                    to_verify_buffer.extend_from_slice(&prefix);
                    to_verify_buffer.extend_from_slice(&raw_tail[..signed_len]);

                    // Verify signature
                    let peer_vk =
                        VerifyingKey::from_bytes(&hello.peer_id.public_key).map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidData, "invalid public key")
                        })?;
                    peer_vk
                        .verify_strict(&to_verify_buffer, &sig)
                        .map_err(|_| {
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

                    let local_nonce = frame::random_nonce();

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
                        let _ = w.into_inner();
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
                    .map_err(io::Error::other)?;
                }
                Tag::FindNodes => {
                    let mut cursor = io::Cursor::new(raw_tail);
                    let q = find_node_frame::Request::read(&mut cursor).map_err(|e| {
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
            Op::Response => match packet.tag {
                Tag::Hello => {
                    let mut cursor = io::Cursor::new(raw_tail);

                    let hello = frame::HelloFrame::read(&mut cursor).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "bad hello frame")
                    })?;

                    let mut sig_bytes = [0u8; Signature::BYTE_SIZE];
                    io::Read::read_exact(&mut cursor, &mut sig_bytes)?;
                    let sig = Signature::from_bytes(&sig_bytes);

                    let sig_len = Signature::BYTE_SIZE;
                    let hello_payload = &raw_tail[..raw_tail.len() - sig_len];

                    let mut prefix = [0u8; 2];
                    {
                        let mut v = Vec::with_capacity(2);
                        Packet {
                            op: Op::Response,
                            tag: Tag::Hello,
                        }
                        .write(&mut v)?;
                        prefix.copy_from_slice(&v[..2]);
                    }

                    let mut to_verify_buffer = Vec::with_capacity(2 + hello_payload.len());
                    to_verify_buffer.extend_from_slice(&prefix);
                    to_verify_buffer.extend_from_slice(hello_payload);

                    let peer_vk =
                        VerifyingKey::from_bytes(&hello.peer_id.public_key).map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidData, "invalid public key")
                        })?;
                    peer_vk
                        .verify_strict(&to_verify_buffer, &sig)
                        .map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "bad hello signature {resp}",
                            )
                        })?;

                    {
                        let mut table = self.table.write().unwrap();
                        match table.put(hello.peer_id) {
                            PutResult::Full => info!(""),
                            PutResult::Updated => info!(""),
                            PutResult::Inserted => info!(""),
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

                    self.configure_peer_after_hello(
                        &mut client,
                        hello.peer_id,
                        hello.public_key,
                        [0u8; 16],
                        hello.nonce,
                    )
                    .await?;
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Unexpected tag for Op::Response",
                    ));
                }
            },
            Op::Command => {
                match packet.tag {
                    Tag::Route => {
                        // NOOP
                    }
                    Tag::Echo => {
                        let mut cursor = io::Cursor::new(raw_tail);
                        let echo = frame::EchoFrame::read(&mut cursor).map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidData, "bad echo frame")
                        })?;

                        match std::str::from_utf8(&echo.txt) {
                            Ok(s) => info!("echo: \"{s}\""),
                            Err(_) => error!("echo: {:02x?}", &echo.txt),
                        }
                    }
                    Tag::Broadcast => {
                        let mut cursor = io::Cursor::new(raw_tail);
                        let frame = frame::BroadcastFrame::read(&mut cursor).map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidData, "bad broadcast frame")
                        })?;
                        let pos = cursor.position() as usize;
                        let payload = &raw_tail[pos..];

                        if frame.n == 5 {
                            debug!(
                                "broadcast IGNORED: nonce={} ttl={} reason=n==5",
                                hex::encode(frame.nonce),
                                frame.n
                            );
                            return Ok(());
                        }

                        {
                            let mut seen = self.processed_nonces.lock().await;
                            if !seen.insert(frame.nonce) {
                                debug!(
                                    "broadcast IGNORED: nonce={} ttl={} reason=already processed",
                                    hex::encode(frame.nonce),
                                    frame.n
                                );
                                return Ok(());
                            }
                        }

                        // Read 2-byte length prefix (big-endian)
                        if payload.len() < 2 {
                            println!(
                                "broadcast from {:x?} (ttl={}): [ERROR] payload too short for length prefix",
                                hex::encode(&frame.src[..8]),
                                frame.n
                            );
                        } else {
                            let msg_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
                            if payload.len() < 2 + msg_len {
                                println!(
                                    "broadcast from {:x?} (ttl={}): [ERROR] payload too short for message",
                                    hex::encode(&frame.src[..8]),
                                    frame.n
                                );
                            } else {
                                let msg_bytes = &payload[2..2 + msg_len];
                                match String::from_utf8(msg_bytes.to_vec()) {
                                    Ok(s) => println!(
                                        "broadcast from {:x?} (ttl={}): \"{}\" ({} bytes)",
                                        hex::encode(&frame.src[..8]),
                                        frame.n,
                                        s,
                                        msg_len
                                    ),
                                    Err(_) => println!(
                                        "broadcast from {:x?} (ttl={}): [HEX] {} ({} bytes)",
                                        hex::encode(&frame.src[..8]),
                                        frame.n,
                                        hex::encode(msg_bytes),
                                        msg_len
                                    ),
                                }
                            }
                        }

                        if frame.n > 0 {
                            let mut next_b = frame;
                            next_b.n -= 1;

                            let map = self.clients.lock().await;
                            for (addr, client_arc) in map.iter() {
                                // Do not relay back to the origin peer
                                if *addr == client_addr {
                                    continue;
                                }
                                let mut client = client_arc.lock().await;
                                client.conn.set_encrypted(false);
                                client.conn.set_signed(true);

                                let mut w = client.writer().writer();
                                Packet {
                                    op: Op::Command,
                                    tag: Tag::Broadcast,
                                }
                                .write(&mut w)?;
                                next_b.write(&mut w)?;
                                std::io::Write::write_all(&mut w, payload)?;
                                let _ = w.into_inner();

                                if let Err(e) = client.flush().await {
                                    log::debug!("broadcast: flush {} failed: {e:?}", addr);
                                }
                            }
                        }
                    }
                    _ => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Unexpected tag",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn connect_and_register(self: &Arc<Self>, addr: SocketAddr) -> io::Result<()> {
        log::info!("dial: connecting to {addr}");
        let stream = TcpStream::connect(addr).await?;
        let (reader, writer) = stream.into_split();

        self.register_client(addr, writer).await?;
        log::info!("dial: registered {addr}, spawning read loop");

        let me = Arc::clone(self);
        tokio::spawn(async move {
            if let Err(e) = me.run_read_loop(reader, addr).await {
                warn!("read loop error from {addr}: {e:?}");
            }
        });

        Ok(())
    }

    async fn register_client(&self, addr: SocketAddr, writer: OwnedWriteHalf) -> io::Result<()> {
        let client_arc = {
            let mut map = self.clients.lock().await;
            let entry = map
                .entry(addr)
                .or_insert_with(|| {
                    Arc::new(AsyncMutex::new(Client::new(
                        addr,
                        writer,
                        self.signer.clone(),
                    )))
                })
                .clone();
            let count = map.len();
            log::info!("register_client: inserted/exists for {addr}. clients.len()={count}");
            entry
        };

        {
            let mut client = client_arc.lock().await;
            self.send_hello(&mut client).await?;
        }

        Ok(())
    }
}

struct Client {
    #[allow(dead_code)]
    address: SocketAddr,
    #[allow(dead_code)]
    writer: Arc<AsyncMutex<OwnedWriteHalf>>,
    conn: Connection,
    peer_id: Option<ID>,
    #[allow(dead_code)]
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
                .ok_or_else(|| io::Error::other("Missing session"))?
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

struct Routing {
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
        for candidate in candidates[..len].iter() {
            let mut ok = true;
            for prev in prev_hops {
                if prev.public_key == src {
                    continue;
                }

                if prev == candidate {
                    ok = false;
                    break;
                }
            }
            if ok {
                return Some(*candidate);
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
                Session::init_remote_key([].to_vec(), key, remote_key)
            }
        };

        let arc = Arc::new(AsyncMutex::new(session));
        self.sessions.lock().unwrap().insert(key, arc.clone());
        arc
    }
}
