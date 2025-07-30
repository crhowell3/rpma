use std::{arch::is_aarch64_feature_detected, collections::HashMap};
use sha2::Sha256;
use hkdf::Hkdf;
use x25519_dalek::{EphemeralSecret, PublicKey};
use anyhow::Result;

type KeyPair = (EphemeralSecret, PublicKey);

pub fn init(id: &[u8], shared_key: [u8; 32], keys: KeyPair) -> Session {
    Session::new(id, shared_key, keys)
}

pub fn init_remote_key(id: [u8], shared_key: [u8; 32], remote_key: [u8; 32]) -> Session {
    Session::init_remote_key(id, shared_key, remote_key)
}

pub fn random_id() -> [u8] {
    let mut id: [u8; 16];
    // crypto.random.bytes(&id);
    id
}

fn kdfRk(root_key: [u8; 32], dh_out: [u8; 32]) {
    let prk = Hkdf::<Sha256>::extract(&root_key, &dh_out);
    let mut out: [u8; 96];
    Hkdf::<Sha256>::expand(&out, "", prk);

    
}

fn dh(kp: KeyPair, public_key: [u8; 32]) -> Result<[u8; 32]> {
    let secret = EphemeralSecret::from(kp.0);
    let public = PublicKey::from(public_key);
    let shared_secret = secret.diffie_hellman(&public);
    Ok(shared_secret.to_bytes())
}
struct RootChain {
    chain_key: [u8; 32],
}

impl RootChain {
    fn next(self, key: [u8; 32]) {
        // let keys = kdfRk(self.chain_key, key);

        // self.chain_key = keys.root_key;
        // return
    }
}


#[derive(Debug, Copy, Clone)]
struct Chain {
    chain_key: [u8; 32],
    n: u32,
}

impl Chain {
    fn next(self) -> [u8; 32] {
        let keys = KdfCK(&self.chain_key);

        self.n += 1;
        self.chain_key = keys.chain_key;

        return keys.message_key;
    }
}

#[derive(Debug)]
pub enum CryptoError {
    InvalidKey
}

struct SkippedKey {
    key: [u8; 32],
    nr: u32,
    mk: [u8; 32],
    seq: u32,
}

impl SkippedKey {
    fn new(key: [u8;32], nr: u32, mk: [u8; 32], seq: u32) -> Self {
        Self {
            key,
            nr,
            mk,
            seq,
        }
    }
}

#[derive(Debug, Copy, Clone)]
struct State {
    DHr: [u8; 32],
    DHs: KeyPair,
    root_chain: RootChain,
    send_chain: Chain,
    receive_chain: Chain,
    pn: u32,
    mk_skipped: KeyStorage,
    max_skip: u32,
    max_keep: u32,
    max_message_keys_per_session: u32,
    step: u32,
    keys_count: u32,
}

impl State {
    fn new(shared_key: [u8; 32], kp: KeyPair) -> Self {
        Self {
            DHr: shared_key,
            DHs: kp,
            root_chain: RootChain{chain_key: shared_key},
            send_chain: Chain{chain_key: shared_key, n: 0},
            receive_chain: Chain {chain_key: shared_key, n: 0},
            pn: 0,
            mk_skipped: KeyStorage::new(),
            max_skip: 1000,
            max_keep: 2000,
            max_message_keys_per_session: 2000,
            keys_count: 0,
            step: 0,
        }
    }

    fn skip_message_keys(mut self, key: [u8; 32], until: u32) -> Vec<SkippedKey> {
        if until < self.receive_chain.n {
            unreachable!()
        }

        if self.receive_chain.n + self.max_skip < until {
            unreachable!()
        }

        let count: usize = (until - self.receive_chain.n) as usize;
        let mut skipped_keys = Vec::<SkippedKey>::with_capacity(count);

        while self.receive_chain.n < until {
            let mk = self.receive_chain.next();

            let index: usize = (until - self.receive_chain.n) as usize;
            skipped_keys[index] = SkippedKey::new(key, self.receive_chain.n - 1, mk, self.keys_count);
            self.keys_count += 1;
        }

        skipped_keys
    }
}

struct Entry {
    session_id: Vec<u8>,
    message_key: [u8; 32],
    seq_num: u32,
}

struct KeyStorage {
    storage: HashMap<[u8; 32], HashMap<u32, Entry>>,
}

impl KeyStorage {
    fn new() -> Self {
        Self {
            storage: HashMap::new(),
        }
    }

    fn get(self, k: [u8; 32], msg_num: u32) -> [u8; 32] {
        let msgs = self.storage.get(&k);
        let entry = msgs.unwrap().get(&msg_num);
        entry.unwrap().message_key
    }

    fn put(&mut self, session_id: &[u8], pub_key: [u8;32], msg_num: u32, mk: [u8; 32], seq_num: u32) -> Result<(), CryptoError> {
        let inner_map = self.storage.entry(pub_key).or_insert_with(HashMap::new);

        inner_map.insert(msg_num, Entry {
            session_id: session_id.to_vec(),
            message_key: mk,
            seq_num
        });

        Ok(())
    }
}


struct Header {
    dh: [u8; 32],
    n: u32,
    pn: u32,
}

impl Header {
    pub const ENCODED_LEN: usize = std::mem::size_of::<[u8; 32]>() + std::mem::size_of::<u32>() + std::mem::size_of::<u32>();

    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0u8; Self::ENCODED_LEN];
        out[0..32].copy_from_slice(&self.dh);
        out[32..36].copy_from_slice(&self.n.to_le_bytes());
        out[36..40].copy_from_slice(&self.pn.to_le_bytes());
        out
    }
}

struct Encrypted {
    dh: [u8; 32],
    n: u32,
    pn: u32,
    cipher_text: Vec<u8>,
}

pub struct Session {
    id: Vec<u8>,
    state: State,
}

impl Session {
    fn new(id: &[u8], shared_key: [u8; 32], keys: KeyPair) -> Self {
        Self {
            id: id.to_vec(),
            state: State::new(shared_key, keys),
        }
    }

    fn init_remote_key(id: Vec<u8>, shared_key: [u8; 32], remote_key: [u8; 32]) -> Self {
        let keys = KeyPair.generate();
        let mut session = Self {id, state: State::new(shared_key, keys)};

        session.state.DHr = remote_key;

        let key = dh(session.state.DHs, session.state.DHr);
        session.state.send_chain = session.state.root_chain.next(key).chain;

        session
    }

    pub fn encrypt(self, plain_text: Vec<u8>) -> Encrypted {
        let h = Header{
            dh: self.state.DHs.public_key,
            n: self.state.send_chain.n,
            pn: self.state.pn,
        };

        let message_key = self.state.send_chain.next();

        Encrypted { dh: h.dh, n: h.n, pn: h.pn, cipher_text: _encrypt(message_key, plain_text, &h.encode()) }
    }

    pub fn decrypt(self, message: Encrypted) -> Vec<u8> {
        let ad = (Header{
            dh: message.dh,
            n: message.n,
            pn: message.pn,
        }).encode();

        // if self.state.mk_skipped.get(message.dh, message.n) |message_key| {
        //     return _decrypt(message_key, message.cipher_text, &ad);
        // }

        let mut next_state = self.state;
        let mut skipped_keys: Vec<SkippedKey> = Vec::new();

        if message.dh != next_state.DHr {
            let skipped_message_keys = next_state.skip_message_keys(next_state.DHr, message.pn);
            skipped_keys.extend(skipped_message_keys);

            next_state.next(message.dh);
        }

        let message_key = next_state.receive_chain.next();
        let plain_text = _decrypt(message_key, message.cipher_text, &ad);

        next_state.keys_count += 1;
        for (skipped_keys.items) |skipped| {
            next_state.mk_skipped.put(self.id, skipped.key, skipped.nr, skipped.mk, skipped.seq);
        }

        self.state = next_state;
        plain_text
    }
}
