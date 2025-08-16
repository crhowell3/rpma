use aes::{
    Aes256,
    cipher::{KeyIvInit, StreamCipher},
};
use anyhow::Result;
use ctr::Ctr128LE;
use hkdf::{
    Hkdf,
    hmac::{Hmac, Mac},
};
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use std::collections::HashMap;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

type AesCtr = Ctr128LE<Aes256>;

#[derive(Clone)]
pub struct KeyPair {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let rng = OsRng {};
        let secret = StaticSecret::random_from_rng(rng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn diffie_hellman(&self, their_public: &PublicKey) -> SharedSecret {
        self.secret.diffie_hellman(their_public)
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }
}

pub fn init(id: &[u8], shared_key: [u8; 32], keys: KeyPair) -> Session {
    Session::new(id, shared_key, keys)
}

pub fn init_remote_key(id: &[u8], shared_key: [u8; 32], remote_key: [u8; 32]) -> Session {
    Session::init_remote_key(id.to_vec(), shared_key, remote_key)
}

pub fn random_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    OsRng.fill_bytes(&mut id);
    id
}

#[derive(Debug, Clone)]
struct RootKeyWithHeader {
    root_key: [u8; 32],
    chain_key: [u8; 32],
    new_header_key: [u8; 32],
}

fn kdf_rk(root_key: [u8; 32], dh_out: [u8; 32]) -> RootKeyWithHeader {
    let (_prk, hk) = Hkdf::<Sha256>::extract(Some(root_key.as_slice()), &dh_out);
    let mut out = [0u8; 96];
    let info = "rsZUpEuXUqqwXBvSy3EcievAh4cMj6QL";
    let _ = hk.expand(info.as_bytes(), &mut out);

    RootKeyWithHeader {
        root_key: out[0..32].try_into().expect("Slice with incorrect length"),
        chain_key: out[32..64].try_into().expect("Slice with incorrect length"),
        new_header_key: out[64..].try_into().expect("Slice with incorrect length"),
    }
}

#[derive(Debug, Clone)]
pub struct KdfResult {
    chain_key: [u8; 32],
    message_key: [u8; 32],
}

pub fn kdf_ck(ck: &[u8]) -> KdfResult {
    let mut h1 = Hmac::<Sha256>::new_from_slice(ck).expect("HMAC can take any key size");
    h1.update(&[15]);
    let chain_key_bytes = h1.finalize().into_bytes();
    let mut chain_key = [0u8; 32];
    chain_key.copy_from_slice(&chain_key_bytes);

    let mut h2 = Hmac::<Sha256>::new_from_slice(ck).expect("HMAC can take any key size");
    h2.update(&[16]);
    let message_key_bytes = h2.finalize().into_bytes();
    let mut message_key = [0u8; 32];
    message_key.copy_from_slice(&message_key_bytes);

    KdfResult {
        chain_key,
        message_key,
    }
}

fn dh_gen(kp: KeyPair, public_key: [u8; 32]) -> Result<[u8; 32]> {
    let secret = kp.secret;
    let public = PublicKey::from(public_key);
    let shared_secret = secret.diffie_hellman(&public);
    Ok(shared_secret.to_bytes())
}

struct DerivedKeys {
    enc_key: [u8; 32],
    auth_key: [u8; 32],
    iv: [u8; 16],
}

fn derive_enc_keys(mk: [u8; 32]) -> DerivedKeys {
    let (_prk, hk) = Hkdf::<Sha256>::extract(Some(&mk), &mk);
    let mut out = [0u8; 80];
    let info = "pcwSByyx2CRdryCffXJwy7xgVZWtW5Sh";
    let _ = hk.expand(info.as_bytes(), &mut out);

    DerivedKeys {
        enc_key: out[0..32].try_into().expect(""),
        auth_key: out[32..64].try_into().expect(""),
        iv: out[64..].try_into().expect(""),
    }
}

fn _encrypt(mk: [u8; 32], in_key: &[u8], ad: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let keys = derive_enc_keys(mk);
    let out_size = in_key.len() + keys.iv.len() + 32;

    let mut out = Vec::with_capacity(out_size);

    out.extend_from_slice(&keys.iv);

    let mut cipher = AesCtr::new(&keys.enc_key.into(), &keys.iv.into());
    let mut cipher_text = in_key.to_vec();
    cipher.apply_keystream(&mut cipher_text);
    out.extend_from_slice(&cipher_text);

    let sig = compute_signature(&keys.auth_key, &out, ad);
    out.extend_from_slice(&sig);

    Ok(out)
}

fn compute_signature(key: &[u8; 32], cipher_text: &[u8], ad: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of this size");
    mac.update(cipher_text);
    mac.update(ad);
    let result = mac.finalize().into_bytes();
    let mut sig = [0u8; 32];
    sig.copy_from_slice(&result);
    sig
}

fn _decrypt(mk: [u8; 32], in_key: &[u8], ad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let sig_offset = in_key.len() - 32;
    let signature = &in_key[sig_offset..];
    let iv = &in_key[0..32];
    let cipher_text = &in_key[32..sig_offset];

    let keys = derive_enc_keys(mk);

    let to_mac = &in_key[0..sig_offset];
    let expected_sig = compute_signature(&keys.auth_key, to_mac, ad);

    if signature.ct_eq(&expected_sig).unwrap_u8() != 1 {
        return Err(CryptoError::SignatureMismatch);
    }

    let mut out = cipher_text.to_vec();
    let mut cipher = AesCtr::new(&keys.enc_key.into(), iv.into());
    cipher.apply_keystream(&mut out);

    Ok(out)
}

#[derive(Debug, Clone)]
struct ChainLink {
    chain: Chain,
    nhk: [u8; 32],
}

#[derive(Debug, Clone)]
struct RootChain {
    chain_key: [u8; 32],
}

impl RootChain {
    fn next(&mut self, key: [u8; 32]) -> ChainLink {
        let keys = kdf_rk(self.chain_key, key);

        self.chain_key = keys.root_key;

        ChainLink {
            chain: Chain {
                chain_key: keys.chain_key,
                n: 0,
            },
            nhk: keys.new_header_key,
        }
    }
}

#[derive(Debug, Clone)]
struct Chain {
    chain_key: [u8; 32],
    n: u32,
}

impl Chain {
    fn next(&mut self) -> [u8; 32] {
        let keys = kdf_ck(&self.chain_key);

        self.n += 1;
        self.chain_key = keys.chain_key;

        keys.message_key
    }
}

#[derive(Debug)]
pub enum CryptoError {
    InvalidKey,
    SignatureMismatch,
}

struct SkippedKey {
    key: [u8; 32],
    nr: u32,
    mk: [u8; 32],
    seq: u32,
}

impl SkippedKey {
    fn new(key: [u8; 32], nr: u32, mk: [u8; 32], seq: u32) -> Self {
        Self { key, nr, mk, seq }
    }
}

#[derive(Clone)]
struct State {
    dhr: [u8; 32],
    dhs: KeyPair,
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
            dhr: shared_key,
            dhs: kp,
            root_chain: RootChain {
                chain_key: shared_key,
            },
            send_chain: Chain {
                chain_key: shared_key,
                n: 0,
            },
            receive_chain: Chain {
                chain_key: shared_key,
                n: 0,
            },
            pn: 0,
            mk_skipped: KeyStorage::new(),
            max_skip: 1000,
            max_keep: 2000,
            max_message_keys_per_session: 2000,
            keys_count: 0,
            step: 0,
        }
    }

    fn skip_message_keys(&mut self, key: [u8; 32], until: u32) -> Vec<SkippedKey> {
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
            skipped_keys[index] =
                SkippedKey::new(key, self.receive_chain.n - 1, mk, self.keys_count);
            self.keys_count += 1;
        }

        skipped_keys
    }

    fn next(&mut self, dh: [u8; 32]) {
        self.pn = self.send_chain.n;
        self.dhr = dh;

        let recv_key = dh_gen(self.dhs.clone(), self.dhr);
        self.receive_chain = self.root_chain.next(recv_key.unwrap()).chain;

        self.dhs = KeyPair::generate();

        let send_key = dh_gen(self.dhs.clone(), self.dhr);
        self.send_chain = self.root_chain.next(send_key.unwrap()).chain;
    }
}

#[derive(Clone, Debug)]
struct Entry {
    session_id: Vec<u8>,
    message_key: [u8; 32],
    seq_num: u32,
}

#[derive(Clone, Debug)]
struct KeyStorage {
    storage: HashMap<[u8; 32], HashMap<u32, Entry>>,
}

impl KeyStorage {
    fn new() -> Self {
        Self {
            storage: HashMap::new(),
        }
    }

    fn get(&mut self, k: [u8; 32], msg_num: u32) -> Option<[u8; 32]> {
        let msgs = self.storage.get(&k)?;
        let entry = msgs.get(&msg_num)?;
        Some(entry.message_key)
    }

    fn put(
        &mut self,
        session_id: &[u8],
        pub_key: [u8; 32],
        msg_num: u32,
        mk: [u8; 32],
        seq_num: u32,
    ) -> Result<(), CryptoError> {
        let inner_map = self.storage.entry(pub_key).or_default();

        inner_map.insert(
            msg_num,
            Entry {
                session_id: session_id.to_vec(),
                message_key: mk,
                seq_num,
            },
        );

        Ok(())
    }
}

struct Header {
    dh: [u8; 32],
    n: u32,
    pn: u32,
}

impl Header {
    pub const ENCODED_LEN: usize =
        std::mem::size_of::<[u8; 32]>() + std::mem::size_of::<u32>() + std::mem::size_of::<u32>();

    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0u8; Self::ENCODED_LEN];
        out[0..32].copy_from_slice(&self.dh);
        out[32..36].copy_from_slice(&self.n.to_le_bytes());
        out[36..40].copy_from_slice(&self.pn.to_le_bytes());
        out
    }
}

pub struct Encrypted {
    pub dh: [u8; 32],
    pub n: u32,
    pub pn: u32,
    pub cipher_text: Vec<u8>,
}

#[derive(Clone)]
pub struct Session {
    id: Vec<u8>,
    state: State,
}

impl Session {
    pub fn new(id: &[u8], shared_key: [u8; 32], keys: KeyPair) -> Self {
        Self {
            id: id.to_vec(),
            state: State::new(shared_key, keys),
        }
    }

    pub fn init_remote_key(id: Vec<u8>, shared_key: [u8; 32], remote_key: [u8; 32]) -> Self {
        let keys = KeyPair::generate();
        let mut session = Self {
            id,
            state: State::new(shared_key, keys),
        };

        session.state.dhr = remote_key;

        let key = dh_gen(session.state.dhs.clone(), session.state.dhr);
        session.state.send_chain = session.state.root_chain.next(key.unwrap()).chain;

        session
    }

    pub fn encrypt(&mut self, plain_text: Vec<u8>) -> Encrypted {
        let h = Header {
            dh: self.state.dhs.public.to_bytes(),
            n: self.state.send_chain.n,
            pn: self.state.pn,
        };

        let message_key = self.state.send_chain.next();

        Encrypted {
            dh: h.dh,
            n: h.n,
            pn: h.pn,
            cipher_text: _encrypt(message_key, plain_text.as_slice(), &h.encode()).unwrap(),
        }
    }

    pub fn decrypt(&mut self, message: Encrypted) -> Vec<u8> {
        let ad = (Header {
            dh: message.dh,
            n: message.n,
            pn: message.pn,
        })
        .encode();

        if let Some(message_key) = self.state.mk_skipped.get(message.dh, message.n) {
            return _decrypt(message_key, message.cipher_text.as_slice(), &ad).unwrap();
        }

        let mut next_state = self.state.clone();
        let mut skipped_keys: Vec<SkippedKey> = Vec::new();

        if message.dh != next_state.dhr {
            let skipped_message_keys = next_state.skip_message_keys(next_state.dhr, message.pn);
            skipped_keys.extend(skipped_message_keys);

            next_state.next(message.dh);
        }

        let message_key = next_state.receive_chain.next();
        let plain_text = _decrypt(message_key, message.cipher_text.as_slice(), &ad);

        skipped_keys.push(SkippedKey {
            key: next_state.dhr,
            nr: message.n,
            mk: message_key,
            seq: next_state.keys_count,
        });

        next_state.keys_count += 1;

        for skipped in skipped_keys {
            let _ = next_state.mk_skipped.put(
                self.id.as_slice(),
                skipped.key,
                skipped.nr,
                skipped.mk,
                skipped.seq,
            );
        }

        self.state = next_state;
        plain_text.unwrap()
    }
}
