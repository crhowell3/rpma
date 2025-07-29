use std::collections::HashMap;

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

struct State {}

impl State {}

struct KeyStorage {
    storage: HashMap,
}

impl KeyStorage {
    fn new() -> Self {
        Self {
            storage: HashMap::new(),
        }
    }

    fn get(self, k: [u8; 32], msg_num: u32) {
        let msgs = self.storage.get(k);
        let entry = msgs.get(msg_num);
        entry.message_key
    }
}

pub struct Session {
    id: Vec<u8>,
    state: State,
}

impl Session {
    fn new(id: Vec<u8>, shared_key: [u8; 32], keys: KeyPair) -> Self {
        Self {
            id: id,
            state: State::new(shared_key, keys),
        }
    }
}
