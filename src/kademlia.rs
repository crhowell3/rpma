use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::ops::{AddAssign, SubAssign};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ID {
    pub public_key: [u8; 32],
    pub address: SocketAddr,
}

impl ID {
    pub fn default() -> Self {
        Self {
            public_key: [0u8; 32],
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
        }
    }

    fn size(&self) -> u32 {
        let ip_size = match self.address {
            SocketAddr::V4(_) => 4,
            SocketAddr::V6(_) => 16 + 4,
        };

        (32 + 1 + ip_size + 2) as u32
    }

    pub fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(&self.public_key)?;

        match self.address {
            SocketAddr::V4(addr) => {
                writer.write_all(&[libc::AF_INET as u8])?;
                writer.write_all(&addr.ip().octets())?;
                writer.write_all(&addr.port().to_le_bytes())?;
            }
            SocketAddr::V6(addr) => {
                writer.write_all(&[libc::AF_INET6 as u8])?;
                writer.write_all(&addr.ip().octets())?;
                writer.write_all(&addr.scope_id().to_le_bytes())?;
                writer.write_all(&0u32.to_le_bytes())?;
                writer.write_all(&addr.port().to_le_bytes())?;
            }
        }

        Ok(())
    }

    pub fn read<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let mut public_key = [0u8; 32];
        reader.read_exact(&mut public_key)?;

        let mut family = [0u8; 1];
        reader.read_exact(&mut family)?;
        let family = family[0];

        let address = match family as i32 {
            libc::AF_INET => {
                let mut ip_bytes = [0u8; 4];
                reader.read_exact(&mut ip_bytes)?;
                let mut port_bytes = [0u8; 2];
                reader.read_exact(&mut port_bytes)?;
                let ip = Ipv4Addr::from(ip_bytes);
                let port = u16::from_le_bytes(port_bytes);
                SocketAddr::new(IpAddr::V4(ip), port)
            }
            libc::AF_INET6 => {
                let mut ip_bytes = [0u8; 16];
                reader.read_exact(&mut ip_bytes)?;
                let mut scope_id_bytes = [0u8; 4];
                reader.read_exact(&mut scope_id_bytes)?;
                let mut flowinfo_bytes = [0u8; 4];
                reader.read_exact(&mut flowinfo_bytes)?;
                let mut port_bytes = [0u8; 2];
                reader.read_exact(&mut port_bytes)?;

                let ip = Ipv6Addr::from(ip_bytes);
                let scope_id = u32::from_le_bytes(scope_id_bytes);
                let port = u16::from_le_bytes(port_bytes);
                let flowinfo = u32::from_le_bytes(flowinfo_bytes);
                SocketAddr::V6(SocketAddrV6::new(ip, port, flowinfo, scope_id))
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Unknown",
                ));
            }
        };

        Ok(ID {
            public_key,
            address,
        })
    }

    pub fn eql(&self, other: &ID) -> bool {
        self.public_key == other.public_key && self.address == other.address
    }
}

impl fmt::Display for ID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.public_key {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, "[{}]", self.address)
    }
}

const BUCKET_SIZE: usize = 16;
const BUCKET_COUNT: usize = 256;

#[derive(Debug)]
pub struct RoutingTable {
    pub public_key: [u8; 32],
    buckets: [StaticRingBuffer<ID, u64, BUCKET_SIZE>; BUCKET_COUNT],
    addresses: HashMap<SocketAddr, ID>,
    len: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PutResult {
    Full,
    Updated,
    Inserted,
}

pub enum BinarySearchResult {
    Found(usize),
    NotFound(usize),
}

impl RoutingTable {
    pub fn new(public_key: [u8; 32]) -> Self {
        Self {
            public_key,
            buckets: std::array::from_fn(|_| StaticRingBuffer::new()),
            addresses: HashMap::with_capacity(BUCKET_SIZE * BUCKET_COUNT),
            len: 0,
        }
    }

    fn xor_keys(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = a[i] ^ b[i];
        }
        out
    }

    fn clz(bytes: &[u8; 32]) -> usize {
        for (i, byte) in bytes.iter().enumerate() {
            if *byte != 0 {
                return i * 8 + byte.leading_zeros() as usize;
            }
        }
        256
    }

    pub fn put(&mut self, id: ID) -> PutResult {
        if self.public_key == id.public_key {
            return PutResult::Full;
        }

        let index = Self::clz(&Self::xor_keys(&self.public_key, &id.public_key));
        let bucket = &mut self.buckets[index];

        let removed = if let Some(existing) = self.addresses.insert(id.address.clone(), id.clone())
        {
            let other_index = Self::clz(&Self::xor_keys(&self.public_key, &existing.public_key));
            Self::remove_from_bucket(&mut self.buckets[other_index], &existing.public_key)
        } else {
            Self::remove_from_bucket(bucket, &id.public_key)
        };

        if !removed && bucket.count() == BUCKET_SIZE {
            return PutResult::Full;
        }

        bucket.push(id);

        if removed {
            PutResult::Updated
        } else {
            self.len += 1;
            PutResult::Inserted
        }
    }

    pub fn delete(&mut self, public_key: &[u8; 32]) -> bool {
        if self.len == 0 || &self.public_key == public_key {
            return false;
        }

        let index = Self::clz(&Self::xor_keys(&self.public_key, &*public_key));
        let bucket = &mut self.buckets[index];
        if Self::remove_from_bucket(bucket, public_key) {
            self.len -= 1;
            true
        } else {
            false
        }
    }

    pub fn get(&self, public_key: &[u8; 32]) -> Option<ID> {
        let index = Self::clz(&Self::xor_keys(&self.public_key, &*public_key));
        let bucket = &self.buckets[index];
        for id in bucket.iter() {
            if &id.public_key == public_key {
                return Some(*id);
            }
        }
        None
    }

    pub fn closest_to(&self, dst: &mut [ID], public_key: &[u8; 32]) -> usize {
        let mut count = 0;
        let index = Self::clz(&Self::xor_keys(&self.public_key, &*public_key));

        if &self.public_key != public_key {
            self.fill_sort(dst, &mut count, public_key, index);
        }

        let mut i = 1;
        while count < dst.len() {
            let mut stop = true;

            if index >= i {
                self.fill_sort(dst, &mut count, public_key, index - i);
                stop = false;
            }
            if index + i < BUCKET_COUNT {
                self.fill_sort(dst, &mut count, public_key, index + i);
                stop = false;
            }
            if stop {
                break;
            }
            i += 1;
        }

        count
    }

    fn fill_sort(&self, dst: &mut [ID], count: &mut usize, public_key: &[u8; 32], index: usize) {
        for id in self.buckets[index].iter() {
            if &id.public_key != public_key {
                match Self::binary_search(&self.public_key, &dst[..*count], &id.public_key) {
                    BinarySearchResult::Found(_) => continue,
                    BinarySearchResult::NotFound(insert_index) => {
                        if *count < dst.len() {
                            *count += 1;
                        } else if insert_index >= *count {
                            continue;
                        }
                        for j in (*count - 1)..insert_index {
                            dst[j + 1] = dst[j];
                        }
                        dst[insert_index] = *id;
                    }
                }
            }
        }
    }

    fn remove_from_bucket(
        bucket: &mut StaticRingBuffer<ID, u64, BUCKET_SIZE>,
        public_key: &[u8; 32],
    ) -> bool {
        let mut found = false;
        let mut new_bucket = StaticRingBuffer::new();
        while let Some(item) = bucket.pop_or_null() {
            if &item.public_key != public_key {
                new_bucket.push(item);
            } else {
                found = true;
            }
        }
        *bucket = new_bucket;
        found
    }
    pub fn binary_search(
        our_pk: &[u8; 32],
        slice: &[ID],
        target_pk: &[u8; 32],
    ) -> BinarySearchResult {
        let mut left = 0;
        let mut right = slice.len();

        while left < right {
            let mid = left + (right - left) / 2;
            let mid_xor = Self::xor_keys(&slice[mid].public_key, &*our_pk);
            let target_xor = Self::xor_keys(&*target_pk, &*our_pk);

            match mid_xor.cmp(&target_xor) {
                Ordering::Less => left = mid + 1,
                Ordering::Greater => right = mid,
                Ordering::Equal => return BinarySearchResult::Found(mid),
            }
        }

        BinarySearchResult::NotFound(left)
    }
}

#[derive(Debug)]
pub struct StaticRingBuffer<T, Counter, const CAPACITY: usize>
where
    Counter: Copy + Default + PartialOrd + AddAssign<u64> + SubAssign<u64> + From<u8> + Into<u64>,
{
    head: Counter,
    tail: Counter,
    entries: [Option<T>; CAPACITY],
}

impl<T, Counter, const CAPACITY: usize> StaticRingBuffer<T, Counter, CAPACITY>
where
    T: Copy,
    Counter: Copy + Default + PartialOrd + AddAssign<u64> + SubAssign<u64> + From<u8> + Into<u64>,
{
    pub fn new() -> Self {
        assert!(CAPACITY.is_power_of_two());
        Self {
            head: Counter::default(),
            tail: Counter::default(),
            entries: [(); CAPACITY].map(|_| None),
        }
    }

    fn mask_index(&self, counter: Counter) -> usize {
        (counter.into() & ((CAPACITY as u64) - 1)) as usize
    }

    pub fn push_or_null(&mut self, item: T) -> Option<T> {
        let evicted = if self.count() == CAPACITY {
            Some(self.pop())
        } else {
            None
        };

        self.push(item);
        evicted
    }

    pub fn push(&mut self, item: T) {
        assert!(self.count() < CAPACITY);
        let index = self.mask_index(self.head);
        self.entries[index] = Some(item);
        self.head += 1usize.into();
    }

    pub fn push_one(&mut self) -> &mut Option<T> {
        assert!(self.count() < CAPACITY);
        let index = self.mask_index(self.head);
        self.head += 1usize.into();
        &mut self.entries[index]
    }

    pub fn prepend(&mut self, item: T) {
        assert!(self.count() < CAPACITY);
        self.tail -= 1usize.into();
        let index = self.mask_index(self.tail);
        self.entries[index] = Some(item);
    }

    pub fn pop_or_null(&mut self) -> Option<T> {
        if self.count() == 0 {
            None
        } else {
            Some(self.pop())
        }
    }

    pub fn pop(&mut self) -> T {
        assert!(self.count() > 0);
        let index = self.mask_index(self.tail);
        let item = self.entries[index].take().expect("Entry must exist");
        self.tail += 1usize.into();
        item
    }

    pub fn get(&self, i: Counter) -> Option<T> {
        if i < self.tail || i >= self.head {
            None
        } else {
            let index = self.mask_index(i);
            self.entries[index]
        }
    }

    pub fn count(&self) -> usize {
        (self.head.into() as isize - self.tail.into() as isize) as usize
    }

    pub fn latest(&self) -> Option<T> {
        if self.count() == 0 {
            None
        } else {
            let index = self.mask_index(self.head - 1usize.into());
            self.entries[index]
        }
    }

    pub fn oldest(&self) -> Option<T> {
        if self.count() == 0 {
            None
        } else {
            let index = self.mask_index(self.tail);
            self.entries[index]
        }
    }
}
