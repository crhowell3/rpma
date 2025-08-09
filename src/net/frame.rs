use std::io::{Read, Write};

use anyhow::{Result, bail};
use ed25519_dalek::{Signature, VerifyingKey};
use rand::RngCore;

use crate::Client;
use crate::encryption::{Encrypted, Session};
use crate::kademlia::ID;
use crate::net::packet::{EncryptionMetadata, PacketHeader};

pub struct HelloFrame {
    pub peer_id: ID,
    pub public_key: [u8; 32],
    pub nonce: [u8; 16],
}

impl HelloFrame {
    pub fn read<R: Read>(reader: &mut R) -> Result<Self> {
        let peer_id = ID::read(&mut *reader)?;

        let mut public_key = [0u8; 32];
        reader.read_exact(&mut public_key)?;

        let mut nonce = [0u8; 16];
        reader.read_exact(&mut nonce)?;

        Ok(Self {
            peer_id,
            public_key,
            nonce,
        })
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        self.peer_id.write(&mut *writer)?;
        writer.write_all(&self.public_key)?;
        writer.write_all(&self.nonce)?;
        Ok(())
    }
}

pub mod find_node_frame {
    use super::*;

    pub struct Request {
        pub public_key: [u8; 32],
    }

    impl Request {
        pub fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
            writer.write_all(&self.public_key)?;
            Ok(())
        }

        pub fn read<R: Read>(reader: &mut R) -> Result<Self> {
            let mut public_key = [0u8; 32];
            reader.read_exact(&mut public_key)?;
            Ok(Self { public_key })
        }
    }

    pub struct Response {
        pub peer_ids: Vec<ID>,
    }

    impl Response {
        pub fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
            writer.write_all(&[self.peer_ids.len() as u8])?;
            for peer_id in &self.peer_ids {
                peer_id.write(&mut *writer)?;
            }

            Ok(())
        }

        pub fn read<R: Read>(&self, reader: &mut R) -> Result<Self> {
            let mut len_buf = [0u8; 1];
            reader.read_exact(&mut len_buf)?;
            let len = len_buf[0] as usize;

            let mut peer_ids = Vec::with_capacity(len);
            for _ in 0..len {
                peer_ids.push(ID::read(&mut *reader)?);
            }

            Ok(Self { peer_ids })
        }
    }
}

pub struct RouteFrame {
    pub src: [u8; 32],
    pub dst: [u8; 32],
    pub hops: Vec<ID>,
}

impl RouteFrame {
    pub fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.src)?;
        writer.write_all(&self.dst)?;
        writer.write_all(&[self.hops.len() as u8])?;
        for peer_id in &self.hops {
            peer_id.write(&mut *writer)?;
        }
        Ok(())
    }

    pub fn read<R: Read>(reader: &mut R) -> Result<Self> {
        let mut src = [0u8; 32];
        reader.read_exact(&mut src)?;

        let mut dst = [0u8; 32];
        reader.read_exact(&mut dst)?;

        let mut len_buf = [0u8; 1];
        reader.read_exact(&mut len_buf)?;
        let len = len_buf[0] as usize;

        let mut hops = Vec::with_capacity(len);
        for _ in 0..len {
            hops.push(ID::read(&mut *reader)?);
        }

        Ok(Self { src, dst, hops })
    }
}

impl std::fmt::Display for RouteFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RouteFrame[{} => {} ({:?})]",
            hex::encode(self.src),
            hex::encode(self.dst),
            self.hops
        )
    }
}

pub struct EchoFrame {
    pub txt: Vec<u8>,
}

impl EchoFrame {
    pub fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&(self.txt.len() as u64).to_le_bytes())?;
        writer.write_all(&self.txt)?;
        Ok(())
    }

    pub fn read<R: Read>(reader: &mut R) -> Result<Self> {
        let mut len_buf = [0u8; 8];
        reader.read_exact(&mut len_buf)?;
        let len = u64::from_le_bytes(len_buf) as usize;

        let mut txt = vec![0u8; len];
        reader.read_exact(&mut txt)?;

        Ok(Self { txt })
    }
}

pub struct BroadcastFrame {
    pub src: [u8; 32],
    pub nonce: [u8; 16],
    pub ts: i128,
    pub n: u8,
}

impl BroadcastFrame {
    pub fn read<R: Read>(reader: &mut R) -> Result<Self> {
        let mut src = [0u8; 32];
        reader.read_exact(&mut src)?;

        let mut nonce = [0u8; 16];
        reader.read_exact(&mut nonce)?;

        let mut ts_buf = [0u8; 16];
        reader.read_exact(&mut ts_buf)?;
        let ts = i128::from_le_bytes(ts_buf);

        let mut n_buf = [0u8; 1];
        reader.read_exact(&mut n_buf)?;
        let n = n_buf[0];

        Ok(Self { src, nonce, ts, n })
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.src)?;
        writer.write_all(&self.nonce)?;
        writer.write_all(&self.ts.to_le_bytes())?;
        writer.write_all(&[self.n])?;
        Ok(())
    }
}

pub fn random_nonce() -> [u8; 16] {
    let mut buf = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

pub fn read_frame(client: &mut Client) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let num_bytes = client.socket.read(&mut buf)?;

    if num_bytes == 0 {
        bail!("EOF");
    }

    buf.truncate(num_bytes);

    let packet_header = PacketHeader::read(&mut &buf[..])?;
    if buf.len() < packet_header.len as usize {
        let mut extra = vec![0u8; packet_header.len as usize - buf.len()];
        client.socket.read_exact(&mut extra)?;
        buf.extend_from_slice(&extra);
    }

    let raw_frame = buf.split_off(0);
    let session = client.conn.session.as_ref();

    let processed_frame = process_frame(
        client.peer_id.public_key,
        session,
        packet_header,
        &raw_frame,
    )?;

    Ok(processed_frame)
}

pub fn process_frame(
    peer_id_pk: [u8; 32],
    session: Option<&Session>,
    packet_header: PacketHeader,
    raw_frame: &[u8],
) -> Result<Vec<u8>> {
    let mut frame = raw_frame.to_vec();

    if packet_header.flags & 0x1 != 0 {
        if frame.len() < 64 {
            bail!("Frame too short for signature");
        }
        let signature_bytes: [u8; 64] = frame[frame.len() - 64..].try_into().unwrap();
        frame.truncate(frame.len() - 64);

        verify_signature(peer_id_pk, signature_bytes, &frame)?;
    }

    if packet_header.flags & 0x2 != 0 {
        let s = session.ok_or_else(|| anyhow::anyhow!("MissingSession"))?;
        let mut reader = &frame[..];
        let encryption_metadata = EncryptionMetadata::read(&mut reader)?;

        frame = s.decrypt(Encrypted {
            dh: encryption_metadata.dh,
            n: encryption_metadata.n,
            pn: encryption_metadata.pn,
            cipher_text: reader.to_vec(),
        });
    }

    Ok(frame)
}

pub fn verify_signature(public_key: [u8; 32], raw_signature: [u8; 64], msg: &[u8]) -> Result<()> {
    let pk = VerifyingKey::from_bytes(&public_key)?;
    let sig = Signature::from_bytes(&raw_signature);
    pk.verify_strict(msg, &sig)?;
    Ok(())
}
