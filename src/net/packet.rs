use std::io::{Read, Result, Write};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Request,
    Response,
    Command,
}

impl From<u8> for Op {
    fn from(value: u8) -> Self {
        match value {
            0 => Op::Request,
            1 => Op::Response,
            2 => Op::Command,
            _ => panic!("Invalid Op value"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tag {
    Ping,
    Hello,
    FindNodes,
    Route,
    Echo,
    Broadcast,
}

impl From<u8> for Tag {
    fn from(value: u8) -> Self {
        match value {
            0 => Tag::Ping,
            1 => Tag::Hello,
            2 => Tag::FindNodes,
            3 => Tag::Route,
            4 => Tag::Echo,
            5 => Tag::Broadcast,
            _ => panic!("Invalid Tag value"),
        }
    }
}

pub struct Packet {
    pub op: Op,
    pub tag: Tag,
}

impl Packet {
    pub fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&[self.op as u8])?;
        writer.write_all(&[self.tag as u8])?;
        Ok(())
    }

    pub fn read<R: Read>(reader: &mut R) -> Result<Self> {
        let mut op_buf = [0u8; 1];
        let mut tag_buf = [0u8; 1];
        reader.read_exact(&mut op_buf)?;
        reader.read_exact(&mut tag_buf)?;

        Ok(Packet {
            op: Op::from(op_buf[0]),
            tag: Tag::from(tag_buf[0]),
        })
    }
}

pub struct PacketHeader {
    pub len: u32,
    pub flags: u8,
}

impl PacketHeader {
    pub const SIZE: usize = std::mem::size_of::<u32>() + std::mem::size_of::<u8>();

    pub fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.len.to_le_bytes())?;
        writer.write_all(&[self.flags])?;
        Ok(())
    }

    pub fn read<R: Read>(reader: &mut R) -> Result<Self> {
        let mut len_buf = [0u8; 4];
        let mut flags_buf = [0u8; 1];
        reader.read_exact(&mut len_buf)?;
        reader.read_exact(&mut flags_buf)?;

        Ok(PacketHeader {
            len: u32::from_le_bytes(len_buf),
            flags: flags_buf[0],
        })
    }
}

pub struct EncryptionMetadata {
    pub dh: [u8; 32],
    pub n: u32,
    pub pn: u32,
}

impl EncryptionMetadata {
    pub const SIZE: usize = 32 + 4 + 4;

    pub fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.dh)?;
        writer.write_all(&self.n.to_le_bytes())?;
        writer.write_all(&self.pn.to_le_bytes())?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn read<R: Read>(reader: &mut R) -> Result<Self> {
        let mut dh = [0u8; 32];
        reader.read_exact(&mut dh)?;

        let mut n_buf = [0u8; 4];
        let mut pn_buf = [0u8; 4];
        reader.read_exact(&mut n_buf)?;
        reader.read_exact(&mut pn_buf)?;

        Ok(EncryptionMetadata {
            dh,
            n: u32::from_le_bytes(n_buf),
            pn: u32::from_le_bytes(pn_buf),
        })
    }
}
