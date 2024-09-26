use std::io::{Read, Write};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use crate::content::*;
use crate::error::*;

pub const RECORD_LAYER_HEADER_SIZE: usize = 13;
// RECORD_LAYER_HEADER_LEN_IDX is the index at which the record layer content length is
// specified in a fixed length header (i.e. one that does not include a
// Connection ID).
pub const RECORD_LAYER_HEADER_LEN_IDX: usize = 11;

pub const MAX_SEQUENCE_NUMBER: u64 = 0x0000FFFFFFFFFFFF;

pub const DTLS1_2MAJOR: u8 = 0xfe;
pub const DTLS1_2MINOR: u8 = 0xfd;

pub const DTLS1_0MAJOR: u8 = 0xfe;
pub const DTLS1_0MINOR: u8 = 0xff;

// VERSION_DTLS12 is the DTLS version in the same style as
// VersionTLSXX from crypto/tls
pub const VERSION_DTLS12: u16 = 0xfefd;

pub const PROTOCOL_VERSION1_0: ProtocolVersion = ProtocolVersion {
    major: DTLS1_0MAJOR,
    minor: DTLS1_0MINOR,
};
pub const PROTOCOL_VERSION1_2: ProtocolVersion = ProtocolVersion {
    major: DTLS1_2MAJOR,
    minor: DTLS1_2MINOR,
};

/// ## Specifications
///
/// * [RFC 4346 §6.2.1]
///
/// [RFC 4346 §6.2.1]: https://tools.ietf.org/html/rfc4346#section-6.2.1
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct ProtocolVersion {
    pub major: u8,
    pub minor: u8,
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct RecordLayerHeader {
    pub content_type: ContentType,
    pub protocol_version: ProtocolVersion,
    pub epoch: u16,
    pub sequence_number: u64, // uint48 in spec
    pub content_len: u16,
    pub connection_id: Option<Vec<u8>>,
}

impl RecordLayerHeader {
    pub fn new() -> Self {
        Self {
            content_type: ContentType::Invalid,
            protocol_version: ProtocolVersion::default(),
            epoch: 0,
            sequence_number: 0,
            content_len: 0,
            connection_id: None,
        }
    }
    pub fn marshal<W: Write>(&self, writer: &mut W) -> Result<()> {
        if self.sequence_number > MAX_SEQUENCE_NUMBER {
            return Err(Error::ErrSequenceNumberOverflow);
        }

        writer.write_u8(self.content_type as u8)?;
        writer.write_u8(self.protocol_version.major)?;
        writer.write_u8(self.protocol_version.minor)?;
        writer.write_u16::<BigEndian>(self.epoch)?;

        let be: [u8; 8] = self.sequence_number.to_be_bytes();
        writer.write_all(&be[2..])?; // uint48 in spec

        writer.write_all(self.connection_id.as_ref().unwrap_or(&vec![]))?; // Connection ID
        writer.write_u16::<BigEndian>(self.content_len)?;

        Ok(writer.flush()?)
    }

    pub fn unmarshal<R: Read>(&mut self, reader: &mut R) -> Result<()> {
        let content_type = reader.read_u8()?.into();
        let major = reader.read_u8()?;
        let minor = reader.read_u8()?;
        let epoch = reader.read_u16::<BigEndian>()?;

        // SequenceNumber is stored as uint48, make into uint64
        let mut be: [u8; 8] = [0u8; 8];
        reader.read_exact(&mut be[2..])?;
        let sequence_number = u64::from_be_bytes(be);

        let protocol_version = ProtocolVersion { major, minor };
        if protocol_version != PROTOCOL_VERSION1_0 && protocol_version != PROTOCOL_VERSION1_2 {
            return Err(Error::ErrUnsupportedProtocolVersion);
        }
        let connection_id = match content_type {
            ContentType::ConnectionId => match &self.connection_id {
                Some(cid) => {
                    let mut connection_id = vec![0u8; cid.len()];
                    reader.read_exact(&mut connection_id)?;
                    Some(connection_id)
                }
                None => {
                    return Err(Error::ErrInvalidContentType);
                }
            },
            _ => None,
        };
        let content_len = reader.read_u16::<BigEndian>()?;

        self.content_type = content_type;
        self.protocol_version = protocol_version;
        self.epoch = epoch;
        self.sequence_number = sequence_number;
        self.content_len = content_len;
        self.connection_id = connection_id;
        Ok(())
    }

    pub fn size(&self) -> usize {
        RECORD_LAYER_HEADER_SIZE
            + self
                .connection_id
                .as_ref()
                .map(|cid| cid.len())
                .unwrap_or(0)
    }
}
