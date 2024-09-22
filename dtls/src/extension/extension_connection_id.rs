use std::io::{Read, Write};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtensionConnectionId {
    pub(crate) connection_id: Vec<u8>,
}

impl ExtensionConnectionId {
    pub fn extension_value(&self) -> ExtensionValue {
        ExtensionValue::ConnectionId
    }

    pub fn size(&self) -> usize {
        // data is [u16_len, u8_len, [connection_id]]
        // size is 2 + 1 +  connection_id_len
        2 + 1 + self.connection_id.len()
    }

    pub fn marshal<W: Write>(&self, writer: &mut W) -> Result<()> {
        /* From pion implementation
         * b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
         *   b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
         *     b.AddBytes(c.CID)
         *   })
         * })
         */
        // we add u16 containing the length of
        // he connection id prefixed by the length of the connection id in u8
        // [u16_len, u8_len, [connection_id]]
        let connection_id_len = self.connection_id.len();
        writer.write_u16::<BigEndian>((connection_id_len + 1) as u16)?;
        writer.write_u8(connection_id_len as u8)?;
        writer.write_all(&self.connection_id)?;
        Ok(writer.flush()?)
    }

    pub fn unmarshal<R: Read>(reader: &mut R) -> Result<Self> {
        let _ = reader.read_u16::<BigEndian>()?;
        let connection_id_len = reader.read_u8()? as usize;
        let mut connection_id = vec![0; connection_id_len];
        reader.read_exact(&mut connection_id)?;
        Ok(ExtensionConnectionId { connection_id })
    }
}
