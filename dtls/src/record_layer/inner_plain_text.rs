use byteorder::WriteBytesExt;

use super::super::error::*;
use crate::content::ContentType;
use std::io::Write;

pub(crate) struct InnerPlainText {
    pub(crate) content: Vec<u8>,
    pub(crate) real_type: ContentType,
    pub(crate) zeros: usize,
}

impl InnerPlainText {
    pub fn marshal<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write(&self.content)?;
        writer.write_u8(self.real_type.into())?;
        writer.write(&vec![0; self.zeros])?;
        Ok(())
    }

    pub fn unmarshal(buf: &[u8]) -> Result<Self> {
        let mut i = buf.len() - 1;
        let mut zeros = 0;
        while i > 0 {
            if buf[i] != 0 {
                break;
            }
            zeros += 1;
            i -= 1;
        }
        if i == 0 {
            return Err(Error::ErrBufferTooSmall);
        }
        let real_type = buf[i].into();
        let content = buf[..i].to_vec();
        Ok(InnerPlainText {
            content,
            real_type,
            zeros,
        })
    }
}
