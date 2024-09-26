// AES-CCM (Counter with CBC-MAC)
// Alternative to GCM mode.
// Available in OpenSSL as of TLS 1.3 (2018), but disabled by default.
// Two AES computations per block, thus expected to be somewhat slower than AES-GCM.
// RFC 6655 year 2012 https://tools.ietf.org/html/rfc6655
// Much lower adoption, probably because it came after GCM and offer no significant benefit.

// https://github.com/RustCrypto/AEADs
// https://docs.rs/ccm/0.3.0/ccm/ Or https://crates.io/crates/aes-ccm?

use std::io::Cursor;

use aes::Aes128;
use ccm::aead::generic_array::GenericArray;
use ccm::aead::AeadInPlace;
use ccm::consts::{U12, U16, U8};
use ccm::Ccm;
use ccm::KeyInit;
use rand::Rng;

use super::*;
use crate::content::*;
use crate::error::*;
use crate::record_layer::record_layer_header::*;

const CRYPTO_CCM_8_TAG_LENGTH: usize = 8;
const CRYPTO_CCM_TAG_LENGTH: usize = 16;
const CRYPTO_CCM_NONCE_LENGTH: usize = 12;

type AesCcm8 = Ccm<Aes128, U8, U12>;
type AesCcm = Ccm<Aes128, U16, U12>;

#[derive(Clone)]
pub enum CryptoCcmTagLen {
    CryptoCcm8TagLength,
    CryptoCcmTagLength,
}

enum CryptoCcmType {
    CryptoCcm8(AesCcm8),
    CryptoCcm(AesCcm),
}

// State needed to handle encrypted input/output
pub struct CryptoCcm {
    local_ccm: CryptoCcmType,
    remote_ccm: CryptoCcmType,
    local_write_iv: Vec<u8>,
    remote_write_iv: Vec<u8>,
    // used by clone()
    local_write_key: Vec<u8>,
    remote_write_key: Vec<u8>,
}

impl Clone for CryptoCcm {
    fn clone(&self) -> Self {
        match self.local_ccm {
            CryptoCcmType::CryptoCcm(_) => Self::new(
                &CryptoCcmTagLen::CryptoCcmTagLength,
                &self.local_write_key,
                &self.local_write_iv,
                &self.remote_write_key,
                &self.remote_write_iv,
            ),
            CryptoCcmType::CryptoCcm8(_) => Self::new(
                &CryptoCcmTagLen::CryptoCcm8TagLength,
                &self.local_write_key,
                &self.local_write_iv,
                &self.remote_write_key,
                &self.remote_write_iv,
            ),
        }
    }
}

impl CryptoCcm {
    pub fn new(
        tag_len: &CryptoCcmTagLen,
        local_key: &[u8],
        local_write_iv: &[u8],
        remote_key: &[u8],
        remote_write_iv: &[u8],
    ) -> Self {
        let key = GenericArray::from_slice(local_key);
        let local_ccm = match tag_len {
            CryptoCcmTagLen::CryptoCcmTagLength => CryptoCcmType::CryptoCcm(AesCcm::new(key)),
            CryptoCcmTagLen::CryptoCcm8TagLength => CryptoCcmType::CryptoCcm8(AesCcm8::new(key)),
        };

        let key = GenericArray::from_slice(remote_key);
        let remote_ccm = match tag_len {
            CryptoCcmTagLen::CryptoCcmTagLength => CryptoCcmType::CryptoCcm(AesCcm::new(key)),
            CryptoCcmTagLen::CryptoCcm8TagLength => CryptoCcmType::CryptoCcm8(AesCcm8::new(key)),
        };

        CryptoCcm {
            local_ccm,
            local_write_key: local_key.to_vec(),
            local_write_iv: local_write_iv.to_vec(),
            remote_ccm,
            remote_write_key: remote_key.to_vec(),
            remote_write_iv: remote_write_iv.to_vec(),
        }
    }

    pub fn encrypt(&self, pkt_rlh: &RecordLayerHeader, raw: &[u8]) -> Result<Vec<u8>> {
        let payload = &raw[pkt_rlh.size()..];
        let raw = &raw[..pkt_rlh.size()];

        let mut nonce = vec![0u8; CRYPTO_CCM_NONCE_LENGTH];
        nonce[..4].copy_from_slice(&self.local_write_iv[..4]);
        rand::thread_rng().fill(&mut nonce[4..]);
        let nonce = GenericArray::from_slice(&nonce);

        let additional_data = if pkt_rlh.content_type == ContentType::ConnectionId {
            generate_aead_additional_data_cid(pkt_rlh, payload.len())
        } else {
            generate_aead_additional_data(pkt_rlh, payload.len())
        };

        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend_from_slice(payload);

        match &self.local_ccm {
            CryptoCcmType::CryptoCcm(ccm) => {
                ccm.encrypt_in_place(nonce, &additional_data, &mut buffer)
                    .map_err(|e| Error::Other(e.to_string()))?;
            }
            CryptoCcmType::CryptoCcm8(ccm8) => {
                ccm8.encrypt_in_place(nonce, &additional_data, &mut buffer)
                    .map_err(|e| Error::Other(e.to_string()))?;
            }
        }

        let mut r = Vec::with_capacity(raw.len() + nonce.len() + buffer.len());

        r.extend_from_slice(raw);
        r.extend_from_slice(&nonce[4..]);
        r.extend_from_slice(&buffer);

        // Update recordLayer size to include explicit nonce
        let r_len = (r.len() - pkt_rlh.size()) as u16;
        r[pkt_rlh.size() - 2..pkt_rlh.size()].copy_from_slice(&r_len.to_be_bytes());

        Ok(r)
    }

    pub fn decrypt(&self, h: &mut RecordLayerHeader, r: &[u8]) -> Result<Vec<u8>> {
        let mut reader = Cursor::new(r);
        h.unmarshal(&mut reader)?;
        if h.content_type == ContentType::ChangeCipherSpec {
            // Nothing to encrypt with ChangeCipherSpec
            return Ok(r.to_vec());
        }

        if r.len() <= (h.size() + 8) {
            return Err(Error::ErrNotEnoughRoomForNonce);
        }

        let mut nonce = vec![];
        nonce.extend_from_slice(&self.remote_write_iv[..4]);
        nonce.extend_from_slice(&r[h.size()..h.size() + 8]);
        let nonce = GenericArray::from_slice(&nonce);

        let out = &r[h.size() + 8..];

        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend_from_slice(out);

        match &self.remote_ccm {
            CryptoCcmType::CryptoCcm(ccm) => {
                let additional_data = if h.content_type == ContentType::ConnectionId {
                    generate_aead_additional_data_cid(&h, out.len() - CRYPTO_CCM_TAG_LENGTH)
                } else {
                    generate_aead_additional_data(&h, out.len() - CRYPTO_CCM_TAG_LENGTH)
                };
                ccm.decrypt_in_place(nonce, &additional_data, &mut buffer)
                    .map_err(|e| Error::Other(e.to_string()))?;
            }
            CryptoCcmType::CryptoCcm8(ccm8) => {
                let additional_data = if h.content_type == ContentType::ConnectionId {
                    generate_aead_additional_data_cid(&h, out.len() - CRYPTO_CCM_8_TAG_LENGTH)
                } else {
                    generate_aead_additional_data(&h, out.len() - CRYPTO_CCM_8_TAG_LENGTH)
                };
                ccm8.decrypt_in_place(nonce, &additional_data, &mut buffer)
                    .map_err(|e| Error::Other(e.to_string()))?;
            }
        }

        let mut d = Vec::with_capacity(h.size() + buffer.len());
        d.extend_from_slice(&r[..h.size()]);
        d.extend_from_slice(&buffer);

        Ok(d)
    }
}
