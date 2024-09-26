// AES-GCM (Galois Counter Mode)
// The most widely used block cipher worldwide.
// Mandatory as of TLS 1.2 (2008) and used by default by most clients.
// RFC 5288 year 2008 https://tools.ietf.org/html/rfc5288

// https://github.com/RustCrypto/AEADs
// https://docs.rs/aes-gcm/0.8.0/aes_gcm/

use std::io::Cursor;

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, KeyInit};
use rand::Rng;

use super::*;
use crate::content::*;
use crate::error::*;
use crate::record_layer::record_layer_header::*; // what about Aes256Gcm?

const CRYPTO_GCM_TAG_LENGTH: usize = 16;
const CRYPTO_GCM_NONCE_LENGTH: usize = 12;

// State needed to handle encrypted input/output
#[derive(Clone)]
pub struct CryptoGcm {
    local_gcm: Aes128Gcm,
    remote_gcm: Aes128Gcm,
    local_write_iv: Vec<u8>,
    remote_write_iv: Vec<u8>,
}

impl CryptoGcm {
    pub fn new(
        local_key: &[u8],
        local_write_iv: &[u8],
        remote_key: &[u8],
        remote_write_iv: &[u8],
    ) -> Self {
        let key = GenericArray::from_slice(local_key);
        let local_gcm = Aes128Gcm::new(key);

        let key = GenericArray::from_slice(remote_key);
        let remote_gcm = Aes128Gcm::new(key);

        CryptoGcm {
            local_gcm,
            local_write_iv: local_write_iv.to_vec(),
            remote_gcm,
            remote_write_iv: remote_write_iv.to_vec(),
        }
    }

    pub fn encrypt(&self, pkt_rlh: &RecordLayerHeader, raw: &[u8]) -> Result<Vec<u8>> {
        let payload = &raw[pkt_rlh.size()..];
        let raw = &raw[..pkt_rlh.size()];

        let mut nonce = vec![0u8; CRYPTO_GCM_NONCE_LENGTH];
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

        self.local_gcm
            .encrypt_in_place(nonce, &additional_data, &mut buffer)
            .map_err(|e| Error::Other(e.to_string()))?;

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

        let additional_data = if h.content_type == ContentType::ConnectionId {
            generate_aead_additional_data_cid(&h, out.len() - CRYPTO_GCM_TAG_LENGTH)
        } else {
            generate_aead_additional_data(&h, out.len() - CRYPTO_GCM_TAG_LENGTH)
        };

        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend_from_slice(out);

        self.remote_gcm
            .decrypt_in_place(nonce, &additional_data, &mut buffer)
            .map_err(|e| Error::Other(e.to_string()))?;

        let mut d = Vec::with_capacity(h.size() + buffer.len());
        d.extend_from_slice(&r[..h.size()]);
        d.extend_from_slice(&buffer);

        Ok(d)
    }
}
