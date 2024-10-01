use std::future::Future;
use std::io::BufReader;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::ToSocketAddrs;
use util::conn::conn_udp_listener::*;
use util::conn::*;

use crate::config::*;
use crate::conn::DTLSConn;
use crate::content::ContentType;
use crate::error::Result;
use crate::extension::Extension;
use crate::handshake::HandshakeType;
use crate::handshake::handshake_header::HandshakeHeader;
use crate::handshake::handshake_message_client_hello::HandshakeMessageClientHello;
use crate::handshake::handshake_message_server_hello::HandshakeMessageServerHello;
use crate::record_layer::record_layer_header::RecordLayerHeader;
use crate::record_layer::{unpack_datagram, content_aware_unpack_datagram};

/// Listen creates a DTLS listener
pub async fn listen<A: 'static + ToSocketAddrs>(laddr: A, config: Config) -> Result<impl Listener> {
    validate_config(false, &config)?;

    let cid_size = config.connection_id_generator.map(|f| f().len());
    let mut lc = create_dtls_listen_config(cid_size);
    let parent = Arc::new(lc.listen(laddr).await?);
    Ok(DTLSListener { parent, config })
}

pub fn create_dtls_listen_config(cid_size: Option<usize>) -> ListenConfig {
    ListenConfig {
        accept_filter: Some(Box::new(
            |packet: &[u8]| -> Pin<Box<dyn Future<Output = bool> + Send + 'static>> {
                let pkts = match unpack_datagram(packet) {
                    Ok(pkts) => {
                        if pkts.is_empty() {
                            return Box::pin(async { false });
                        }
                        pkts
                    }
                    Err(_) => return Box::pin(async { false }),
                };

                let mut reader = BufReader::new(pkts[0].as_slice());
                let mut h = RecordLayerHeader::new();
                match h.unmarshal(&mut reader) {
                    Ok(_) => {
                        let content_type = h.content_type;
                        Box::pin(async move { content_type == ContentType::Handshake })
                    }
                    Err(_) => Box::pin(async { false }),
                }
            },
        )),
        new_conn_filter: Some(Box::new(
            |packet: &[u8]| -> Pin<Box<dyn Future<Output = bool> + Send + 'static>> {
                let pkts = match unpack_datagram(packet) {
                    Ok(pkts) => {
                        if pkts.is_empty() {
                            return Box::pin(async { false });
                        }
                        pkts
                    }
                    Err(_) => return Box::pin(async { false }),
                };

                let mut reader = BufReader::new(pkts[0].as_slice());
                let mut h = RecordLayerHeader::new();
                match (
                    h.unmarshal(&mut reader),
                    HandshakeHeader::unmarshal(&mut reader),
                    HandshakeMessageClientHello::unmarshal(&mut reader),
                ) {
                    (Ok(_), Ok(hh), Ok(ch)) => {
                        let epoch = h.epoch;
                        let content_type = h.content_type;
                        let handshake_type = hh.handshake_type;
                        let cookie = ch.cookie;
                        Box::pin(async move {
                            epoch == 0 &&
                                content_type == ContentType::Handshake &&
                                handshake_type == HandshakeType::ClientHello &&
                                cookie.is_empty()
                        })
                    }
                    _ => Box::pin(async { false }),
                }
            },
        )),
        connection_id_extractor_outgoing_msg: Some(
            |packet: &[u8]| {
                let pkts = match unpack_datagram(packet) {
                    Ok(pkts) => {
                        if pkts.is_empty() {
                            return Box::pin(async { None });
                        }
                        pkts
                    }
                    Err(_) => return Box::pin(async { None })
                };

                let mut reader = BufReader::new(pkts[0].as_slice());
                let mut h = RecordLayerHeader::new();
                if let Err(_) = h.unmarshal(&mut reader) {
                    return Box::pin(async { None });
                }
                if h.content_type != ContentType::Handshake {
                    return Box::pin(async { None });
                }
                let mut sh = None;
                for pkt in pkts {
                    let mut reader = BufReader::new(pkt.as_slice());
                    let mut record_layer_header = RecordLayerHeader::new();
                    record_layer_header.unmarshal(&mut reader).ok();
                    let handshake_header = match HandshakeHeader::unmarshal(&mut reader) {
                        Ok(h) => h,
                        Err(_) => continue
                    };
                    if handshake_header.handshake_type == HandshakeType::ServerHello {
                        sh = HandshakeMessageServerHello::unmarshal(&mut reader).ok();
                        match &sh {
                            Some(_) => break,
                            None => continue,
                        }
                    }
                }

                if let Some(sh) = sh {
                    for ext in sh.extensions {
                        match ext {
                            Extension::ConnectionId(cid) => return Box::pin(async { Some(cid.connection_id) }),
                            _ => continue,
                        }
                    }
                }
                Box::pin(async { None })
            }),
        connection_id_extractor_incoming_msg: Some(Box::new(
            move |packet: &[u8]| {
                let cid_size = match cid_size {
                    Some(l) => l,
                    None => return Box::pin(async { None }),
                };
                let pkts = match content_aware_unpack_datagram(packet, cid_size) {
                    Ok(pkts) => {
                        if pkts.is_empty() {
                            return Box::pin(async { None });
                        }
                        pkts
                    }
                    Err(_) => return Box::pin(async { None }),
                };
                for pkt in pkts {
                    let mut reader = BufReader::new(pkt.as_slice());
                    let mut h = RecordLayerHeader::new();
                    h.connection_id = vec![0; cid_size].into();
                    if let Err(_) = h.unmarshal(&mut reader) {
                        continue;
                    }
                    if h.content_type == ContentType::ConnectionId {
                        return Box::pin(async { h.connection_id });
                    }
                }
                return Box::pin(async { None });
            }
        )),
        ..Default::default()
    }
}

/// DTLSListener represents a DTLS listener
pub struct DTLSListener {
    parent: Arc<dyn Listener + Send + Sync>,
    config: Config,
}

impl DTLSListener {
    ///  creates a DTLS listener which accepts connections from an inner Listener.
    pub fn new(parent: Arc<dyn Listener + Send + Sync>, config: Config) -> Result<Self> {
        validate_config(false, &config)?;

        Ok(DTLSListener { parent, config })
    }
}

type UtilResult<T> = std::result::Result<T, util::Error>;

#[async_trait]
impl Listener for DTLSListener {
    /// Accept waits for and returns the next connection to the listener.
    /// You have to either close or read on all connection that are created.
    /// Connection handshake will timeout using ConnectContextMaker in the Config.
    /// If you want to specify the timeout duration, set ConnectContextMaker.
    async fn accept(&self) -> UtilResult<(Arc<dyn Conn + Send + Sync>, SocketAddr)> {
        let (conn, raddr) = self.parent.accept().await?;
        let dtls_conn = DTLSConn::new(conn, self.config.clone(), false, None)
            .await
            .map_err(util::Error::from_std)?;
        Ok((Arc::new(dtls_conn), raddr))
    }

    /// Close closes the listener.
    /// Any blocked Accept operations will be unblocked and return errors.
    /// Already Accepted connections are not closed.
    async fn close(&self) -> UtilResult<()> {
        self.parent.close().await
    }

    /// Addr returns the listener's network address.
    async fn addr(&self) -> UtilResult<SocketAddr> {
        self.parent.addr().await
    }
}
