use core::sync::atomic::Ordering;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use portable_atomic::AtomicBool;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch, Mutex};

use super::*;
use crate::error::Error;
use crate::Buffer;
use crate::sync::RwLock;

const RECEIVE_MTU: usize = 8192;
const DEFAULT_LISTEN_BACKLOG: usize = 128; // same as Linux default

pub type AcceptFilterFn =
    Box<dyn (Fn(&[u8]) -> Pin<Box<dyn Future<Output = bool> + Send + 'static>>) + Send + Sync>;

pub type ConnectionIdExtractorOutgoingMsgsFn =
    fn(&[u8]) -> Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send + 'static>>;

pub type ConnectionIdExtractorIncomingMsgsFn =
    Box<dyn (Fn(&[u8]) -> Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send + 'static>>) + Send + Sync>;

type AcceptDoneCh = (mpsc::Receiver<Arc<UdpConn>>, watch::Receiver<()>);

#[derive(Debug, PartialEq, Eq, Hash)]
struct SessionId(String);
/// listener is used in the [DTLS](https://github.com/webrtc-rs/dtls) and
/// [SCTP](https://github.com/webrtc-rs/sctp) transport to provide a connection-oriented
/// listener over a UDP.
struct ListenerImpl {
    pconn: Arc<dyn Conn + Send + Sync>,
    accepting: Arc<AtomicBool>,
    accept_ch_tx: Arc<Mutex<Option<mpsc::Sender<Arc<UdpConn>>>>>,
    done_ch_tx: Arc<Mutex<Option<watch::Sender<()>>>>,
    ch_rx: Arc<Mutex<AcceptDoneCh>>,
    conns_map: Arc<RwLock<HashMap<String, Vec<Arc<UdpConn>>>>>,
}

#[async_trait]
impl Listener for ListenerImpl {
    /// accept waits for and returns the next connection to the listener.
    async fn accept(&self) -> Result<(Arc<dyn Conn + Send + Sync>, SocketAddr)> {
        let (accept_ch_rx, done_ch_rx) = &mut *self.ch_rx.lock().await;

        tokio::select! {
            c = accept_ch_rx.recv() =>{
                if let Some(c) = c{
                    let raddr = *c.raddr.read();
                    Ok((c, raddr))
                }else{
                    Err(Error::ErrClosedListenerAcceptCh)
                }
            }
            _ = done_ch_rx.changed() =>  Err(Error::ErrClosedListener),
        }
    }

    /// close closes the listener.
    /// Any blocked Accept operations will be unblocked and return errors.
    async fn close(&self) -> Result<()> {
        if self.accepting.load(Ordering::SeqCst) {
            self.accepting.store(false, Ordering::SeqCst);
            {
                let mut done_ch = self.done_ch_tx.lock().await;
                done_ch.take();
            }
            {
                let mut accept_ch = self.accept_ch_tx.lock().await;
                accept_ch.take();
            }
        }

        Ok(())
    }

    /// Addr returns the listener's network address.
    async fn addr(&self) -> Result<SocketAddr> {
        self.pconn.local_addr()
    }
}

/// ListenConfig stores options for listening to an address.
#[derive(Default)]
pub struct ListenConfig {
    /// Backlog defines the maximum length of the queue of pending
    /// connections. It is equivalent of the backlog argument of
    /// POSIX listen function.
    /// If a connection request arrives when the queue is full,
    /// the request will be silently discarded, unlike TCP.
    /// Set zero to use default value 128 which is same as Linux default.
    pub backlog: usize,

    /// AcceptFilter determines whether the new conn should be made for
    /// the incoming packet. If not set, any packet creates new conn.
    pub accept_filter: Option<AcceptFilterFn>,
    /// New connection filter determines whether new conn should be
    /// made for the incoming packet if the source port / address is the same
    /// as in the existing connection.
    /// It's done to satisfy the requirement rfc6347#section-4.2.8
    pub new_conn_filter: Option<AcceptFilterFn>,

    // connection_id_extractor extracts connection IDs from outgoing ServerHello records
    // and associates them with the associated connection.
    // NOTE: a ServerHello should always be the first record in a datagram if
    // multiple are present, so we avoid iterating through all packets if the first
    // is not a ServerHello.
    pub connection_id_extractor_outgoing_msg: Option<ConnectionIdExtractorOutgoingMsgsFn>,

    // connection_id_router extracts connection IDs from incoming datagram payloads and
    // uses them to route to the proper connection.
    // NOTE: properly routing datagrams based on connection IDs requires using
    // constant size connection IDs.
    pub connection_id_extractor_incoming_msg: Option<ConnectionIdExtractorIncomingMsgsFn>

}

pub async fn listen<A: ToSocketAddrs>(laddr: A) -> Result<impl Listener> {
    ListenConfig::default().listen(laddr).await
}

pub async fn listen_with_config<A: ToSocketAddrs>(laddr: A, config: ListenConfig) -> Result<impl Listener> {
    let mut config = config;
    config.listen(laddr).await
}

impl ListenConfig {
    /// Listen creates a new listener based on the ListenConfig.
    pub async fn listen<A: ToSocketAddrs>(&mut self, laddr: A) -> Result<impl Listener> {
        if self.backlog == 0 {
            self.backlog = DEFAULT_LISTEN_BACKLOG;
        }

        let pconn = Arc::new(UdpSocket::bind(laddr).await?);
        let (accept_ch_tx, accept_ch_rx) = mpsc::channel(self.backlog);
        let (done_ch_tx, done_ch_rx) = watch::channel(());

        let l = ListenerImpl {
            pconn,
            accepting: Arc::new(AtomicBool::new(true)),
            accept_ch_tx: Arc::new(Mutex::new(Some(accept_ch_tx))),
            done_ch_tx: Arc::new(Mutex::new(Some(done_ch_tx))),
            ch_rx: Arc::new(Mutex::new((accept_ch_rx, done_ch_rx.clone()))),
            conns_map: Arc::new(RwLock::new(HashMap::new())),
        };

        let pconn = Arc::clone(&l.pconn);
        let accepting = Arc::clone(&l.accepting);
        let accept_filter = self.accept_filter.take();
        let new_conn_filter = self.new_conn_filter.take();
        let connection_id_extractor_incoming_msg = self.connection_id_extractor_incoming_msg.take();
        let connection_id_extractor_outgoing_msg = self.connection_id_extractor_outgoing_msg.take();
        let accept_ch_tx = Arc::clone(&l.accept_ch_tx);
        let conns_map = Arc::clone(&l.conns_map);
        tokio::spawn(async move {
            ListenConfig::read_loop(
                done_ch_rx,
                pconn,
                accepting,
                accept_filter,
                new_conn_filter,
                connection_id_extractor_incoming_msg,
                connection_id_extractor_outgoing_msg,
                accept_ch_tx,
                conns_map,
            )
            .await;
        });

        Ok(l)
    }

    /// read_loop has to tasks:
    /// 1. Dispatching incoming packets to the correct Conn.
    ///    It can therefore not be ended until all Conns are closed.
    /// 2. Creating a new Conn when receiving from a new remote.
    async fn read_loop(
        mut done_ch_rx: watch::Receiver<()>,
        pconn: Arc<dyn Conn + Send + Sync>,
        accepting: Arc<AtomicBool>,
        accept_filter: Option<AcceptFilterFn>,
        new_conn_filter: Option<AcceptFilterFn>,
        connection_id_extractor_incoming_msg: Option<ConnectionIdExtractorIncomingMsgsFn>,
        connection_id_extractor_outgoing_msg: Option<ConnectionIdExtractorOutgoingMsgsFn>,
        accept_ch_tx: Arc<Mutex<Option<mpsc::Sender<Arc<UdpConn>>>>>,
        conns_map: Arc<RwLock<HashMap<String, Vec<Arc<UdpConn>>>>>,
    ) {
        let mut buf = vec![0u8; RECEIVE_MTU];

        loop {
            let connection_id_extractor_outgoing_msg = connection_id_extractor_outgoing_msg;
            tokio::select! {
                _ = done_ch_rx.changed() => {
                    break;
                }
                result = pconn.recv_from(&mut buf) => {
                    match result {
                        Ok((n, raddr)) => {
                            let udp_conn = match ListenConfig::get_udp_conn(
                                &pconn,
                                &accepting,
                                &accept_filter,
                                &new_conn_filter,
                                &connection_id_extractor_incoming_msg,
                                connection_id_extractor_outgoing_msg,
                                &accept_ch_tx,
                                &conns_map,
                                raddr,
                                &buf[..n],
                            )
                            .await
                            {
                                Ok(conn) => conn,
                                Err(_) => continue,
                            };

                            if let Some(conn) = udp_conn {
                                let _ = conn.buffer.write(&buf[..n]).await;
                            }
                        }
                        Err(err) => {
                            log::warn!("ListenConfig pconn.recv_from error: {}", err);
                            break;
                        }
                    };
                }
            }
        }
    }

    async fn get_udp_conn(
        pconn: &Arc<dyn Conn + Send + Sync>,
        accepting: &Arc<AtomicBool>,
        accept_filter: &Option<AcceptFilterFn>,
        new_conn_filter: &Option<AcceptFilterFn>,
        connection_id_extractor_incoming_msg: &Option<ConnectionIdExtractorIncomingMsgsFn>,
        connection_id_extractor_outgoing_msg: Option<ConnectionIdExtractorOutgoingMsgsFn>,
        accept_ch_tx: &Arc<Mutex<Option<mpsc::Sender<Arc<UdpConn>>>>>,
        conns_map: &Arc<RwLock<HashMap<String, Vec<Arc<UdpConn>>>>>,
        raddr: SocketAddr,
        buf: &[u8],
    ) -> Result<Option<Arc<UdpConn>>> {
        {
            if let Some(f) = connection_id_extractor_incoming_msg {
                if let Some(connection_id) = f(buf).await {
                    let m = conns_map.read();
                    if let Some(conn) = m.get(connection_id_to_string(&connection_id).as_str()).and_then(|v| v.last()) {
                        return Ok(Some(conn.clone()));
                    }
                }
            }
        }
        {
            let conn = {
                let m = conns_map.read();
            if let Some(conn) = m.get(raddr.to_string().as_str()).and_then(|v| v.last()) {
                conn.clone().into()
            } else {
                None
            }
            };
            if let Some(conn) = conn {
                if let Some(f) = new_conn_filter {
                    if !(f(buf).await) {
                        return Ok(Some(conn.clone()));
                    }
                } else {
                    return Ok(Some(conn.clone()));
                }
            }
        }

        if !accepting.load(Ordering::SeqCst) {
            return Err(Error::ErrClosedListener);
        }

        if let Some(f) = accept_filter {
            if !(f(buf).await) {
                return Ok(None);
            }
        }

        let session_id = SessionId(rand::random::<u64>().to_string());
        let udp_conn = Arc::new(UdpConn::new(
            Arc::clone(pconn),
            Arc::clone(conns_map),
            raddr,
            session_id,
            connection_id_extractor_outgoing_msg,
        ));
        {
            let accept_ch = accept_ch_tx.lock().await;
            if let Some(tx) = &*accept_ch {
                if tx.try_send(Arc::clone(&udp_conn)).is_err() {
                    return Err(Error::ErrListenQueueExceeded);
                }
            } else {
                return Err(Error::ErrClosedListenerAcceptCh);
            }
        }

        {
            let mut m = conns_map.write();
            let existing_value = m.entry(raddr.to_string()).or_insert_with(Vec::new);
            existing_value.push(Arc::clone(&udp_conn));
        }

        Ok(Some(udp_conn))
    }
}

/// UdpConn augments a connection-oriented connection over a UdpSocket
pub struct UdpConn {
    pconn: Arc<dyn Conn + Send + Sync>,
    conns_map: Arc<RwLock<HashMap<String, Vec<Arc<UdpConn>>>>>,
    raddr: RwLock<SocketAddr>,
    buffer: Buffer,
    session_id: SessionId,
    connection_id_extractor: Option<ConnectionIdExtractorOutgoingMsgsFn>,
    connection_id: RwLock<Option<Vec<u8>>>
}

impl UdpConn {
    fn new(
        pconn: Arc<dyn Conn + Send + Sync>,
        conns_map: Arc<RwLock<HashMap<String, Vec<Arc<UdpConn>>>>>,
        raddr: SocketAddr,
        session_id: SessionId,
        connection_id_extractor: Option<ConnectionIdExtractorOutgoingMsgsFn>,
    ) -> Self {
        UdpConn {
            pconn,
            conns_map,
            raddr: RwLock::new(raddr),
            session_id,
            connection_id_extractor,
            connection_id: RwLock::new(None),
            buffer: Buffer::new(0, 0),
        }
    }
}

#[async_trait]
impl Conn for UdpConn {
    async fn connect(&self, addr: SocketAddr) -> Result<()> {
        self.pconn.connect(addr).await
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        Ok(self.buffer.read(buf, None).await?)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let n = self.buffer.read(buf, None).await?;
        Ok((n, *self.raddr.read()))
    }

    async fn send(&self, buf: &[u8]) -> Result<usize> {
        // TODO: connection id concept is related to DTLS only,
        // it should not live in the util module and should not be related to the generic
        // UDP listener
        if let Some(f) = self.connection_id_extractor {
            if let Some(cid) = f(buf).await {
                self.update_connection_id(cid.clone());
                let mut conns_map = self.conns_map.write();
                if let Some(exisiting_value) = conns_map.remove(self.raddr.read().to_string().as_str()) {
                    conns_map.insert(connection_id_to_string(&cid), exisiting_value.to_vec());
                }
            }
        }
        let raddr = *self.raddr.read();
        self.pconn.send_to(buf, raddr).await
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> Result<usize> {
        self.pconn.send_to(buf, target).await
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        self.pconn.local_addr()
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(*self.raddr.read())
    }

    async fn close(&self) -> Result<()> {
        let mut conns_map = self.conns_map.write();
        if let Some(existing_value) = conns_map.get_mut(self.raddr.read().to_string().as_str()) {
            existing_value.retain(|c| c.session_id != self.session_id);
            if existing_value.is_empty() {
                conns_map.remove(self.raddr.read().to_string().as_str());
            }
        }
        if let Some(connection_id) = self.connection_id.read().clone() {
            if let Some(existing_value) = conns_map.get_mut(connection_id_to_string(&connection_id).as_str()) {
                existing_value.retain(|c| c.session_id != self.session_id);
                if existing_value.is_empty() {
                    conns_map.remove(connection_id_to_string(&connection_id).as_str());
                }
            }
        }
        Ok(())
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
    fn update_remote_addr(&self, raddr: SocketAddr) {
        if *self.raddr.read() != raddr {
            *self.raddr.write() = raddr;
        }
    }
}

impl UdpConn {
    fn update_connection_id(&self, connection_id: Vec<u8>) {
        *self.connection_id.write() = Some(connection_id);
    }
}

fn connection_id_to_string(cid: &Vec<u8>) -> String {
    format!("{:02x?}", cid)
}
