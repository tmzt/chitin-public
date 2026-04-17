//! Shared yamux multiplexer for chitin network connections.
//!
//! Provides `MuxSession` — a self-running yamux session with background
//! poller, reader, and writer tasks. Used by both the concentrator (server)
//! and node clients.
//!
//! ```text
//! MuxSession
//!   ├── poller_task: drives yamux Connection (poll_next_inbound)
//!   ├── reader_task: reads frames from stream 0 → on_frame callback
//!   └── writer_task: drains OutboundHeap → writes to stream 0
//! ```

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use futures_lite::io::{AsyncReadExt, AsyncWriteExt};
use network_transport::heap::{OutboundHeap, Priority};
use network_transport::Frame;

/// Connection lifecycle state — stored as AtomicU32 for cross-task sharing.
#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConnState {
    /// Connection is active and healthy.
    Active = 0,
    /// Connection died (yamux error, read EOF, write error).
    Dead = 1,
    /// Clean shutdown requested (Drop or explicit close).
    Shutdown = 2,
    /// Connecting (not yet established).
    Connecting = 3,
}

impl ConnState {
    pub fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::Active,
            1 => Self::Dead,
            2 => Self::Shutdown,
            _ => Self::Connecting,
        }
    }

    pub fn is_alive(self) -> bool {
        self == Self::Active
    }
}

/// Shared connection state — checked by all tasks.
pub type SharedState = Arc<AtomicU32>;

/// Events emitted by the mux session.
pub enum MuxEvent<'a> {
    /// A frame was received on stream 0.
    Frame(&'a Frame),
    /// Connection state changed.
    StateChanged(ConnState),
    /// An additional inbound stream was opened by the remote side.
    InboundStream(yamux::Stream),
}

/// Frame handler callback — receives frames from stream 0.
pub type FrameHandler = Arc<dyn Fn(&Frame) + Send + Sync>;

/// A self-running yamux session over TCP.
///
/// Owns background tasks for polling the yamux connection, reading frames,
/// and writing frames. Callers push frames via `send()` and receive them
/// through the `on_frame` callback provided at construction.
pub struct MuxSession {
    heap: Arc<OutboundHeap>,
    state: SharedState,
    conn: Arc<smol::lock::Mutex<yamux::Connection<smol::net::TcpStream>>>,
    // Keep task handles to cancel on drop
    _poller: smol::Task<()>,
    _reader: smol::Task<()>,
    _writer: smol::Task<()>,
}

impl MuxSession {
    /// Connect to a remote address as a yamux client.
    /// Opens stream 0 and starts background tasks.
    pub async fn connect(
        addr: &str,
        on_frame: FrameHandler,
    ) -> Result<Self, String> {
        let tcp = smol::net::TcpStream::connect(addr).await
            .map_err(|e| format!("tcp connect {addr}: {e}"))?;
        tcp.set_nodelay(true).ok();
        log::info!("[mux] connected to {addr}");

        let cfg = yamux::Config::default();
        let mut conn = yamux::Connection::new(tcp, cfg, yamux::Mode::Client);

        // Open stream 0
        let stream0 = futures_lite::future::poll_fn(|cx| conn.poll_new_outbound(cx))
            .await
            .map_err(|e| format!("yamux stream 0: {e}"))?;
        log::info!("[mux] stream 0 open");

        Self::from_parts(conn, stream0, on_frame)
    }

    /// Accept a yamux session from an incoming TCP connection (server mode).
    /// Waits for the client to open stream 0.
    pub async fn accept(
        tcp: smol::net::TcpStream,
        on_frame: FrameHandler,
    ) -> Result<Self, String> {
        tcp.set_nodelay(true).ok();

        let cfg = yamux::Config::default();
        let mut conn = yamux::Connection::new(tcp, cfg, yamux::Mode::Server);

        // Wait for client to open stream 0
        let stream0 = match futures_lite::future::poll_fn(|cx| conn.poll_next_inbound(cx)).await {
            Some(Ok(s)) => s,
            Some(Err(e)) => return Err(format!("accept stream 0: {e}")),
            None => return Err("connection closed before stream 0".into()),
        };

        Self::from_parts(conn, stream0, on_frame)
    }

    /// Build from existing connection + stream 0.
    fn from_parts(
        conn: yamux::Connection<smol::net::TcpStream>,
        stream0: yamux::Stream,
        on_frame: FrameHandler,
    ) -> Result<Self, String> {
        let (reader, writer) = futures_lite::io::split(stream0);
        let heap = Arc::new(OutboundHeap::new());
        let state = Arc::new(AtomicU32::new(ConnState::Active as u32));
        let conn = Arc::new(smol::lock::Mutex::new(conn));

        // ── Poller task: drive yamux connection ──
        let poller_conn = conn.clone();
        let poller_state = state.clone();
        let poller = smol::spawn(async move {
            loop {
                if !ConnState::from_u32(poller_state.load(Ordering::Relaxed)).is_alive() {
                    break;
                }
                let closed = {
                    let mut c = poller_conn.lock().await;
                    futures_lite::future::poll_fn(|cx| {
                        match c.poll_next_inbound(cx) {
                            std::task::Poll::Ready(Some(Ok(_))) => {
                                log::debug!("[mux] unexpected inbound stream");
                            }
                            std::task::Poll::Ready(Some(Err(e))) => {
                                log::warn!("[mux] yamux error: {e}");
                                return std::task::Poll::Ready(true);
                            }
                            std::task::Poll::Ready(None) => {
                                log::info!("[mux] yamux connection closed");
                                return std::task::Poll::Ready(true);
                            }
                            std::task::Poll::Pending => {}
                        }
                        std::task::Poll::Ready(false)
                    }).await
                };
                if closed {
                    poller_state.store(ConnState::Dead as u32, Ordering::Relaxed);
                    break;
                }
                smol::Timer::after(std::time::Duration::from_millis(1)).await;
            }
            log::debug!("[mux] poller exit");
        });

        // ── Reader task: stream 0 → on_frame callback ──
        let reader_state = state.clone();
        let reader_task = smol::spawn(async move {
            let mut reader = reader;
            let mut buf = vec![0u8; 65536];
            let mut pending = Vec::new();
            loop {
                if !ConnState::from_u32(reader_state.load(Ordering::Relaxed)).is_alive() {
                    break;
                }
                match reader.read(&mut buf).await {
                    Ok(0) => {
                        log::info!("[mux] reader: stream closed");
                        reader_state.store(ConnState::Dead as u32, Ordering::Relaxed);
                        break;
                    }
                    Ok(n) => {
                        pending.extend_from_slice(&buf[..n]);
                        while let Some((frame, consumed)) = Frame::decode(&pending) {
                            on_frame(&frame);
                            pending = pending[consumed..].to_vec();
                        }
                    }
                    Err(e) => {
                        log::warn!("[mux] read error: {e}");
                        reader_state.store(ConnState::Dead as u32, Ordering::Relaxed);
                        break;
                    }
                }
            }
            log::debug!("[mux] reader exit");
        });

        // ── Writer task: heap drain → stream 0 ──
        let writer_heap = heap.clone();
        let writer_state = state.clone();
        let writer_task = smol::spawn(async move {
            let mut writer = writer;
            loop {
                if !ConnState::from_u32(writer_state.load(Ordering::Relaxed)).is_alive() {
                    break;
                }
                let frames = writer_heap.drain();
                if !frames.is_empty() {
                    for frame in &frames {
                        if let Err(e) = writer.write_all(&frame.encode()).await {
                            log::warn!("[mux] write error: {e}");
                            writer_state.store(ConnState::Dead as u32, Ordering::Relaxed);
                            return;
                        }
                    }
                    if let Err(e) = writer.flush().await {
                        log::warn!("[mux] flush error: {e}");
                        writer_state.store(ConnState::Dead as u32, Ordering::Relaxed);
                        return;
                    }
                } else {
                    smol::Timer::after(std::time::Duration::from_millis(10)).await;
                }
            }
            log::debug!("[mux] writer exit");
        });

        Ok(Self {
            heap,
            state,
            conn,
            _poller: poller,
            _reader: reader_task,
            _writer: writer_task,
        })
    }

    /// Push a frame to send with Normal priority.
    pub fn send(&self, frame: Frame) {
        self.heap.push(Priority::Normal, frame);
    }

    /// Push a frame with specific priority.
    pub fn send_priority(&self, frame: Frame, priority: Priority) {
        self.heap.push(priority, frame);
    }

    /// Check if the connection is alive.
    pub fn is_alive(&self) -> bool {
        self.state().is_alive()
    }

    /// Get the connection state.
    pub fn state(&self) -> ConnState {
        ConnState::from_u32(self.state.load(Ordering::Relaxed))
    }

    /// Get the shared state for external monitoring.
    pub fn shared_state(&self) -> &SharedState {
        &self.state
    }

    /// Get the outbound heap for direct access.
    pub fn heap(&self) -> &Arc<OutboundHeap> {
        &self.heap
    }

    /// Open an additional yamux stream (e.g., for terminal).
    pub async fn open_stream(&self) -> Result<yamux::Stream, String> {
        let mut c = self.conn.lock().await;
        futures_lite::future::poll_fn(|cx| c.poll_new_outbound(cx))
            .await
            .map_err(|e| format!("open stream: {e}"))
    }
}

impl Drop for MuxSession {
    fn drop(&mut self) {
        self.state.store(ConnState::Shutdown as u32, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use network_transport::{endpoint, mesh_key, NODE_CONC, SVC_NODE};

    #[test]
    fn conn_state_roundtrip() {
        assert_eq!(ConnState::from_u32(0), ConnState::Active);
        assert_eq!(ConnState::from_u32(1), ConnState::Dead);
        assert_eq!(ConnState::from_u32(2), ConnState::Shutdown);
        assert_eq!(ConnState::from_u32(3), ConnState::Connecting);
        assert_eq!(ConnState::from_u32(99), ConnState::Connecting);
        assert!(ConnState::Active.is_alive());
        assert!(!ConnState::Dead.is_alive());
        assert!(!ConnState::Shutdown.is_alive());
    }

    #[test]
    fn frame_encode_decode() {
        let frame = Frame::jsonl(
            endpoint(1, SVC_NODE),
            endpoint(NODE_CONC, SVC_NODE),
            r#"{"type":"Ping"}"#,
        );
        let encoded = frame.encode();
        let (decoded, consumed) = Frame::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.payload, frame.payload);
    }
}
