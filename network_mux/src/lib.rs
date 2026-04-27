//! Shared yamux multiplexer for chitin network connections.
//!
//! Provides `MuxSession<T>` — a self-running yamux session with background
//! poller, reader, and writer tasks. Generic over any `AsyncRead+AsyncWrite`
//! transport, with TCP-specific `connect` / `connect_with_heap` / `accept_tcp`
//! convenience methods for the common case. Used by both the concentrator
//! (server) and node clients; the generic form also supports wrapping
//! authenticated streams (e.g. libp2p-Noise) in front of yamux.
//!
//! ```text
//! MuxSession<T>
//!   ├── poller_task: drives yamux Connection (poll_next_inbound)
//!   ├── reader_task: reads frames from stream 0 → on_frame callback
//!   └── writer_task: drains OutboundHeap → writes to stream 0
//! ```

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use futures_lite::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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

/// Inbound-stream callback — called when a new yamux substream (1+)
/// arrives. The handler takes ownership of the Stream and is
/// responsible for its read/write task. The poller continues driving
/// the yamux Connection in the background so the handler's I/O
/// progresses without holding the Connection lock.
pub type StreamHandler = Arc<dyn Fn(yamux::Stream) + Send + Sync>;

/// Trait bound bundle for the underlying transport type. Any type satisfying
/// this can back a `MuxSession` — raw TCP, noise-wrapped streams, in-memory
/// pipes for tests, etc.
pub trait MuxTransport: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> MuxTransport for T {}

/// A self-running yamux session over any `AsyncRead+AsyncWrite` transport.
///
/// Owns background tasks for polling the yamux connection, reading frames,
/// and writing frames. Callers push frames via `send()` and receive them
/// through the `on_frame` callback provided at construction.
///
/// For TCP use, prefer `MuxSession::connect(addr, ...)` or
/// `MuxSession::accept_tcp(tcp, ...)` which set `TCP_NODELAY`. For
/// pre-wrapped transports (e.g. libp2p-noise), call the generic
/// `MuxSession::accept(transport, ...)` directly.
pub struct MuxSession<T: MuxTransport> {
    heap: Arc<OutboundHeap>,
    state: SharedState,
    conn: Arc<smol::lock::Mutex<yamux::Connection<T>>>,
    // Keep task handles to cancel on drop
    _poller: smol::Task<()>,
    _reader: smol::Task<()>,
    _writer: smol::Task<()>,
}

// ── TCP-specific convenience constructors ──
//
// `connect` needs a concrete transport type because it materializes a
// TcpStream from an address string; there's no generic analogue. Likewise
// `accept_tcp` preserves the pre-refactor TCP_NODELAY behavior for callers
// passing raw TcpStreams. New callers can put a Noise / TLS wrapper around
// a TcpStream and hand it to the generic `accept`.

impl MuxSession<smol::net::TcpStream> {
    /// Connect to a remote address as a yamux client.
    /// Opens stream 0 and starts background tasks.
    /// `on_stream` is called when a bridged substream arrives from a
    /// peer (via the concentrator). Pass `None` to ignore inbound
    /// substreams.
    pub async fn connect(
        addr: &str,
        on_frame: FrameHandler,
        on_stream: Option<StreamHandler>,
    ) -> Result<Self, String> {
        let tcp = smol::net::TcpStream::connect(addr)
            .await
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

        Self::from_parts(conn, stream0, on_frame, on_stream)
    }

    /// Connect with an externally-owned heap.
    /// Frames pushed to this heap will be written by the session's writer task.
    pub async fn connect_with_heap(
        addr: &str,
        heap: Arc<OutboundHeap>,
        on_frame: FrameHandler,
        on_stream: Option<StreamHandler>,
    ) -> Result<Self, String> {
        let tcp = smol::net::TcpStream::connect(addr)
            .await
            .map_err(|e| format!("tcp connect {addr}: {e}"))?;
        tcp.set_nodelay(true).ok();
        log::info!("[mux] connected to {addr}");

        let cfg = yamux::Config::default();
        let mut conn = yamux::Connection::new(tcp, cfg, yamux::Mode::Client);

        let stream0 = futures_lite::future::poll_fn(|cx| conn.poll_new_outbound(cx))
            .await
            .map_err(|e| format!("yamux stream 0: {e}"))?;
        log::info!("[mux] stream 0 open");

        Self::from_parts_with_heap(conn, stream0, heap, on_frame, on_stream)
    }

    /// Accept a yamux session from an incoming TCP connection. Sets
    /// `TCP_NODELAY` before handing off to the generic `accept`. Pre-refactor
    /// callers that called `MuxSession::accept(tcp, ...)` should migrate to
    /// `MuxSession::accept_tcp(tcp, ...)` to preserve nodelay behavior.
    pub async fn accept_tcp(
        tcp: smol::net::TcpStream,
        on_frame: FrameHandler,
        on_stream: Option<StreamHandler>,
    ) -> Result<Self, String> {
        tcp.set_nodelay(true).ok();
        Self::accept(tcp, on_frame, on_stream).await
    }
}

// ── Generic constructors (work on any transport) ──

impl<T: MuxTransport> MuxSession<T> {
    /// Accept a yamux session from an incoming transport (server mode).
    /// Waits for the client to open stream 0.
    /// `on_stream` is called when the peer opens additional substreams —
    /// the concentrator uses this to accept Connect control messages
    /// and bridge to target peers.
    ///
    /// This is generic over any `AsyncRead+AsyncWrite` transport. For raw
    /// TCP with `TCP_NODELAY`, use `MuxSession::<TcpStream>::accept_tcp`.
    pub async fn accept(
        transport: T,
        on_frame: FrameHandler,
        on_stream: Option<StreamHandler>,
    ) -> Result<Self, String> {
        let cfg = yamux::Config::default();
        let mut conn = yamux::Connection::new(transport, cfg, yamux::Mode::Server);

        // Wait for client to open stream 0
        let stream0 = match futures_lite::future::poll_fn(|cx| conn.poll_next_inbound(cx)).await {
            Some(Ok(s)) => s,
            Some(Err(e)) => return Err(format!("accept stream 0: {e}")),
            None => return Err("connection closed before stream 0".into()),
        };

        Self::from_parts(conn, stream0, on_frame, on_stream)
    }

    /// Connect over an arbitrary already-open transport as the
    /// yamux client. Mirrors `accept` for callers that don't want
    /// the TCP-specific `connect(addr)` — e.g. UDS yamux sessions
    /// where the caller has the `UnixStream` in hand.
    ///
    /// Opens stream 0 outbound and starts background tasks.
    ///
    /// **Note**: yamux opens stream 0 optimistically — the SYN bytes
    /// are queued but won't reach the server until the connection's
    /// poller flushes them. In practice this happens as soon as the
    /// client pushes its first application frame (e.g. Register /
    /// Ident); a connect followed by a long idle period may leave
    /// the server's `accept` blocked. Production callers always send
    /// something right after connect; tests should do the same.
    pub async fn connect_with_transport(
        transport: T,
        on_frame: FrameHandler,
        on_stream: Option<StreamHandler>,
    ) -> Result<Self, String> {
        let cfg = yamux::Config::default();
        let mut conn = yamux::Connection::new(transport, cfg, yamux::Mode::Client);

        let stream0 = futures_lite::future::poll_fn(|cx| conn.poll_new_outbound(cx))
            .await
            .map_err(|e| format!("yamux stream 0: {e}"))?;

        Self::from_parts(conn, stream0, on_frame, on_stream)
    }

    /// Build from existing connection + stream 0.
    fn from_parts(
        conn: yamux::Connection<T>,
        stream0: yamux::Stream,
        on_frame: FrameHandler,
        on_stream: Option<StreamHandler>,
    ) -> Result<Self, String> {
        let heap = Arc::new(OutboundHeap::new());
        Self::from_parts_with_heap(conn, stream0, heap, on_frame, on_stream)
    }

    /// Build from connection + stream 0 + external heap.
    fn from_parts_with_heap(
        conn: yamux::Connection<T>,
        stream0: yamux::Stream,
        heap: Arc<OutboundHeap>,
        on_frame: FrameHandler,
        on_stream: Option<StreamHandler>,
    ) -> Result<Self, String> {
        let (reader, writer) = futures_lite::io::split(stream0);
        let state = Arc::new(AtomicU32::new(ConnState::Active as u32));
        let conn = Arc::new(smol::lock::Mutex::new(conn));

        // ── Poller task: drive yamux connection ──
        let poller_conn = conn.clone();
        let poller_state = state.clone();
        let poller_on_stream = on_stream.clone();
        let poller = smol::spawn(async move {
            loop {
                if !ConnState::from_u32(poller_state.load(Ordering::Relaxed)).is_alive() {
                    break;
                }
                let (closed, new_stream) = {
                    let mut c = poller_conn.lock().await;
                    let mut new_stream: Option<yamux::Stream> = None;
                    let closed = futures_lite::future::poll_fn(|cx| {
                        match c.poll_next_inbound(cx) {
                            std::task::Poll::Ready(Some(Ok(s))) => {
                                new_stream = Some(s);
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
                    })
                    .await;
                    (closed, new_stream)
                };
                // Hand inbound substream to the caller's handler (if any)
                // outside the Connection lock so the handler's I/O can
                // progress without deadlocking the poller.
                if let Some(stream) = new_stream {
                    match poller_on_stream.as_ref() {
                        Some(handler) => handler(stream),
                        None => log::debug!("[mux] inbound stream dropped (no on_stream handler)"),
                    }
                }
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
                        log::info!("[mux] reader: {} bytes (pending {})", n, pending.len() + n);
                        pending.extend_from_slice(&buf[..n]);
                        let hex_sample: String = pending.iter().take(48)
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<_>>()
                            .join(" ");
                        log::info!("[mux] pending hex: {hex_sample} (total {} bytes)", pending.len());
                        let mut decoded = 0usize;
                        while let Some((frame, consumed)) = Frame::decode(&pending) {
                            decoded += 1;
                            log::info!("[mux] decoded frame {decoded}: {}B fmt={} from=0x{:04x} to=0x{:04x}",
                                frame.payload.len(), frame.format(), frame.from_ep(), frame.to_ep());
                            on_frame(&frame);
                            pending = pending[consumed..].to_vec();
                        }
                        if decoded == 0 {
                            log::warn!("[mux] no frame decoded from {} pending bytes", pending.len());
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

impl<T: MuxTransport> Drop for MuxSession<T> {
    fn drop(&mut self) {
        self.state.store(ConnState::Shutdown as u32, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use network_transport::{endpoint, NODE_CONC, SVC_NODE};

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
