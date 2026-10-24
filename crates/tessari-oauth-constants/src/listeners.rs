/// How long a client has to send a request's headers, in seconds; a client that trickles them is closed rather than
/// holding a connection slot.
pub const SERVE_HEADER_READ_SECS: u64 = 30;

/// The longest pause allowed between pieces of a request body, in seconds; a body that stops arriving fails its
/// request.
pub const SERVE_BODY_IDLE_SECS: u64 = 60;

/// How many connections one listener holds at once; the next waits in the kernel's listen backlog.
pub const SERVE_MAX_CONNECTIONS: usize = 4096;

/// How long a client has to complete its TLS handshake, in seconds; it runs in the connection's own task.
pub const TLS_HANDSHAKE_SECS: u64 = 10;

/// How long the listener has after a shutdown signal to finish the requests in flight, in seconds; past it the
/// process exits anyway. Shorter than the 30 s an orchestrator commonly waits before killing a process, so the drain
/// ends first.
pub const SHUTDOWN_DRAIN_SECS: u64 = 25;
