//! Serving a surface on a listener: in the clear, or over TLS where the handshake must complete before a request is
//! read — each connection in its own tracked task under deadlines (the handshake, the headers, every pause in a body)
//! and in one of a bounded number of slots, so a slow or idle client holds only itself and never the listener.
//! Handlers see the client's address as `ConnectInfo`. On shutdown the listener stops accepting and the connections
//! in flight finish.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{ConnectInfo, Request};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::server::graceful::{GracefulShutdown, Watcher};
use hyper_util::service::TowerToHyperService;
use rustls::ServerConfig;
use tessari_oauth_constants::{
    SERVE_BODY_IDLE_SECS, SERVE_HEADER_READ_SECS, SERVE_MAX_CONNECTIONS, TLS_HANDSHAKE_SECS,
};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tower::util::MapRequestLayer;

use crate::idle_body::IdleBody;

/// Serves `router` on `listener` until `shutdown` completes, over TLS when `tls` is given; `surface` names it in the
/// log.
///
/// # Errors
///
/// The listener's failure.
pub async fn serve(
    listener: TcpListener,
    router: axum::Router,
    tls: Option<Arc<ServerConfig>>,
    shutdown: impl Future<Output = ()> + Send + 'static,
    surface: &'static str,
) -> std::io::Result<()> {
    serve_with(
        listener,
        router,
        tls,
        shutdown,
        surface,
        &Patience::STANDARD,
    )
    .await
}

/// How long a client may take over a request's headers, its TLS handshake and between pieces of its body, and how
/// many connections one listener holds open at once.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Patience {
    pub(crate) headers: Duration,
    pub(crate) handshake: Duration,
    pub(crate) body_idle: Duration,
    pub(crate) connections: usize,
}

impl Patience {
    pub(crate) const STANDARD: Self = Self {
        headers: Duration::from_secs(SERVE_HEADER_READ_SECS),
        handshake: Duration::from_secs(TLS_HANDSHAKE_SECS),
        body_idle: Duration::from_secs(SERVE_BODY_IDLE_SECS),
        connections: SERVE_MAX_CONNECTIONS,
    };
}

/// [`serve`] under `patience`: every connection, in the clear or over TLS, runs in its own tracked task and holds one
/// of `patience.connections` slots; its handshake and headers must arrive within their deadlines and its body may
/// pause no longer than `patience.body_idle`.
pub(crate) async fn serve_with(
    listener: TcpListener,
    router: axum::Router,
    tls: Option<Arc<ServerConfig>>,
    shutdown: impl Future<Output = ()> + Send + 'static,
    surface: &'static str,
    patience: &Patience,
) -> std::io::Result<()> {
    let acceptor = tls.map(TlsAcceptor::from);
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(patience.headers);
    let idle = patience.body_idle;
    let handshake = patience.handshake;
    let router = router.layer(MapRequestLayer::new(move |request: Request| {
        request.map(|body| Body::new(IdleBody::new(body, idle)))
    }));
    let slots = Arc::new(Semaphore::new(patience.connections));
    let graceful = GracefulShutdown::new();
    let mut connections = JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        // Finished connections are reaped as the loop turns, so the set holds only live ones.
        while connections.try_join_next().is_some() {}
        // A connection is accepted only into a free slot; meanwhile the next waits in the listen backlog.
        let slot = tokio::select! {
            biased;
            () = &mut shutdown => break,
            slot = Arc::clone(&slots).acquire_owned() => match slot {
                Ok(slot) => slot,
                Err(_) => break,
            },
        };
        let (stream, peer) = tokio::select! {
            biased;
            () = &mut shutdown => break,
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(error) => {
                    tracing::warn!(surface, error = %error, "a connection could not be accepted");
                    continue;
                }
            },
        };
        let (acceptor, builder, watcher) = (acceptor.clone(), builder.clone(), graceful.watcher());
        let router = router.clone().layer(axum::Extension(ConnectInfo(peer)));
        connections.spawn(async move {
            let _slot = slot;
            let Some(acceptor) = acceptor else {
                connect(&builder, watcher, stream, router, surface, peer).await;
                return;
            };
            // The handshake runs in the connection's own task: a client slow to finish it holds only itself.
            let Ok(Ok(stream)) = tokio::time::timeout(handshake, acceptor.accept(stream)).await
            else {
                tracing::warn!(surface, %peer, "a connection did not complete its TLS handshake");
                return;
            };
            connect(&builder, watcher, stream, router, surface, peer).await;
        });
    }
    graceful.shutdown().await;
    while connections.join_next().await.is_some() {}
    Ok(())
}

/// Serves one connection's requests with `router` until it closes or the shutdown drains it.
async fn connect<I>(
    builder: &Builder<TokioExecutor>,
    watcher: Watcher,
    io: I,
    router: axum::Router,
    surface: &'static str,
    peer: SocketAddr,
) where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let connection = builder
        .serve_connection_with_upgrades(TokioIo::new(io), TowerToHyperService::new(router))
        .into_owned();
    if let Err(error) = watcher.watch(connection).await {
        tracing::debug!(surface, %peer, error = %error, "a connection ended with an error");
    }
}

#[cfg(test)]
#[path = "serve_tests.rs"]
mod tests;
