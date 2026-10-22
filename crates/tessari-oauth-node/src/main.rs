//! The `tessaridb-oauth` binary: the composition root. It wires tracing, configuration, the TessariDB connection,
//! storage, the protocol core and the listeners, and owns graceful shutdown; it holds no logic of its own.
//!
//! Every file is read and every value checked before the runtime starts, so a server that starts is one that can
//! serve, and one that cannot says why and exits non-zero.

use std::collections::HashMap;
use std::error::Error;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tessari_oauth_api::{PublicState, public_router, serve};
use tessari_oauth_constants::{
    KEY_ROTATION_CHECK_SECS, KEY_ROTATION_RUN_TIMEOUT_SECS, SHUTDOWN_DRAIN_SECS,
};
use tessari_oauth_core::discovery;
use tessari_oauth_daemons::KeyRotation;
use tessari_oauth_infrastructure::config::NodeConfig;
use tessari_oauth_infrastructure::custody::{Kek, Passwords};
use tessari_oauth_infrastructure::tessaridb::{Database, StoreConfig};
use tessari_oauth_infrastructure::{ListenerTls, listener_config};
use tessari_oauth_storage::throttle::Limit;
use tessari_oauth_storage::{Storage, Tenancy};
use tessari_oauth_types::{Algorithm, Clock, Timestamp};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;

type Failure = Box<dyn Error + Send + Sync>;

/// The algorithm new signing keys are made for, and the only one an access token is verified under.
const SIGNING_ALGORITHM: Algorithm = Algorithm::Es256;

fn main() -> ExitCode {
    let Ok(_flush_on_exit) = tessari_oauth_observability::init_tracing() else {
        return ExitCode::FAILURE;
    };
    match start() {
        Ok(()) => {
            tracing::info!("shutdown complete");
            ExitCode::SUCCESS
        }
        Err(failure) => {
            tracing::error!(error = %failure, "the server stopped");
            ExitCode::FAILURE
        }
    }
}

/// Read and check everything, then run the server on a multi-thread runtime until a signal stops it.
fn start() -> Result<(), Failure> {
    let config = NodeConfig::from_env()?;
    tracing::debug!(?config, "loaded configuration");
    let tls = listener_config(&ListenerTls::new(
        std::fs::read(&config.public.tls_cert)?,
        std::fs::read(&config.public.tls_key)?,
    ))?;
    let kek = Arc::new(Kek::load(&config.kek)?);
    let passwords = Passwords::load(
        &config.pepper,
        config.password_cost,
        config.password_concurrency.get(),
    )?;
    let store = StoreConfig {
        address: config.store.address.clone(),
        user: config.store.user.clone(),
        password: config.store.password.clone(),
        authority: config
            .store
            .authority
            .as_ref()
            .map(std::fs::read)
            .transpose()?,
    };
    let mut issuers = HashMap::new();
    for tenant in &config.tenants {
        let issuer = format!("{}/{}", config.public.url, tenant.as_str());
        discovery::metadata(&issuer).map_err(|_| format!("{issuer} is not a valid issuer"))?;
        issuers.insert(tenant.clone(), issuer);
    }
    let database = Database::new(store, config.store.connections.get())?;
    let storage = Storage::new(&database, &Tenancy::for_region(&config.region)?);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run(config, storage, issuers, kek, passwords, tls))
}

/// The system clock as the core's clock port; a clock before the epoch reads as the epoch.
fn system_clock() -> Clock {
    Arc::new(|| {
        Timestamp::from_unix_secs(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        )
    })
}

async fn run(
    config: NodeConfig,
    storage: Storage,
    issuers: HashMap<tessari_oauth_types::TenantId, String>,
    kek: Arc<Kek>,
    passwords: Arc<Passwords>,
    tls: Arc<rustls::ServerConfig>,
) -> Result<(), Failure> {
    for tenant in &config.tenants {
        storage.tenants.provision(tenant).await?;
    }
    storage.throttle.prepare().await?;
    let clock = system_clock();
    let (stop, stopped) = watch::channel(false);
    let rotation = Arc::new(KeyRotation {
        keys: Arc::clone(&storage.keys),
        kek: Arc::clone(&kek),
        tenants: config.tenants.clone(),
        algorithm: SIGNING_ALGORITHM,
        clock: Arc::clone(&clock),
        interval: Duration::from_secs(KEY_ROTATION_CHECK_SECS),
        timeout: Duration::from_secs(KEY_ROTATION_RUN_TIMEOUT_SECS),
    });
    let rotating = tokio::spawn(tessari_oauth_daemons::run(rotation, stopped.clone()));
    let state = PublicState {
        keys: Arc::clone(&storage.keys),
        clients: Arc::clone(&storage.clients),
        codes: Arc::clone(&storage.codes),
        refresh: Arc::clone(&storage.refresh),
        replay: Arc::clone(&storage.replay),
        subjects: Arc::clone(&storage.subjects),
        kek,
        throttle: Arc::clone(&storage.throttle),
        audit: Arc::clone(&storage.audit),
        signing_algorithm: SIGNING_ALGORITHM,
        interactions: Arc::clone(&storage.interactions),
        users: Arc::clone(&storage.users),
        factors: Arc::clone(&storage.factors),
        signins: Arc::clone(&storage.signins),
        sessions: Arc::clone(&storage.sessions),
        passwords,
        read_limit: Limit {
            requests: config.read_limit.requests,
            window_secs: config.read_limit.window_secs,
        },
        token_limit: Limit {
            requests: config.token_limit.requests,
            window_secs: config.token_limit.window_secs,
        },
        authorize_limit: Limit {
            requests: config.authorize_limit.requests,
            window_secs: config.authorize_limit.window_secs,
        },
        login_limit: Limit {
            requests: config.login_limit.requests,
            window_secs: config.login_limit.window_secs,
        },
        issuers: Arc::new(issuers),
        clock,
    };
    // Signals are taken before the listener opens, so no signal can arrive while the default action still applies.
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let listener = tokio::net::TcpListener::bind(config.public.address).await?;
    tracing::info!(address = %config.public.address, tenants = config.tenants.len(), "server started");
    let mut until_stopped = stopped;
    let serving = tokio::spawn(serve(
        listener,
        public_router(state),
        Some(tls),
        // A sender that is gone means stop as well.
        async move { until_stopped.changed().await.unwrap_or_default() },
        "public",
    ));
    tokio::select! {
        _ = interrupt.recv() => tracing::info!(signal = "SIGINT", "shutting down"),
        _ = terminate.recv() => tracing::info!(signal = "SIGTERM", "shutting down"),
    }
    stop.send(true)?;
    let (served, rotated) = tokio::time::timeout(Duration::from_secs(SHUTDOWN_DRAIN_SECS), async {
        let rotated = rotating.await;
        (serving.await, rotated)
    })
    .await
    .map_err(|_| format!("requests still in flight after {SHUTDOWN_DRAIN_SECS} s"))?;
    rotated?;
    Ok(served??)
}
