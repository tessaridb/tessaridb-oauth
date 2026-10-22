//! The `tessaridb-oauth` binary: the composition root. It wires tracing, configuration, the TessariDB connection,
//! storage, the protocol core and the listeners, and owns graceful shutdown; it holds no logic of its own.
//!
//! Every file is read and every value checked before the runtime starts, so a server that starts is one that can
//! serve, and one that cannot says why and exits non-zero.

use std::error::Error;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tessari_oauth_api::{AdminState, PublicState, admin_router, public_router, serve};
use tessari_oauth_constants::{
    DIRECTORY_REFRESH_SECS, DIRECTORY_REFRESH_TIMEOUT_SECS, KEY_ROTATION_CHECK_SECS,
    KEY_ROTATION_RUN_TIMEOUT_SECS, LOGOUT_DELIVERY_INTERVAL_SECS, LOGOUT_DELIVERY_RUN_TIMEOUT_SECS,
    LOGOUT_SEND_TIMEOUT_SECS, SHUTDOWN_DRAIN_SECS,
};
use tessari_oauth_core::discovery;
use tessari_oauth_daemons::{DirectoryRefresh, KeyRotation, LogoutDelivery};
use tessari_oauth_infrastructure::backchannel::Poster;
use tessari_oauth_infrastructure::config::NodeConfig;
use tessari_oauth_infrastructure::custody::{Kek, Passwords};
use tessari_oauth_infrastructure::tessaridb::{Database, StoreConfig};
use tessari_oauth_infrastructure::{ListenerTls, listener_config};
use tessari_oauth_storage::companies::{CompanyStatus, Served};
use tessari_oauth_storage::throttle::Limit;
use tessari_oauth_storage::{Storage, Tenancy};
use tessari_oauth_types::{Algorithm, Clock, Timestamp};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;

mod bootstrap;

pub(crate) type Failure = Box<dyn Error + Send + Sync>;

/// The TLS configuration of each listener: the public one always, the admin console's when it was given one.
struct Listeners {
    public: Arc<rustls::ServerConfig>,
    admin: Option<Arc<rustls::ServerConfig>>,
}

/// The algorithm new signing keys are made for, and the only one an access token is verified under.
const SIGNING_ALGORITHM: Algorithm = Algorithm::Es256;

fn main() -> ExitCode {
    let Ok(_flush_on_exit) = tessari_oauth_observability::init_tracing() else {
        return ExitCode::FAILURE;
    };
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let outcome = match arguments.split_first() {
        Some((command, rest)) if command == bootstrap::COMMAND => {
            return bootstrap::run(rest).map_or_else(
                |failure| {
                    tracing::error!(error = %failure, "the emergency path failed");
                    ExitCode::FAILURE
                },
                |()| ExitCode::SUCCESS,
            );
        }
        Some((other, _)) => {
            tracing::error!(command = %other, "not a command this binary knows");
            return ExitCode::FAILURE;
        }
        None => start(),
    };
    match outcome {
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
    let tls = Listeners {
        public: listener_config(&ListenerTls::new(
            std::fs::read(&config.public.tls_cert)?,
            std::fs::read(&config.public.tls_key)?,
        ))?,
        admin: match &config.admin.tls {
            Some(admin) => Some(listener_config(&ListenerTls::new(
                std::fs::read(&admin.cert)?,
                std::fs::read(&admin.key)?,
            ))?),
            None => None,
        },
    };
    let kek = Arc::new(Kek::load(&config.kek)?);
    let passwords = Passwords::load(
        &config.pepper,
        config.password_cost,
        config.password_concurrency.get(),
    )?;
    let store = store_config(&config)?;
    for tenant in &config.tenants {
        let issuer = format!("{}/{}", config.public.url, tenant.as_str());
        discovery::metadata(&issuer, SIGNING_ALGORITHM)
            .map_err(|_| format!("{issuer} is not a valid issuer"))?;
    }
    let served = Arc::new(Served::new(&config.public.url));
    let poster = Poster::with_native_roots(Duration::from_secs(LOGOUT_SEND_TIMEOUT_SECS))?;
    let database = Database::new(store, config.store.connections.get())?;
    let storage = Storage::new(&database, &Tenancy::for_region(&config.region)?);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run(config, storage, served, kek, passwords, tls, poster))
}

/// How to reach the store the configuration names, its authority read from disk.
pub(crate) fn store_config(config: &NodeConfig) -> Result<StoreConfig, Failure> {
    Ok(StoreConfig {
        address: config.store.address.clone(),
        user: config.store.user.clone(),
        password: config.store.password.clone(),
        authority: config
            .store
            .authority
            .as_ref()
            .map(std::fs::read)
            .transpose()?,
    })
}

/// The system clock as the core's clock port; a clock before the epoch reads as the epoch.
pub(crate) fn system_clock() -> Clock {
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
    served: Arc<Served>,
    kek: Arc<Kek>,
    passwords: Arc<Passwords>,
    tls: Listeners,
    poster: Poster,
) -> Result<(), Failure> {
    let clock = system_clock();
    // The companies the configuration names are served from the start: created when new, provisioned with their admin
    // console, and made active unless an operator suspended one, which the configuration does not override.
    storage.companies.prepare().await?;
    for tenant in &config.tenants {
        storage
            .companies
            .create(tenant, tenant.as_str(), "configuration", clock())
            .await?;
        storage
            .provision_company(tenant, &config.public.url, &config.admin.url, clock())
            .await?;
        storage
            .companies
            .transition(tenant, CompanyStatus::Provisioning, CompanyStatus::Active)
            .await?;
    }
    served.replace(storage.companies.active().await?);
    storage.throttle.prepare().await?;
    let (stop, stopped) = watch::channel(false);
    let rotation = Arc::new(KeyRotation {
        keys: Arc::clone(&storage.keys),
        kek: Arc::clone(&kek),
        served: Arc::clone(&served),
        algorithm: SIGNING_ALGORITHM,
        clock: Arc::clone(&clock),
        interval: Duration::from_secs(KEY_ROTATION_CHECK_SECS),
        timeout: Duration::from_secs(KEY_ROTATION_RUN_TIMEOUT_SECS),
    });
    let rotating = tokio::spawn(tessari_oauth_daemons::run(rotation, stopped.clone()));
    let delivery = Arc::new(LogoutDelivery {
        logouts: Arc::clone(&storage.logouts),
        clients: Arc::clone(&storage.clients),
        subjects: Arc::clone(&storage.subjects),
        keys: Arc::clone(&storage.keys),
        kek: Arc::clone(&kek),
        served: Arc::clone(&served),
        sender: Arc::new(poster),
        clock: Arc::clone(&clock),
        interval: Duration::from_secs(LOGOUT_DELIVERY_INTERVAL_SECS),
        timeout: Duration::from_secs(LOGOUT_DELIVERY_RUN_TIMEOUT_SECS),
    });
    let delivering = tokio::spawn(tessari_oauth_daemons::run(delivery, stopped.clone()));
    let refresh = Arc::new(DirectoryRefresh {
        companies: Arc::clone(&storage.companies),
        served: Arc::clone(&served),
        interval: Duration::from_secs(DIRECTORY_REFRESH_SECS),
        timeout: Duration::from_secs(DIRECTORY_REFRESH_TIMEOUT_SECS),
    });
    let refreshing = tokio::spawn(tessari_oauth_daemons::run(refresh, stopped.clone()));
    let console = AdminState {
        admin: Arc::clone(&storage.admin),
        codes: Arc::clone(&storage.codes),
        clients: Arc::clone(&storage.clients),
        operators: Arc::clone(&storage.operators),
        audit: Arc::clone(&storage.audit),
        sessions: Arc::clone(&storage.sessions),
        throttle: Arc::clone(&storage.throttle),
        limit: Limit {
            requests: config.login_limit.requests,
            window_secs: config.login_limit.window_secs,
        },
        served: Arc::clone(&served),
        console: Arc::from(config.admin.url.as_str()),
        clock: Arc::clone(&clock),
    };
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
        enrolments: Arc::clone(&storage.enrolments),
        factors: Arc::clone(&storage.factors),
        policies: Arc::clone(&storage.policies),
        signins: Arc::clone(&storage.signins),
        passkeys: Arc::clone(&storage.passkeys),
        consents: Arc::clone(&storage.consents),
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
        served,
        clock,
    };
    // Signals are taken before the listener opens, so no signal can arrive while the default action still applies.
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let listener = tokio::net::TcpListener::bind(config.public.address).await?;
    tracing::info!(address = %config.public.address, tenants = config.tenants.len(), "server started");
    let admin_listener = tokio::net::TcpListener::bind(config.admin.address).await?;
    if tls.admin.is_none() {
        tracing::warn!(
            address = %config.admin.address,
            "the admin console serves in the clear; reach it only from this host or through a TLS terminator"
        );
    }
    tracing::info!(address = %config.admin.address, "admin console started");
    let mut until_stopped = stopped.clone();
    let serving = tokio::spawn(serve(
        listener,
        public_router(state),
        Some(tls.public),
        // A sender that is gone means stop as well.
        async move { until_stopped.changed().await.unwrap_or_default() },
        "public",
    ));
    let mut admin_until_stopped = stopped;
    let serving_admin = tokio::spawn(serve(
        admin_listener,
        admin_router(console),
        tls.admin,
        async move { admin_until_stopped.changed().await.unwrap_or_default() },
        "admin",
    ));
    tokio::select! {
        _ = interrupt.recv() => tracing::info!(signal = "SIGINT", "shutting down"),
        _ = terminate.recv() => tracing::info!(signal = "SIGTERM", "shutting down"),
    }
    stop.send(true)?;
    let (answered, answered_admin, rotated, delivered, refreshed) =
        tokio::time::timeout(Duration::from_secs(SHUTDOWN_DRAIN_SECS), async {
            let rotated = rotating.await;
            let delivered = delivering.await;
            let refreshed = refreshing.await;
            let answered_admin = serving_admin.await;
            (serving.await, answered_admin, rotated, delivered, refreshed)
        })
        .await
        .map_err(|_| format!("requests still in flight after {SHUTDOWN_DRAIN_SECS} s"))?;
    rotated?;
    delivered?;
    refreshed?;
    answered_admin??;
    Ok(answered??)
}
