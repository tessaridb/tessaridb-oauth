//! The `tessaridb-oauth` binary: the composition root. It wires tracing, configuration, the TessariDB connection,
//! storage, the protocol core and the listeners, and owns graceful shutdown; it holds no logic of its own.
//!
//! Every file is read and every value checked before the runtime starts, so a server that starts is one that can
//! serve, and one that cannot says why and exits non-zero.

use std::error::Error;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tessari_oauth_api::{AdminState, PublicState, admin_router, public_router, serve, trusting};
use tessari_oauth_constants::{
    BREACHED_PASSWORDS_TIMEOUT_SECS, DIRECTORY_REFRESH_SECS, DIRECTORY_REFRESH_TIMEOUT_SECS,
    EMAIL_CHANGE_APPLY_INTERVAL_SECS, EMAIL_CHANGE_APPLY_RUN_TIMEOUT_SECS, KEY_ROTATION_CHECK_SECS,
    KEY_ROTATION_RUN_TIMEOUT_SECS, LOGOUT_DELIVERY_INTERVAL_SECS, LOGOUT_DELIVERY_RUN_TIMEOUT_SECS,
    LOGOUT_SEND_TIMEOUT_SECS, MAIL_DELIVERY_INTERVAL_SECS, MAIL_DELIVERY_RUN_TIMEOUT_SECS,
    MAIL_SEND_TIMEOUT_SECS, PEER_DIRECTORIES_SECS, PEER_DIRECTORIES_TIMEOUT_SECS,
    SHUTDOWN_DRAIN_SECS,
};
use tessari_oauth_core::discovery;
use tessari_oauth_daemons::{
    DirectoryRefresh, EmailChangeApply, KeyRotation, LogoutDelivery, MailDelivery, Peer,
    PeerDirectories,
};
use tessari_oauth_infrastructure::backchannel::Poster;
use tessari_oauth_infrastructure::breached::BreachedPasswords;
use tessari_oauth_infrastructure::config::NodeConfig;
use tessari_oauth_infrastructure::custody::{Kek, Passwords};
use tessari_oauth_infrastructure::mail::MailRelay;
use tessari_oauth_infrastructure::tessaridb::{Database, StoreConfig};
use tessari_oauth_infrastructure::{ListenerTls, listener_config};
use tessari_oauth_storage::companies::{CompanyStatus, Elsewhere, Served};
use tessari_oauth_storage::throttle::Limit;
use tessari_oauth_storage::{Storage, Tenancy};
use tessari_oauth_types::{Algorithm, Clock, Timestamp};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;

mod bootstrap;
mod peers;
mod reseal;

pub(crate) type Failure = Box<dyn Error + Send + Sync>;

/// Where the server reaches out: clients' back-channel endpoints always, the mail relay when one is configured, and
/// the breached-password list unless it is turned off.
struct Outbound {
    poster: Poster,
    relay: Option<MailRelay>,
    breached: Option<Arc<BreachedPasswords>>,
}

/// The TLS configuration of each listener: the public one always, the admin console's when it was given one.
struct Listeners {
    public: Option<Arc<rustls::ServerConfig>>,
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
        Some((command, rest)) if command == reseal::COMMAND => {
            return reseal::run(rest).unwrap_or_else(|failure| {
                tracing::error!(error = %failure, "the re-seal failed");
                ExitCode::FAILURE
            });
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
        public: match &config.public.tls {
            Some(public) => Some(listener_config(&ListenerTls::new(
                std::fs::read(&public.cert)?,
                std::fs::read(&public.key)?,
            ))?),
            None => None,
        },
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
    let outbound = Outbound {
        poster: Poster::with_native_roots(Duration::from_secs(LOGOUT_SEND_TIMEOUT_SECS))?,
        relay: config
            .mail
            .as_ref()
            .map(|mail| MailRelay::load(mail, Duration::from_secs(MAIL_SEND_TIMEOUT_SECS)))
            .transpose()?,
        breached: config
            .breached_passwords
            .as_deref()
            .map(|base| {
                BreachedPasswords::with_native_roots(
                    base,
                    Duration::from_secs(BREACHED_PASSWORDS_TIMEOUT_SECS),
                )
                .map(Arc::new)
            })
            .transpose()?,
    };
    let database = Database::new(store, config.store.connections.get())?;
    let storage = Storage::new(&database, &Tenancy::for_region(&config.region)?);
    let peers = peers::peers(&config)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run(config, storage, peers, kek, passwords, tls, outbound))
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
    peers: Vec<Peer>,
    kek: Arc<Kek>,
    passwords: Arc<Passwords>,
    tls: Listeners,
    outbound: Outbound,
) -> Result<(), Failure> {
    let clock = system_clock();
    let served = Arc::new(Served::new(&config.public.url));
    // The companies the configuration names are served from the start: created when new, provisioned with their admin
    // console, and made active unless an operator suspended one, which the configuration does not override.
    storage.companies.prepare().await?;
    // Other regions send this region's companies here, to the public URL recorded beside them.
    storage.companies.record_base(&config.public.url).await?;
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
    // A company made through the console is provisioned again too, so what a newer release declares reaches it.
    let provisioned = storage
        .reprovision_companies(&config.public.url, &config.admin.url, clock())
        .await?;
    tracing::info!(companies = provisioned, "companies provisioned");
    served.replace(storage.companies.active().await?);
    storage.throttle.prepare().await?;
    storage.mail_templates.seed_defaults(clock()).await?;
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
        sender: Arc::new(outbound.poster),
        clock: Arc::clone(&clock),
        interval: Duration::from_secs(LOGOUT_DELIVERY_INTERVAL_SECS),
        timeout: Duration::from_secs(LOGOUT_DELIVERY_RUN_TIMEOUT_SECS),
    });
    let delivering = tokio::spawn(tessari_oauth_daemons::run(delivery, stopped.clone()));
    let mailing = outbound.relay.map(|relay| {
        let mail = Arc::new(MailDelivery {
            outbox: Arc::clone(&storage.outbox),
            kek: Arc::clone(&kek),
            served: Arc::clone(&served),
            sender: Arc::new(relay),
            interval: Duration::from_secs(MAIL_DELIVERY_INTERVAL_SECS),
            timeout: Duration::from_secs(MAIL_DELIVERY_RUN_TIMEOUT_SECS),
        });
        tokio::spawn(tessari_oauth_daemons::run(mail, stopped.clone()))
    });
    // Always: a change confirmed while mail was set up still takes effect, and its notices wait in the queue.
    let changes = Arc::new(EmailChangeApply {
        email_changes: Arc::clone(&storage.email_changes),
        mail_templates: Arc::clone(&storage.mail_templates),
        outbox: Arc::clone(&storage.outbox),
        audit: Arc::clone(&storage.audit),
        kek: Arc::clone(&kek),
        served: Arc::clone(&served),
        clock: Arc::clone(&clock),
        interval: Duration::from_secs(EMAIL_CHANGE_APPLY_INTERVAL_SECS),
        timeout: Duration::from_secs(EMAIL_CHANGE_APPLY_RUN_TIMEOUT_SECS),
    });
    let changing = tokio::spawn(tessari_oauth_daemons::run(changes, stopped.clone()));
    let refresh = Arc::new(DirectoryRefresh {
        companies: Arc::clone(&storage.companies),
        served: Arc::clone(&served),
        interval: Duration::from_secs(DIRECTORY_REFRESH_SECS),
        timeout: Duration::from_secs(DIRECTORY_REFRESH_TIMEOUT_SECS),
    });
    let refreshing = tokio::spawn(tessari_oauth_daemons::run(refresh, stopped.clone()));
    let elsewhere = Arc::new(Elsewhere::new());
    let reading_peers = (!peers.is_empty()).then(|| {
        let directories = Arc::new(PeerDirectories::new(
            peers,
            Arc::clone(&elsewhere),
            Duration::from_secs(PEER_DIRECTORIES_SECS),
            Duration::from_secs(PEER_DIRECTORIES_TIMEOUT_SECS),
        ));
        tokio::spawn(tessari_oauth_daemons::run(directories, stopped.clone()))
    });
    let console = AdminState {
        admin: Arc::clone(&storage.admin),
        codes: Arc::clone(&storage.codes),
        clients: Arc::clone(&storage.clients),
        client_removals: Arc::clone(&storage.client_removals),
        consents: Arc::clone(&storage.consents),
        groups: Arc::clone(&storage.groups),
        operators: Arc::clone(&storage.operators),
        services: Arc::clone(&storage.services),
        replay: Arc::clone(&storage.replay),
        subjects: Arc::clone(&storage.subjects),
        audit: Arc::clone(&storage.audit),
        sessions: Arc::clone(&storage.sessions),
        policies: Arc::clone(&storage.policies),
        brands: Arc::clone(&storage.brands),
        keys: Arc::clone(&storage.keys),
        mail_templates: Arc::clone(&storage.mail_templates),
        outbox: Arc::clone(&storage.outbox),
        mail: mailing.is_some(),
        kek: Arc::clone(&kek),
        signing_algorithm: SIGNING_ALGORITHM,
        users: Arc::clone(&storage.users),
        refresh: Arc::clone(&storage.refresh),
        enrolments: Arc::clone(&storage.enrolments),
        companies: Arc::clone(&storage.companies),
        tenants: Arc::clone(&storage.tenants),
        public: Arc::from(config.public.url.as_str()),
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
        groups: Arc::clone(&storage.groups),
        brands: Arc::clone(&storage.brands),
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
        elsewhere,
        clock,
        outbox: Arc::clone(&storage.outbox),
        resets: Arc::clone(&storage.resets),
        verifications: Arc::clone(&storage.verifications),
        email_changes: Arc::clone(&storage.email_changes),
        mail_templates: Arc::clone(&storage.mail_templates),
        mail: mailing.is_some(),
        breached: outbound.breached.clone(),
    };
    // Signals are taken before the listener opens, so no signal can arrive while the default action still applies.
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let listener = tokio::net::TcpListener::bind(config.public.address).await?;
    if tls.public.is_none() {
        tracing::warn!(
            address = %config.public.address,
            "the server serves in the clear; reach it only through a TLS terminator at its https PUBLIC_URL"
        );
    }
    tracing::info!(address = %config.public.address, tenants = config.tenants.len(), "server started");
    let admin_listener = tokio::net::TcpListener::bind(config.admin.address).await?;
    if tls.admin.is_none() {
        tracing::warn!(
            address = %config.admin.address,
            "the admin console serves in the clear; reach it only from this host or through a TLS terminator"
        );
    }
    tracing::info!(address = %config.admin.address, "admin console started");
    // The proxies whose forwarded header names the client, for the request limits on both listeners.
    let proxies = Arc::new(config.public.trusted_proxies.clone());
    let mut until_stopped = stopped.clone();
    let serving = tokio::spawn(serve(
        listener,
        trusting(public_router(state), Arc::clone(&proxies)),
        tls.public,
        // A sender that is gone means stop as well.
        async move { until_stopped.changed().await.unwrap_or_default() },
        "public",
    ));
    let mut admin_until_stopped = stopped;
    let serving_admin = tokio::spawn(serve(
        admin_listener,
        trusting(admin_router(console), proxies),
        tls.admin,
        async move { admin_until_stopped.changed().await.unwrap_or_default() },
        "admin",
    ));
    tokio::select! {
        _ = interrupt.recv() => tracing::info!(signal = "SIGINT", "shutting down"),
        _ = terminate.recv() => tracing::info!(signal = "SIGTERM", "shutting down"),
    }
    stop.send(true)?;
    let (answered, answered_admin, rotated, delivered, mailed, changed, refreshed, peered) =
        tokio::time::timeout(Duration::from_secs(SHUTDOWN_DRAIN_SECS), async {
            let rotated = rotating.await;
            let delivered = delivering.await;
            let mailed = match mailing {
                Some(mailing) => Some(mailing.await),
                None => None,
            };
            let changed = changing.await;
            let refreshed = refreshing.await;
            let peered = match reading_peers {
                Some(reading) => Some(reading.await),
                None => None,
            };
            let answered_admin = serving_admin.await;
            (
                serving.await,
                answered_admin,
                rotated,
                delivered,
                mailed,
                changed,
                refreshed,
                peered,
            )
        })
        .await
        .map_err(|_| format!("requests still in flight after {SHUTDOWN_DRAIN_SECS} s"))?;
    rotated?;
    delivered?;
    mailed.transpose()?;
    changed?;
    refreshed?;
    peered.transpose()?;
    answered_admin??;
    Ok(answered??)
}
