//! `tessaridb-oauth bootstrap-operator [--company <id>] --email <address>`: the emergency path that makes an
//! operator, of `system` unless another served company is named.
//!
//! It reads the same environment as the server and needs only the store, so it works when no operator can sign in.
//! The enrolment code it mints is printed once, to the terminal of whoever ran it, and never logged; every use is
//! logged at ERROR so whoever watches the logs sees it as it happens, and is recorded on that company's audit trail by
//! the operation itself.

use tessari_oauth_constants::SYSTEM_COMPANY;
use tessari_oauth_infrastructure::config::{NodeConfig, operator_target};
use tessari_oauth_infrastructure::custody::random_secret;
use tessari_oauth_infrastructure::tessaridb::Database;
use tessari_oauth_storage::{Storage, Tenancy};
use tessari_oauth_types::{EnrolmentCode, base64url};

use crate::{Failure, store_config, system_clock};

/// The subcommand's name.
pub(crate) const COMMAND: &str = "bootstrap-operator";

/// Make the operator `arguments` name, and tell whoever ran it how they set their first password.
pub(crate) fn run(arguments: &[String]) -> Result<(), Failure> {
    let (company, email) = operator_target(arguments)?;
    let config = NodeConfig::from_env()?;
    let database = Database::new(store_config(&config)?, config.store.connections.get())?;
    let storage = Storage::new(&database, &Tenancy::for_region(&config.region)?);
    let code = EnrolmentCode::from_secret(base64url::encode(&random_secret()?));
    let clock = system_clock();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let done = runtime.block_on(async {
        storage
            .bootstrap_operator(
                &company,
                &email,
                &code,
                &config.public.url,
                &config.admin.url,
                clock(),
            )
            .await
    })?;
    tracing::error!(
        event = "break_glass",
        company = company.as_str(),
        user = done.user.as_str(),
        code_issued = done.code_issued,
        "a platform operator was made by the emergency path"
    );
    let issuer = format!("{}/{}", config.public.url, company.as_str());
    let roles = if company.as_str() == SYSTEM_COMPANY {
        "companies and users"
    } else {
        "users, clients, policy, keys and audit"
    };
    if done.code_issued {
        println!(
            "operator {} holds {roles} at {issuer}\n\
             enrolment code (shown once, valid 72 hours): {}\n\
             set the first password with POST {issuer}/login/api/enroll",
            done.user.as_str(),
            code.expose()
        );
    } else {
        println!(
            "operator {} holds {roles} at {issuer}; the account already has a password",
            done.user.as_str()
        );
    }
    Ok(())
}
