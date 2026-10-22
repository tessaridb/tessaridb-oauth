//! `tessaridb-oauth bootstrap-operator --email <address>`: the emergency path that makes a platform operator.
//!
//! It reads the same environment as the server and needs only the store, so it works when no operator can sign in.
//! The enrolment code it mints is printed once, to the terminal of whoever ran it, and never logged; every use is
//! logged at ERROR so whoever watches the logs sees it as it happens, and is recorded on the `system` company's audit
//! trail by the operation itself.

use tessari_oauth_constants::SYSTEM_COMPANY;
use tessari_oauth_infrastructure::config::NodeConfig;
use tessari_oauth_infrastructure::custody::random_secret;
use tessari_oauth_infrastructure::tessaridb::Database;
use tessari_oauth_storage::{Storage, Tenancy};
use tessari_oauth_types::{EmailAddress, EnrolmentCode, base64url};

use crate::{Failure, store_config, system_clock};

/// The subcommand's name.
pub(crate) const COMMAND: &str = "bootstrap-operator";

/// The address `--email <address>` names in `arguments`, which follow the subcommand.
fn email(arguments: &[String]) -> Result<EmailAddress, Failure> {
    match arguments {
        [flag, address] if flag == "--email" => EmailAddress::parse(address.as_str())
            .map_err(|_| format!("{address} is not an email address").into()),
        _ => Err(format!("usage: tessaridb-oauth {COMMAND} --email <address>").into()),
    }
}

/// Make the platform operator `arguments` name, and tell whoever ran it how they set their first password.
pub(crate) fn run(arguments: &[String]) -> Result<(), Failure> {
    let email = email(arguments)?;
    let config = NodeConfig::from_env()?;
    let database = Database::new(store_config(&config)?, config.store.connections.get())?;
    let storage = Storage::new(&database, &Tenancy::for_region(&config.region)?);
    let code = EnrolmentCode::from_secret(base64url::encode(&random_secret()?));
    let clock = system_clock();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let done =
        runtime.block_on(async { storage.bootstrap_operator(&email, &code, clock()).await })?;
    tracing::error!(
        event = "break_glass",
        user = done.user.as_str(),
        code_issued = done.code_issued,
        "a platform operator was made by the emergency path"
    );
    let issuer = format!("{}/{SYSTEM_COMPANY}", config.public.url);
    if done.code_issued {
        println!(
            "operator {} holds companies and users at {issuer}\n\
             enrolment code (shown once, valid 72 hours): {}\n\
             set the first password with POST {issuer}/login/api/enroll",
            done.user.as_str(),
            code.expose()
        );
    } else {
        println!(
            "operator {} holds companies and users at {issuer}; the account already has a password",
            done.user.as_str()
        );
    }
    Ok(())
}
