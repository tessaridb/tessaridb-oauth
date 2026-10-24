//! `tessaridb-oauth reseal --old-kek <file>`: seal every company's sealed values again under the server's
//! key-encryption key (`TESSARIDB_OAUTH_KEK`), opening them with the old one, so the old file can be destroyed.
//!
//! Run it with every node stopped. It reads the same environment as the server, walks every company in the region's
//! directory, and then walks them again to prove every value opens under the new key. It prints one line of counts
//! and exits 0 only when that second walk wrote nothing and found nothing it could not open, and no company was
//! still being provisioned (its database may not exist yet, so it is counted rather than read).

use std::process::ExitCode;

use tessari_oauth_constants::COMPANY_PAGE_MAX;
use tessari_oauth_infrastructure::config::{NodeConfig, old_kek_path};
use tessari_oauth_infrastructure::custody::Kek;
use tessari_oauth_infrastructure::tessaridb::Database;
use tessari_oauth_storage::companies::CompanyStatus;
use tessari_oauth_storage::sealed::Resealed;
use tessari_oauth_storage::{Storage, Tenancy};
use tessari_oauth_types::TenantId;

use crate::{Failure, store_config};

/// The subcommand's name.
pub(crate) const COMMAND: &str = "reseal";

/// What one walk over the directory found.
#[derive(Debug, Default)]
struct Walk {
    companies: u64,
    provisioning: u64,
    found: Resealed,
}

impl Walk {
    fn add(&mut self, found: Resealed) {
        self.found.resealed = self.found.resealed.saturating_add(found.resealed);
        self.found.already = self.found.already.saturating_add(found.already);
        self.found.unopened = self.found.unopened.saturating_add(found.unopened);
    }
}

/// Re-seal every company `arguments` lead to, and say whether it is finished.
pub(crate) fn run(arguments: &[String]) -> Result<ExitCode, Failure> {
    let old = Kek::load(&old_kek_path(arguments)?)?;
    let config = NodeConfig::from_env()?;
    let new = Kek::load(&config.kek)?;
    let database = Database::new(store_config(&config)?, config.store.connections.get())?;
    let storage = Storage::new(&database, &Tenancy::for_region(&config.region)?);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let (first, check) = runtime.block_on(async {
        let first = walk(&storage, &old, &new).await?;
        let check = walk(&storage, &old, &new).await?;
        Ok::<_, Failure>((first, check))
    })?;
    let finished =
        check.found.resealed == 0 && check.found.unopened == 0 && check.provisioning == 0;
    println!(
        concat!(
            "{{\"companies\":{},\"provisioning\":{},\"resealed\":{},",
            "\"already\":{},\"unopened\":{},\"finished\":{}}}"
        ),
        first.companies,
        first.provisioning,
        first.found.resealed,
        first.found.already,
        first.found.unopened,
        finished
    );
    Ok(if finished {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// One pass over every company of the directory, page by page.
async fn walk(storage: &Storage, old: &Kek, new: &Kek) -> Result<Walk, Failure> {
    let mut walked = Walk::default();
    let mut after: Option<TenantId> = None;
    loop {
        let page = storage
            .companies
            .page(after.as_ref(), COMPANY_PAGE_MAX)
            .await?;
        let Some(last) = page.last() else {
            return Ok(walked);
        };
        after = Some(last.id.clone());
        for company in page {
            walked.companies = walked.companies.saturating_add(1);
            if company.status == CompanyStatus::Provisioning {
                walked.provisioning = walked.provisioning.saturating_add(1);
                continue;
            }
            let found = storage.sealed.reseal(&company.id, old, new).await?;
            tracing::info!(
                company = company.id.as_str(),
                resealed = found.resealed,
                already = found.already,
                unopened = found.unopened,
                "company resealed"
            );
            walked.add(found);
        }
    }
}
