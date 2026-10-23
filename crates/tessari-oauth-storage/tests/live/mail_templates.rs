//! Mail wording: a company sends the region's default until it keeps its own, its own wins for that company alone,
//! a reset brings the default back, and wording that breaks its kind's rules is refused and never stored.

use tessari_oauth_core::mail_template::{MailKind, Placeholder, Template, TemplateRefused};
use tessari_oauth_types::{TenantId, Timestamp};

use crate::fresh;

fn tenant(name: &str) -> TenantId {
    TenantId::parse(name).expect("a tenant id")
}

fn at() -> Timestamp {
    Timestamp::from_unix_secs(1_800_000_000)
}

fn own() -> Template {
    Template {
        subject: "Acme: reset your password".to_owned(),
        text: "Open {link} to choose a new password at {issuer}.\n".to_owned(),
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_company_sends_the_default_until_it_keeps_its_own_wording() {
    let storage = fresh(&tenant("acme"), 2).await;
    storage
        .tenants
        .provision(&tenant("globex"))
        .await
        .expect("provisioned");
    let templates = &storage.mail_templates;
    templates.seed_defaults(at()).await.expect("seeded");
    templates
        .seed_defaults(at())
        .await
        .expect("seeding again changes nothing");

    let shipped = MailKind::Reset.built_in();
    assert_eq!(
        templates.resolve(&tenant("acme"), MailKind::Reset).await,
        Ok(shipped.clone())
    );
    assert_eq!(templates.overrides(&tenant("acme")).await, Ok(Vec::new()));

    let set = templates
        .set(&tenant("acme"), MailKind::Reset, &own(), "operator-1", at())
        .await;
    assert_eq!(set, Ok(Ok(())));
    assert_eq!(
        templates.resolve(&tenant("acme"), MailKind::Reset).await,
        Ok(own())
    );
    assert_eq!(
        templates.resolve(&tenant("globex"), MailKind::Reset).await,
        Ok(shipped.clone()),
        "another company keeps the default"
    );
    assert_eq!(
        templates.resolve(&tenant("acme"), MailKind::Verify).await,
        Ok(MailKind::Verify.built_in()),
        "the other kinds keep theirs"
    );
    assert_eq!(
        templates.overrides(&tenant("acme")).await,
        Ok(vec![(MailKind::Reset, own())])
    );

    assert_eq!(
        templates.reset(&tenant("acme"), MailKind::Reset).await,
        Ok(true)
    );
    assert_eq!(
        templates.reset(&tenant("acme"), MailKind::Reset).await,
        Ok(false)
    );
    assert_eq!(
        templates.resolve(&tenant("acme"), MailKind::Reset).await,
        Ok(shipped)
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn wording_that_drops_the_link_is_refused_and_never_stored() {
    let storage = fresh(&tenant("acme"), 2).await;
    let templates = &storage.mail_templates;
    templates.seed_defaults(at()).await.expect("seeded");
    let no_link = Template {
        subject: "Reset".to_owned(),
        text: "Call us to reset your password.\n".to_owned(),
    };

    let set = templates
        .set(
            &tenant("acme"),
            MailKind::Reset,
            &no_link,
            "operator-1",
            at(),
        )
        .await;

    assert_eq!(set, Ok(Err(TemplateRefused::Missing(Placeholder::Link))));
    assert_eq!(templates.overrides(&tenant("acme")).await, Ok(Vec::new()));
    assert_eq!(
        templates.resolve(&tenant("acme"), MailKind::Reset).await,
        Ok(MailKind::Reset.built_in())
    );
}
