//! Mail wording: a company sends the region's default until it keeps its own, its own wins for that company alone,
//! a reset brings the default back, and wording that breaks its kind's rules is refused and never stored.

use tessari_oauth_core::mail_template::{MailKind, Placeholder, Template, TemplateRefused};
use tessari_oauth_storage::mail_templates::{Reset, Set};
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
    let own_kinds = |wording: Vec<tessari_oauth_storage::mail_templates::Wording>| {
        wording
            .into_iter()
            .filter(|row| row.own)
            .map(|row| (row.kind, row.template, row.revision))
            .collect::<Vec<_>>()
    };
    let before = templates
        .wording(&tenant("acme"))
        .await
        .expect("the wording");
    assert_eq!(before.len(), MailKind::ALL.len());
    assert_eq!(own_kinds(before), Vec::new());

    let set = templates
        .set(
            &tenant("acme"),
            (MailKind::Reset, 0),
            &own(),
            "operator-1",
            at(),
        )
        .await;
    assert_eq!(set, Ok(Set::Made(1)));
    let stale = templates
        .set(
            &tenant("acme"),
            (MailKind::Reset, 0),
            &own(),
            "operator-2",
            at(),
        )
        .await;
    assert_eq!(stale, Ok(Set::Moved), "set meanwhile by somebody else");
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
        templates.wording(&tenant("acme")).await.map(own_kinds),
        Ok(vec![(MailKind::Reset, own(), 1)])
    );

    assert_eq!(
        templates.reset(&tenant("acme"), MailKind::Reset, 2).await,
        Ok(Reset::Moved)
    );
    assert_eq!(
        templates.reset(&tenant("acme"), MailKind::Reset, 1).await,
        Ok(Reset::Made)
    );
    assert_eq!(
        templates.reset(&tenant("acme"), MailKind::Reset, 1).await,
        Ok(Reset::None)
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
            (MailKind::Reset, 0),
            &no_link,
            "operator-1",
            at(),
        )
        .await;

    assert_eq!(
        set,
        Ok(Set::Refused(TemplateRefused::Missing(Placeholder::Link)))
    );
    let wording = templates
        .wording(&tenant("acme"))
        .await
        .expect("the wording");
    assert!(wording.iter().all(|row| !row.own && row.revision == 0));
    assert_eq!(
        templates.resolve(&tenant("acme"), MailKind::Reset).await,
        Ok(MailKind::Reset.built_in())
    );
}
