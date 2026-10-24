use super::{MailSecurity, MailVariables, mail_settings};
use crate::Error;

fn variables(url: Option<&str>) -> MailVariables {
    MailVariables {
        url: url.map(str::to_owned),
        user: None,
        password_file: None,
        from: Some("TessariDB <no-reply@id.example.com>".to_owned()),
        authority: None,
    }
}

#[test]
fn without_a_relay_no_mail_is_sent_and_a_stray_mail_setting_is_refused() {
    let none = MailVariables {
        from: None,
        ..variables(None)
    };
    assert_eq!(mail_settings(none).expect("no relay"), None);
    let stray = variables(None);
    assert!(
        matches!(
            mail_settings(stray),
            Err(Error::Unset {
                key: "TESSARIDB_OAUTH_SMTP_URL"
            })
        ),
        "a sender without a relay names the relay"
    );
}

#[test]
fn the_relay_is_reached_over_implicit_tls_or_starttls_and_in_the_clear_only_on_loopback() {
    let implicit = mail_settings(variables(Some("smtps://mail.example.com")))
        .expect("read")
        .expect("a relay");
    assert_eq!(
        (implicit.host.as_str(), implicit.port, implicit.security),
        ("mail.example.com", 465, MailSecurity::ImplicitTls)
    );
    let starttls = mail_settings(variables(Some("smtp://mail.example.com:2525")))
        .expect("read")
        .expect("a relay");
    assert_eq!(
        (starttls.port, starttls.security),
        (2525, MailSecurity::StartTls)
    );
    let submission = mail_settings(variables(Some("smtp://mail.example.com")))
        .expect("read")
        .expect("a relay");
    assert_eq!(submission.port, 587, "submission by default");
    let local = mail_settings(variables(Some("smtp://127.0.0.1:2525?plain")))
        .expect("read")
        .expect("a relay");
    assert_eq!(local.security, MailSecurity::PlainLoopback);
    for refused in [
        "smtp://mail.example.com:25?plain",
        "smtp://localhost:2525?plain",
        "http://mail.example.com",
        "smtps://user:secret@mail.example.com",
        "smtps://",
        "smtp://mail.example.com:0",
    ] {
        assert!(
            matches!(
                mail_settings(variables(Some(refused))),
                Err(Error::Invalid {
                    key: "TESSARIDB_OAUTH_SMTP_URL",
                    ..
                })
            ),
            "{refused}"
        );
    }
}

#[test]
fn the_sender_is_required_with_a_relay_and_must_be_one_address() {
    let mut missing = variables(Some("smtps://mail.example.com"));
    missing.from = None;
    assert!(matches!(
        mail_settings(missing),
        Err(Error::Unset {
            key: "TESSARIDB_OAUTH_SMTP_FROM"
        })
    ));
    let read = mail_settings(variables(Some("smtps://mail.example.com")))
        .expect("read")
        .expect("a relay");
    assert_eq!(
        (read.from_name.as_deref(), read.from_address.as_str()),
        (Some("TessariDB"), "no-reply@id.example.com")
    );
    for bad in [
        "not an address",
        "a@b.example, c@d.example",
        "Bob <bob@x.example>\r\nBcc: e@f.example",
        "Bob\r\nBcc: e@f.example <bob@x.example>",
    ] {
        let mut sender = variables(Some("smtps://mail.example.com"));
        sender.from = Some(bad.to_owned());
        assert!(
            matches!(
                mail_settings(sender),
                Err(Error::Invalid {
                    key: "TESSARIDB_OAUTH_SMTP_FROM",
                    ..
                })
            ),
            "{bad:?}"
        );
    }
}

#[test]
fn credentials_come_together() {
    let mut half = variables(Some("smtps://mail.example.com"));
    half.user = Some("relay-user".to_owned());
    assert!(matches!(
        mail_settings(half),
        Err(Error::Unset {
            key: "TESSARIDB_OAUTH_SMTP_PASSWORD_FILE"
        })
    ));
    let mut whole = variables(Some("smtps://mail.example.com"));
    whole.user = Some("relay-user".to_owned());
    whole.password_file = Some("/run/secrets/smtp".to_owned());
    let read = mail_settings(whole).expect("read").expect("a relay");
    let credentials = read.credentials.expect("credentials");
    assert_eq!(credentials.user, "relay-user");
    assert_eq!(
        credentials.password_file.to_str(),
        Some("/run/secrets/smtp")
    );
}
