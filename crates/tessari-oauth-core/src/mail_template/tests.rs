use super::{MailKind, Placeholder, Template, TemplateRefused, check, render};

fn template(subject: &str, text: &str) -> Template {
    Template {
        subject: subject.to_owned(),
        text: text.to_owned(),
    }
}

/// A value for every placeholder `kind` allows, each distinct so a swapped substitution shows.
fn values(kind: MailKind) -> Vec<(Placeholder, String)> {
    kind.placeholders()
        .iter()
        .map(|placeholder| (*placeholder, format!("<{}-value>", placeholder.name())))
        .collect()
}

fn pairs(values: &[(Placeholder, String)]) -> Vec<(Placeholder, &str)> {
    values
        .iter()
        .map(|(placeholder, value)| (*placeholder, value.as_str()))
        .collect()
}

#[test]
fn every_built_in_template_is_valid_and_renders_each_of_its_values() {
    for kind in MailKind::ALL {
        let built_in = kind.built_in();
        assert_eq!(check(kind, &built_in), Ok(()), "{}", kind.name());
        let values = values(kind);
        let rendered = render(&built_in, &pairs(&values)).expect("renders");
        for placeholder in kind.required() {
            let value = format!("<{}-value>", placeholder.name());
            assert!(
                rendered.text.contains(&value),
                "{} carries {value}",
                kind.name()
            );
        }
        assert!(
            !rendered.text.contains('{'),
            "{} leaves nothing unfilled",
            kind.name()
        );
        assert!(!rendered.subject.contains('\n'));
    }
}

#[test]
fn the_reset_mail_renders_its_link_and_issuer_in_place() {
    let rendered = render(
        &template("Reset at {issuer}", "Open {link} for {issuer}.\n"),
        &[
            (Placeholder::Issuer, "https://id.example.com/acme"),
            (
                Placeholder::Link,
                "https://id.example.com/acme/login/reset#token=t",
            ),
        ],
    )
    .expect("renders");
    assert_eq!(rendered.subject, "Reset at https://id.example.com/acme");
    assert_eq!(
        rendered.text,
        "Open https://id.example.com/acme/login/reset#token=t for https://id.example.com/acme.\n"
    );
}

#[test]
fn a_template_that_drops_or_adds_a_placeholder_is_refused() {
    let reset = MailKind::Reset;
    assert_eq!(
        check(reset, &template("Reset", "No link here.")),
        Err(TemplateRefused::Missing(Placeholder::Link))
    );
    assert_eq!(
        check(
            MailKind::Verify,
            &template("Verify", "{link} {new_address}")
        ),
        Err(TemplateRefused::NotAllowed(Placeholder::NewAddress))
    );
    assert_eq!(
        check(reset, &template("Reset", "{link} {password}")),
        Err(TemplateRefused::Unknown("password".to_owned()))
    );
    assert_eq!(
        check(reset, &template("Reset", "{link} {")),
        Err(TemplateRefused::Unbalanced)
    );
    assert_eq!(
        check(reset, &template("Reset", "{link} }")),
        Err(TemplateRefused::Unbalanced)
    );
    assert_eq!(
        check(MailKind::EmailCancel, &template("Cancel", "{link}")),
        Err(TemplateRefused::Missing(Placeholder::NewAddress))
    );
}

#[test]
fn a_subject_or_text_out_of_shape_is_refused() {
    let reset = MailKind::Reset;
    assert_eq!(
        check(reset, &template("", "{link}")),
        Err(TemplateRefused::SubjectLength)
    );
    assert_eq!(
        check(reset, &template(&"s".repeat(201), "{link}")),
        Err(TemplateRefused::SubjectLength)
    );
    assert_eq!(check(reset, &template(&"s".repeat(200), "{link}")), Ok(()));
    assert_eq!(
        check(reset, &template("Two\nlines", "{link}")),
        Err(TemplateRefused::ControlCharacter)
    );
    assert_eq!(
        check(reset, &template("Reset", "")),
        Err(TemplateRefused::TextLength)
    );
    assert_eq!(
        check(
            reset,
            &template("Reset", &format!("{{link}}{}", "t".repeat(10_000)))
        ),
        Err(TemplateRefused::TextLength)
    );
    assert_eq!(
        check(reset, &template("Reset", "{link}\u{7}")),
        Err(TemplateRefused::ControlCharacter)
    );
    assert_eq!(check(reset, &template("Reset", "Line\n{link}\n")), Ok(()));
}

#[test]
fn doubled_braces_are_literal_and_a_value_is_never_read_as_a_placeholder() {
    let rendered = render(
        &template("Hi", "{{link}} is {link}"),
        &[(Placeholder::Link, "{issuer}")],
    )
    .expect("renders");
    assert_eq!(rendered.text, "{link} is {issuer}");
}

#[test]
fn a_template_naming_a_value_not_given_does_not_render() {
    assert_eq!(render(&template("Hi", "{link}"), &[]), None);
    assert_eq!(render(&template("Hi", "{nope}"), &[]), None);
}

#[test]
fn a_kind_is_named_and_read_back_by_its_name_alone() {
    for kind in MailKind::ALL {
        assert_eq!(MailKind::parse(kind.name()), Some(kind));
    }
    assert_eq!(MailKind::parse("reset "), None);
    assert_eq!(MailKind::parse("Reset"), None);
}

#[test]
fn the_enrolment_mail_carries_its_link_and_names_nothing_else_but_the_issuer() {
    let enrolment = MailKind::parse("enrolment").expect("a kind");
    assert_eq!(enrolment.required(), &[Placeholder::Link]);
    assert_eq!(
        check(
            enrolment,
            &template("Set your password", "Ask {issuer} for help.")
        ),
        Err(TemplateRefused::Missing(Placeholder::Link))
    );
    assert_eq!(
        check(enrolment, &template("Hi", "{link} for {new_address}")),
        Err(TemplateRefused::NotAllowed(Placeholder::NewAddress))
    );
    assert_eq!(check(enrolment, &enrolment.built_in()), Ok(()));
}

#[test]
fn a_registration_mail_carries_its_link_and_the_notice_to_an_owner_carries_none() {
    let registration = MailKind::parse("registration").expect("a kind");
    assert_eq!(registration.required(), &[Placeholder::Link]);
    assert_eq!(
        check(registration, &template("Welcome", "Ask {issuer}.")),
        Err(TemplateRefused::Missing(Placeholder::Link))
    );
    assert_eq!(check(registration, &registration.built_in()), Ok(()));
    let existing = MailKind::parse("registration_existing").expect("a kind");
    assert_eq!(existing.required(), &[] as &[Placeholder]);
    assert_eq!(
        check(existing, &template("Hi", "{link}")),
        Err(TemplateRefused::NotAllowed(Placeholder::Link)),
        "the owner's notice carries no link a requester could have asked to be sent"
    );
    assert_eq!(check(existing, &existing.built_in()), Ok(()));
    assert!(
        existing.built_in().text.contains("{issuer}"),
        "the notice names the sign-in service it is about"
    );
}
