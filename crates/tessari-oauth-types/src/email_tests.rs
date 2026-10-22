use tessari_oauth_constants::{EMAIL_LOCAL_MAX_LEN, EMAIL_MAX_LEN};

use super::EmailAddress;
use crate::Error;

fn kept(raw: &str) -> String {
    EmailAddress::parse(raw)
        .map(|address| address.as_str().to_owned())
        .expect("an address")
}

#[test]
fn an_address_is_kept_lowercased_so_case_never_makes_a_second_account() {
    assert_eq!(
        kept("Alice.Smith+news@Example.COM"),
        "alice.smith+news@example.com"
    );
    assert_eq!(kept("bob@mail.example.org"), "bob@mail.example.org");
    assert_eq!(
        EmailAddress::parse("A@X.io"),
        EmailAddress::parse("a@x.io"),
        "one address"
    );
    let longest_local = format!("{}@example.com", "a".repeat(EMAIL_LOCAL_MAX_LEN));
    assert_eq!(kept(&longest_local), longest_local);
    let domain = format!("{}.com", "d".repeat(EMAIL_MAX_LEN - 6));
    let longest = format!("a@{domain}");
    assert_eq!(longest.len(), EMAIL_MAX_LEN);
    assert_eq!(kept(&longest), longest);
}

#[test]
fn what_is_not_an_address_is_refused() {
    let too_long = format!("a@{}.com", "d".repeat(EMAIL_MAX_LEN - 5));
    let local_too_long = format!("{}@example.com", "a".repeat(EMAIL_LOCAL_MAX_LEN + 1));
    // 254 bytes as written; lowercasing turns each two-byte U+0130 into three, past the limit as kept.
    let longer_when_kept = format!("a@{}.com", "\u{130}".repeat(124));
    assert_eq!(longer_when_kept.len(), EMAIL_MAX_LEN);
    for raw in [
        "",
        "alice",
        "@example.com",
        "alice@",
        "alice@@example.com",
        "alice@bob@example.com",
        "alice@localhost",
        "alice@example..com",
        "alice@.example.com",
        "alice@example.com.",
        " alice@example.com",
        "alice@example.com ",
        "al ice@example.com",
        "alice@exa\tmple.com",
        "alice\u{0}@example.com",
        too_long.as_str(),
        local_too_long.as_str(),
        longer_when_kept.as_str(),
    ] {
        assert_eq!(
            EmailAddress::parse(raw),
            Err(Error::Invalid {
                field: "email",
                reason: "an address of a local part, one @ and a domain with a dot, without spaces"
            }),
            "{raw:?}"
        );
    }
}
