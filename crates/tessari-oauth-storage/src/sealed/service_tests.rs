use tessari_oauth_infrastructure::custody::Kek;
use tessari_oauth_test_support::kek_of;
use tessari_oauth_types::{TenantId, base64url};

use super::{Family, Outcome, decide, label, same_key};

const LABEL: &str = "totp:user-1";
const SECRET: &[u8] = b"twenty byte secret!!";

fn acme() -> TenantId {
    TenantId::parse("acme").expect("a tenant id")
}

fn key(byte: u8) -> Kek {
    kek_of(byte).expect("a key-encryption key")
}

fn sealed(kek: &Kek, label: &str) -> String {
    base64url::encode(&kek.seal(&acme(), label, SECRET).expect("sealed"))
}

#[test]
fn a_value_under_the_old_key_is_sealed_again_under_the_new_one_for_the_same_label() {
    let (old, new) = (key(1), key(2));
    let Outcome::Reseal(resealed) =
        decide(&acme(), LABEL, &sealed(&old, LABEL), &old, &new).expect("decided")
    else {
        panic!("a value under the old key is resealed");
    };
    let bytes = base64url::decode(&resealed).expect("base64url");
    let opened = new
        .unseal(&acme(), LABEL, &bytes)
        .expect("opens under the new key");
    assert_eq!(opened.as_slice(), SECRET);
    assert!(
        old.unseal(&acme(), LABEL, &bytes).is_err(),
        "and not under the old one"
    );
}

#[test]
fn a_value_already_under_the_new_key_is_left_alone() {
    let (old, new) = (key(1), key(2));
    assert_eq!(
        decide(&acme(), LABEL, &sealed(&new, LABEL), &old, &new).expect("decided"),
        Outcome::Already
    );
}

#[test]
fn a_value_under_neither_key_or_for_another_label_or_not_base64url_is_unopened() {
    let (old, new) = (key(1), key(2));
    for value in [
        sealed(&key(3), LABEL),
        sealed(&old, "totp:user-2"),
        "not base64url!".to_owned(),
    ] {
        assert_eq!(
            decide(&acme(), LABEL, &value, &old, &new).expect("decided"),
            Outcome::Unopened
        );
    }
}

#[test]
fn each_family_reads_the_label_its_own_service_seals_for() {
    assert_eq!(
        label(Family::SigningKeys, "kid-1", None).as_deref(),
        Some("kid-1")
    );
    assert_eq!(
        label(Family::Secrets, "pairwise", None).as_deref(),
        Some("pairwise")
    );
    assert_eq!(
        label(Family::MailOutbox, "m1", None).as_deref(),
        Some("mail:m1")
    );
    assert_eq!(
        label(Family::TotpFactors, "user-1", None).as_deref(),
        Some("totp:user-1")
    );
    assert_eq!(
        label(Family::TotpPending, "p1", Some("user-1")).as_deref(),
        Some("totp-pending:user-1")
    );
    assert_eq!(
        label(Family::TotpPending, "p1", None),
        None,
        "a pending factor with no user names no label"
    );
}

#[test]
fn two_copies_of_one_key_are_told_apart_from_two_keys() {
    assert!(same_key(&acme(), &key(1), &key(1)).expect("probed"));
    assert!(!same_key(&acme(), &key(1), &key(2)).expect("probed"));
}
