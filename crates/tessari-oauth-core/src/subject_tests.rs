use tessari_oauth_types::{ClientId, Sector, UserId};

use super::{SubjectSector, pairwise};

fn client(id: &str) -> SubjectSector {
    SubjectSector::Client(ClientId::parse(id).expect("a client id"))
}

fn sector(name: &str) -> SubjectSector {
    SubjectSector::Named(Sector::parse(name).expect("a sector"))
}

fn user(id: &str) -> UserId {
    UserId::parse(id).expect("a user id")
}

const SALT: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

#[test]
fn a_pairwise_subject_is_the_keyed_hash_of_the_sector_and_the_user() {
    // HMAC-SHA-256(salt 00..1f, u64-BE len("svc-1") || "svc-1" || "user-7"), computed outside this code.
    assert_eq!(
        pairwise(&SALT, &client("svc-1"), &user("user-7")),
        "tPp8gKh4hfDoIpCpYvMaDAGG3lRUTG75ijfAUS3HZ04"
    );
}

#[test]
fn the_subject_differs_per_client_per_user_and_per_salt() {
    let base = pairwise(&SALT, &client("svc-1"), &user("user-7"));
    assert_ne!(base, pairwise(&SALT, &client("svc-2"), &user("user-7")));
    assert_ne!(base, pairwise(&SALT, &client("svc-1"), &user("user-8")));
    assert_ne!(base, pairwise(&[7; 32], &client("svc-1"), &user("user-7")));
    assert_ne!(
        pairwise(&SALT, &client("ab"), &user("c")),
        pairwise(&SALT, &client("a"), &user("bc")),
        "the boundary between client and user is part of the input"
    );
}

#[test]
fn a_client_without_a_sector_keeps_the_subject_it_always_had() {
    // The same vector as the first test: registering sectors changes no subject an existing client holds.
    assert_eq!(
        pairwise(&SALT, &client("svc-1"), &user("user-7")),
        "tPp8gKh4hfDoIpCpYvMaDAGG3lRUTG75ijfAUS3HZ04"
    );
}

#[test]
fn a_named_sector_gives_one_subject_whatever_the_client_and_another_per_user() {
    let site = pairwise(&SALT, &sector("cloud"), &user("user-7"));
    assert_eq!(site, pairwise(&SALT, &sector("cloud"), &user("user-7")));
    assert_ne!(site, pairwise(&SALT, &sector("cloud"), &user("user-8")));
    assert_ne!(site, pairwise(&SALT, &sector("other"), &user("user-7")));
}

#[test]
fn a_named_sector_never_shares_a_subject_with_a_client_of_the_same_name() {
    // Otherwise registering sector `x` would join everything client `x` holds.
    assert_ne!(
        pairwise(&SALT, &sector("cloud"), &user("user-7")),
        pairwise(&SALT, &client("cloud"), &user("user-7"))
    );
    assert_ne!(sector("cloud").key(), client("cloud").key());
    assert!(
        sector("cloud")
            .key()
            .bytes()
            .any(|byte| !(0x20..=0x7e).contains(&byte)),
        "a sector key holds a byte no client id may hold"
    );
}
