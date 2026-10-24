use tessari_oauth_types::{ClientId, UserId};

use super::pairwise;

fn client(id: &str) -> ClientId {
    ClientId::parse(id).expect("a client id")
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
