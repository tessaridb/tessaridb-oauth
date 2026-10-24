use tessari_oauth_types::base64url;

use super::token_id;

#[test]
fn a_token_id_is_sixteen_random_bytes_and_never_repeats() {
    let ids: Vec<String> = (0..64).map(|_| token_id().expect("an id")).collect();
    for id in &ids {
        assert_eq!(base64url::decode(id).expect("base64url").len(), 16, "{id}");
    }
    let distinct: std::collections::BTreeSet<&String> = ids.iter().collect();
    assert_eq!(distinct.len(), ids.len());
}

#[test]
fn a_random_secret_is_thirty_two_bytes_and_never_repeats() {
    let first = super::random_secret().expect("a secret");
    let second = super::random_secret().expect("a secret");
    assert_eq!(first.len(), 32);
    assert_ne!(*first, *second);
}
