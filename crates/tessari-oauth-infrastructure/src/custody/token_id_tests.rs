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
