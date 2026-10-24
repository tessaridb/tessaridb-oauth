use std::collections::BTreeSet;

use tessari_oauth_constants::RECOVERY_CODE_COUNT;

use super::{recovery_codes, recovery_digest};

const CROCKFORD: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

#[test]
fn a_set_is_ten_distinct_codes_of_four_groups_of_four_crockford_characters() {
    let codes = recovery_codes().expect("codes");
    assert_eq!(codes.len(), RECOVERY_CODE_COUNT);
    for code in &codes {
        let groups: Vec<&str> = code.split('-').collect();
        assert_eq!(groups.len(), 4, "{code}");
        assert!(
            groups
                .iter()
                .all(|group| group.len() == 4 && group.chars().all(|c| CROCKFORD.contains(c))),
            "{code}"
        );
    }
    assert_eq!(codes.iter().collect::<BTreeSet<_>>().len(), codes.len());
    let again = recovery_codes().expect("codes");
    assert!(
        codes.iter().all(|code| !again.contains(code)),
        "a fresh set"
    );
    let first_characters: BTreeSet<char> = codes
        .iter()
        .chain(&again)
        .flat_map(|code| code.chars().filter(|c| *c != '-'))
        .collect();
    assert!(first_characters.len() > 16, "the whole alphabet is in use");
}

#[test]
fn a_code_is_found_however_it_is_typed_and_only_a_code_has_a_digest() {
    let codes = recovery_codes().expect("codes");
    let code = codes.first().expect("a code");
    let digest = recovery_digest(code).expect("a digest");
    assert_eq!(digest.len(), 43, "unpadded base64url of 32 bytes");
    let typed = code.to_lowercase().replace('-', " ");
    assert_eq!(recovery_digest(&typed).as_deref(), Some(digest.as_str()));
    let compact = code.replace('-', "");
    assert_eq!(recovery_digest(&compact).as_deref(), Some(digest.as_str()));
    // Crockford reads I and L as 1 and O as 0.
    assert_eq!(
        recovery_digest("0000-1111-2222-3333"),
        recovery_digest("oOoO-iIlL-2222-3333")
    );
    assert_ne!(
        recovery_digest(codes.get(1).expect("a code")).as_deref(),
        Some(digest.as_str())
    );
    for not_a_code in [
        "",
        "ABCD-EFGH-JKMN-PQR",
        "ABCD-EFGH-JKMN-PQRST",
        "ABCD-EFGH-JKMN-PQRU",
        "ABCD+EFGH-JKMN-PQRS",
    ] {
        assert_eq!(recovery_digest(not_a_code), None, "{not_a_code}");
    }
}
