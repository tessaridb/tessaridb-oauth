use tessari_oauth_constants::GROUP_NAME_MAX_LEN;

use super::{GroupId, GroupRole};
use crate::Error;

#[test]
fn names_inside_the_grammar_are_accepted_as_written() {
    for raw in ["staff", "0-ops_eu", &"a".repeat(GROUP_NAME_MAX_LEN)] {
        assert_eq!(
            GroupId::parse(raw).map(|id| id.as_str().to_owned()),
            Ok(raw.to_owned())
        );
        assert_eq!(
            GroupRole::parse(raw).map(|role| role.as_str().to_owned()),
            Ok(raw.to_owned())
        );
    }
}

#[test]
fn names_outside_the_grammar_are_refused() {
    for raw in [
        String::new(),
        "a".repeat(GROUP_NAME_MAX_LEN + 1),
        "Staff".to_owned(),
        "sTaff".to_owned(),
        "-staff".to_owned(),
        "_staff".to_owned(),
        "has space".to_owned(),
        "dot.ted".to_owned(),
    ] {
        assert_eq!(
            GroupId::parse(raw.clone()),
            Err(Error::Invalid {
                field: "group",
                reason: "1 to 64 lowercase letters, digits, hyphens and underscores, starting with a letter or digit"
            }),
            "{raw:?}"
        );
        assert_eq!(
            GroupRole::parse(raw.clone()),
            Err(Error::Invalid {
                field: "role",
                reason: "1 to 64 lowercase letters, digits, hyphens and underscores, starting with a letter or digit"
            }),
            "{raw:?}"
        );
    }
}
