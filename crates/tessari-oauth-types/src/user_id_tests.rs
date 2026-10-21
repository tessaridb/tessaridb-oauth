use tessari_oauth_constants::USER_ID_MAX_LEN;

use super::UserId;
use crate::Error;

#[test]
fn ids_inside_the_grammar_are_accepted_as_written() {
    for raw in ["u1", "Zm9v_bar-42", &"a".repeat(USER_ID_MAX_LEN)] {
        assert_eq!(
            UserId::parse(raw).map(|id| id.as_str().to_owned()),
            Ok(raw.to_owned())
        );
    }
}

#[test]
fn ids_outside_the_grammar_are_refused() {
    for raw in [
        String::new(),
        "a".repeat(USER_ID_MAX_LEN + 1),
        "alice@example.com".to_owned(),
        "has space".to_owned(),
        "dot.ted".to_owned(),
    ] {
        assert_eq!(
            UserId::parse(raw.clone()),
            Err(Error::Invalid {
                field: "user",
                reason: "1 to 64 letters, digits, hyphens and underscores"
            }),
            "{raw:?}"
        );
    }
}
