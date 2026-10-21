use tessari_oauth_constants::CLIENT_ID_MAX_LEN;

use super::ClientId;
use crate::Error;

#[test]
fn visible_ascii_ids_are_accepted_as_written() {
    for raw in [
        "s6BhdRkqt3",
        "my app",
        "https://app.example.com/client.json",
        "~",
        &"x".repeat(CLIENT_ID_MAX_LEN),
    ] {
        assert_eq!(
            ClientId::parse(raw).map(|id| id.as_str().to_owned()),
            Ok(raw.to_owned())
        );
    }
}

#[test]
fn empty_overlong_and_control_character_ids_are_refused() {
    for raw in [
        String::new(),
        "x".repeat(CLIENT_ID_MAX_LEN + 1),
        "client\nid".to_owned(),
        "client\r\nX-Header: 1".to_owned(),
        "client\u{7f}".to_owned(),
        "clïent".to_owned(),
    ] {
        assert!(
            matches!(
                ClientId::parse(raw.clone()),
                Err(Error::Invalid {
                    field: "client_id",
                    ..
                })
            ),
            "{raw:?} should be refused"
        );
    }
}
