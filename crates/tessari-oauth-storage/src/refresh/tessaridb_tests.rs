use super::text_id;
use crate::Error;

#[test]
fn a_quoted_text_id_is_read_as_its_text() {
    assert_eq!(text_id("'family-f1'").expect("read"), "family-f1");
}

#[test]
fn an_id_that_is_not_plain_quoted_text_is_refused() {
    for spelled in [
        "family-f1",
        "'family-f1",
        "family-f1'",
        "'it\\'s'",
        "'a\\\\b'",
        "'",
        "7",
    ] {
        assert!(
            matches!(text_id(spelled), Err(Error::Unreadable { .. })),
            "{spelled}"
        );
    }
}
