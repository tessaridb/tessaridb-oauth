use super::Place;
use crate::Error;

#[test]
fn plain_names_make_a_place_and_its_preamble() {
    let place = Place::new("oauth_eu", "t_acme_corp").expect("plain names");
    assert_eq!(
        place.preamble(),
        "USE NAMESPACE oauth_eu; USE DATABASE t_acme_corp;"
    );
}

#[test]
fn anything_but_a_plain_name_is_refused_in_either_position() {
    for bad in [
        "",
        "1abc",
        "a-b",
        "a b",
        "a;DROP",
        "a`b",
        "ä",
        &"a".repeat(65),
    ] {
        assert!(
            matches!(Place::new(bad, "db"), Err(Error::InvalidName { .. })),
            "namespace {bad:?} should be refused"
        );
        assert!(
            matches!(Place::new("ns", bad), Err(Error::InvalidName { .. })),
            "database {bad:?} should be refused"
        );
    }
}
