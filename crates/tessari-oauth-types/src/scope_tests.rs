use super::ScopeSet;
use crate::Error;

fn set(raw: &str) -> ScopeSet {
    ScopeSet::parse(raw).unwrap_or_else(|error| panic!("{raw:?} should parse: {error}"))
}

#[test]
fn tokens_are_read_as_a_sorted_set() {
    let scopes = set("profile openid email:read profile");
    assert_eq!(
        scopes.iter().collect::<Vec<_>>(),
        ["email:read", "openid", "profile"]
    );
    assert_eq!(set("b a"), set("a b"));
}

#[test]
fn a_value_outside_the_grammar_is_refused() {
    for raw in [
        "", " ", "a  b", " a", "a ", "a\tb", "a\"b", "a\\b", "café", "a\nb",
    ] {
        assert!(
            matches!(
                ScopeSet::parse(raw),
                Err(Error::Invalid { field: "scope", .. })
            ),
            "{raw:?} should be refused"
        );
    }
}

#[test]
fn a_set_is_within_a_ceiling_only_when_every_scope_is_in_it() {
    let ceiling = set("openid profile notes:read");
    assert!(set("openid").is_within(&ceiling));
    assert!(set("notes:read openid").is_within(&ceiling));
    assert!(!set("notes:write").is_within(&ceiling));
    assert!(!set("openid notes:write").is_within(&ceiling));
}
