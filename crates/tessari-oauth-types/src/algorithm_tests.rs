use super::Algorithm;

#[test]
fn the_algorithms_are_named_as_the_jose_registry_names_them() {
    assert_eq!(Algorithm::EdDsa.name(), "EdDSA");
    assert_eq!(Algorithm::Es256.name(), "ES256");
}
