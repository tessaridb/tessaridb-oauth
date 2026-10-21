use super::Resource;
use crate::Error;

const REFUSED: Error = Error::Invalid {
    field: "resource",
    reason: "an https URI in normalised form, without query, fragment or user information",
};

#[test]
fn https_uris_in_normalised_form_are_accepted_as_written() {
    for raw in [
        "https://api.example.com/",
        "https://api.example.com/invoices",
        "https://api.example.com:8443/v1",
    ] {
        assert_eq!(
            Resource::parse(raw).map(|resource| resource.as_str().to_owned()),
            Ok(raw.to_owned())
        );
    }
}

#[test]
fn anything_else_is_refused() {
    for raw in [
        "api.example.com",
        "http://api.example.com/",
        "https://API.example.com/",
        "https://api.example.com",
        "https://api.example.com/#part",
        "https://api.example.com/?tenant=a",
        "https://user@api.example.com/",
        "https://:secret@api.example.com/",
        "urn:example:api",
    ] {
        assert_eq!(Resource::parse(raw), Err(REFUSED), "{raw}");
    }
}
