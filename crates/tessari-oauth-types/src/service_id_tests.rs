use super::ServiceId;
use crate::Error;

#[test]
fn a_service_id_inside_the_name_grammar_is_accepted_as_written() {
    assert_eq!(
        ServiceId::parse("cloud-backend").map(|service| service.as_str().to_owned()),
        Ok("cloud-backend".to_owned())
    );
}

#[test]
fn a_service_id_outside_the_name_grammar_is_refused_by_field() {
    for raw in ["", "Backend", "-backend", "has space", "service:backend"] {
        assert!(
            matches!(
                ServiceId::parse(raw),
                Err(Error::Invalid {
                    field: "service",
                    ..
                })
            ),
            "{raw:?} must be refused"
        );
    }
}
