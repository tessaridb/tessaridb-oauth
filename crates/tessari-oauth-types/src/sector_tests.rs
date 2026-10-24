use super::Sector;
use crate::Error;

#[test]
fn a_sector_inside_the_name_grammar_is_accepted_as_written() {
    assert_eq!(
        Sector::parse("tessaridb-cloud").map(|sector| sector.as_str().to_owned()),
        Ok("tessaridb-cloud".to_owned())
    );
}

#[test]
fn a_sector_outside_the_name_grammar_is_refused_by_field() {
    for raw in ["", "Cloud", "-cloud", "has space", "dot.ted"] {
        assert!(
            matches!(
                Sector::parse(raw),
                Err(Error::Invalid {
                    field: "sector",
                    ..
                })
            ),
            "{raw:?} must be refused"
        );
    }
}
