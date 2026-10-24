use std::collections::BTreeSet;

use super::OperatorRole;

#[test]
fn every_role_reads_back_from_its_own_distinct_name() {
    let names: BTreeSet<&str> = OperatorRole::ALL.iter().map(|role| role.name()).collect();
    assert_eq!(names.len(), OperatorRole::ALL.len(), "names are distinct");
    for role in OperatorRole::ALL {
        assert_eq!(OperatorRole::parse(role.name()), Some(role), "{role:?}");
    }
    assert_eq!(OperatorRole::parse("admin"), None, "no all-granting role");
}
