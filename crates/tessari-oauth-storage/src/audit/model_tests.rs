use std::collections::BTreeSet;

use super::AuditKind;

#[test]
fn every_kind_reads_back_from_its_own_distinct_name() {
    let names: BTreeSet<&str> = AuditKind::ALL.iter().map(|kind| kind.as_str()).collect();
    assert_eq!(names.len(), AuditKind::ALL.len(), "names are distinct");
    for kind in AuditKind::ALL {
        assert_eq!(AuditKind::parse(kind.as_str()), Some(kind), "{kind:?}");
    }
    assert_eq!(AuditKind::parse("issued"), None);
}
