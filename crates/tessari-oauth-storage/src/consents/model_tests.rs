use tessari_oauth_types::UserId;

use super::Revoker;

#[test]
fn every_revoker_reads_back_as_itself() {
    let operator = Revoker::Operator(UserId::parse("op-1").expect("a user id"));
    for revoker in [Revoker::User, operator, Revoker::ClientRemoved] {
        assert_eq!(
            Revoker::read(&revoker.spelled()),
            Some(revoker.clone()),
            "{revoker:?}"
        );
    }
}

#[test]
fn an_unknown_or_malformed_actor_is_not_read_as_any_revoker() {
    for spelled in ["", "admin", "operator:", "operator:not a user", "User"] {
        assert_eq!(Revoker::read(spelled), None, "{spelled:?}");
    }
}
