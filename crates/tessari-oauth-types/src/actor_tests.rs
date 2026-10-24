use super::Actor;
use crate::{ServiceId, UserId};

#[test]
fn an_operator_keeps_its_user_id_and_a_service_is_named_apart() {
    let operator = Actor::Operator(UserId::parse("backend").expect("a user id"));
    let service = Actor::Service(ServiceId::parse("backend").expect("a service id"));
    assert_eq!(operator.name(), "backend");
    assert_eq!(service.name(), "service:backend");
    assert_ne!(operator.name(), service.name());
}
