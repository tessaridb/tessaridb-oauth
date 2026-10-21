use super::init_tracing;
use crate::Error;

#[test]
fn the_subscriber_is_installed_once_and_a_second_attempt_is_refused_rather_than_panicking() {
    let guard = init_tracing().expect("the first installation");
    assert!(matches!(init_tracing(), Err(Error::AlreadyInstalled)));
    drop(guard);
}
