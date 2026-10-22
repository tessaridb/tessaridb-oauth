use tessari_oauth_infrastructure::tessaridb::RefusalClass;

use super::take_once;
use crate::{Error, Result};

fn refused() -> Error {
    Error::Store(tessari_oauth_infrastructure::Error::Refused {
        message: "another request holds it".to_owned(),
        class: Some(RefusalClass::Conflict),
    })
}

/// `take_once` over a take that answers `taken` and a look that answers `there`.
async fn take(taken: Result<Option<u8>>, there: bool) -> Result<Option<u8>> {
    take_once(
        1,
        || {
            let taken = taken.clone();
            async move { taken }
        },
        || async move { Ok(there) },
    )
    .await
}

#[tokio::test]
async fn a_refused_take_of_a_record_still_there_keeps_the_refusal() {
    assert_eq!(take(Err(refused()), true).await, Err(refused()));
}

#[tokio::test]
async fn a_refused_take_of_a_record_now_gone_took_nothing() {
    assert_eq!(take(Err(refused()), false).await, Ok(None));
}

#[tokio::test]
async fn a_take_that_answered_is_answered_as_it_came() {
    assert_eq!(take(Ok(Some(7)), false).await, Ok(Some(7)));
    assert_eq!(take(Ok(None), true).await, Ok(None));
}
