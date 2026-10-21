//! Reading the store's answers into rows: the shape each statement answers in, mapped once for every domain.

use tessari_oauth_infrastructure::tessaridb::{Answer, FromRecord, Row};

use crate::{Error, Result};

fn unreadable(record: &'static str, reason: String) -> Error {
    Error::Unreadable { record, reason }
}

/// Every record the first answer holds — the shape a `SELECT` answers in.
pub(crate) fn records<T: FromRecord>(answers: Vec<Answer>, record: &'static str) -> Result<Vec<T>> {
    let Some(answer) = answers.into_iter().next() else {
        return Ok(Vec::new());
    };
    answer
        .records_into::<T>()
        .map_err(|fault| unreadable(record, fault.to_string()))
}

/// The one record a statement addressed by id answered with, if any.
pub(crate) fn single<T: FromRecord>(
    answers: Vec<Answer>,
    record: &'static str,
) -> Result<Option<T>> {
    Ok(records(answers, record)?.pop())
}

/// The record a `RETURN BEFORE` or `RETURN AFTER` answered with: one value rather than a set of records, so it is
/// opened as a row under the id it was addressed by.
pub(crate) fn returned<T: FromRecord>(
    answers: Vec<Answer>,
    id: &str,
    record: &'static str,
) -> Result<Option<T>> {
    match answers.into_iter().next() {
        Some(Answer::Value { value, .. }) => {
            let row = Row::new(id.to_owned(), value)
                .map_err(|fault| unreadable(record, fault.to_string()))?;
            T::from_row(row)
                .map(Some)
                .map_err(|fault| unreadable(record, fault.to_string()))
        }
        Some(_) => Err(unreadable(
            record,
            "a write answered something other than the record it returned".to_owned(),
        )),
        None => Ok(None),
    }
}
