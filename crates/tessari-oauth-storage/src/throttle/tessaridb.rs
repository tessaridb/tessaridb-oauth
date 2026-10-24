//! Request counters on TessariDB: a bounded space whose keys expire, counted by `INCR`.

use async_trait::async_trait;
use tessari_oauth_constants::THROTTLE_SPACE_MAX_KEYS;
use tessari_oauth_infrastructure::tessaridb::{Answer, Database, Number, Place, Value};

use super::model::Counters;
use super::repository::ThrottleRepository;
use crate::{Error, Result};

pub(crate) struct TessaridbThrottleRepository {
    database: Database,
}

impl TessaridbThrottleRepository {
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }
}

fn unreadable(reason: &str) -> Error {
    Error::Unreadable {
        record: "request counter",
        reason: reason.to_owned(),
    }
}

#[async_trait]
impl ThrottleRepository for TessaridbThrottleRepository {
    async fn prepare(&self, place: &Place) -> Result<()> {
        // Names are checked plain by `Place`, which is what allows them into the text. Each space holds at most
        // `THROTTLE_SPACE_MAX_KEYS` counters and evicts the least recently written past it, so a flood of distinct
        // clients cannot grow it without bound. Request counts are held in the node's memory: no log record and no
        // disk sync per request, and nothing a restart must keep.
        let namespace = place.namespace();
        let database = place.database();
        let requests = Counters::Requests.space();
        let signins = Counters::Signins.space();
        let script = format!(
            "DEFINE NAMESPACE IF NOT EXISTS {namespace}; USE NAMESPACE {namespace}; \
             DEFINE DATABASE IF NOT EXISTS {database}; USE DATABASE {database}; \
             DEFINE SPACE IF NOT EXISTS {requests} IN MEMORY MAX {THROTTLE_SPACE_MAX_KEYS}; \
             DEFINE SPACE IF NOT EXISTS {signins} MAX {THROTTLE_SPACE_MAX_KEYS};"
        );
        self.database.run_unplaced(&script, Vec::new()).await?;
        Ok(())
    }

    async fn count(
        &self,
        place: &Place,
        counters: Counters,
        key: &str,
        by: u64,
        seconds: u64,
    ) -> Result<u64> {
        let seconds =
            i64::try_from(seconds).map_err(|_| unreadable("a lifetime beyond i64 seconds"))?;
        let by = i64::try_from(by).map_err(|_| unreadable("an addition beyond i64"))?;
        // `INCR` keeps an existing expiry but gives a missing key none, so the counter is first created with its
        // expiry. Each statement reads and writes the key atomically; should the key lapse between the two, the
        // `INCR` makes a counter without expiry, which its window index retires from use and the space's bound
        // evicts.
        // The space's name is one of this crate's own, never a request's.
        let space = counters.space();
        let statement = format!(
            "SET {space}:$key = 0 IF ABSENT EXPIRE duration::from_secs($seconds); INCR {space}:$key BY $by;"
        );
        let answers = self
            .database
            .run_at(
                place,
                &statement,
                vec![
                    ("key".to_owned(), Value::from(key)),
                    ("by".to_owned(), Value::from(by)),
                    ("seconds".to_owned(), Value::from(seconds)),
                ],
            )
            .await?;
        match answers.into_iter().nth(1) {
            Some(Answer::Value {
                value: Value::Number(Number::Integer(count)),
                ..
            }) => u64::try_from(count).map_err(|_| unreadable("a negative count")),
            _ => Err(unreadable("an INCR answered something other than a count")),
        }
    }

    async fn hold(
        &self,
        place: &Place,
        key: &str,
        from: Option<u64>,
        until: u64,
        seconds: u64,
    ) -> Result<bool> {
        let until = i64::try_from(until).map_err(|_| unreadable("an instant beyond i64"))?;
        let seconds =
            i64::try_from(seconds).map_err(|_| unreadable("a lifetime beyond i64 seconds"))?;
        // A conditional `SET` reads and writes the key in one transaction and answers whether it wrote; a `SET`
        // replaces the whole version, so the expiry is restated with every write.
        let mut values = vec![
            ("key".to_owned(), Value::from(key)),
            ("until".to_owned(), Value::from(until)),
            ("seconds".to_owned(), Value::from(seconds)),
        ];
        let statement = match from {
            None => "SET counters:$key = $until IF ABSENT EXPIRE duration::from_secs($seconds);",
            Some(from) => {
                let from = i64::try_from(from).map_err(|_| unreadable("an instant beyond i64"))?;
                values.push(("from".to_owned(), Value::from(from)));
                "SET counters:$key = $until IF = $from EXPIRE duration::from_secs($seconds);"
            }
        };
        let answers = self.database.run_at(place, statement, values).await?;
        match answers.into_iter().next() {
            Some(Answer::Value {
                value: Value::Bool(written),
                ..
            }) => Ok(written),
            _ => Err(unreadable(
                "a conditional SET answered something other than whether it wrote",
            )),
        }
    }

    async fn held_until(&self, place: &Place, key: &str) -> Result<Option<u64>> {
        let answers = self
            .database
            .run_at(
                place,
                "GET counters:$key;",
                vec![("key".to_owned(), Value::from(key))],
            )
            .await?;
        match answers.into_iter().next() {
            Some(Answer::Value {
                value: Value::None, ..
            }) => Ok(None),
            Some(Answer::Value {
                value: Value::Number(Number::Integer(until)),
                ..
            }) => u64::try_from(until)
                .map(Some)
                .map_err(|_| unreadable("a negative instant")),
            _ => Err(unreadable("a GET answered something other than an instant")),
        }
    }

    async fn forget(&self, place: &Place, key: &str) -> Result<()> {
        self.database
            .run_at(
                place,
                "DEL counters:$key;",
                vec![("key".to_owned(), Value::from(key))],
            )
            .await?;
        Ok(())
    }
}
