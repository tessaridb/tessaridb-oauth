//! The TessariDB connection: where work runs, and the pool that runs it.

mod config;
mod place;
mod pool;

pub use config::StoreConfig;
pub use place::Place;
pub use pool::Database;
pub use tessaridb_client::{Answer, FromRecord, MappingFault, Number, RefusalClass, Row, Value};
