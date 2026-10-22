//! The region namespaces a live run makes are removed by the next run, before any of its tests starts: the first
//! fixture a process builds removes every `oauth_live<pid>x<rest>` whose process is gone, and every other fixture
//! waits for that. Removing them during a run instead would put catalog changes beside the tests' own writes and
//! turn their races into failures. Nothing this harness did not name is touched.

use std::future::Future;
use std::sync::Once;

use tessari_oauth_infrastructure::tessaridb::{Answer, Database, StoreConfig, Value};

/// The prefix of every region namespace the live fixtures make: `oauth_` and the region `live<pid>x<nanos>x<turn>`.
const PREFIX: &str = "oauth_live";

static SWEPT: Once = Once::new();

/// Removes, once per process and before the caller goes on, the namespaces of live runs that are no longer running.
pub fn earlier_runs_removed(config: &StoreConfig) {
    SWEPT.call_once(|| {
        let config = config.clone();
        on_own_runtime(async move { sweep(config).await });
    });
}

/// Runs `work` to completion on a thread and runtime of its own, from a synchronous fixture inside a test's runtime,
/// which cannot block on it. One removal at a time on one connection needs no more than a single-threaded runtime.
fn on_own_runtime(work: impl Future<Output = ()> + Send + 'static) {
    // bgv-allow(raw-thread-spawn): a synchronous fixture inside a test's runtime cannot block on that runtime; one
    // thread hosts the sweep and is joined before the fixture goes on.
    let finished = std::thread::spawn(move || {
        // bgv-allow(current-thread-runtime): one sweep on one connection, run from that fixture.
        match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime.block_on(work),
            Err(error) => report(format_args!(
                "the live suite has no runtime for its namespace work: {error}"
            )),
        }
    })
    .join();
    if finished.is_err() {
        report(format_args!("the live suite's namespace work panicked"));
    }
}

/// Says what went wrong on stderr, which the test harness shows for a failed test.
fn report(message: std::fmt::Arguments<'_>) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr(), "{message}");
}

/// Removes the namespaces a run that is no longer running left behind.
async fn sweep(config: StoreConfig) {
    let namespaces = match Database::new(config.clone(), 1) {
        Ok(database) => names(&database, "INFO FOR STORE;", 0, "namespaces").await,
        Err(error) => Err(error.to_string()),
    };
    let namespaces = match namespaces {
        Ok(found) => found,
        Err(message) => {
            report(format_args!(
                "the live suite could not read the test node's namespaces: {message}"
            ));
            return;
        }
    };
    for namespace in namespaces.iter().filter(|name| left_over(name)) {
        if let Err(message) = remove(&config, namespace).await {
            report(format_args!(
                "the live suite could not remove leftover namespace {namespace}: {message}"
            ));
        }
    }
}

/// Whether `namespace` is one this harness makes whose process is gone.
fn left_over(namespace: &str) -> bool {
    namespace
        .strip_prefix(PREFIX)
        .and_then(|rest| rest.split_once('x'))
        .filter(|(pid, _)| pid.parse::<u32>().is_ok())
        .is_some_and(|(pid, _)| !running(pid))
}

/// Whether a process `pid` runs on this machine.
fn running(pid: &str) -> bool {
    std::process::Command::new("ps")
        .args(["-p", pid])
        .stdout(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Removes `namespace` and everything in it; a namespace that does not exist is done. The engine drops no further
/// than one name, so each database goes with all its tables in one transaction, then the namespace.
async fn remove(config: &StoreConfig, namespace: &str) -> Result<(), String> {
    let database = Database::new(config.clone(), 1).map_err(|error| error.to_string())?;
    let present = names(&database, "INFO FOR STORE;", 0, "namespaces").await?;
    if !present.iter().any(|name| name == namespace) {
        return Ok(());
    }
    let scope = format!("USE NAMESPACE {namespace};");
    let databases = names(
        &database,
        &format!("{scope} INFO FOR NAMESPACE;"),
        1,
        "databases",
    )
    .await?;
    for name in databases {
        let inner = format!("{scope} USE DATABASE {name};");
        let tables = names(
            &database,
            &format!("{inner} INFO FOR DATABASE;"),
            2,
            "tables",
        )
        .await?;
        let drops: String = tables
            .iter()
            .map(|table| format!(" DROP TABLE {table};"))
            .collect();
        run(
            &database,
            &format!("{inner} BEGIN;{drops} DROP DATABASE {name}; COMMIT;"),
        )
        .await?;
    }
    run(&database, &format!("DROP NAMESPACE {namespace};")).await
}

/// The text items of the array `field` in the object answer at position `at` of `script`.
async fn names(
    database: &Database,
    script: &str,
    at: usize,
    field: &str,
) -> Result<Vec<String>, String> {
    let answers = database
        .run_unplaced(script, Vec::new())
        .await
        .map_err(|error| error.to_string())?;
    let Some(Answer::Value {
        value: Value::Object(info),
        ..
    }) = answers.get(at)
    else {
        return Ok(Vec::new());
    };
    let Some(Value::Array(items)) = info.get(field) else {
        return Ok(Vec::new());
    };
    Ok(items
        .iter()
        .filter_map(|item| match item {
            Value::String(text) => Some(text.clone()),
            _ => None,
        })
        .collect())
}

async fn run(database: &Database, script: &str) -> Result<(), String> {
    database
        .run_unplaced(script, Vec::new())
        .await
        .map(drop)
        .map_err(|error| error.to_string())
}
