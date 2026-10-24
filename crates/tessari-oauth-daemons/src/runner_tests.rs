use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use tokio::sync::watch;

use super::run;
use crate::daemon::{Daemon, DaemonFuture, DaemonReport};

/// A daemon that counts its runs, each taking `work` of (paused) time.
struct Counting {
    runs: Arc<AtomicU32>,
    finished: Arc<AtomicU32>,
    work: Duration,
}

impl Daemon for Counting {
    fn name(&self) -> &'static str {
        "counting"
    }

    fn interval(&self) -> Duration {
        Duration::from_secs(10)
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(3)
    }

    fn run_once(&self) -> DaemonFuture<'_> {
        Box::pin(async move {
            self.runs.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(self.work).await;
            self.finished.fetch_add(1, Ordering::Relaxed);
            Ok(DaemonReport {
                message: "done".to_owned(),
            })
        })
    }
}

fn counting(work: Duration) -> (Arc<Counting>, Arc<AtomicU32>, Arc<AtomicU32>) {
    let runs = Arc::new(AtomicU32::new(0));
    let finished = Arc::new(AtomicU32::new(0));
    let daemon = Arc::new(Counting {
        runs: Arc::clone(&runs),
        finished: Arc::clone(&finished),
        work,
    });
    (daemon, runs, finished)
}

/// Let the paused clock reach `secs` from the start, a second at a time so every task gets to run.
async fn advance_to(secs: u64) {
    for _ in 0..secs {
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn it_runs_on_every_tick_and_stops_on_shutdown() {
    let (daemon, runs, finished) = counting(Duration::from_secs(1));
    let (stop, shutdown) = watch::channel(false);
    let runner = tokio::spawn(run(daemon, shutdown));
    advance_to(25).await;
    // Ticks at 0, 10 and 20.
    assert_eq!(runs.load(Ordering::Relaxed), 3);
    assert_eq!(finished.load(Ordering::Relaxed), 3);
    stop.send(true).expect("the runner listens");
    runner.await.expect("the runner ends without panicking");
}

#[tokio::test(start_paused = true)]
async fn a_run_past_its_timeout_is_cut_and_the_next_tick_still_runs() {
    let (daemon, runs, finished) = counting(Duration::from_secs(5));
    let (stop, shutdown) = watch::channel(false);
    let runner = tokio::spawn(run(daemon, shutdown));
    advance_to(25).await;
    assert_eq!(runs.load(Ordering::Relaxed), 3, "every tick started a run");
    assert_eq!(
        finished.load(Ordering::Relaxed),
        0,
        "every run was cut at 3 s"
    );
    stop.send(true).expect("the runner listens");
    runner.await.expect("the runner ends without panicking");
}

#[tokio::test(start_paused = true)]
async fn shutdown_lets_the_current_run_finish_and_starts_no_other() {
    let (daemon, runs, finished) = counting(Duration::from_secs(2));
    let (stop, shutdown) = watch::channel(false);
    let runner = tokio::spawn(run(daemon, shutdown));
    advance_to(1).await;
    stop.send(true).expect("the runner listens");
    advance_to(30).await;
    assert!(runner.is_finished());
    assert_eq!(
        runs.load(Ordering::Relaxed),
        1,
        "no run started after shutdown"
    );
    assert_eq!(
        finished.load(Ordering::Relaxed),
        1,
        "the run in progress finished"
    );
}
