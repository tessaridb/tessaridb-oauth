//! Which of the region's two counter spaces a count goes to.

/// A space of counters in the region's `throttle` database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Counters {
    /// Requests per route group and client, held in the store node's memory: one is counted with every request, so
    /// it costs no disk sync, and a count starts again from zero after the node restarts or its leader changes.
    Requests,
    /// Sign-in failures and the holds they earn, written to disk, so a restart does not clear them.
    Signins,
}

impl Counters {
    /// The space's name.
    pub(crate) const fn space(self) -> &'static str {
        match self {
            Self::Requests => "requests",
            Self::Signins => "counters",
        }
    }
}
