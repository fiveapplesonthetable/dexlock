//! Core data types: one monitor-contention observation and the query that selects
//! a batch of them.

/// One monitor-contention observation. `blocked_src` / `blocking_src` are the two
/// source sites (the thread that was waiting and the thread that held the lock);
/// resolution turns each into the canonical lock taken there. `raw` preserves the
/// full input record so output can round-trip every original column.
#[derive(Clone, Debug)]
pub struct Contention {
    pub build_id: String,
    pub device: String,
    pub blocked_src: String,
    pub blocking_src: String,
    pub short_blocked_method: String,
    pub short_blocking_method: String,
    /// Every field of the source record, in header order.
    pub raw: Vec<String>,
    /// Resolved lock for `blocked_src` (`"N/A"` until resolved).
    pub resolved_blocked_lock: String,
    /// Resolved lock for `blocking_src` (`"N/A"` until resolved).
    pub resolved_blocking_lock: String,
}

impl Contention {
    /// The `(build_id, device)` this observation belongs to — the grouping key,
    /// since all sites for one build resolve against the same artifacts.
    pub fn group_key(&self) -> (String, String) {
        (self.build_id.clone(), self.device.clone())
    }
}

/// Parameters selecting a batch of contention observations from a [`TraceSource`].
///
/// [`TraceSource`]: crate::traces::TraceSource
#[derive(Clone, Debug, Default)]
pub struct Query {
    /// Maximum number of observations to return.
    pub limit: usize,
    /// Look back this many days.
    pub last_days: u32,
    /// Restrict to one build, if set.
    pub build_id: Option<String>,
    /// Restrict to one device, if set.
    pub device: Option<String>,
}
