//! Flood detection: counts what each source sends and logs when it goes well
//! past what playing the service needs. Reports only, refuses nothing.
//!
//! Counted against `SourceKey`, the grouping the circuit limits use: per subnet
//! for subscribers, per connection for the checker. Cells are counted per
//! sender and recipient pair as well.
//!
//! Counting never takes the table's lock. A source's counters are atomics behind
//! an `Arc` handed out once per connection, so a flood cannot park a worker
//! thread on the data path.

use std::{
    collections::HashMap,
    fmt::Display,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use tokio::{
    fs::{File, OpenOptions},
    io::AsyncWriteExt,
    time::Instant,
};
use tokio_util::sync::CancellationToken;

use crate::{
    connection::{ConnectionId, SourceKey},
    debug_log::{self, Log},
};

/// Window that rates are measured over
const WINDOW: Duration = Duration::from_secs(1);

// `rate` divides by the window in milliseconds, which the guard in `sample`
// only keeps above zero while the window is milliseconds or more.
const _: () = assert!(WINDOW.as_millis() >= 2);

/// Windows over the threshold before a flood is reported, counted up on a window
/// over it and down on one under it rather than reset
const DWELL: u32 = 4;

/// How long a source has to stay under its threshold before its flood is over.
/// Without it, traffic hovering at the threshold reports one flood per window.
const COOLDOWN: Duration = Duration::from_secs(10);

/// Samples a source may be idle for before it is dropped from the table
const IDLE_SAMPLES: u32 = 5;

/// Cells counted per atomic add; a connection holds back at most this many until
/// it closes
const CELL_BATCH: u64 = 64;

/// How often the tallies behind the flood detection also go to the debug log.
/// This is the resolution of every per-team figure over time the statistics
/// tooling can produce, and the batching above is why a single window's count
/// can lag by up to `CELL_BATCH` cells per connection.
const TRAFFIC_EXPORT: Duration = Duration::from_secs(10);

/// What a flood is counted in
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Kind {
    /// Connections accepted from this source
    Connections,
    /// Call setups, counted as they arrive rather than as the switchboard gets to
    /// them, so the rate is the one offered
    Circuits,
    /// Cells read from this source, signalling included, forwardable or not
    Cells,
    /// Cells one source sends another, keyed on the pair
    CellsToPeer,
}

impl Kind {
    /// Events per second one source may sustain before it is reported, set well
    /// above what playing needs rather than at what hurts
    const fn threshold(self) -> u64 {
        match self {
            Kind::Connections => 100,
            Kind::Circuits => 200,
            Kind::Cells => 2_000,
            Kind::CellsToPeer => 300,
        }
    }

    /// How this kind is named in the log and the export. Stable: something
    /// else parses it.
    const fn name(self) -> &'static str {
        match self {
            Kind::Connections => "connections",
            Kind::Circuits => "circuits",
            Kind::Cells => "cells",
            Kind::CellsToPeer => "cells-to-peer",
        }
    }

    const fn unit(self) -> &'static str {
        match self {
            Kind::Connections => "connections/s",
            Kind::Circuits => "call setups/s",
            Kind::Cells | Kind::CellsToPeer => "cells/s",
        }
    }
}

/// A source's counters, shared with its connections. Atomic, so that counting
/// never waits on the table.
#[derive(Default)]
struct Counters {
    connections: AtomicU64,
    setups: AtomicU64,
    cells: AtomicU64,
}

/// A flood in progress. Opened by the first window over the threshold, reported
/// once `DWELL` of them have accumulated, and dropped without a word if it
/// decays before that.
struct Episode {
    started: Instant,
    /// Last window over the threshold, for the cooldown
    exceeded: Instant,
    /// Windows over the threshold in a row
    streak: u32,
    reported: bool,
    peak: u64,
    total: u64,
}

impl Episode {
    fn starting_at(now: Instant) -> Self {
        Self {
            started: now,
            exceeded: now,
            streak: 0,
            reported: false,
            peak: 0,
            total: 0,
        }
    }
}

/// Events per second over a window of `elapsed`
fn rate(events: u64, elapsed: Duration) -> u64 {
    events.saturating_mul(1000) / elapsed.as_millis() as u64
}

/// What a closed window did to an episode, when that is worth reporting
struct Reported {
    over: bool,
    peak: u64,
    total: u64,
    duration: Duration,
}

/// Feeds one closed window to an episode, and says whether to report it. Shared
/// by the per-source and per-path samplers, so the dwell and the cooldown only
/// exist once.
fn step(
    episode: &mut Option<Episode>,
    now: Instant,
    value: u64,
    counted: u64,
    threshold: u64,
) -> Option<Reported> {
    if value > threshold {
        let flood = episode.get_or_insert_with(|| Episode::starting_at(now));
        flood.exceeded = now;
        flood.streak += 1;
        flood.peak = flood.peak.max(value);
        flood.total += counted;
        if flood.reported || flood.streak < DWELL {
            return None;
        }
        flood.reported = true;
        return Some(Reported {
            over: false,
            peak: flood.peak,
            total: flood.total,
            duration: now.duration_since(flood.started),
        });
    }

    let flood = episode.as_mut()?;
    flood.streak = flood.streak.saturating_sub(1);
    flood.total += counted;
    if !flood.reported {
        if flood.streak == 0 {
            // Decayed away before the dwell, so it was a burst, not a flood
            *episode = None;
        }
        return None;
    }
    if now.duration_since(flood.exceeded) < COOLDOWN {
        return None;
    }
    let reported = Reported {
        over: true,
        peak: flood.peak,
        total: flood.total,
        duration: now.duration_since(flood.started),
    };
    *episode = None;
    Some(reported)
}

/// What a source counted, for the debug log. Window counts rather than running
/// totals: a figure over any period is the sum of its windows, and a source
/// that goes quiet leaves nothing behind to keep.
#[derive(Clone, Copy, Default)]
struct Counts {
    cells: u64,
    setups: u64,
    connections: u64,
}

impl Counts {
    fn is_zero(&self) -> bool {
        self.cells == 0 && self.setups == 0 && self.connections == 0
    }

    fn add(&mut self, other: &Counts) {
        self.cells += other.cells;
        self.setups += other.setups;
        self.connections += other.connections;
    }
}

/// Everything tracked for one source
struct State {
    /// Shared with the source's connections
    counters: Arc<Counters>,
    connections: Option<Episode>,
    setups: Option<Episode>,
    cells: Option<Episode>,
    /// Consecutive samples with nothing counted and no episode
    idle: u32,
    /// Counted since the last debug log export
    pending: Counts,
}

impl State {
    fn new() -> Self {
        Self {
            counters: Arc::new(Counters::default()),
            connections: None,
            setups: None,
            cells: None,
            idle: 0,
            pending: Counts::default(),
        }
    }

    /// Closes the window: every per-source kind, what it counted, and the episode
    /// it belongs to. The only place a kind is tied to a counter; `CellsToPeer`
    /// is absent because it is counted per path.
    fn take_window(&mut self) -> [(Kind, u64, &mut Option<Episode>); 3] {
        let connections = self.counters.connections.swap(0, Ordering::Relaxed);
        let setups = self.counters.setups.swap(0, Ordering::Relaxed);
        let cells = self.counters.cells.swap(0, Ordering::Relaxed);
        [
            (Kind::Connections, connections, &mut self.connections),
            (Kind::Circuits, setups, &mut self.setups),
            (Kind::Cells, cells, &mut self.cells),
        ]
    }
}

/// Something worth saying about one source, or one path between two
#[derive(Clone, Copy, Debug)]
pub struct Alert {
    pub source: SourceKey,
    /// Who the source was sending to, for `Kind::CellsToPeer`
    pub peer: Option<SourceKey>,
    pub kind: Kind,
    /// Whether this reports the end of a flood rather than its start
    pub over: bool,
    /// Rate in the window that just closed
    pub value: u64,
    pub peak: u64,
    /// Events counted since the flood started
    pub total: u64,
    pub duration: Duration,
}

impl Display for Alert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Flood from {:?}", self.source)?;
        if let Some(peer) = self.peer {
            write!(f, " to {peer:?}")?;
        }
        if self.over {
            write!(
                f,
                " is over after {}s: peak {} {}",
                self.duration.as_secs(),
                self.peak,
                self.kind.unit()
            )?;
            write!(f, ", {} in total", self.total)
        } else {
            write!(
                f,
                ": {} {}, over the threshold of {}",
                self.value,
                self.kind.unit(),
                self.kind.threshold()
            )
        }
    }
}

impl Alert {
    /// Logs this alert: the fields are what a query filters on, the message is for
    /// reading by hand. Both ends of a flood go out at the same level.
    fn log(&self) {
        // Formatted, so the field is the peer or absent rather than `Some(..)`
        let peer = self.peer.map(|peer| format!("{peer:?}"));
        tracing::warn!(
            flood = self.kind.name(),
            source = ?self.source,
            peer = peer.as_deref(),
            over = self.over,
            value = self.value,
            threshold = self.kind.threshold(),
            peak = self.peak,
            total = self.total,
            seconds = self.duration.as_secs(),
            "{self}"
        );
    }
}

/// What one sender-to-recipient path carries. Only the sampler and the batched
/// flush touch these, so they need no atomics.
#[derive(Default)]
struct Path {
    cells: u64,
    episode: Option<Episode>,
    idle: u32,
    /// Counted since the last debug log export
    pending: u64,
}

/// Appends alerts to a file as JSON lines, for something in another container
/// to tail.
pub struct Export {
    file: File,
}

/// One line of the export.
///
/// Flat and spelled out rather than derived from `Alert`, because something else
/// parses this: a field renamed here breaks that reader. A source is an address
/// when it is pooled by subnet and a connection when it is the checker's, so
/// each is its own field and exactly one of the pair is present.
#[derive(Serialize)]
struct Record<'a> {
    /// Milliseconds since the epoch
    time: u64,
    flood: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_connection: Option<ConnectionId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_connection: Option<ConnectionId>,
    over: bool,
    value: u64,
    threshold: u64,
    peak: u64,
    total: u64,
    seconds: u64,
}

/// A source as the export spells it: an address, or a connection for the checker
fn flatten(source: SourceKey) -> (Option<String>, Option<ConnectionId>) {
    match source {
        SourceKey::Subnet(network) => (Some(network.to_string()), None),
        SourceKey::Connection(id) => (None, Some(id)),
    }
}

impl Export {
    /// Opens the export, appending to whatever is there already: a restart must
    /// not throw away what the reader has not picked up yet.
    pub async fn create(path: &std::path::Path) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;
        Ok(Self { file })
    }

    /// Appends one alert, as one line written in one call so that a reader
    /// tailing the file never sees half a record. Flushed to the OS, not synced:
    /// the reader shares the page cache, and a game is not worth an fsync a
    /// flood.
    async fn write(&mut self, alert: &Alert) -> std::io::Result<()> {
        let (source, source_connection) = flatten(alert.source);
        let (peer, peer_connection) = alert.peer.map(flatten).unwrap_or_default();
        let record = Record {
            time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            flood: alert.kind.name(),
            source,
            source_connection,
            peer,
            peer_connection,
            over: alert.over,
            value: alert.value,
            threshold: alert.kind.threshold(),
            peak: alert.peak,
            total: alert.total,
            seconds: alert.duration.as_secs(),
        };
        let mut line = serde_json::to_vec(&record).map_err(std::io::Error::other)?;
        line.push(b'\n');
        self.file.write_all(&line).await?;
        self.file.flush().await
    }
}

struct Table {
    sources: HashMap<SourceKey, State>,
    /// Keyed on (sender, recipient)
    paths: HashMap<(SourceKey, SourceKey), Path>,
    /// When the last window closed
    sampled: Instant,
    /// What entries dropped for being idle had counted since the last debug log
    /// export. Without this, a short burst from a source that then goes quiet
    /// would be pruned away before it was ever exported.
    carried: Vec<(SourceKey, Option<SourceKey>, Counts)>,
}

/// Counts what arrives and reports what crosses a threshold
pub struct Monitor {
    table: Mutex<Table>,
}

impl Monitor {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            table: Mutex::new(Table {
                sources: HashMap::new(),
                paths: HashMap::new(),
                sampled: Instant::now(),
                carried: Vec::new(),
            }),
        })
    }

    /// The counters for a source, created on first sight. Taken once per
    /// connection, not once per cell.
    fn counters(&self, source: SourceKey) -> Arc<Counters> {
        // Detection must not be the reason the DSLAM stops forwarding, so a
        // poisoned lock is taken over rather than propagated.
        let mut table = self
            .table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state = table.sources.entry(source).or_insert_with(State::new);
        state.idle = 0;
        state.counters.clone()
    }

    /// Counts a new connection
    pub fn connected(&self, source: SourceKey) {
        self.counters(source)
            .connections
            .fetch_add(1, Ordering::Relaxed);
    }

    /// A handle for counting one connection's traffic
    pub fn traffic(self: &Arc<Self>, source: SourceKey) -> Traffic {
        Traffic {
            monitor: self.clone(),
            counters: self.counters(source),
            from: source,
            cells: 0,
            to: HashMap::new(),
            forwarded: 0,
        }
    }

    /// Adds a batch of forwarded cells, one entry per recipient
    fn record_paths(&self, from: SourceKey, to: &HashMap<SourceKey, u64>) {
        let mut table = self
            .table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for (peer, cells) in to {
            table.paths.entry((from, *peer)).or_default().cells += cells;
        }
    }

    /// Closes the current window for every source and path, and returns what to
    /// report. Idle entries are dropped.
    ///
    /// A sample less than half a window after the last one is folded into the next:
    /// over a very short window, a rate says more about when the sample ran than
    /// about the traffic.
    pub fn sample(&self, now: Instant) -> Vec<Alert> {
        let mut table = self
            .table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let elapsed = now.saturating_duration_since(table.sampled);
        if elapsed < WINDOW / 2 {
            return Vec::new();
        }
        table.sampled = now;

        let mut alerts = Vec::new();
        for (source, state) in table.sources.iter_mut() {
            // A source any handle still refers to is never idle: dropping the
            // entry would orphan the counters that handle writes to
            let mut busy = Arc::strong_count(&state.counters) > 1;
            let mut counts = Counts::default();
            for (kind, counted, episode) in state.take_window() {
                busy |= counted > 0;
                match kind {
                    Kind::Connections => counts.connections = counted,
                    Kind::Circuits => counts.setups = counted,
                    Kind::Cells => counts.cells = counted,
                    Kind::CellsToPeer => {}
                }
                let value = rate(counted, elapsed);
                if let Some(reported) = step(episode, now, value, counted, kind.threshold()) {
                    alerts.push(Alert {
                        source: *source,
                        peer: None,
                        kind,
                        over: reported.over,
                        value,
                        peak: reported.peak,
                        total: reported.total,
                        duration: reported.duration,
                    });
                }
                busy |= episode.is_some();
            }
            state.pending.add(&counts);
            state.idle = if busy { 0 } else { state.idle + 1 };
        }
        let mut carried = Vec::new();
        table.sources.retain(|source, state| {
            let keep = state.idle < IDLE_SAMPLES;
            if !keep && !state.pending.is_zero() {
                carried.push((*source, None, state.pending));
            }
            keep
        });

        for ((from, to), path) in table.paths.iter_mut() {
            let counted = std::mem::take(&mut path.cells);
            path.pending += counted;
            let value = rate(counted, elapsed);
            if let Some(reported) = step(
                &mut path.episode,
                now,
                value,
                counted,
                Kind::CellsToPeer.threshold(),
            ) {
                alerts.push(Alert {
                    source: *from,
                    peer: Some(*to),
                    kind: Kind::CellsToPeer,
                    over: reported.over,
                    value,
                    peak: reported.peak,
                    total: reported.total,
                    duration: reported.duration,
                });
            }
            path.idle = if counted > 0 || path.episode.is_some() {
                0
            } else {
                path.idle + 1
            };
        }
        table.paths.retain(|(from, to), path| {
            let keep = path.idle < IDLE_SAMPLES;
            if !keep && path.pending > 0 {
                carried.push((
                    *from,
                    Some(*to),
                    Counts {
                        cells: path.pending,
                        ..Counts::default()
                    },
                ));
            }
            keep
        });
        table.carried.extend(carried);
        alerts
    }

    /// Hands what has been counted since the last export to the debug log.
    ///
    /// `traffic` is every cell a source sent, before HEC and PTI validation and
    /// including signalling; `traffic-path` is the user-plane cells one source
    /// aimed at another, which is the team to team matrix. Only entries with
    /// something to report produce a line.
    fn drain_traffic(&self, seconds: u64) -> Vec<debug_log::Record> {
        let mut table = self
            .table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let mut records = Vec::new();
        let mut emit = |source: SourceKey, peer: Option<SourceKey>, counts: Counts| {
            let (from, from_connection) = debug_log::flatten(source);
            match peer {
                Some(peer) => {
                    let (to, to_connection) = debug_log::flatten(peer);
                    records.push(debug_log::Record::TrafficPath {
                        from,
                        from_connection,
                        to,
                        to_connection,
                        cells: counts.cells,
                        seconds,
                    });
                }
                None => records.push(debug_log::Record::Traffic {
                    from,
                    from_connection,
                    cells: counts.cells,
                    setups: counts.setups,
                    connections: counts.connections,
                    seconds,
                }),
            }
        };

        for (source, peer, counts) in table.carried.drain(..) {
            emit(source, peer, counts);
        }
        for (source, state) in table.sources.iter_mut() {
            let counts = std::mem::take(&mut state.pending);
            if !counts.is_zero() {
                emit(*source, None, counts);
            }
        }
        for ((from, to), path) in table.paths.iter_mut() {
            let cells = std::mem::take(&mut path.pending);
            if cells > 0 {
                emit(
                    *from,
                    Some(*to),
                    Counts {
                        cells,
                        ..Counts::default()
                    },
                );
            }
        }
        records
    }

    /// Samples once per window and reports the result, until shutdown
    pub async fn run(
        self: Arc<Self>,
        shutdown: CancellationToken,
        mut export: Option<Export>,
        log: Log,
    ) {
        let mut windows = tokio::time::interval(WINDOW);
        windows.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut exported = Instant::now();
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    // Hand over the part-window the tick never got to
                    self.export_traffic(&log, &mut exported);
                    return;
                },
                _ = windows.tick() => {
                    for alert in self.sample(Instant::now()) {
                        alert.log();
                        if let Some(writer) = &mut export
                            && let Err(error) = writer.write(&alert).await
                        {
                            // Keep detecting and keep logging; a full disk is
                            // no reason to stop either
                            tracing::error!("Failed to write the flood export: {error}");
                            export = None;
                        }
                    }
                    if Instant::now().duration_since(exported) >= TRAFFIC_EXPORT {
                        self.export_traffic(&log, &mut exported);
                    }
                }
            }
        }
    }

    /// Writes the tallies since `exported` to the debug log, and notes when that
    /// was. The counting itself is what the flood detection already does, so an
    /// export costs a pass over the table and nothing on the data path.
    fn export_traffic(&self, log: &Log, exported: &mut Instant) {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(*exported);
        *exported = now;
        if !log.enabled() {
            return;
        }
        for record in self.drain_traffic(elapsed.as_secs()) {
            log.record(|| record);
        }
    }

    /// How many sources are tracked
    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .sources
            .len()
    }

    /// How many paths are tracked
    #[cfg(test)]
    fn tracked_paths(&self) -> usize {
        self.table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .paths
            .len()
    }
}

/// Counts one connection's traffic towards its source
pub struct Traffic {
    monitor: Arc<Monitor>,
    counters: Arc<Counters>,
    from: SourceKey,
    /// Cells not yet added, up to `CELL_BATCH`
    cells: u64,
    /// Forwarded cells not yet added, by recipient. Bounded by how many
    /// recipients one batch can reach, since a flush empties it.
    to: HashMap<SourceKey, u64>,
    forwarded: u64,
}

impl Traffic {
    /// Counts a cell read from the connection
    pub fn cell(&mut self) {
        self.cells += 1;
        if self.cells >= CELL_BATCH {
            self.flush();
        }
    }

    /// Counts a cell the DSLAM handed to `peer` -- or tried to, since a cell
    /// dropped on a full queue is one the recipient was still sent
    pub fn cell_to(&mut self, peer: SourceKey) {
        *self.to.entry(peer).or_insert(0) += 1;
        self.forwarded += 1;
        if self.forwarded >= CELL_BATCH {
            self.flush_paths();
        }
    }

    /// Counts a call setup from the connection
    pub fn setup(&self) {
        self.counters.setups.fetch_add(1, Ordering::Relaxed);
    }

    fn flush(&mut self) {
        if self.cells > 0 {
            self.counters.cells.fetch_add(self.cells, Ordering::Relaxed);
            self.cells = 0;
        }
        self.flush_paths();
    }

    /// Hands the per-recipient counts over. Unlike the source's counters these
    /// live in the table, so this is the one place the data path takes its lock
    /// -- once per `CELL_BATCH` cells, not once per cell.
    fn flush_paths(&mut self) {
        if self.forwarded > 0 {
            self.monitor.record_paths(self.from, &self.to);
            self.to.clear();
            self.forwarded = 0;
        }
    }
}

impl Drop for Traffic {
    fn drop(&mut self) {
        self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A subscriber subnet, as the DSLAM pools one
    fn subnet() -> SourceKey {
        SourceKey::Subnet("10.55.7.0".parse().expect("valid test network"))
    }

    /// Events for one window at `per_second`
    fn per_window(per_second: u64) -> u64 {
        per_second * WINDOW.as_secs()
    }

    /// Windows it takes to run the cooldown down
    fn cooldown_windows() -> u32 {
        (COOLDOWN.as_secs() / WINDOW.as_secs()) as u32
    }

    /// Closes `count` windows, returning the alerts from the last one
    async fn quiet(monitor: &Arc<Monitor>, count: u32) -> Vec<Alert> {
        let mut alerts = Vec::new();
        for _ in 0..count {
            tokio::time::advance(WINDOW).await;
            alerts = monitor.sample(Instant::now());
        }
        alerts
    }

    /// Counts `cells` cells and closes a window
    async fn cell_window(monitor: &Arc<Monitor>, traffic: &mut Traffic, cells: u64) -> Vec<Alert> {
        for _ in 0..cells {
            traffic.cell();
        }
        traffic.flush();
        quiet(monitor, 1).await
    }

    /// Counts `setups` call setups and closes a window
    async fn setup_window(monitor: &Arc<Monitor>, traffic: &Traffic, setups: u64) -> Vec<Alert> {
        for _ in 0..setups {
            traffic.setup();
        }
        quiet(monitor, 1).await
    }

    #[tokio::test(start_paused = true)]
    async fn traffic_at_the_threshold_is_not_reported() {
        let monitor = Monitor::new();
        let mut traffic = monitor.traffic(subnet());
        for _ in 0..DWELL + cooldown_windows() {
            let alerts =
                cell_window(&monitor, &mut traffic, per_window(Kind::Cells.threshold())).await;
            assert!(alerts.is_empty(), "{alerts:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_burst_that_decays_before_the_dwell_is_not_a_flood() {
        let monitor = Monitor::new();
        let mut traffic = monitor.traffic(subnet());
        let flood = per_window(20_000);

        // A team firing off a round's work at once: over the threshold, then gone
        // before the dwell is up
        for _ in 0..DWELL - 1 {
            assert!(cell_window(&monitor, &mut traffic, flood).await.is_empty());
        }
        assert!(quiet(&monitor, DWELL - 1).await.is_empty());

        // ...so the next burst starts from nothing
        for _ in 0..DWELL - 1 {
            assert!(cell_window(&monitor, &mut traffic, flood).await.is_empty());
        }
        assert!(quiet(&monitor, DWELL).await.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_flood_that_pauses_to_dodge_the_dwell_is_still_reported() {
        let monitor = Monitor::new();
        let mut traffic = monitor.traffic(subnet());
        let flood = per_window(20_000);

        // Two windows on, one off: never `DWELL` in a row, but the streak
        // climbs faster than it decays
        let mut alerts = Vec::new();
        for _ in 0..DWELL * 2 {
            alerts.extend(cell_window(&monitor, &mut traffic, flood).await);
            alerts.extend(cell_window(&monitor, &mut traffic, flood).await);
            alerts.extend(quiet(&monitor, 1).await);
        }
        let [alert] = &alerts[..] else {
            panic!("expected one alert, got {alerts:?}");
        };
        assert!(!alert.over);
        assert_eq!(alert.kind, Kind::Cells);
    }

    #[tokio::test(start_paused = true)]
    async fn a_sustained_flood_is_reported_once_and_summarised_when_it_ends() {
        let monitor = Monitor::new();
        let mut traffic = monitor.traffic(subnet());
        let flood = per_window(20_000);

        for _ in 0..DWELL - 1 {
            assert!(cell_window(&monitor, &mut traffic, flood).await.is_empty());
        }
        let alerts = cell_window(&monitor, &mut traffic, flood).await;
        let [alert] = &alerts[..] else {
            panic!("expected one alert, got {alerts:?}");
        };
        assert_eq!(alert.source, subnet());
        assert_eq!(alert.kind, Kind::Cells);
        assert!(!alert.over);
        assert_eq!(alert.value, 20_000);
        assert_eq!(alert.total, flood * DWELL as u64);
        assert_eq!(alert.duration, WINDOW * (DWELL - 1));

        // Nothing further while it lasts, and a dip does not end it early
        assert!(cell_window(&monitor, &mut traffic, flood).await.is_empty());
        assert!(quiet(&monitor, 1).await.is_empty());
        assert!(cell_window(&monitor, &mut traffic, flood).await.is_empty());
        assert!(quiet(&monitor, cooldown_windows() - 1).await.is_empty());

        let alerts = quiet(&monitor, 1).await;
        let [alert] = &alerts[..] else {
            panic!("expected one alert, got {alerts:?}");
        };
        assert!(alert.over);
        assert_eq!(alert.value, 0);
        assert_eq!(alert.peak, 20_000);
        assert_eq!(alert.total, flood * (DWELL as u64 + 2));
    }

    #[tokio::test(start_paused = true)]
    async fn call_setups_are_counted_as_they_arrive() {
        let monitor = Monitor::new();
        let traffic = monitor.traffic(subnet());
        let flood = per_window(Kind::Circuits.threshold() + 50);

        for _ in 0..DWELL - 1 {
            assert!(setup_window(&monitor, &traffic, flood).await.is_empty());
        }
        let alerts = setup_window(&monitor, &traffic, flood).await;
        let [alert] = &alerts[..] else {
            panic!("expected one alert, got {alerts:?}");
        };
        assert_eq!(alert.kind, Kind::Circuits);
        assert_eq!(alert.value, Kind::Circuits.threshold() + 50);
    }

    #[tokio::test(start_paused = true)]
    async fn connections_opened_too_fast_are_reported() {
        let monitor = Monitor::new();
        let rate = Kind::Connections.threshold() + 1;

        // Dropped as fast as they are opened, so only the rate can trip
        for window in 0..DWELL {
            for _ in 0..per_window(rate) {
                monitor.connected(subnet());
            }
            let alerts = quiet(&monitor, 1).await;
            if window + 1 < DWELL {
                assert!(alerts.is_empty(), "{alerts:?}");
                continue;
            }
            let [alert] = &alerts[..] else {
                panic!("expected one alert, got {alerts:?}");
            };
            assert_eq!(alert.kind, Kind::Connections);
            assert_eq!(alert.value, rate);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_checker_is_counted_per_connection() {
        let monitor = Monitor::new();
        // One key per connection, so its connection rate cannot pool into a
        // flood however many it opens
        for id in 0..per_window(Kind::Connections.threshold() + 1) {
            monitor.connected(SourceKey::Connection(id));
        }
        let alerts = quiet(&monitor, DWELL + 1).await;
        assert!(alerts.is_empty(), "{alerts:?}");
    }

    /// What the statistics tooling folds into per-team volume over time
    #[tokio::test(start_paused = true)]
    async fn the_debug_log_gets_what_every_source_and_path_counted() {
        let monitor = Monitor::new();
        let peer = SourceKey::Subnet("10.55.9.0".parse().expect("valid test network"));
        let mut traffic = monitor.traffic(subnet());

        monitor.connected(subnet());
        traffic.setup();
        for _ in 0..5 {
            traffic.cell();
            traffic.cell_to(peer);
        }
        traffic.flush();
        quiet(&monitor, 1).await;

        let records = monitor.drain_traffic(10);
        let [source] = records
            .iter()
            .filter(|record| matches!(record, debug_log::Record::Traffic { .. }))
            .collect::<Vec<_>>()[..]
        else {
            panic!("expected one source record in {records:?}");
        };
        let debug_log::Record::Traffic {
            from,
            cells,
            setups,
            connections,
            seconds,
            ..
        } = source
        else {
            unreachable!("filtered above")
        };
        assert_eq!(from.as_deref(), Some("10.55.7.0"));
        assert_eq!((*cells, *setups, *connections, *seconds), (5, 1, 1, 10));

        let [path] = records
            .iter()
            .filter(|record| matches!(record, debug_log::Record::TrafficPath { .. }))
            .collect::<Vec<_>>()[..]
        else {
            panic!("expected one path record in {records:?}");
        };
        let debug_log::Record::TrafficPath {
            from, to, cells, ..
        } = path
        else {
            unreachable!("filtered above")
        };
        assert_eq!(from.as_deref(), Some("10.55.7.0"));
        assert_eq!(to.as_deref(), Some("10.55.9.0"));
        assert_eq!(*cells, 5);

        // Draining takes what it reports, so a quiet window says nothing
        quiet(&monitor, 1).await;
        assert!(monitor.drain_traffic(10).is_empty());
    }

    /// A source may be pruned for being idle before the next export runs. Its
    /// counts still have to come out, or a short burst would vanish.
    #[tokio::test(start_paused = true)]
    async fn counts_survive_the_source_being_pruned() {
        let monitor = Monitor::new();
        let peer = SourceKey::Subnet("10.55.9.0".parse().expect("valid test network"));
        let mut traffic = monitor.traffic(subnet());
        traffic.cell();
        traffic.cell_to(peer);
        // Dropping the handle flushes it, and lets the source go idle
        drop(traffic);

        quiet(&monitor, IDLE_SAMPLES + 2).await;
        let records = monitor.drain_traffic(10);
        assert_eq!(records.len(), 2, "{records:?}");
        assert!(
            records
                .iter()
                .any(|record| matches!(record, debug_log::Record::Traffic { cells: 1, .. }))
        );
        assert!(
            records
                .iter()
                .any(|record| matches!(record, debug_log::Record::TrafficPath { cells: 1, .. }))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cells_to_one_recipient_are_reported_against_the_path() {
        let monitor = Monitor::new();
        let victim = SourceKey::Subnet("10.55.9.0".parse().expect("valid test network"));
        let bystander = SourceKey::Subnet("10.55.3.0".parse().expect("valid test network"));
        let mut traffic = monitor.traffic(subnet());
        let flood = per_window(Kind::CellsToPeer.threshold() + 100);

        // Spread thinly, nothing is wrong: the same cells against one victim
        // would be well over the path threshold
        for _ in 0..DWELL + 1 {
            for _ in 0..flood / 2 {
                traffic.cell_to(victim);
                traffic.cell_to(bystander);
            }
            traffic.flush();
            let alerts = quiet(&monitor, 1).await;
            assert!(alerts.is_empty(), "{alerts:?}");
        }

        // The same volume aimed at one of them is
        for window in 0..DWELL {
            for _ in 0..flood {
                traffic.cell_to(victim);
            }
            traffic.flush();
            let alerts = quiet(&monitor, 1).await;
            if window + 1 < DWELL {
                assert!(alerts.is_empty(), "{alerts:?}");
                continue;
            }
            let [alert] = &alerts[..] else {
                panic!("expected one alert, got {alerts:?}");
            };
            assert_eq!(alert.kind, Kind::CellsToPeer);
            assert_eq!(alert.source, subnet());
            assert_eq!(alert.peer, Some(victim));
            assert_eq!(alert.value, Kind::CellsToPeer.threshold() + 100);
            assert!(
                alert.to_string().contains("to Subnet(10.55.9.0)"),
                "{alert}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn idle_sources_are_dropped_and_busy_ones_are_not() {
        let monitor = Monitor::new();

        // A connection that sent a cell and went away
        {
            let mut traffic = monitor.traffic(subnet());
            traffic.cell();
        }
        assert_eq!(monitor.tracked(), 1);
        quiet(&monitor, IDLE_SAMPLES + 1).await;
        assert_eq!(monitor.tracked(), 0);

        // A live connection keeps its source, however quiet it is: its counts
        // would go nowhere otherwise
        let traffic = monitor.traffic(SourceKey::Connection(1));
        quiet(&monitor, IDLE_SAMPLES + 1).await;
        assert_eq!(monitor.tracked(), 1);
        drop(traffic);
        quiet(&monitor, IDLE_SAMPLES + 1).await;
        assert_eq!(monitor.tracked(), 0);

        // So does a flood in progress, so that it can still be closed out
        let mut traffic = monitor.traffic(subnet());
        for _ in 0..DWELL {
            cell_window(&monitor, &mut traffic, per_window(20_000)).await;
        }
        drop(traffic);
        quiet(&monitor, IDLE_SAMPLES).await;
        assert_eq!(monitor.tracked(), 1);

        // Paths are tracked and dropped on their own
        let mut traffic = monitor.traffic(subnet());
        traffic.cell_to(SourceKey::Connection(2));
        traffic.flush();
        assert_eq!(monitor.tracked_paths(), 1);
        drop(traffic);
        quiet(&monitor, IDLE_SAMPLES + 1).await;
        assert_eq!(monitor.tracked_paths(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_short_window_is_folded_into_the_next() {
        let monitor = Monitor::new();
        let mut traffic = monitor.traffic(subnet());

        // Sampled immediately, ten cells would read as thousands per second
        for _ in 0..10 {
            traffic.cell();
        }
        traffic.flush();
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(monitor.sample(Instant::now()).is_empty());

        for _ in 0..DWELL {
            cell_window(&monitor, &mut traffic, per_window(20_000)).await;
        }
        let alerts = quiet(&monitor, cooldown_windows()).await;
        let [alert] = &alerts[..] else {
            panic!("expected one alert, got {alerts:?}");
        };
        assert_eq!(alert.total, per_window(20_000) * DWELL as u64 + 10);
    }

    #[tokio::test]
    async fn the_export_appends_one_json_line_per_alert() {
        let path = std::env::temp_dir().join(format!("dslam-flood-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let alert = Alert {
            source: subnet(),
            peer: None,
            kind: Kind::Cells,
            over: false,
            value: 20_000,
            peak: 20_000,
            total: 40_000,
            duration: Duration::from_secs(4),
        };

        let mut export = Export::create(&path).await.expect("creates the file");
        export.write(&alert).await.expect("writes a line");
        export
            .write(&Alert {
                peer: Some(SourceKey::Connection(7)),
                kind: Kind::CellsToPeer,
                over: true,
                ..alert
            })
            .await
            .expect("writes another");

        // Reopening appends, so a restart does not lose what nobody read yet
        drop(export);
        let mut export = Export::create(&path).await.expect("reopens the file");
        export.write(&alert).await.expect("writes a third");

        let written = std::fs::read_to_string(&path).expect("readable");
        let lines: Vec<serde_json::Value> = written
            .lines()
            .map(|line| serde_json::from_str(line).expect("each line is a JSON object"))
            .collect();
        assert_eq!(lines.len(), 3);

        assert_eq!(lines[0]["flood"], "cells");
        assert_eq!(lines[0]["source"], "10.55.7.0");
        assert_eq!(lines[0]["over"], false);
        assert_eq!(lines[0]["value"], 20_000);
        assert_eq!(lines[0]["threshold"], Kind::Cells.threshold());
        assert_eq!(lines[0]["total"], 40_000);
        assert_eq!(lines[0]["seconds"], 4);
        assert!(lines[0]["time"].as_u64().expect("a timestamp") > 0);
        // A pooled source has no connection field, and vice versa
        assert!(lines[0].get("source_connection").is_none());
        assert!(lines[0].get("peer").is_none());

        assert_eq!(lines[1]["flood"], "cells-to-peer");
        assert_eq!(lines[1]["peer_connection"], 7);
        assert!(lines[1].get("peer").is_none());
        assert_eq!(lines[1]["over"], true);

        std::fs::remove_file(&path).expect("cleans up");
    }

    #[tokio::test(start_paused = true)]
    async fn cells_are_counted_in_batches_and_flushed_when_the_connection_ends() {
        let monitor = Monitor::new();
        let counters = monitor.counters(subnet());
        let mut traffic = monitor.traffic(subnet());

        for _ in 0..CELL_BATCH + 1 {
            traffic.cell();
        }
        // The full batch is counted, the cell over it is not...
        assert_eq!(counters.cells.load(Ordering::Relaxed), CELL_BATCH);
        // ...until the connection ends
        drop(traffic);
        assert_eq!(counters.cells.load(Ordering::Relaxed), CELL_BATCH + 1);
    }
}
