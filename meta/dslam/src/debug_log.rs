//! The debug log: a JSON Lines record of who connected, who called whom, and how
//! much each team sent, written to the volume named by `DSLAM_DEBUG_LOG_DIR`.
//!
//! All of a team's traffic shares one TCP connection and the DSLAM translates
//! VPI/VCI between the two legs of a call, so an externally captured pcap cannot
//! say which cells came from which team on its own. This log is what makes that
//! correlation possible afterwards: every connection is pinned to its TCP
//! endpoints, and every call to both legs' circuits and transaction IDs.
//!
//! It also de-anonymizes callers, which the service deliberately hides from the
//! teams. The volume is for organisers only.
//!
//! Writing never blocks the data path or the switchboard: records go through a
//! bounded queue with `try_send`, and what does not fit is counted and reported
//! rather than waited on. A full disk or an unwritable volume costs records, not
//! forwarding.
//!
//! A segment is closed on the clock and gzipped once it is, off the writer's
//! task. Everything but the minute being written is therefore a finished file
//! about eight times smaller than what it holds, which is what makes the log
//! both copyable off the machine during a game and worth its budget.

use std::{
    collections::VecDeque,
    fmt::Display,
    net::IpAddr,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use flate2::{Compression, write::GzEncoder};
use serde::Serialize;
use thiserror::Error;
use tokio::{
    fs::{File, OpenOptions},
    io::AsyncWriteExt,
    sync::mpsc::{self, Receiver, Sender, error::TrySendError},
    task::{JoinError, JoinSet},
};
use tokio_util::sync::CancellationToken;

use crate::{
    connection::{AddressAssignment, Connection, ConnectionId, LegDirection, SourceKey},
    dslam::NumberingPlan,
};

/// Records held before the queue sheds. Deep enough to ride out a disk hiccup at
/// the record rates a flood produces, and bounded so a stalled disk cannot grow
/// it without limit.
const QUEUE_SIZE: usize = 16384;

/// Segment size when no budget is set
const DEFAULT_SEGMENT_LIMIT: u64 = 1024 * 1024 * 1024;

/// Smallest and largest segment a budget may imply
const MIN_SEGMENT_LIMIT: u64 = 1024 * 1024;

/// How a budget is divided into segments. A budget keeps the newest segments, so
/// enough of them have to fit that trimming one does not throw away most of the
/// log.
const SEGMENTS_PER_BUDGET: u64 = 8;

/// How often a segment is closed. Everything the analysis tooling reads is a
/// closed segment, so this is how far behind a game it runs.
pub const SEGMENT_INTERVAL: Duration = Duration::from_secs(60);

/// Where a segment is written while it is being compressed. A copy taken on the
/// minute must never pick up half a file, so the gzip is renamed into place.
const STAGING_SUFFIX: &str = ".part";

/// What a run does with its segments, beyond where it puts them
#[derive(Clone, Copy, Debug)]
pub struct Settings {
    /// How much space the log may use, counted as the files on disk are
    pub budget: Option<Budget>,
    /// How often a segment is rolled over, or zero to roll on size alone
    pub interval: Duration,
    /// Whether a segment is gzipped once it is closed
    pub compress: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            budget: None,
            interval: SEGMENT_INTERVAL,
            compress: true,
        }
    }
}

/// How long the writer keeps taking records after the shutdown was signalled.
///
/// The rest of the DSLAM writes some of its most interesting records *while* it
/// stops -- the last traffic windows, the circuits being torn down -- and all of
/// them are on their way in when the token is cancelled. Leaving without them
/// loses the end of the run, so wait briefly for stragglers, bounded so that a
/// busy DSLAM still shuts down promptly.
const SHUTDOWN_GRACE: Duration = Duration::from_millis(500);

/// A size in bytes, with an optional `K`, `M` or `G` suffix (powers of 1024).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Budget(pub u64);

#[derive(Debug, Error)]
pub enum BudgetError {
    #[error("a size must not be empty")]
    Empty,
    #[error("{0} is not a size in bytes, optionally suffixed with K, M or G")]
    Invalid(String),
    #[error("{0} does not fit a 64-bit byte count")]
    TooLarge(String),
}

impl FromStr for Budget {
    type Err = BudgetError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let text = value.trim();
        if text.is_empty() {
            return Err(BudgetError::Empty);
        }
        // Accept both `4G` and the `4GB` an operator is likely to type
        let digits = text.trim_end_matches(['b', 'B']);
        let (digits, scale) = match digits.chars().last() {
            Some('k' | 'K') => (&digits[..digits.len() - 1], 1024),
            Some('m' | 'M') => (&digits[..digits.len() - 1], 1024 * 1024),
            Some('g' | 'G') => (&digits[..digits.len() - 1], 1024 * 1024 * 1024),
            _ => (digits, 1),
        };
        let digits = digits.trim();
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(BudgetError::Invalid(value.to_string()));
        }
        digits
            .parse::<u64>()
            .ok()
            .and_then(|count| count.checked_mul(scale))
            .map(Budget)
            .ok_or_else(|| BudgetError::TooLarge(value.to_string()))
    }
}

impl Display for Budget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// How a call's leg ended. Only legs that carried a call report one.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DownReason {
    /// The leg's owner released the circuit
    Release,
    /// The owner established a new call on a circuit this one still held
    Replaced,
    /// The circuit outlived `CIRCUIT_LIFETIME`
    Lifetime,
    /// The other side of the call is gone
    PeerGone,
    /// The leg's owner disconnected
    ConnectionClosed,
    /// The callee refused the call, or the DSLAM passed a refusal back
    Rejected,
    /// Call setup was never answered
    SetupTimeout,
    /// The release handshake was never answered
    ReleaseTimeout,
}

/// Who refused a call
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RejectedBy {
    /// The DSLAM, on policy or a limit
    Dslam,
    /// The callee answered with an error
    Callee,
    /// The callee never answered
    Timeout,
}

/// Why a connection was not accepted
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RefusedReason {
    /// The source already holds `MAX_CONNECTIONS_PER_SOURCE` connections
    ConnectionLimit,
    /// No free number in the numbering plan
    NoNumber,
    /// The packet capture would not take the connection
    CaptureBackpressure,
}

/// How a connection's number was assigned
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Assignment {
    Static,
    Dynamic,
}

/// Which leg of a call this is, from the owner's point of view
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Leg {
    /// The owner placed the call
    Outgoing,
    /// The owner received it
    Incoming,
}

impl From<LegDirection> for Leg {
    fn from(direction: LegDirection) -> Self {
        match direction {
            LegDirection::Outgoing => Leg::Outgoing,
            LegDirection::Incoming => Leg::Incoming,
        }
    }
}

/// The configuration a run was started with, repeated at the head of every
/// segment so a file can be read without the rest of the game's artefacts.
#[derive(Clone, Debug, Serialize)]
pub struct Start {
    /// Identifies this DSLAM run; connection and call IDs only mean anything
    /// within one
    pub run: String,
    pub segment: u64,
    /// Segments deleted to stay inside the budget, cumulative over the run
    pub trimmed: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    pub pid: u32,
    pub version: &'static str,
    pub listen: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget: Option<u64>,
    pub segment_limit: u64,
    /// How often a segment is rolled over, or zero for on size alone
    pub segment_seconds: u64,
    /// Whether the segments before this one are gzipped
    pub compressed: bool,
    pub policy: PolicySnapshot,
    pub limits: Limits,
    pub plan: NumberingPlan,
}

/// The call policy in force, which decides what the call records can contain
#[derive(Clone, Debug, Serialize)]
pub struct PolicySnapshot {
    pub allow_calls_to_dynamic: bool,
    pub allow_calls_from_static: bool,
    pub checker_reserve: usize,
    pub subscriber_ipv4_prefix: u32,
    pub subscriber_ipv6_prefix: u32,
    pub checker_mask: IpAddr,
    pub checker_pattern: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mirror_circuit: Option<String>,
}

/// The limits a refusal in the log is explained by
#[derive(Clone, Copy, Debug, Serialize)]
#[allow(clippy::struct_field_names)] // they are named after the constants
pub struct Limits {
    pub max_connections_per_source: usize,
    pub max_incoming_circuits_per_connection: usize,
    pub max_incoming_circuits_per_source: usize,
    pub max_releasing_per_connection: usize,
    pub circuit_lifetime_seconds: u64,
    pub establish_retransmit_seconds: u64,
    pub establish_retries: u8,
    pub release_retransmit_seconds: u64,
    pub release_retries: u8,
}

impl Limits {
    /// What this build enforces, so a log explains its own refusals
    pub fn current() -> Self {
        use crate::switchboard;
        Self {
            max_connections_per_source: crate::dslam::MAX_CONNECTIONS_PER_SOURCE,
            max_incoming_circuits_per_connection: switchboard::MAX_INCOMING_CIRCUITS_PER_CONNECTION,
            max_incoming_circuits_per_source: switchboard::MAX_INCOMING_CIRCUITS_PER_SOURCE,
            max_releasing_per_connection: switchboard::MAX_RELEASING_PER_CONNECTION,
            circuit_lifetime_seconds: switchboard::CIRCUIT_LIFETIME.as_secs(),
            establish_retransmit_seconds: switchboard::ESTABLISH_RETRANSMIT.as_secs(),
            establish_retries: switchboard::ESTABLISH_RETRIES,
            release_retransmit_seconds: switchboard::RELEASE_RETRANSMIT.as_secs(),
            release_retries: switchboard::RELEASE_RETRIES,
        }
    }
}

/// One record in the log.
///
/// Flat and spelled out rather than derived from the DSLAM's own types, because
/// something else parses this: a field renamed here breaks that reader. A source
/// is an address when it is pooled by subnet and a connection when it is the
/// checker's, so each is its own field and exactly one of the pair is present.
#[derive(Debug, Serialize)]
#[serde(tag = "event", rename_all = "kebab-case")]
pub enum Record {
    /// Opens a segment
    Start(Box<Start>),

    /// A connection was accepted and numbered. The TCP endpoints are what an
    /// externally captured pcap is matched on; `conn` keys everything else.
    Connection {
        conn: ConnectionId,
        remote_ip: IpAddr,
        remote_port: u16,
        local_ip: IpAddr,
        local_port: u16,
        number: String,
        assignment: Assignment,
        #[serde(skip_serializing_if = "Option::is_none")]
        source: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        source_connection: Option<ConnectionId>,
        /// Whether this is the checker, whose traffic is scoring rather than play
        checker: bool,
    },

    /// A connection was dropped before it could be used
    ConnectionRefused {
        remote_ip: IpAddr,
        remote_port: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        source: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        source_connection: Option<ConnectionId>,
        reason: RefusedReason,
    },

    /// A connection ended
    ConnectionClosed {
        conn: ConnectionId,
        seconds: u64,
        calls_placed: u64,
        calls_received: u64,
        /// Another connection that took this one's number over
        #[serde(skip_serializing_if = "Option::is_none")]
        successor_conn: Option<ConnectionId>,
    },

    /// A number moved to another connection, so two connections from one
    /// subscriber briefly answer to it
    NumberMoved {
        number: String,
        from_conn: ConnectionId,
        to_conn: ConnectionId,
    },

    /// A call was set up: the record that ties a victim-side circuit back to the
    /// team that placed the call. `presented` is the (anonymous) number the
    /// callee was told the call came from.
    CallSetup {
        call: u64,
        caller_conn: ConnectionId,
        caller_ip: IpAddr,
        caller_vpi: u8,
        caller_vci: u16,
        caller_id: u32,
        callee_conn: ConnectionId,
        callee_ip: IpAddr,
        callee_vpi: u8,
        callee_vci: u16,
        callee_id: u32,
        dialled: String,
        presented: String,
    },

    /// The callee accepted; cells flow from here
    CallUp {
        call: u64,
        caller_conn: ConnectionId,
        callee_conn: ConnectionId,
    },

    /// A call that was already up when a segment was opened
    CallLive {
        call: u64,
        conn: ConnectionId,
        vpi: u8,
        vci: u16,
        direction: Leg,
        #[serde(skip_serializing_if = "Option::is_none")]
        peer_conn: Option<ConnectionId>,
        peer_vpi: u8,
        peer_vci: u16,
        seconds: u64,
        cells: u64,
    },

    /// A call never came up
    CallRejected {
        #[serde(skip_serializing_if = "Option::is_none")]
        call: Option<u64>,
        caller_conn: ConnectionId,
        caller_vpi: u8,
        caller_vci: u16,
        caller_id: u32,
        dialled: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        callee_conn: Option<ConnectionId>,
        error: String,
        by: RejectedBy,
    },

    /// One leg of a call stopped carrying traffic. Both legs report, so a call
    /// may produce two of these.
    CallDown {
        call: u64,
        conn: ConnectionId,
        vpi: u8,
        vci: u16,
        direction: Leg,
        reason: DownReason,
        seconds: u64,
        /// Cells this leg's owner sent into the call
        cells: u64,
        /// ...of which these were dropped on the peer's full queue
        cells_queue_full: u64,
    },

    /// What one source sent in the window that just closed. Totals over a period
    /// are the sum of its windows.
    Traffic {
        #[serde(skip_serializing_if = "Option::is_none")]
        from: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        from_connection: Option<ConnectionId>,
        /// Every cell read, before HEC and PTI validation, signalling included
        cells: u64,
        /// Call setups offered, before policy and quota
        setups: u64,
        connections: u64,
        seconds: u64,
    },

    /// What one source sent another in the window that just closed: the team to
    /// team cell matrix. Counts user-plane cells aimed at the recipient, whether
    /// or not its queue had room.
    TrafficPath {
        #[serde(skip_serializing_if = "Option::is_none")]
        from: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        from_connection: Option<ConnectionId>,
        #[serde(skip_serializing_if = "Option::is_none")]
        to: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        to_connection: Option<ConnectionId>,
        cells: u64,
        seconds: u64,
    },

    /// Run-wide counts, for cross-checking a fold over the records above
    Totals {
        connections_open: u64,
        connections_total: u64,
        calls_open: u64,
        calls_total: u64,
        calls_rejected_total: u64,
        records_dropped: u64,
    },

    /// Records the queue shed. The gap in `seq` is the same size.
    Dropped { count: u64 },

    /// Closes a run
    Stop {
        records: u64,
        bytes: u64,
        segments: u64,
        trimmed: u64,
        records_dropped: u64,
        write_errors: u64,
    },
}

/// A source as the log spells it: an address, or a connection for the checker
pub fn flatten(source: SourceKey) -> (Option<String>, Option<ConnectionId>) {
    match source {
        SourceKey::Subnet(network) => (Some(network.to_string()), None),
        SourceKey::Connection(id) => (None, Some(id)),
    }
}

/// How a connection introduces itself: once when it is accepted, and again at
/// the head of every later segment, so that a file can be read on its own.
pub fn connection_record(connection: &Connection) -> Record {
    let (source, source_connection) = flatten(connection.source);
    Record::Connection {
        conn: connection.id,
        remote_ip: connection.remote.ip(),
        remote_port: connection.remote.port(),
        local_ip: connection.endpoint.ip(),
        local_port: connection.endpoint.port(),
        number: connection.local.to_string(),
        assignment: match connection.assignment {
            AddressAssignment::Static => Assignment::Static,
            AddressAssignment::Dynamic => Assignment::Dynamic,
        },
        source,
        source_connection,
        checker: connection.reserved,
    }
}

/// A record plus the time it happened at
struct Entry {
    time_us: u64,
    record: Record,
}

/// One line of the log: the envelope, then the record's own fields
#[derive(Serialize)]
struct Line<'a> {
    /// Microseconds since the epoch, taken when the event happened rather than
    /// when it was written, to line up with pcap timestamps (the flood export's
    /// `time` is milliseconds)
    time_us: u64,
    /// Counts the records written over the run. Contiguous within a segment, so
    /// a jump across segments is the budget having trimmed the ones between.
    /// Records the queue shed never reach it and are reported on their own.
    seq: u64,
    #[serde(flatten)]
    record: &'a Record,
}

/// Shared between the handle and the writer
struct Shared {
    channel: Sender<Entry>,
    dropped: AtomicU64,
    /// Bumped when the writer opens a new segment, so the switchboard knows to
    /// repeat the live state into it
    segment: AtomicU64,
}

/// A handle for writing to the debug log. Cheap to clone, and a no-op when no
/// log directory was configured.
#[derive(Clone)]
pub struct Log(Option<Arc<Shared>>);

impl Log {
    /// A handle that writes nothing
    pub fn disabled() -> Self {
        Self(None)
    }

    /// Whether anything is being written
    pub fn enabled(&self) -> bool {
        self.0.is_some()
    }

    /// The current segment number, which changes when the writer rolls over
    pub fn segment(&self) -> u64 {
        match &self.0 {
            Some(shared) => shared.segment.load(Ordering::Relaxed),
            None => 0,
        }
    }

    /// Records the queue has shed over the run
    pub fn dropped(&self) -> u64 {
        match &self.0 {
            Some(shared) => shared.dropped.load(Ordering::Relaxed),
            None => 0,
        }
    }

    /// Writes a record, building it only if the log is enabled.
    ///
    /// Never blocks and never fails: a record that does not fit the queue is
    /// counted and reported as a `dropped` record instead.
    pub fn record(&self, make: impl FnOnce() -> Record) {
        let Some(shared) = &self.0 else {
            return;
        };
        let entry = Entry {
            time_us: now_us(),
            record: make(),
        };
        match shared.channel.try_send(entry) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Closed(_)) => {
                shared.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Microseconds since the Unix epoch
fn now_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

/// One of this run's segments, as the budget sees it
struct SegmentFile {
    path: PathBuf,
    /// What it costs on the volume, which is the gzip once there is one
    bytes: u64,
    /// Being gzipped: its size is about to change, so trimming leaves it be
    compressing: bool,
}

/// Writes the log, one segment at a time
pub struct Writer {
    channel: Receiver<Entry>,
    shared: Arc<Shared>,
    directory: PathBuf,
    start: Start,
    file: File,
    /// This run's segments, oldest first, with their sizes
    segments: VecDeque<SegmentFile>,
    budget: Option<u64>,
    segment_limit: u64,
    /// How often the segment is rolled over, or zero to roll on size alone
    interval: Duration,
    /// Whether a segment is gzipped once it is closed
    compress: bool,
    /// The segments being gzipped right now
    compressing: JoinSet<(PathBuf, std::io::Result<(PathBuf, u64)>)>,
    /// Bytes in the segment being written
    written: u64,
    /// Records in the segment being written, its own header included
    lines: u64,
    /// Bytes across every segment still on disk
    total: u64,
    records: u64,
    /// Records the writer has reported as dropped, so it only reports new ones
    reported_drops: u64,
    errors: u64,
}

impl Writer {
    /// Opens the log in `directory`, creating it if need be, and returns the
    /// handle to write through.
    ///
    /// A log that cannot be opened is a misconfiguration, and refusing to start
    /// says so before a game rather than during one.
    pub async fn create(
        directory: &Path,
        settings: Settings,
        mut start: Start,
    ) -> std::io::Result<(Log, Self)> {
        tokio::fs::create_dir_all(directory).await?;

        let budget = settings.budget.map(|budget| budget.0);
        let segment_limit = match budget {
            Some(budget) => (budget / SEGMENTS_PER_BUDGET).clamp(MIN_SEGMENT_LIMIT, u64::MAX),
            None => DEFAULT_SEGMENT_LIMIT,
        };
        start.segment = 0;
        start.budget = budget;
        start.segment_limit = segment_limit;
        start.segment_seconds = settings.interval.as_secs();
        start.compressed = settings.compress;

        let path = Self::segment_path(directory, &start.run, 0);
        let file = Self::open(&path).await?;
        Self::link_latest(directory, &path).await;

        let (sender, channel) = mpsc::channel(QUEUE_SIZE);
        let shared = Arc::new(Shared {
            channel: sender,
            dropped: AtomicU64::new(0),
            segment: AtomicU64::new(0),
        });
        let writer = Self {
            channel,
            shared: shared.clone(),
            directory: directory.to_path_buf(),
            start,
            file,
            segments: VecDeque::from([SegmentFile {
                path,
                bytes: 0,
                compressing: false,
            }]),
            budget,
            segment_limit,
            interval: settings.interval,
            compress: settings.compress,
            compressing: JoinSet::new(),
            written: 0,
            lines: 0,
            total: 0,
            records: 0,
            reported_drops: 0,
            errors: 0,
        };
        Ok((Log(Some(shared)), writer))
    }

    /// Rolls segments over at `limit` bytes instead of what the budget implies
    #[cfg(test)]
    pub fn with_segment_limit(mut self, limit: u64) -> Self {
        self.segment_limit = limit;
        self.start.segment_limit = limit;
        self
    }

    /// Where a segment lives. Sorted by name is sorted by time.
    fn segment_path(directory: &Path, run: &str, segment: u64) -> PathBuf {
        directory.join(format!("dslam-{run}-{segment:04}.jsonl"))
    }

    async fn open(path: &Path) -> std::io::Result<File> {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await
    }

    /// Points `latest` at the segment being written, for tailing. Best effort:
    /// a volume that does not do symlinks is no reason to lose the log.
    async fn link_latest(directory: &Path, target: &Path) {
        let Some(name) = target.file_name() else {
            return;
        };
        let link = directory.join("latest.jsonl");
        let staging = directory.join(".latest.jsonl");
        let _ = tokio::fs::remove_file(&staging).await;
        if tokio::fs::symlink(name, &staging).await.is_ok() {
            let _ = tokio::fs::rename(&staging, &link).await;
        }
    }

    /// Writes one line, as one call so that a reader tailing the file never sees
    /// half a record. Flushed to the OS, not synced: the reader shares the page
    /// cache, and a game is not worth an fsync a record.
    async fn write(&mut self, entry: &Entry) -> std::io::Result<()> {
        let line = Line {
            time_us: entry.time_us,
            // Taken here rather than on the way in, so that the numbers are the
            // order of the file and a reader can tell a complete stretch of log
            // from one the budget has eaten into
            seq: self.records,
            record: &entry.record,
        };
        let mut bytes = serde_json::to_vec(&line).map_err(std::io::Error::other)?;
        bytes.push(b'\n');
        self.file.write_all(&bytes).await?;
        self.file.flush().await?;
        self.records += 1;
        self.lines += 1;
        self.written += bytes.len() as u64;
        self.total += bytes.len() as u64;
        if let Some(last) = self.segments.back_mut() {
            last.bytes = self.written;
        }
        Ok(())
    }

    /// Writes a record the writer makes up itself
    async fn emit(&mut self, record: Record) -> std::io::Result<()> {
        let entry = Entry {
            time_us: now_us(),
            record,
        };
        self.write(&entry).await
    }

    /// Opens the next segment, hands the one it closed to gzip, and trims the
    /// oldest ones down to the budget.
    async fn roll(&mut self) -> std::io::Result<()> {
        let segment = self.start.segment + 1;
        let path = Self::segment_path(&self.directory, &self.start.run, segment);
        let file = Self::open(&path).await?;

        let closed = self.segments.back().map(|segment| segment.path.clone());
        self.file = file;
        self.start.segment = segment;
        self.written = 0;
        self.lines = 0;
        self.segments.push_back(SegmentFile {
            path: path.clone(),
            bytes: 0,
            compressing: false,
        });
        self.shared.segment.store(segment, Ordering::Relaxed);
        Self::link_latest(&self.directory, &path).await;

        if self.compress
            && let Some(closed) = closed
        {
            self.spawn_compression(closed);
        }
        if let Some(budget) = self.budget {
            self.trim(budget).await;
        }

        let start = self.start.clone();
        self.emit(Record::Start(Box::new(start))).await
    }

    /// Rolls the segment over on the clock.
    ///
    /// A segment with nothing but its own header in it is left alone: an idle
    /// log is not worth a file a minute.
    async fn rollover(&mut self) {
        if self.lines <= 1 {
            return;
        }
        if let Err(error) = self.roll().await {
            tracing::error!("Failed to roll the debug log over: {error}");
            self.errors += 1;
        }
    }

    /// Deletes the oldest segments until the run is back inside its budget.
    ///
    /// The newest records are the ones worth keeping: a log that stopped writing
    /// when the volume filled would lose exactly the traffic someone is looking
    /// at the log for.
    async fn trim(&mut self, budget: u64) {
        while self.total > budget && self.segments.len() > 1 {
            // A segment being gzipped is about to cost a fraction of what it
            // does now, which is worth one more roll to find out
            if self
                .segments
                .front()
                .is_some_and(|oldest| oldest.compressing)
            {
                break;
            }
            let oldest = self.segments.pop_front().expect("checked above");
            self.total = self.total.saturating_sub(oldest.bytes);
            match tokio::fs::remove_file(&oldest.path).await {
                Ok(()) => {
                    self.start.trimmed += 1;
                    tracing::warn!(
                        "Debug log is over its budget, dropped {}",
                        oldest.path.display()
                    );
                }
                Err(error) => {
                    // It stays out of the books either way, so that the next
                    // roll does not try the same file again and spin
                    tracing::error!("Failed to trim the debug log: {error}");
                    break;
                }
            }
        }
    }

    /// Gzips a closed segment, off the writer's task: a minute of a game is a
    /// few megabytes, and the log must not stop for them.
    fn spawn_compression(&mut self, path: PathBuf) {
        if let Some(segment) = self.segments.iter_mut().find(|held| held.path == path) {
            segment.compressing = true;
        }
        self.compressing.spawn_blocking(move || {
            let compressed = compress(&path);
            (path, compressed)
        });
    }

    /// Takes a finished gzip into the books, which is where the budget learns
    /// what a segment really costs
    fn compressed(&mut self, done: Result<(PathBuf, std::io::Result<(PathBuf, u64)>), JoinError>) {
        let (source, result) = match done {
            Ok(done) => done,
            Err(error) => {
                tracing::error!("Compressing a debug log segment failed: {error}");
                self.errors += 1;
                return;
            }
        };
        let held = self
            .segments
            .iter_mut()
            .find(|segment| segment.path == source);
        match (result, held) {
            (Ok((target, bytes)), Some(segment)) => {
                let was = segment.bytes;
                segment.path = target;
                segment.bytes = bytes;
                segment.compressing = false;
                self.total = self.total.saturating_sub(was).saturating_add(bytes);
            }
            // Trimmed while it was being compressed, so this is the gzip of a
            // segment the budget has already given up on
            (Ok((target, _)), None) => {
                let _ = std::fs::remove_file(target);
            }
            (Err(error), segment) => {
                tracing::error!("Failed to compress a debug log segment: {error}");
                self.errors += 1;
                if let Some(segment) = segment {
                    segment.compressing = false;
                }
            }
        }
    }

    /// Reports records the queue shed since the last report
    async fn report_drops(&mut self) -> std::io::Result<()> {
        let dropped = self.shared.dropped.load(Ordering::Relaxed);
        if dropped > self.reported_drops {
            let count = dropped - self.reported_drops;
            self.reported_drops = dropped;
            tracing::warn!("Debug log dropped {count} records");
            return self.emit(Record::Dropped { count }).await;
        }
        Ok(())
    }

    /// Writes until shutdown, then drains what is still queued.
    ///
    /// Write errors are counted and logged rather than fatal: a full disk must
    /// not take the DSLAM down with it.
    pub async fn run(mut self, shutdown: CancellationToken) {
        let start = self.start.clone();
        if let Err(error) = self.emit(Record::Start(Box::new(start))).await {
            tracing::error!("Failed to write the debug log header: {error}");
            self.errors += 1;
        }

        // Aligned to the clock, so that a segment is a minute of the game and
        // the one being written is the only unfinished file in the directory
        let mut rollover = (!self.interval.is_zero())
            .then(|| tokio::time::interval_at(next_boundary(self.interval), self.interval));

        loop {
            let entry = tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = tick(rollover.as_mut()) => {
                    self.rollover().await;
                    continue;
                }
                Some(done) = self.compressing.join_next(), if !self.compressing.is_empty() => {
                    self.compressed(done);
                    continue;
                }
                entry = self.channel.recv() => match entry {
                    Some(entry) => entry,
                    None => break,
                },
            };
            self.handle(entry).await;
        }

        // Keep taking records for a moment, so the ones the rest of the DSLAM
        // writes on its way out are not left in the queue
        let grace = tokio::time::sleep(SHUTDOWN_GRACE);
        tokio::pin!(grace);
        loop {
            tokio::select! {
                entry = self.channel.recv() => match entry {
                    Some(entry) => self.handle(entry).await,
                    None => break,
                },
                _ = &mut grace => break,
            }
        }

        // Then drain whatever is still queued: the records from a shutdown are
        // the ones that say why it happened.
        self.channel.close();
        while let Some(entry) = self.channel.recv().await {
            self.handle(entry).await;
        }
        let _ = self.report_drops().await;
        // Let the gzips finish, so that the sizes the run signs off with are
        // the files it leaves behind
        while let Some(done) = self.compressing.join_next().await {
            self.compressed(done);
        }
        let stop = Record::Stop {
            records: self.records,
            bytes: self.total,
            segments: self.start.segment + 1,
            trimmed: self.start.trimmed,
            records_dropped: self.shared.dropped.load(Ordering::Relaxed),
            write_errors: self.errors,
        };
        if let Err(error) = self.emit(stop).await {
            tracing::error!("Failed to close the debug log: {error}");
        }
    }

    /// Writes one record, rolling the segment over first if this one would not
    /// fit any more
    async fn handle(&mut self, entry: Entry) {
        if self.written >= self.segment_limit
            && let Err(error) = self.roll().await
        {
            tracing::error!("Failed to roll the debug log over: {error}");
            self.errors += 1;
        }
        if let Err(error) = self.write(&entry).await {
            tracing::error!("Failed to write to the debug log: {error}");
            self.errors += 1;
        }
        if let Err(error) = self.report_drops().await {
            tracing::error!("Failed to report dropped debug log records: {error}");
            self.errors += 1;
        }
    }
}

/// Gzips `path` to `<path>.gz` and removes it, returning where it went and what
/// it came to.
///
/// The gzip is written under a dotted name and renamed into place, so that a
/// copy running while it does never picks up half a file.
fn compress(path: &Path) -> std::io::Result<(PathBuf, u64)> {
    let target = suffixed(path, ".gz");
    let staging = suffixed(&target, STAGING_SUFFIX);
    let written = (|| {
        let mut source = std::io::BufReader::new(std::fs::File::open(path)?);
        let mut encoder = GzEncoder::new(
            std::io::BufWriter::new(std::fs::File::create(&staging)?),
            Compression::default(),
        );
        std::io::copy(&mut source, &mut encoder)?;
        let file = encoder
            .finish()?
            .into_inner()
            .map_err(|error| error.into_error())?;
        file.sync_all()?;
        file.metadata().map(|metadata| metadata.len())
    })();
    let written = match written {
        Ok(written) => written,
        Err(error) => {
            let _ = std::fs::remove_file(&staging);
            return Err(error);
        }
    };
    std::fs::rename(&staging, &target)?;
    std::fs::remove_file(path)?;
    Ok((target, written))
}

/// `path` with something on the end of its name, which `with_extension` cannot
/// do to a name that has one already
fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// When the next whole interval falls, so that segments line up with the clock
/// rather than with whenever the DSLAM happened to start
fn next_boundary(interval: Duration) -> tokio::time::Instant {
    let period = (interval.as_micros() as u64).max(1);
    tokio::time::Instant::now() + Duration::from_micros(period - now_us() % period)
}

/// The rollover timer, or nothing to wait for when rolling on the clock is off
async fn tick(timer: Option<&mut tokio::time::Interval>) {
    match timer {
        Some(timer) => {
            timer.tick().await;
        }
        None => std::future::pending().await,
    }
}

/// Seconds elapsed since `since`, for the duration fields
pub fn seconds_since(since: tokio::time::Instant) -> u64 {
    tokio::time::Instant::now()
        .saturating_duration_since(since)
        .as_secs()
}

/// Helpers the log's own tests and the switchboard's share
#[cfg(test)]
pub(crate) mod testing {
    use std::{collections::HashMap, path::PathBuf};

    use super::{Limits, PolicySnapshot, Settings, Start};
    use crate::dslam::{NumberingPlan, RandomNumberingPlan};

    /// An empty directory for one test's log
    pub fn directory(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("dslam-debug-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        path
    }

    /// A log that rolls over only when a test says so, and keeps its segments
    /// as they were written, so that a test reads what it wrote
    pub fn settings() -> Settings {
        Settings {
            budget: None,
            interval: std::time::Duration::ZERO,
            compress: false,
        }
    }

    /// A run header with nothing interesting in it
    pub fn start() -> Start {
        Start {
            run: "test".into(),
            segment: 0,
            trimmed: 0,
            host: None,
            pid: std::process::id(),
            version: "test",
            listen: "127.0.0.1:9000".into(),
            budget: None,
            segment_limit: 0,
            segment_seconds: 0,
            compressed: false,
            policy: PolicySnapshot {
                allow_calls_to_dynamic: true,
                allow_calls_from_static: true,
                checker_reserve: 0,
                subscriber_ipv4_prefix: 24,
                subscriber_ipv6_prefix: 64,
                checker_mask: "255.0.255.0".parse().expect("valid test mask"),
                checker_pattern: "10.0.249.0".parse().expect("valid test pattern"),
                mirror_circuit: None,
            },
            limits: Limits::current(),
            plan: NumberingPlan {
                random: RandomNumberingPlan {
                    prefix: "+49".parse().expect("valid test prefix"),
                    length: 10,
                },
                fixed: HashMap::new(),
            },
        }
    }

    /// The segments a run wrote, oldest first (`latest.jsonl` points at the last
    /// one, so it is skipped rather than read twice)
    pub fn segments(directory: &std::path::Path) -> Vec<PathBuf> {
        let mut paths: Vec<PathBuf> = std::fs::read_dir(directory)
            .expect("the log directory exists")
            .map(|entry| entry.expect("readable entry").path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.starts_with("dslam-") && !name.ends_with(super::STAGING_SUFFIX)
                    })
            })
            .collect();
        paths.sort();
        paths
    }

    /// One segment's lines, whether or not it has been gzipped
    pub fn read(path: &std::path::Path) -> String {
        use std::io::Read;

        let file = std::fs::File::open(path).expect("readable segment");
        let mut text = String::new();
        match path.extension().is_some_and(|extension| extension == "gz") {
            true => flate2::read::GzDecoder::new(file)
                .read_to_string(&mut text)
                .expect("a readable gzip"),
            false => std::io::BufReader::new(file)
                .read_to_string(&mut text)
                .expect("a readable segment"),
        };
        text
    }

    /// Every record a run wrote, in order
    pub fn records(directory: &std::path::Path) -> Vec<serde_json::Value> {
        segments(directory)
            .iter()
            .flat_map(|path| {
                let text = read(path);
                text.lines()
                    .map(|line| serde_json::from_str(line).expect("each line is a JSON object"))
                    .collect::<Vec<serde_json::Value>>()
            })
            .collect()
    }

    /// The records of one kind
    pub fn of_kind<'a>(
        records: &'a [serde_json::Value],
        event: &str,
    ) -> Vec<&'a serde_json::Value> {
        records
            .iter()
            .filter(|record| record["event"] == event)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{directory, of_kind, read, records, segments, settings, start};
    use super::*;

    /// Runs a writer over `records`, then returns everything in the directory
    async fn write(
        directory: &Path,
        settings: Settings,
        segment_limit: Option<u64>,
        records: Vec<Record>,
    ) {
        let (log, writer) = Writer::create(directory, settings, start())
            .await
            .expect("opens the log");
        let writer = match segment_limit {
            Some(limit) => writer.with_segment_limit(limit),
            None => writer,
        };
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(writer.run(shutdown.clone()));
        for record in records {
            log.record(|| record);
        }
        // Everything queued before the shutdown is still written
        shutdown.cancel();
        task.await.expect("the writer finishes");
    }

    #[tokio::test]
    async fn every_record_is_one_line_between_a_start_and_a_stop() {
        let directory = directory("lines");
        write(
            &directory,
            settings(),
            None,
            vec![
                Record::Dropped { count: 3 },
                Record::NumberMoved {
                    number: "+4912667".into(),
                    from_conn: 1,
                    to_conn: 2,
                },
            ],
        )
        .await;

        let lines = records(&directory);
        let events: Vec<&str> = lines
            .iter()
            .map(|line| line["event"].as_str().expect("an event tag"))
            .collect();
        assert_eq!(events, ["start", "dropped", "number-moved", "stop"]);

        // The envelope is on every line, and a stretch of log that was never
        // trimmed has no gaps in it
        for (index, line) in lines.iter().enumerate() {
            assert!(line["time_us"].as_u64().expect("a timestamp") > 0);
            assert_eq!(
                line["seq"].as_u64().expect("a sequence number"),
                index as u64
            );
        }

        // The header carries what the run was configured with, so the file can
        // be read without the rest of the game's artefacts
        let start = &lines[0];
        assert_eq!(start["run"], "test");
        assert_eq!(start["segment"], 0);
        assert_eq!(start["plan"]["random"]["prefix"], "+49");
        assert_eq!(start["limits"]["circuit_lifetime_seconds"], 180);
        assert_eq!(start["policy"]["subscriber_ipv4_prefix"], 24);
        // An unset budget is absent rather than null
        assert!(start.get("budget").is_none());

        // The record's own fields sit next to the envelope, not nested
        assert_eq!(lines[1]["count"], 3);
        assert_eq!(lines[2]["number"], "+4912667");

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[tokio::test]
    async fn a_budget_keeps_the_newest_segments() {
        let directory = directory("budget");
        // Small enough that every record or two rolls the segment over
        let records_written = 40;
        let budget = 3000;
        write(
            &directory,
            Settings {
                budget: Some(Budget(budget)),
                ..settings()
            },
            Some(120),
            (0..records_written)
                .map(|count| Record::Dropped { count })
                .collect(),
        )
        .await;

        let segments = segments(&directory);
        assert!(segments.len() > 1, "expected a rollover, got {segments:?}");
        // Trimming happens as a segment is opened, so the run may sit one
        // segment over its budget while it fills that one
        let total: u64 = segments
            .iter()
            .map(|path| std::fs::metadata(path).expect("a segment").len())
            .sum();
        assert!(
            total <= 2 * budget,
            "kept {total} bytes of a {budget} byte budget"
        );

        // What is left is the end of the run, which is what someone reading the
        // log is after, and every segment opens with its own header
        let lines = records(&directory);
        let counts: Vec<u64> = lines
            .iter()
            .filter(|line| line["event"] == "dropped")
            .map(|line| line["count"].as_u64().expect("a count"))
            .collect();
        assert_eq!(
            counts.last().copied(),
            Some(records_written - 1),
            "the newest records were trimmed away"
        );
        assert!(
            counts.len() < records_written as usize,
            "nothing was trimmed"
        );
        for segment in &segments {
            let text = std::fs::read_to_string(segment).expect("readable segment");
            let first: serde_json::Value =
                serde_json::from_str(text.lines().next().expect("a line")).expect("a record");
            assert_eq!(first["event"], "start");
        }
        assert!(
            of_kind(&lines, "start").last().expect("a header")["trimmed"]
                .as_u64()
                .expect("a count")
                > 0
        );

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[tokio::test]
    async fn a_closed_segment_is_gzipped_and_the_one_being_written_is_not() {
        let directory = directory("compressed");
        // Small enough that every record or two rolls the segment over
        write(
            &directory,
            Settings {
                compress: true,
                ..settings()
            },
            Some(120),
            (0..20).map(|count| Record::Dropped { count }).collect(),
        )
        .await;

        let segments = segments(&directory);
        assert!(segments.len() > 2, "expected rollovers, got {segments:?}");
        let (live, closed) = segments.split_last().expect("a segment");
        for segment in closed {
            let name = segment.to_string_lossy();
            assert!(name.ends_with(".jsonl.gz"), "{name} was left uncompressed");
        }
        // The one being written is still plain, and still the one `latest`
        // points at, so that it can be read as it is written
        let name = live.to_string_lossy();
        assert!(name.ends_with(".jsonl"), "{name} was compressed while live");
        assert_eq!(
            std::fs::read_link(directory.join("latest.jsonl")).expect("a symlink"),
            PathBuf::from(live.file_name().expect("a file name")),
        );

        // Nothing is left half written: a copy taken from this directory at any
        // moment picks up whole files
        for path in std::fs::read_dir(&directory).expect("the log directory") {
            let path = path.expect("a readable entry").path();
            let name = path.to_string_lossy();
            assert!(!name.ends_with(STAGING_SUFFIX), "{name} was left behind");
        }

        // What comes back out is what went in, in the order it went in
        let lines = records(&directory);
        let counts: Vec<u64> = of_kind(&lines, "dropped")
            .iter()
            .map(|line| line["count"].as_u64().expect("a count"))
            .collect();
        assert_eq!(counts, (0..20).collect::<Vec<u64>>());
        for (index, line) in lines.iter().enumerate() {
            assert_eq!(line["seq"], index as u64);
        }
        // And the header says how the run was keeping them
        assert_eq!(lines[0]["compressed"], true);

        // The books the budget trims by are the files that are really there,
        // which is the gzips and not what went into them. All that is between
        // them is the `stop` written after the count was taken.
        let on_disk: i64 = segments
            .iter()
            .map(|path| std::fs::metadata(path).expect("a segment").len() as i64)
            .sum();
        let signed_off = of_kind(&lines, "stop")[0]["bytes"]
            .as_i64()
            .expect("a count");
        assert!(
            (0..512).contains(&(on_disk - signed_off)),
            "the run signed off with {signed_off} bytes and left {on_disk} on disk"
        );

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[tokio::test(start_paused = true)]
    async fn a_segment_is_rolled_over_on_the_clock() {
        let directory = directory("clock");
        let interval = Duration::from_secs(60);
        let (log, writer) = Writer::create(
            &directory,
            Settings {
                interval,
                ..settings()
            },
            start(),
        )
        .await
        .expect("opens the log");
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(writer.run(shutdown.clone()));

        log.record(|| Record::Dropped { count: 1 });
        // Two intervals: the first closes the segment this record is in, and
        // the second finds a segment with nothing but its own header in it,
        // which is not worth a file
        tokio::time::sleep(2 * interval).await;
        log.record(|| Record::Dropped { count: 2 });
        shutdown.cancel();
        task.await.expect("the writer finishes");

        let segments = segments(&directory);
        assert_eq!(segments.len(), 2, "expected one rollover, got {segments:?}");
        assert_eq!(
            of_kind(&records(&directory), "dropped")
                .iter()
                .map(|line| line["count"].as_u64().expect("a count"))
                .collect::<Vec<u64>>(),
            [1, 2],
        );
        // Each record is in the segment it was written in, and in it once
        assert!(read(&segments[0]).contains("\"count\":1"));
        assert!(!read(&segments[1]).contains("\"count\":1"));
        assert!(read(&segments[1]).contains("\"count\":2"));

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[tokio::test]
    async fn shed_records_are_reported_rather_than_quietly_lost() {
        let directory = directory("dropped");
        let (log, writer) = Writer::create(&directory, settings(), start())
            .await
            .expect("opens the log");
        let shutdown = CancellationToken::new();

        // Nothing is draining the queue yet, so this fills it and then sheds
        for count in 0..(QUEUE_SIZE as u64 + 8) {
            log.record(|| Record::Dropped { count });
        }
        assert_eq!(log.dropped(), 8);

        let task = tokio::spawn(writer.run(shutdown.clone()));
        shutdown.cancel();
        task.await.expect("the writer finishes");

        let lines = records(&directory);
        let reported: u64 = of_kind(&lines, "dropped")
            .iter()
            .filter(|line| line["count"].as_u64() == Some(8))
            .count() as u64;
        assert!(reported > 0, "the shed records were never reported");
        assert_eq!(
            of_kind(&lines, "stop")[0]["records_dropped"]
                .as_u64()
                .expect("a count"),
            8
        );

        // What did get written is still a contiguous stretch: the records that
        // never made it in do not leave holes to explain
        let sequences: Vec<u64> = lines
            .iter()
            .map(|line| line["seq"].as_u64().expect("a sequence number"))
            .collect();
        assert!(
            sequences.windows(2).all(|pair| pair[1] == pair[0] + 1),
            "expected no gaps in {sequences:?}"
        );

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn sizes_parse_with_and_without_a_suffix() {
        assert_eq!("1024".parse::<Budget>().expect("plain bytes"), Budget(1024));
        assert_eq!("4K".parse::<Budget>().expect("kibibytes"), Budget(4096));
        assert_eq!(
            "16M".parse::<Budget>().expect("mebibytes"),
            Budget(16 * 1024 * 1024)
        );
        assert_eq!(
            "2G".parse::<Budget>().expect("gibibytes"),
            Budget(2 * 1024 * 1024 * 1024)
        );
        // Lowercase, a trailing B, and surrounding space are all what someone
        // typing a budget into a compose file is likely to produce
        assert_eq!("8g".parse::<Budget>().expect("lowercase"), Budget(8 << 30));
        assert_eq!(
            "8GB".parse::<Budget>().expect("trailing B"),
            Budget(8 << 30)
        );
        assert_eq!(" 8 G ".parse::<Budget>().expect("spaces"), Budget(8 << 30));
        assert_eq!("0".parse::<Budget>().expect("zero"), Budget(0));
    }

    #[test]
    fn sizes_that_are_not_sizes_are_refused() {
        assert!(matches!("".parse::<Budget>(), Err(BudgetError::Empty)));
        assert!(matches!("  ".parse::<Budget>(), Err(BudgetError::Empty)));
        assert!(matches!(
            "G".parse::<Budget>(),
            Err(BudgetError::Invalid(_))
        ));
        assert!(matches!(
            "4T".parse::<Budget>(),
            Err(BudgetError::Invalid(_))
        ));
        assert!(matches!(
            "1.5G".parse::<Budget>(),
            Err(BudgetError::Invalid(_))
        ));
        assert!(matches!(
            "-1".parse::<Budget>(),
            Err(BudgetError::Invalid(_))
        ));
        // Overflowing the scale is a size that cannot be honoured, not a zero
        assert!(matches!(
            "18446744073709551615G".parse::<Budget>(),
            Err(BudgetError::TooLarge(_))
        ));
    }
}
