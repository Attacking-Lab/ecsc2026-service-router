use std::{
    cmp::{Eq, PartialEq},
    collections::HashMap,
    fmt::Display,
    hash::Hash,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Weak,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    time::SystemTime,
};

use std::borrow::Borrow;

use atm::{
    AtmCell, Pti, VirtualCircuit,
    aal5::{CpcsPdu, CpcsPduTrailer, Pdu, Reassembler},
    signalling,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    sync::{
        RwLock,
        mpsc::{Receiver, Sender, error::TrySendError},
    },
    time::Instant,
};
use tokio_util::sync::CancellationToken;

use crate::{
    addresses::AtmAddress,
    capture::{Client, Direction, Packet},
    flood::Monitor,
    switchboard::Event,
};

/// A connection ID
pub type ConnectionId = u64;

/// What a connection's incoming circuits are counted against.
///
/// Callers share one allowance per subnet, so a client cannot widen it by
/// opening more connections. The checker is counted per connection instead: it
/// dials from one address but makes each call on a connection of its own.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SourceKey {
    /// The subnet a caller dialled in from
    Subnet(IpAddr),
    /// The checker, which is exempt from pooling
    Connection(ConnectionId),
}

/// How a connection's phone number was assigned
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressAssignment {
    /// Randomly drawn from the numbering plan's dynamic range
    Dynamic,
    /// Fixed in the numbering plan for this remote endpoint
    Static,
}

/// Connection metadata stored in the server's evmap
pub struct Connection {
    pub id: ConnectionId,
    pub remote: SocketAddr,
    /// Our own end of the TCP connection, so that a pcap captured elsewhere can
    /// be matched to this connection by its four-tuple
    pub endpoint: SocketAddr,
    pub local: AtmAddress,
    pub assignment: AddressAssignment,
    pub source: SourceKey,
    pub reserved: bool,
    pub counter: AtomicU32,
    pub outbound: Sender<AtmCell>,
    pub circuits: RwLock<CircuitTable>,
    /// When the connection was accepted, for the debug log's durations
    pub opened: Instant,
    /// Calls placed and received, reported when the connection closes
    pub calls_placed: AtomicU64,
    pub calls_received: AtomicU64,
}

/// State of a circuit entry.
///
/// The switchboard is the only writer for these states; the data path only reads them
/// (and only forwards cells on `Connected` circuits).
#[derive(Clone, Copy, Debug)]
pub enum CircuitState {
    /// This client sent ESTABLISH (its ID is `local`); we forwarded the request to the
    /// callee using the DSLAM-issued ID `remote` and are waiting for its ESTABLISHED.
    OutgoingPending { local: u32, remote: u32 },
    /// We forwarded an ESTABLISH (with the DSLAM-issued ID `remote`) to this client and
    /// are waiting for its ESTABLISHED. The caller's own ID is `local`.
    IncomingPending { local: u32, remote: u32 },
    /// We sent RELEASE (with the DSLAM-issued ID `remote`) to this client and are
    /// waiting for its RELEASED.
    DisconnectionPending { remote: u32 },
    /// Connected; cells are forwarded. On the leg of the client that placed the call,
    /// `local` holds that client's ESTABLISH ID: if our ESTABLISHED confirmation is
    /// lost, the client retransmits its ESTABLISH, and the ID lets us recognize it and
    /// confirm again instead of tearing down the live call.
    Connected { local: Option<u32> },
}

/// Which side of a call a circuit leg belongs to.
///
/// Incoming and outgoing legs count against separate limits, so that a flood of
/// incoming calls cannot exhaust a connection's ability to place its own calls
/// (and vice versa).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegDirection {
    /// This connection placed the call
    Outgoing,
    /// This connection received the call
    Incoming,
}

/// A circuit pair that is essentially a NAT table entry
pub struct CircuitEntry {
    pub state: CircuitState,
    pub direction: LegDirection,
    pub connection: Weak<Connection>,
    pub circuit: VirtualCircuit,
    pub source: SourceKey,
    /// When this leg was created, for the circuit lifetime cap
    pub established_at: Instant,
    /// The call this leg belongs to, for the debug log. Legs that carry no call
    /// -- the testing mirror, and legs mid-release -- have none.
    pub call: Option<u64>,
    /// Cells the owner of this leg sent into the call, counted on the forwarding
    /// path that already holds the entry
    pub cells: AtomicU64,
    /// ...of which these found the peer's queue full
    pub cells_queue_full: AtomicU64,
}

impl CircuitEntry {
    /// Whether this leg counts against the *incoming* limits (total and per-source).
    /// Legs mid-release are exempt (they are bounded separately).
    fn is_incoming_active(&self) -> bool {
        self.direction == LegDirection::Incoming
            && !matches!(self.state, CircuitState::DisconnectionPending { .. })
    }

    /// Whether this leg is mid-release (counts against the releasing limit)
    fn is_releasing(&self) -> bool {
        matches!(self.state, CircuitState::DisconnectionPending { .. })
    }
}

/// A connection's circuit table, plus per-state counters maintained on every mutation.
///
/// The limit checks and teardown paths read these counters instead of scanning the whole
/// table, so a client cannot force the switchboard into per-message or quadratic
/// (per-disconnect) scans of a large table. The switchboard is the only writer, so these
/// counts are always consistent with `entries`.
#[derive(Default)]
pub struct CircuitTable {
    entries: HashMap<VirtualCircuit, CircuitEntry>,
    /// Incoming legs that are not mid-release
    incoming: usize,
    /// Legs mid-release (`DisconnectionPending`), in either direction
    releasing: usize,
    /// Incoming (non-releasing) legs, bucketed by the source that placed the call, so
    /// a single source cannot monopolize a popular callee's incoming table.
    incoming_by_source: HashMap<SourceKey, usize>,
}

impl CircuitTable {
    /// Applies an entry's contribution to the counters (`add` to insert, else to remove)
    fn account(&mut self, entry: &CircuitEntry, add: bool) {
        let step = |value: &mut usize| {
            *value = if add {
                *value + 1
            } else {
                value.saturating_sub(1)
            };
        };
        if entry.is_releasing() {
            step(&mut self.releasing);
        }
        if entry.is_incoming_active() {
            step(&mut self.incoming);
            if add {
                *self.incoming_by_source.entry(entry.source).or_insert(0) += 1;
            } else if let Some(count) = self.incoming_by_source.get_mut(&entry.source) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.incoming_by_source.remove(&entry.source);
                }
            }
        }
    }

    /// Inserts (or replaces) a leg, returning any leg it displaced
    pub fn insert(&mut self, circuit: VirtualCircuit, entry: CircuitEntry) -> Option<CircuitEntry> {
        self.account(&entry, true);
        let old = self.entries.insert(circuit, entry);
        if let Some(old) = &old {
            self.account(old, false);
        }
        old
    }

    /// Removes a leg, adjusting the counters
    pub fn remove(&mut self, circuit: &VirtualCircuit) -> Option<CircuitEntry> {
        let removed = self.entries.remove(circuit);
        if let Some(removed) = &removed {
            self.account(removed, false);
        }
        removed
    }

    /// Replaces the state of an existing leg, adjusting the counters. Returns whether the
    /// leg existed.
    pub fn set_state(&mut self, circuit: &VirtualCircuit, state: CircuitState) -> bool {
        let Some(entry) = self.entries.get_mut(circuit) else {
            return false;
        };
        // Snapshot the old classification, mutate, then re-account
        let was_releasing = entry.is_releasing();
        let was_incoming = entry.is_incoming_active();
        let source = entry.source;
        entry.state = state;
        let is_releasing = entry.is_releasing();
        let is_incoming = entry.is_incoming_active();

        let apply = |value: &mut usize, before: bool, after: bool| {
            if before && !after {
                *value = value.saturating_sub(1);
            } else if !before && after {
                *value += 1;
            }
        };
        apply(&mut self.releasing, was_releasing, is_releasing);
        apply(&mut self.incoming, was_incoming, is_incoming);
        if was_incoming && !is_incoming {
            if let Some(count) = self.incoming_by_source.get_mut(&source) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.incoming_by_source.remove(&source);
                }
            }
        } else if !was_incoming && is_incoming {
            *self.incoming_by_source.entry(source).or_insert(0) += 1;
        }
        true
    }

    /// Looks up a leg
    pub fn get(&self, circuit: &VirtualCircuit) -> Option<&CircuitEntry> {
        self.entries.get(circuit)
    }

    /// Whether a leg exists for this circuit
    pub fn contains(&self, circuit: &VirtualCircuit) -> bool {
        self.entries.contains_key(circuit)
    }

    /// Number of legs in the table
    #[allow(dead_code)] // used by the test suite
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty
    #[allow(dead_code)] // API symmetry with `len` (clippy::len_without_is_empty)
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Incoming legs that are not mid-release
    pub fn incoming(&self) -> usize {
        self.incoming
    }

    /// Incoming (non-releasing) legs placed by a specific source connection
    pub fn incoming_from(&self, source: SourceKey) -> usize {
        self.incoming_by_source.get(&source).copied().unwrap_or(0)
    }

    /// Legs mid-release
    pub fn releasing(&self) -> usize {
        self.releasing
    }

    /// Borrows the legs, for the lifetime sweep
    pub fn iter(&self) -> impl Iterator<Item = (&VirtualCircuit, &CircuitEntry)> {
        self.entries.iter()
    }

    /// Consumes the table, yielding its legs (used to tear a connection down)
    pub fn into_entries(
        self,
    ) -> std::collections::hash_map::IntoIter<VirtualCircuit, CircuitEntry> {
        self.entries.into_iter()
    }
}

impl Display for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} at {}", self.local, self.remote)
    }
}

impl Hash for Connection {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
        self.remote.hash(state);
        self.local.hash(state);
        // The rest of this is not hashable. But this is OK, we only have one connection per
        // host/port combination anyways, and certainly only one per address.
    }
}

impl PartialEq for Connection {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.remote == other.remote && self.local == other.local
    }
}

impl Eq for Connection {}

/// Errors when enqueueing a signalling message towards a client
#[derive(Debug)]
pub enum SignallingSendError {
    /// The outbound queue is full. The protocol recovers via retransmission.
    QueueFull,
    /// The connection is gone; a `Closed` event will clean up.
    ConnectionClosed,
}

impl Display for SignallingSendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignallingSendError::QueueFull => write!(f, "outbound queue is full"),
            SignallingSendError::ConnectionClosed => write!(f, "connection is closed"),
        }
    }
}

impl Connection {
    /// Creates a new connection
    #[allow(clippy::too_many_arguments)] // all of it is the connection's identity
    pub fn new(
        id: u64,
        remote: SocketAddr,
        endpoint: SocketAddr,
        local: AtmAddress,
        assignment: AddressAssignment,
        source: SourceKey,
        reserved: bool,
        outbound: Sender<AtmCell>,
    ) -> Arc<Self> {
        Arc::new(Self {
            id,
            remote,
            endpoint,
            local,
            assignment,
            source,
            reserved,
            counter: AtomicU32::new(0),
            outbound,
            circuits: RwLock::new(CircuitTable::default()),
            opened: Instant::now(),
            calls_placed: AtomicU64::new(0),
            calls_received: AtomicU64::new(0),
        })
    }

    /// Enqueues an outbound signalling message on this connection.
    ///
    /// This never blocks: on a full queue the message is dropped and the caller relies on
    /// the protocol's retransmissions (a lost RELEASE is retransmitted by our timer, a lost
    /// RELEASED is re-triggered by the peer's RELEASE retransmission, and so on).
    pub fn send_signalling(
        &self,
        message: &signalling::Message,
    ) -> Result<(), SignallingSendError> {
        let mut buffer = [0u8; signalling::MAX_MESSAGE_SIZE];
        let length = message.write_to(&mut buffer);
        let trailer = CpcsPduTrailer::compute(&buffer[..length], 0, 0)
            .expect("signalling messages always fit an AAL5 CPCS-PDU");
        let pdu = CpcsPdu {
            data: &buffer[..length],
            trailer: CpcsPduTrailer(trailer.borrow()),
        };
        // Signalling messages fit a single cell, so each message is enqueued atomically
        // (and this path never allocates, even under a signalling flood).
        for mut cell in pdu.segments() {
            {
                let mut header = cell.header_mut();
                header.set_vpi(0);
                header.set_vci(5);
                header.fix_hec();
            }
            match self.outbound.try_send(cell) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => return Err(SignallingSendError::QueueFull),
                Err(TrySendError::Closed(_)) => return Err(SignallingSendError::ConnectionClosed),
            }
        }
        Ok(())
    }

    /// Processes outbound ATM cells
    pub async fn outbound(
        self: Arc<Self>,
        mut queue: Receiver<AtmCell>,
        mut outbound: OwnedWriteHalf,
        mut capture: Option<Client>,
        connection_shutdown: CancellationToken,
        global_shutdown: CancellationToken,
    ) {
        // Send the address out
        let address_bytes: [u8; _] = self.local.clone().into();
        tokio::select! {
            _ = connection_shutdown.cancelled() => return,
            _ = global_shutdown.cancelled() => return,
            result = outbound.write_all(&address_bytes) => if let Err(error) = result {
                tracing::error!("Failed to send AESA {} to {}: {}", self.local, self.remote, error);
                connection_shutdown.cancel();
                return;
            }
        }
        loop {
            let cell = tokio::select! {
                _ = connection_shutdown.cancelled() => return,
                _ = global_shutdown.cancelled() => return,
                entry = queue.recv() => match entry {
                    Some(cell) => cell,
                    None => {
                        tracing::info!("Transmit queue for {} was shut down", self);
                        connection_shutdown.cancel();
                        return;
                    }
                }
            };
            if let Some(client) = &capture {
                let packet = Packet {
                    cell: cell.clone(),
                    connection: self.clone(),
                    direction: Direction::Outbound,
                    timestamp: SystemTime::now(),
                };
                tokio::select! {
                    _ = connection_shutdown.cancelled() => return,
                    _ = global_shutdown.cancelled() => return,
                    result = client.add_packet(packet) => if let Err(error) = result {
                        tracing::error!("Failed to add packet for {} to the packet capture: {}", self, error);
                        if error.is_permanent() {
                            capture = None;
                        }
                    }
                };
            }
            tokio::select! {
                _ = connection_shutdown.cancelled() => return,
                _ = global_shutdown.cancelled() => return,
                result = outbound.write_all(&*cell) => if let Err(error) = result {
                    tracing::info!("Failed to send cell to {}: {}", self, error);
                    connection_shutdown.cancel();
                    return;
                }
            }
        }
    }

    /// Processes inbound ATM cells
    pub async fn inbound(
        self: Arc<Self>,
        mut inbound: OwnedReadHalf,
        events: Sender<Event>,
        mut capture: Option<Client>,
        monitor: Arc<Monitor>,
        connection_shutdown: CancellationToken,
        global_shutdown: CancellationToken,
    ) {
        /// Outcome of a forwarding attempt, decided while holding the circuit table lock
        enum Outcome {
            /// The cell was handed to the peer's transmit queue on the translated circuit
            Forwarded(Arc<Connection>, VirtualCircuit),
            /// The peer's transmit queue is full; the cell was dropped
            QueueFull(Arc<Connection>),
            /// The peer's transmit queue is gone; the switchboard should release
            PeerClosed(Arc<Connection>),
            /// The circuit is still being set up or torn down
            Pending,
            /// The circuit entry points at a connection that no longer exists
            Stale,
            /// No entry for this circuit
            Unallocated,
        }

        let mut cell: AtmCell = Default::default();
        let mut signalling_reassembler = Reassembler::new();
        let mut traffic = monitor.traffic(self.source);
        loop {
            tokio::select! {
                _ = connection_shutdown.cancelled() => return,
                _ = global_shutdown.cancelled() => return,
                result = inbound.read_exact(&mut *cell) => if let Err(error) = result {
                    tracing::info!("Failed to read cell from {}: {}", self, error);
                    connection_shutdown.cancel();
                    return;
                },
            }
            traffic.cell();

            if let Some(client) = &capture {
                let packet = Packet {
                    cell: cell.clone(),
                    connection: self.clone(),
                    direction: Direction::Inbound,
                    timestamp: SystemTime::now(),
                };
                tokio::select! {
                    _ = connection_shutdown.cancelled() => return,
                    _ = global_shutdown.cancelled() => return,
                    result = client.add_packet(packet) => if let Err(error) = result {
                        tracing::error!("Failed to add packet from {} to the packet capture: {}", self, error);
                        if error.is_permanent() {
                            capture = None;
                        }
                    }
                };
            }

            // What is this cell for? Parse the ATM header to find out.
            let header = cell.header();
            let circuit = header.circuit();

            let hec = header.hec();
            let expected = header.expected_hec();
            if hec != expected {
                tracing::debug!(
                    "Dropping cell from {}: invalid HEC {:02X} (expected {:02X})",
                    self,
                    hec,
                    expected
                );
                continue;
            }

            // Only keep content cells and end-to-end OAM F5.
            if let Some(reason) = match header.pti() {
                Pti::SegmentOamF5Cell => Some("Segment OAM F5 cell"),
                Pti::ResourceManagementCell => Some("Resource Management cell"),
                Pti::Reserved => Some("Cell with reserved PTI"),
                _ => None,
            } {
                tracing::debug!("Dropping {} from {}", reason, self,);
                continue;
            }

            if circuit.is_signalling() {
                // Signalling cell.
                // We need to reassemble AAL5 cells on this path.
                let Some(pdu) = signalling_reassembler.reassemble(&cell) else {
                    // AAL5 PDU is not complete
                    continue;
                };
                let cpcs_pdu = match pdu {
                    Pdu::Reassembled(cpcs_pdu) => cpcs_pdu,
                    Pdu::Raw(_) => {
                        tracing::debug!("Discarding non-AAL5 cell in signalling from {}", self);
                        continue;
                    }
                    Pdu::Discarded(data) => {
                        tracing::debug!(
                            "Discarding overlong AAL5 CPCS-PDU (at {} bytes) in signalling from {}",
                            data.len(),
                            self
                        );
                        continue;
                    }
                    Pdu::Invalid(_, reason) => {
                        tracing::debug!(
                            "Discarding invalid AAL5 CPCS-PDU ({}) in signalling from {}",
                            reason,
                            self
                        );
                        continue;
                    }
                };

                // Now we have a valid CPCS-PDU, check that is actually a signalling message.
                let message: signalling::Message = match (&cpcs_pdu.data[..]).try_into() {
                    Ok(message) => message,
                    Err(error) => {
                        tracing::debug!(
                            "Discarding invalid signalling message from {}: {}",
                            self,
                            error
                        );
                        continue;
                    }
                };

                // Counted here rather than in the switchboard: this is the rate
                // the client offers, not the rate we get around to handling.
                if matches!(message, signalling::Message::Establish { .. }) {
                    traffic.setup();
                }

                // The switchboard handles the signalling to synchronize the necessary
                // state changes. This is sent on the server's event queue (lowest priority),
                // and we deliberately block here so a busy server applies backpressure to
                // all clients. This should reduce the impact of deliberate flooding, as we
                // only ever process one signalling message per client at a time.
                tokio::select! {
                    _ = connection_shutdown.cancelled() => return,
                    _ = global_shutdown.cancelled() => return,
                    result = events.send(Event::Message { from: self.id, message }) => if result.is_err() {
                        tracing::error!("Dropping signalling message from {}: switchboard is gone", self);
                    }
                }
            } else {
                // Check if this is an existing circuit for this connection.
                // If yes, forward the message while holding the read lock on the connection map.
                let outcome = {
                    let circuits = self.circuits.read().await;
                    match circuits.get(&circuit) {
                        Some(entry) => match entry.state {
                            CircuitState::Connected { .. } => match entry.connection.upgrade() {
                                Some(peer) => {
                                    let translated = entry.circuit;
                                    {
                                        let mut header = cell.header_mut();
                                        header.set_vpi(translated.vpi);
                                        header.set_vci(translated.vci);
                                        header.fix_hec();
                                    }
                                    // Counted here, where the entry is already in
                                    // hand, so per-call volume costs one relaxed
                                    // add rather than a second pass over the data
                                    match peer.outbound.try_send(cell.clone()) {
                                        Ok(()) => {
                                            entry.cells.fetch_add(1, Ordering::Relaxed);
                                            Outcome::Forwarded(peer, translated)
                                        }
                                        Err(TrySendError::Full(_)) => {
                                            // A cell the recipient was sent and could
                                            // not keep up with is still one this leg
                                            // put into the call
                                            entry.cells.fetch_add(1, Ordering::Relaxed);
                                            entry.cells_queue_full.fetch_add(1, Ordering::Relaxed);
                                            Outcome::QueueFull(peer)
                                        }
                                        Err(TrySendError::Closed(_)) => Outcome::PeerClosed(peer),
                                    }
                                }
                                None => Outcome::Stale,
                            },
                            _ => Outcome::Pending,
                        },
                        None => Outcome::Unallocated,
                    }
                };
                match outcome {
                    Outcome::Forwarded(peer, translated) => {
                        traffic.cell_to(peer.source);
                        tracing::debug!(
                            "Forwarded cell from {} (on {}) to {} (on {})",
                            self,
                            circuit,
                            peer,
                            translated,
                        );
                    }
                    Outcome::QueueFull(peer) => {
                        // Counted all the same: a cell the recipient was sent
                        // and could not keep up with is still aimed at it
                        traffic.cell_to(peer.source);
                        tracing::debug!(
                            "Dropping cell from {} for {}, outbound queue is full",
                            self,
                            peer,
                        );
                    }
                    Outcome::PeerClosed(peer) => {
                        tracing::debug!(
                            "Dropping cell from {} for {}, connection went away",
                            self,
                            peer,
                        );
                        // The switchboard will release the circuit.
                        // If this event is lost, the next cell will retry here,
                        // so we can afford the try_send.
                        let _ = events.try_send(Event::PeerGone {
                            on: self.id,
                            circuit,
                        });
                    }
                    Outcome::Pending => {
                        tracing::debug!(
                            "Dropping cell from {} ({} is still being set up or torn down)",
                            self,
                            circuit,
                        );
                    }
                    Outcome::Stale => {
                        tracing::debug!("Dropping cell from {} ({} is stale)", self, circuit);
                        let _ = events.try_send(Event::PeerGone {
                            on: self.id,
                            circuit,
                        });
                    }
                    Outcome::Unallocated => {
                        tracing::debug!(
                            "Dropping cell from {} ({} is not allocated)",
                            self,
                            circuit,
                        );
                    }
                }
            }
        }
    }
}
