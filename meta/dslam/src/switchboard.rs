use std::{
    collections::HashMap,
    future::poll_fn,
    sync::{
        Arc, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use atm::{
    VirtualCircuit,
    signalling::{self, MessageType},
};
use evmap::handles::{ReadHandle, WriteHandle};
use rand::RngExt;
use tokio::{sync::mpsc::Receiver, time::Instant};
use tokio_util::{
    sync::CancellationToken,
    time::{DelayQueue, delay_queue},
};

use crate::{
    addresses::AtmAddress,
    connection::{
        AddressAssignment, CircuitEntry, CircuitState, CircuitTable, Connection, ConnectionId,
        LegDirection,
    },
    debug_log::{DownReason, Log, Record, RejectedBy, connection_record, seconds_since},
};

// Sanity check that the map's key and value are Send + Sync.
// This is required because of jonhoo/evmap#12
const fn assert_send_sync<T: Send + Sync>() {}
const _: () = assert_send_sync::<AtmAddress>();
const _: () = assert_send_sync::<Connection>();
const _: () = assert_send_sync::<Arc<Connection>>();

/// Size of the event queue (may block).
pub const EVENT_QUEUE_SIZE: usize = 4096;

/// Size of the control queue (registration/disconnect). Prioritized over the event queue.
pub const CONTROL_QUEUE_SIZE: usize = 64;

// Timers and retries

/// How long to wait for an ESTABLISHED before retransmitting (or giving up)
pub(crate) const ESTABLISH_RETRANSMIT: Duration = Duration::from_secs(2);

/// How often to retransmit a forwarded ESTABLISH before declaring the callee unreachable
pub(crate) const ESTABLISH_RETRIES: u8 = 2;

/// How long to wait for a RELEASED before retransmitting (or giving up)
pub(crate) const RELEASE_RETRANSMIT: Duration = Duration::from_secs(2);

/// How often to retransmit a RELEASE before dropping the circuit anyway
pub(crate) const RELEASE_RETRIES: u8 = 5;

/// Maximum number of incoming circuits (in any state) per connection
/// (must remain below the firmware's `MAX_HANDLERS`)
pub(crate) const MAX_INCOMING_CIRCUITS_PER_CONNECTION: usize = 232;

/// How long a connected circuit lives before it is released
/// (mirrors the firmware's `CONFIG_ATM_CIRCUIT_LIFETIME_SECONDS`)
pub(crate) const CIRCUIT_LIFETIME: Duration = Duration::from_secs(180);

/// How often circuits are checked against `CIRCUIT_LIFETIME`
const CIRCUIT_SWEEP_INTERVAL: Duration = Duration::from_secs(10);

/// Maximum number of incoming circuits a single source may hold on one callee.
/// Low enough that every subscriber can hold this many on every other one at
/// once without reaching `MAX_INCOMING_CIRCUITS_PER_CONNECTION`.
pub(crate) const MAX_INCOMING_CIRCUITS_PER_SOURCE: usize = 4;

/// Maximum number of legs mid-release (`DisconnectionPending`) per connection.
/// Releasing connections that exceed this limit are dropped outright, with no guarantee
/// of a RELEASE arriving.
pub(crate) const MAX_RELEASING_PER_CONNECTION: usize = 64;

/// Smallest VCI handed out by the allocator (VCIs below 32 are reserved)
const MIN_ALLOCATED_VCI: u16 = 32;

/// Attempts at allocating a free circuit before giving up
const ALLOCATION_ATTEMPTS: usize = 96;

/// Call-policy safeguards against connection and circuit exhaustion.
/// We want to prevent outbound calls from vulnboxes, and inbound calls to unsuspecting
/// clients, to make this setup a little bit more resilient.
#[derive(Clone, Copy, Debug, Default)]
pub struct Policy {
    /// Allow calls *to* dynamically-assigned numbers
    pub allow_calls_to_dynamic: bool,
    /// Allow statically-assigned numbers to place outbound calls
    pub allow_calls_from_static: bool,
    /// Incoming circuits held back for the checker, so that a subscriber busy
    /// with everyone else's calls can still be scored
    pub checker_reserve: usize,
}

/// An event for the switchboard.
pub enum Event {
    // Control channel events, must be prioritized
    /// A new client connected (over TCP)
    Register { connection: Arc<Connection> },
    /// A client disconnected
    Closed { connection: ConnectionId },

    // Event channel events
    /// A signalling message arrived from a client
    Message {
        from: ConnectionId,
        message: signalling::Message,
    },
    /// The data path noticed that the peer of this circuit went away
    PeerGone {
        on: ConnectionId,
        circuit: VirtualCircuit,
    },
}

/// A transaction the DSLAM is waiting on, keyed by `(connection, DSLAM-issued ID)`.
/// Client-selected IDs are only used in response to that client's messages.
#[derive(Clone, Copy, Debug)]
enum PendingKind {
    /// We forwarded an ESTABLISH and are waiting for the callee's ESTABLISHED
    Establish {
        /// The caller that sent the ESTABLISH
        caller: ConnectionId,
        /// Circuit that the caller requested on its own link
        caller_circuit: VirtualCircuit,
        /// Transaction ID that the caller sent
        caller_id: u32,
        /// Circuit that the DSLAM allocated on the callee's link
        callee_circuit: VirtualCircuit,
        /// How often we will retry the ESTABLISH to the callee
        retries_left: u8,
    },
    /// We sent a RELEASE and are waiting for the client's RELEASED
    Release {
        circuit: VirtualCircuit,
        retries_left: u8,
    },
}

struct Pending {
    kind: PendingKind,
    timer: delay_queue::Key,
}

/// The caller's side of a call attempt, for the records of one that failed
struct Attempt<'a> {
    caller: &'a Connection,
    circuit: VirtualCircuit,
    id: u32,
}

/// The switchboard actor
pub struct Switchboard {
    /// Control events from the server (`Register` and `Closed`), polled with
    /// priority over `events` so connection churn is never starved by signalling
    control: Receiver<Event>,

    /// Inbound events (from the receive tasks and the data path)
    events: Receiver<Event>,

    /// Connection map write handle
    writer: WriteHandle<AtmAddress, Arc<Connection>>,

    /// Connection map read handle for resolving call targets
    reader: ReadHandle<AtmAddress, Arc<Connection>>,

    /// All currently registered connections
    connections: HashMap<ConnectionId, Arc<Connection>>,

    /// Transactions waiting for a client reply, by connection and our ID
    pending: HashMap<ConnectionId, HashMap<u32, Pending>>,

    /// Timers for the pending transactions
    timers: DelayQueue<(ConnectionId, u32)>,

    /// The mirror circuit, if configured, is never handed out or accepted for calls
    mirror_circuit: Option<VirtualCircuit>,

    /// Exhaustion safeguards for call setup
    policy: Policy,

    /// Structured export of connection and call information
    log: Log,

    /// Identifies a call across both of its legs in the debug log
    next_call: u64,

    /// The segment the debug log was writing to when the live state was last
    /// repeated into it
    segment: u64,

    /// Run-wide counts for the debug log's `totals`
    connections_total: u64,
    calls_total: u64,
    calls_rejected_total: u64,
}

impl Switchboard {
    /// Creates a new switchboard
    #[allow(clippy::too_many_arguments)] // every one of them is wiring, not policy
    pub fn new(
        control: Receiver<Event>,
        events: Receiver<Event>,
        writer: WriteHandle<AtmAddress, Arc<Connection>>,
        reader: ReadHandle<AtmAddress, Arc<Connection>>,
        mirror_circuit: Option<VirtualCircuit>,
        policy: Policy,
        log: Log,
    ) -> Self {
        Self {
            control,
            events,
            writer,
            reader,
            connections: HashMap::new(),
            pending: HashMap::new(),
            timers: DelayQueue::new(),
            mirror_circuit,
            policy,
            log,
            next_call: 0,
            segment: 0,
            connections_total: 0,
            calls_total: 0,
            calls_rejected_total: 0,
        }
    }

    /// Runs the switchboard until shutdown
    pub async fn run(mut self, shutdown: CancellationToken) {
        let mut sweep = tokio::time::interval(CIRCUIT_SWEEP_INTERVAL);
        sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                // Deliberately biased.
                // Protocol timers come first because they drive resource reclamatin.
                // Then, urgent connection control events, so teardown cannot be starved
                // by spamming signalling messages, which are processed last.
                biased;
                _ = shutdown.cancelled() => {
                    // The run's last word on what it handled, so the totals a
                    // reader checks their own fold against are not a tick stale
                    self.log_housekeeping().await;
                    return;
                },
                Some(expired) = poll_fn(|context| self.timers.poll_expired(context)) => {
                    self.handle_timer(expired.into_inner()).await;
                },
                event = self.control.recv() => match event {
                    Some(event) => self.handle_event(event).await,
                    None => {
                        tracing::info!("Switchboard control channel closed, shutting down");
                        return;
                    }
                },
                _ = sweep.tick() => {
                    self.expire_circuits().await;
                    self.log_housekeeping().await;
                },
                event = self.events.recv() => match event {
                    Some(event) => self.handle_event(event).await,
                    None => {
                        tracing::info!("Switchboard event channel closed, shutting down");
                        return;
                    }
                },
            }
        }
    }

    /// Handles a single event
    async fn handle_event(&mut self, event: Event) {
        match event {
            Event::Register { connection } => {
                // If a testing mirror circuit is configured, install it here.
                // The switchboard is the only writer to the circuit map, so this is our job.
                if let Some(mirror) = self.mirror_circuit {
                    connection.circuits.write().await.insert(
                        mirror,
                        CircuitEntry {
                            state: CircuitState::Connected { local: None },
                            direction: LegDirection::Incoming,
                            connection: Arc::downgrade(&connection),
                            circuit: mirror,
                            source: connection.source,
                            established_at: Instant::now(),
                            call: None,
                            cells: AtomicU64::new(0),
                            cells_queue_full: AtomicU64::new(0),
                        },
                    );
                }
                let address = connection.local.clone();
                // Taking the number over is how a subscriber reconnects before its old
                // connection was reaped, but it also means anything else dialling in
                // from that address displaces it. Say so, it is hard to spot otherwise.
                let incumbent = self
                    .reader
                    .get(&address)
                    .and_then(|values| values.get_one().cloned());
                if let Some(incumbent) = incumbent
                    && incumbent.remote != connection.remote
                    && !incumbent.outbound.is_closed()
                {
                    tracing::warn!("{connection} takes {address} from {incumbent}");
                    // Two connections now answer to one number, which would
                    // otherwise quietly blur who a call reached
                    self.log.record(|| Record::NumberMoved {
                        number: address.to_string(),
                        from_conn: incumbent.id,
                        to_conn: connection.id,
                    });
                }
                self.connections_total += 1;
                self.connections.insert(connection.id, connection.clone());
                self.writer.update(address, connection);
                self.writer.publish();
            }
            Event::Closed { connection } => self.handle_closed(connection).await,
            Event::Message { from, message } => self.handle_message(from, message).await,
            Event::PeerGone { on, circuit } => self.handle_peer_gone(on, circuit).await,
        }
    }

    /// Releases connected circuits that outlived `CIRCUIT_LIFETIME`.
    ///
    /// The firmware caps how long one call may hold a handler thread; this keeps our
    /// own accounting from drifting away from it, and makes the teardown a RELEASE
    /// both sides see. Only connected legs are swept, pending ones are already bounded
    /// by their transaction timers.
    async fn expire_circuits(&mut self) {
        let now = Instant::now();
        let connections: Vec<Arc<Connection>> = self.connections.values().cloned().collect();
        for connection in connections {
            let expired: Vec<(VirtualCircuit, Option<Arc<Connection>>, VirtualCircuit)> = {
                let circuits = connection.circuits.read().await;
                circuits
                    .iter()
                    .filter(|(circuit, entry)| {
                        matches!(entry.state, CircuitState::Connected { .. })
                            && !self.is_reserved(**circuit)
                            && now.duration_since(entry.established_at) >= CIRCUIT_LIFETIME
                    })
                    .map(|(circuit, entry)| (*circuit, entry.connection.upgrade(), entry.circuit))
                    .collect()
            };
            for (circuit, peer, peer_circuit) in expired {
                tracing::debug!("Releasing {circuit} on {connection}, past its lifetime");
                self.begin_release(&connection, circuit, DownReason::Lifetime)
                    .await;
                if let Some(peer) = peer {
                    self.begin_release(&peer, peer_circuit, DownReason::Lifetime)
                        .await;
                }
            }
        }
    }

    /// Repeats the live state into a fresh debug log segment and reports the
    /// run's totals.
    ///
    /// Runs on the sweep's tick, so it costs one pass over the connections every
    /// `CIRCUIT_SWEEP_INTERVAL` and nothing at all when no log is configured.
    async fn log_housekeeping(&mut self) {
        if !self.log.enabled() {
            return;
        }
        // The writer opens a segment with the configuration but not the state,
        // so repeat the live connections and calls into it. They land within a
        // tick of the rollover rather than exactly at it.
        let segment = self.log.segment();
        let repeat = segment != self.segment;
        self.segment = segment;

        let mut calls_open = 0u64;
        let connections: Vec<Arc<Connection>> = self.connections.values().cloned().collect();
        for connection in connections {
            if repeat {
                self.log.record(|| connection_record(&connection));
            }
            let circuits = connection.circuits.read().await;
            for (circuit, entry) in circuits.iter() {
                let Some(call) = entry.call else { continue };
                if !matches!(entry.state, CircuitState::Connected { .. }) {
                    continue;
                }
                // Every call has exactly one outgoing leg, so counting those
                // counts calls rather than legs
                if entry.direction == LegDirection::Outgoing {
                    calls_open += 1;
                }
                if repeat {
                    let peer = entry.connection.upgrade().map(|peer| peer.id);
                    self.log.record(|| Record::CallLive {
                        call,
                        conn: connection.id,
                        vpi: circuit.vpi,
                        vci: circuit.vci,
                        direction: entry.direction.into(),
                        peer_conn: peer,
                        peer_vpi: entry.circuit.vpi,
                        peer_vci: entry.circuit.vci,
                        seconds: seconds_since(entry.established_at),
                        cells: entry.cells.load(Ordering::Relaxed),
                    });
                }
            }
        }

        self.log.record(|| Record::Totals {
            connections_open: self.connections.len() as u64,
            connections_total: self.connections_total,
            calls_open,
            calls_total: self.calls_total,
            calls_rejected_total: self.calls_rejected_total,
            records_dropped: self.log.dropped(),
        });
    }

    /// Handles a signalling message from a client
    async fn handle_message(&mut self, from: ConnectionId, message: signalling::Message) {
        if !self.connections.contains_key(&from) {
            tracing::debug!("Dropping signalling message from unknown connection {from}");
            return;
        }
        match message {
            signalling::Message::Establish {
                id,
                address,
                circuit,
            } => self.handle_establish(from, id, address, circuit).await,
            signalling::Message::Established { id } => self.handle_established(from, id).await,
            signalling::Message::Release { id, circuit } => {
                self.handle_release(from, id, circuit).await
            }
            signalling::Message::Released { id } => self.handle_released(from, id).await,
            signalling::Message::Error { id, error } => {
                self.handle_client_error(from, id, error).await
            }
        }
    }

    /// Returns the connection for an ID, if it is still registered
    fn connection(&self, id: ConnectionId) -> Option<Arc<Connection>> {
        self.connections.get(&id).cloned()
    }

    /// Sends a signalling message to a client.
    /// Failures are logged only, if the message was important, the retransmit timer
    /// will fire eventually.
    fn send(connection: &Connection, message: &signalling::Message) {
        if let Err(error) = connection.send_signalling(message) {
            tracing::warn!(
                "Failed to send {} to {}: {}",
                message.message_type(),
                connection,
                error
            );
        }
    }

    /// Whether a circuit may not be used for calls
    fn is_reserved(&self, circuit: VirtualCircuit) -> bool {
        circuit.is_signalling()
            || circuit.is_ilmi()
            || circuit.vci < MIN_ALLOCATED_VCI
            || Some(circuit) == self.mirror_circuit
    }

    /// Allocates a random free circuit on a connection.
    fn allocate_circuit(
        &self,
        existing: &CircuitTable,
        exclude: Option<VirtualCircuit>,
    ) -> Option<VirtualCircuit> {
        let mut rng = rand::rng();
        for _ in 0..ALLOCATION_ATTEMPTS {
            let candidate = VirtualCircuit {
                vpi: rng.random_range(0..=u8::MAX),
                vci: rng.random_range(MIN_ALLOCATED_VCI..=u16::MAX),
            };
            if self.is_reserved(candidate)
                || Some(candidate) == exclude
                || existing.contains(&candidate)
            {
                continue;
            }
            return Some(candidate);
        }
        None
    }

    /// Handles an ESTABLISH from a caller (`from`, wants to have this on circuit `circuit`)
    /// to a callee (`address`). The ESTABLISH has transaction ID `id`.
    async fn handle_establish(
        &mut self,
        from: ConnectionId,
        id: u32,
        address: signalling::E191AddressField,
        circuit: VirtualCircuit,
    ) {
        let Some(caller) = self.connection(from) else {
            return;
        };

        // Statically-numbered connections may not place calls (see `Policy`)
        if caller.assignment == AddressAssignment::Static && !self.policy.allow_calls_from_static {
            tracing::debug!("Rejecting ESTABLISH from statically-numbered {caller}");
            Self::send(
                &caller,
                &signalling::Message::Error {
                    id,
                    error: MessageType::NotPermitted,
                },
            );
            self.log_rejected(
                Attempt {
                    caller: &caller,
                    circuit,
                    id,
                },
                || {
                    AtmAddress::try_from(&address[..])
                        .map_or_else(|_| hex(&address), |to| to.to_string())
                },
                None,
                MessageType::NotPermitted,
                RejectedBy::Dslam,
            );
            return;
        }

        // Validate the target address
        let Ok(address) = AtmAddress::try_from(&address[..]) else {
            tracing::debug!("ESTABLISH to unparseable address from {caller}");
            Self::send(
                &caller,
                &signalling::Message::Error {
                    id,
                    error: MessageType::InvalidAddress,
                },
            );
            self.log_rejected(
                Attempt {
                    caller: &caller,
                    circuit,
                    id,
                },
                || hex(&address),
                None,
                MessageType::InvalidAddress,
                RejectedBy::Dslam,
            );
            return;
        };
        if address.is_nonstandard() {
            tracing::debug!("ESTABLISH to non-standard address {address} from {caller}");
            Self::send(
                &caller,
                &signalling::Message::Error {
                    id,
                    error: MessageType::InvalidAddress,
                },
            );
            self.log_rejected(
                Attempt {
                    caller: &caller,
                    circuit,
                    id,
                },
                || address.to_string(),
                None,
                MessageType::InvalidAddress,
                RejectedBy::Dslam,
            );
            return;
        }

        // Validate the requested circuit
        if self.is_reserved(circuit) {
            tracing::debug!("ESTABLISH on reserved circuit {circuit} from {caller}");
            Self::send(
                &caller,
                &signalling::Message::Error {
                    id,
                    error: MessageType::RejectedCircuit,
                },
            );
            self.log_rejected(
                Attempt {
                    caller: &caller,
                    circuit,
                    id,
                },
                || address.to_string(),
                None,
                MessageType::RejectedCircuit,
                RejectedBy::Dslam,
            );
            return;
        }

        // Deal with an existing leg on the requested circuit
        let existing = {
            let circuits = caller.circuits.read().await;
            circuits.get(&circuit).map(|entry| {
                let peer_address = entry.connection.upgrade().map(|peer| peer.local.clone());
                (
                    entry.state,
                    entry.connection.clone(),
                    entry.circuit,
                    peer_address,
                )
            })
        };
        if let Some((state, peer, peer_circuit, peer_address)) = existing {
            // A retransmit is only a retransmit if it targets the *same* address as the
            // in-flight/live call. An ESTABLISH that reuses an ID on an occupied circuit
            // but names a different callee is a new call, so we must drop the old
            // connection and reconnect.
            let same_target = peer_address.as_ref() == Some(&address);
            match state {
                CircuitState::OutgoingPending { local, remote } if local == id && same_target => {
                    // A retransmitted ESTABLISH for a call that is already in progress:
                    // don't create a second transaction, just forward the request again.
                    if let Some(callee) = peer.upgrade() {
                        Self::send(
                            &callee,
                            &signalling::Message::Establish {
                                id: remote,
                                address: caller.local.clone().into(),
                                circuit: peer_circuit,
                            },
                        );
                    }
                    return;
                }
                CircuitState::Connected { local: Some(local) } if local == id && same_target => {
                    // A retransmitted ESTABLISH for a call that is already up: our
                    // ESTABLISHED confirmation was lost or crossed the retransmission.
                    // Confirm again instead of tearing down the live call.
                    Self::send(&caller, &signalling::Message::Established { id });
                    return;
                }
                _ => {
                    // Anything else: the client knows best what it wants its circuit to
                    // be. Wipe the old call (implicit release); this also heals clients
                    // that lost track of their own circuit state.
                    tracing::debug!(
                        "ESTABLISH on occupied circuit {circuit} from {caller}, wiping the existing call"
                    );
                    self.wipe_leg(from, circuit, DownReason::Replaced).await;
                }
            }
        }

        // Resolve the callee
        let callee = self
            .reader
            .get(&address)
            .and_then(|values| values.get_one().cloned());
        let Some(callee) = callee else {
            tracing::debug!("ESTABLISH to unknown address {address} from {caller}");
            Self::send(
                &caller,
                &signalling::Message::Error {
                    id,
                    error: MessageType::Unreachable,
                },
            );
            self.log_rejected(
                Attempt {
                    caller: &caller,
                    circuit,
                    id,
                },
                || address.to_string(),
                None,
                MessageType::Unreachable,
                RejectedBy::Dslam,
            );
            return;
        };
        if !self.connections.contains_key(&callee.id) || callee.outbound.is_closed() {
            tracing::debug!("ESTABLISH to closed connection {callee} from {caller}");
            Self::send(
                &caller,
                &signalling::Message::Error {
                    id,
                    error: MessageType::Unreachable,
                },
            );
            self.log_rejected(
                Attempt {
                    caller: &caller,
                    circuit,
                    id,
                },
                || address.to_string(),
                Some(callee.id),
                MessageType::Unreachable,
                RejectedBy::Dslam,
            );
            return;
        }

        // Dynamically-numbered connections may not be called (see `Policy`).
        if callee.assignment == AddressAssignment::Dynamic && !self.policy.allow_calls_to_dynamic {
            tracing::debug!("Refusing ESTABLISH to dynamically-numbered {callee} from {caller}");
            Self::send(
                &caller,
                &signalling::Message::Error {
                    id,
                    error: MessageType::Unreachable, // Pretend this address does not exist
                },
            );
            self.log_rejected(
                Attempt {
                    caller: &caller,
                    circuit,
                    id,
                },
                || address.to_string(),
                Some(callee.id),
                MessageType::Unreachable,
                RejectedBy::Dslam,
            );
            return;
        }

        // Allocate a circuit on the callee leg and reserve it. Counting and allocation
        // happen under the *read* lock to keep the callee's data path unblocked; since
        // the switchboard is the only writer, nothing can change the table before the
        // insertion below.
        // For hairpin calls (the caller dials its own number), the callee map *is* the
        // caller map, so additionally keep the requested circuit out of the allocation.
        let remote_id = callee.counter.fetch_add(1, Ordering::Relaxed);
        let callee_circuit = {
            let circuits = callee.circuits.read().await;
            // The reserve is the callee's last few circuits: only the checker
            // may take them, so contention costs a team its attack surface
            // rather than its score.
            let limit = if caller.reserved {
                MAX_INCOMING_CIRCUITS_PER_CONNECTION
            } else {
                MAX_INCOMING_CIRCUITS_PER_CONNECTION.saturating_sub(self.policy.checker_reserve)
            };
            // The caller's own allowance first: it is the one refusal it can do
            // something about, and saying "congested" would send it back to wait
            // for room that is already there.
            if circuits.incoming_from(caller.source) >= MAX_INCOMING_CIRCUITS_PER_SOURCE {
                Err(MessageType::QuotaExceeded)
            } else if circuits.incoming() >= limit {
                Err(MessageType::Congested)
            } else {
                let exclude = (callee.id == from).then_some(circuit);
                self.allocate_circuit(&circuits, exclude)
                    .ok_or(MessageType::Congested)
            }
        };
        let callee_circuit = match callee_circuit {
            Ok(callee_circuit) => callee_circuit,
            Err(error) => {
                tracing::debug!("Refusing ESTABLISH from {caller} to {callee}: {error}");
                Self::send(&caller, &signalling::Message::Error { id, error });
                self.log_rejected(
                    Attempt {
                        caller: &caller,
                        circuit,
                        id,
                    },
                    || address.to_string(),
                    Some(callee.id),
                    error,
                    RejectedBy::Dslam,
                );
                return;
            }
        };

        // Both legs carry the same call ID, so the debug log can tie a victim's
        // circuit to the caller's without re-deriving it from circuit numbers
        // that get reused
        self.next_call += 1;
        self.calls_total += 1;
        let call = self.next_call;
        caller.calls_placed.fetch_add(1, Ordering::Relaxed);
        callee.calls_received.fetch_add(1, Ordering::Relaxed);

        // Reserve the callee leg
        callee.circuits.write().await.insert(
            callee_circuit,
            CircuitEntry {
                state: CircuitState::IncomingPending {
                    local: id,
                    remote: remote_id,
                },
                direction: LegDirection::Incoming,
                connection: Arc::downgrade(&caller),
                circuit,
                source: caller.source,
                established_at: Instant::now(),
                call: Some(call),
                cells: AtomicU64::new(0),
                cells_queue_full: AtomicU64::new(0),
            },
        );

        // Reserve the caller leg
        caller.circuits.write().await.insert(
            circuit,
            CircuitEntry {
                state: CircuitState::OutgoingPending {
                    local: id,
                    remote: remote_id,
                },
                direction: LegDirection::Outgoing,
                connection: Arc::downgrade(&callee),
                circuit: callee_circuit,
                source: callee.source,
                established_at: Instant::now(),
                call: Some(call),
                cells: AtomicU64::new(0),
                cells_queue_full: AtomicU64::new(0),
            },
        );

        // Track the transaction and forward the ESTABLISH. The address field carries the
        // caller's address. In the default config, this is a dynamically allocated address,
        // so this takes care of traffic anonymization for us.
        let timer = self
            .timers
            .insert((callee.id, remote_id), ESTABLISH_RETRANSMIT);
        if let Some(displaced) = self.insert_pending(
            (callee.id, remote_id),
            Pending {
                kind: PendingKind::Establish {
                    caller: from,
                    caller_circuit: circuit,
                    caller_id: id,
                    callee_circuit,
                    retries_left: ESTABLISH_RETRIES,
                },
                timer,
            },
        ) {
            // Should never happen (IDs are per-connection and monotonic), but if it did,
            // cancel the displaced transaction's timer so it cannot keep firing.
            self.timers.try_remove(&displaced.timer);
            tracing::error!("Duplicate pending transaction {remote_id} for {callee}");
        }
        Self::send(
            &callee,
            &signalling::Message::Establish {
                id: remote_id,
                address: caller.local.clone().into(),
                circuit: callee_circuit,
            },
        );
        tracing::info!("Call setup from {caller} ({circuit}) to {callee} ({callee_circuit})");

        // What undoes the two things that hide a caller: the DSLAM's own
        // circuit translation, and the anonymous number the callee is shown
        self.log.record(|| Record::CallSetup {
            call,
            caller_conn: caller.id,
            caller_ip: caller.remote.ip(),
            caller_vpi: circuit.vpi,
            caller_vci: circuit.vci,
            caller_id: id,
            callee_conn: callee.id,
            callee_ip: callee.remote.ip(),
            callee_vpi: callee_circuit.vpi,
            callee_vci: callee_circuit.vci,
            callee_id: remote_id,
            dialled: address.to_string(),
            presented: caller.local.to_string(),
        });
    }

    /// Records a call that never came up. The dialled number is built only when
    /// a log is being written.
    fn log_rejected(
        &mut self,
        attempt: Attempt,
        dialled: impl FnOnce() -> String,
        callee_conn: Option<ConnectionId>,
        error: MessageType,
        by: RejectedBy,
    ) {
        self.calls_rejected_total += 1;
        self.log.record(|| Record::CallRejected {
            call: None,
            caller_conn: attempt.caller.id,
            caller_vpi: attempt.circuit.vpi,
            caller_vci: attempt.circuit.vci,
            caller_id: attempt.id,
            dialled: dialled(),
            callee_conn,
            error: error.to_string(),
            by,
        });
    }

    /// Handles an ESTABLISHED from a client (the callee accepting a forwarded ESTABLISH)
    async fn handle_established(&mut self, from: ConnectionId, id: u32) {
        let key = (from, id);
        let Some(pending) = self.get_pending(key) else {
            tracing::debug!("Ignoring ESTABLISHED with unknown ID {id} from connection {from}");
            return;
        };
        let PendingKind::Establish {
            caller,
            caller_circuit,
            caller_id,
            callee_circuit,
            ..
        } = pending.kind
        else {
            // An ESTABLISHED never completes a RELEASE transaction
            tracing::debug!(
                "Ignoring ESTABLISHED matching a pending RELEASE (ID {id}) from connection {from}"
            );
            return;
        };
        let pending = self.take_pending(key).expect("checked above");
        self.timers.try_remove(&pending.timer);

        // Flip the callee leg
        let callee = self.connection(from);
        if let Some(callee) = &callee {
            let mut circuits = callee.circuits.write().await;
            let matched = matches!(
                circuits.get(&callee_circuit).map(|entry| entry.state),
                Some(CircuitState::IncomingPending { remote, .. }) if remote == id
            );
            if matched {
                // The callee never sent an ESTABLISH of its own, so there is no
                // client-issued ID to remember on this leg
                circuits.set_state(&callee_circuit, CircuitState::Connected { local: None });
            } else {
                tracing::warn!("Callee leg for transaction {id} on {callee} disappeared");
            }
        }

        // Flip the caller leg and confirm the call
        let Some(caller_connection) = self.connection(caller) else {
            // The caller vanished mid-setup. `Closed` should already have cancelled this
            // transaction, but if the callee leg still exists, tear it down again.
            if let Some(callee) = callee {
                self.begin_release(&callee, callee_circuit, DownReason::PeerGone)
                    .await;
            }
            return;
        };
        {
            let mut circuits = caller_connection.circuits.write().await;
            // Remember the caller's own ESTABLISH ID so a retransmission (after a lost
            // ESTABLISHED) is re-confirmed instead of wiping the call.
            let local = match circuits.get(&caller_circuit).map(|entry| entry.state) {
                Some(CircuitState::OutgoingPending { local, remote }) if remote == id => {
                    Some(local)
                }
                _ => None,
            };
            if let Some(local) = local {
                circuits.set_state(
                    &caller_circuit,
                    CircuitState::Connected { local: Some(local) },
                );
            } else {
                tracing::warn!(
                    "Caller leg for transaction {id} on {caller_connection} disappeared"
                );
            }
        }
        Self::send(
            &caller_connection,
            &signalling::Message::Established { id: caller_id },
        );
        tracing::info!(
            "Call established between {caller_connection} ({caller_circuit}) and connection {from} ({callee_circuit})"
        );
        if let Some(call) = Self::call_of(&caller_connection, caller_circuit).await {
            self.log.record(|| Record::CallUp {
                call,
                caller_conn: caller,
                callee_conn: from,
            });
        }
    }

    /// The call a leg belongs to, for the records that only have the leg
    async fn call_of(connection: &Connection, circuit: VirtualCircuit) -> Option<u64> {
        connection
            .circuits
            .read()
            .await
            .get(&circuit)
            .and_then(|entry| entry.call)
    }

    /// Handles an error response from a client (e.g. the callee rejecting a call)
    async fn handle_client_error(&mut self, from: ConnectionId, id: u32, error: MessageType) {
        let key = (from, id);
        let Some(pending) = self.get_pending(key) else {
            tracing::debug!("Ignoring {error} with unknown ID {id} from connection {from}");
            return;
        };
        let PendingKind::Establish {
            caller,
            caller_circuit,
            caller_id,
            callee_circuit,
            ..
        } = pending.kind
        else {
            // Errors never complete a RELEASE; we keep retransmitting until RELEASED
            // or the retry limit.
            tracing::debug!(
                "Ignoring {error} matching a pending RELEASE (ID {id}) from connection {from}"
            );
            return;
        };
        let pending = self.take_pending(key).expect("checked above");
        self.timers.try_remove(&pending.timer);

        // Remove the callee leg
        let dialled = match self.connection(from) {
            Some(callee) => {
                Self::remove_leg_if(
                    &self.log,
                    &callee,
                    callee_circuit,
                    DownReason::Rejected,
                    |state| {
                        matches!(state, CircuitState::IncomingPending { remote, .. } if *remote == id)
                    },
                )
                .await;
                callee.local.to_string()
            }
            None => String::new(),
        };

        // Remove the caller leg and pass the rejection on
        if let Some(caller_connection) = self.connection(caller) {
            Self::remove_leg_if(
                &self.log,
                &caller_connection,
                caller_circuit,
                DownReason::Rejected,
                |state| {
                    matches!(state, CircuitState::OutgoingPending { remote, .. } if *remote == id)
                },
            )
            .await;
            Self::send(
                &caller_connection,
                &signalling::Message::Error {
                    id: caller_id,
                    error: Self::relayable_error(error),
                },
            );
            self.log_rejected(
                Attempt {
                    caller: &caller_connection,
                    circuit: caller_circuit,
                    id: caller_id,
                },
                || dialled,
                Some(from),
                error,
                RejectedBy::Callee,
            );
        }
    }

    /// Clamps a callee's rejection to what a callee may report, so a client
    /// cannot fake a DSLAM error.
    fn relayable_error(error: MessageType) -> MessageType {
        match error {
            MessageType::GenericError | MessageType::RejectedCircuit => error,
            _ => MessageType::GenericError,
        }
    }

    /// Handles a RELEASE from a client
    async fn handle_release(&mut self, from: ConnectionId, id: u32, circuit: VirtualCircuit) {
        // Reserved circuits (signalling, ILMI, the testing mirror) are never client-
        // releasable; refuse them like ESTABLISH does instead of confirming a release
        // that did not happen.
        if self.is_reserved(circuit) {
            if let Some(connection) = self.connection(from) {
                tracing::debug!("RELEASE for reserved circuit {circuit} from {connection}");
                Self::send(
                    &connection,
                    &signalling::Message::Error {
                        id,
                        error: MessageType::RejectedCircuit,
                    },
                );
            }
            return;
        }
        self.wipe_leg(from, circuit, DownReason::Release).await;
        // Always confirm, even for unknown circuits: RELEASE must be idempotent so that
        // client retransmissions and crossing releases always terminate.
        if let Some(connection) = self.connection(from) {
            Self::send(&connection, &signalling::Message::Released { id });
        }
    }

    /// Handles a RELEASED from a client
    async fn handle_released(&mut self, from: ConnectionId, id: u32) {
        let key = (from, id);
        match self.get_pending(key) {
            Some(Pending {
                kind: PendingKind::Release { circuit, .. },
                ..
            }) => {
                let circuit = *circuit;
                let pending = self.take_pending(key).expect("checked above");
                self.timers.try_remove(&pending.timer);
                if let Some(connection) = self.connection(from) {
                    Self::remove_leg_if(
                        &self.log,
                        &connection,
                        circuit,
                        DownReason::Release,
                        |state| {
                            matches!(state, CircuitState::DisconnectionPending { remote } if *remote == id)
                        },
                    )
                    .await;
                }
            }
            Some(_) => {
                // A RELEASED never completes an ESTABLISH transaction
                tracing::debug!(
                    "Ignoring RELEASED matching a pending ESTABLISH (ID {id}) from connection {from}"
                );
            }
            None => {
                // Expected after crossing releases and duplicate retransmissions
                tracing::debug!("Ignoring RELEASED with unknown ID {id} from connection {from}");
            }
        }
    }

    /// Handles a data-path notification that the peer of a circuit went away
    async fn handle_peer_gone(&mut self, on: ConnectionId, circuit: VirtualCircuit) {
        let Some(connection) = self.connection(on) else {
            return;
        };
        // Only act if the leg exists, is connected, and the peer really is gone
        // (the notification may have raced a re-establishment of the circuit).
        let peer_gone = {
            let circuits = connection.circuits.read().await;
            match circuits.get(&circuit) {
                Some(entry) if matches!(entry.state, CircuitState::Connected { .. }) => {
                    match entry.connection.upgrade() {
                        Some(peer) => {
                            peer.outbound.is_closed() || !self.connections.contains_key(&peer.id)
                        }
                        None => true,
                    }
                }
                // Pending legs are handled by their own timers and Closed events
                _ => false,
            }
        };
        if peer_gone {
            tracing::debug!("Peer of circuit {circuit} on {connection} is gone, releasing");
            self.begin_release(&connection, circuit, DownReason::PeerGone)
                .await;
        }
    }

    /// Handles a connection shutdown
    async fn handle_closed(&mut self, id: ConnectionId) {
        let Some(connection) = self.connections.remove(&id) else {
            return;
        };
        tracing::info!("Cleaning up after connection {connection}");
        let mut successor_id = None;

        // Unpublish the address, unless a newer connection has already taken it over
        // (a subscriber with a fixed number reconnecting before the old TCP connection
        // was torn down). The server releases dynamically assigned numbers itself.
        let current = self
            .reader
            .get(&connection.local)
            .and_then(|values| values.get_one().map(|current| current.id));
        if current == Some(id) {
            // Every connection from a subscriber's address is given its fixed number,
            // so another one may still be holding this one. Hand the number to it
            // rather than dropping it, which would leave the subscriber uncallable
            // until it reconnects on its own. Random numbers are drawn uniquely, so
            // only a fixed one can have a successor.
            let successor = if connection.assignment == AddressAssignment::Static {
                self.connections
                    .values()
                    .filter(|other| other.local == connection.local)
                    .max_by_key(|other| other.id)
                    .cloned()
            } else {
                None
            };
            match successor {
                Some(successor) => {
                    tracing::info!("Handing {} back to {successor}", connection.local);
                    successor_id = Some(successor.id);
                    self.writer.update(connection.local.clone(), successor);
                }
                None => {
                    self.writer.remove_entry(connection.local.clone());
                }
            }
            self.writer.publish();
        }

        // Unwind every leg of this connection. The connection died, so a caller still
        // ringing one of its legs is told the number is unreachable.
        let legs = std::mem::take(&mut *connection.circuits.write().await);
        for (circuit, entry) in legs.into_entries() {
            log_down(&self.log, id, circuit, &entry, DownReason::ConnectionClosed);
            self.tear_down_leg(
                id,
                entry,
                MessageType::Unreachable,
                DownReason::ConnectionClosed,
            )
            .await;
        }

        // Reported once its calls have been, so that the records read in the
        // order things actually happened
        self.log.record(|| Record::ConnectionClosed {
            conn: id,
            seconds: seconds_since(connection.opened),
            // Calls it set up or was offered, counted as the ESTABLISH was
            // forwarded rather than when the call came up
            calls_placed: connection.calls_placed.load(Ordering::Relaxed),
            calls_received: connection.calls_received.load(Ordering::Relaxed),
            successor_conn: successor_id,
        });

        // Drop any transactions that are still running on this connection.
        // There _should_ be none of them left (anything we started should have been
        // torn down above), but make sure.
        if let Some(bucket) = self.pending.remove(&id) {
            for (transaction_id, pending) in bucket {
                tracing::warn!("Dropping stale transaction {transaction_id} on connection {id}");
                self.timers.try_remove(&pending.timer);
            }
        }
    }

    /// Handles an expired transaction timer
    async fn handle_timer(&mut self, key: (ConnectionId, u32)) {
        let (connection_id, transaction_id) = key;
        let Some(pending) = self.get_pending(key) else {
            return; // Cancelled in the meantime
        };
        match pending.kind {
            PendingKind::Establish {
                caller,
                caller_circuit,
                caller_id,
                callee_circuit,
                retries_left,
            } => {
                if retries_left > 0 {
                    // Retransmit the forwarded ESTABLISH
                    let timer = self.timers.insert(key, ESTABLISH_RETRANSMIT);
                    let pending = self.get_pending_mut(key).expect("checked above");
                    pending.timer = timer;
                    if let PendingKind::Establish { retries_left, .. } = &mut pending.kind {
                        *retries_left -= 1;
                    }
                    if let (Some(callee), Some(caller_connection)) =
                        (self.connection(connection_id), self.connection(caller))
                    {
                        Self::send(
                            &callee,
                            &signalling::Message::Establish {
                                id: transaction_id,
                                address: caller_connection.local.clone().into(),
                                circuit: callee_circuit,
                            },
                        );
                    }
                } else {
                    // The callee never answered
                    self.take_pending(key);
                    tracing::debug!(
                        "Call setup {transaction_id} on connection {connection_id} timed out"
                    );
                    let dialled = match self.connection(connection_id) {
                        Some(callee) => {
                            // The callee may have accepted into the void (its ESTABLISHED
                            // may be in flight or lost); make sure it lets the circuit go.
                            self.begin_release(&callee, callee_circuit, DownReason::SetupTimeout)
                                .await;
                            callee.local.to_string()
                        }
                        None => String::new(),
                    };
                    if let Some(caller_connection) = self.connection(caller) {
                        Self::remove_leg_if(
                            &self.log,
                            &caller_connection,
                            caller_circuit,
                            DownReason::SetupTimeout,
                            |state| {
                                matches!(
                                    state,
                                    CircuitState::OutgoingPending { remote, .. } if *remote == transaction_id
                                )
                            },
                        )
                        .await;
                        Self::send(
                            &caller_connection,
                            &signalling::Message::Error {
                                id: caller_id,
                                error: MessageType::Unreachable,
                            },
                        );
                        self.log_rejected(
                            Attempt {
                                caller: &caller_connection,
                                circuit: caller_circuit,
                                id: caller_id,
                            },
                            || dialled,
                            Some(connection_id),
                            MessageType::Unreachable,
                            RejectedBy::Timeout,
                        );
                    }
                }
            }
            PendingKind::Release {
                circuit,
                retries_left,
            } => {
                if retries_left > 0 {
                    // Retransmit the RELEASE
                    let timer = self.timers.insert(key, RELEASE_RETRANSMIT);
                    let pending = self.get_pending_mut(key).expect("checked above");
                    pending.timer = timer;
                    if let PendingKind::Release { retries_left, .. } = &mut pending.kind {
                        *retries_left -= 1;
                    }
                    if let Some(connection) = self.connection(connection_id) {
                        Self::send(
                            &connection,
                            &signalling::Message::Release {
                                id: transaction_id,
                                circuit,
                            },
                        );
                    }
                } else {
                    // Give up and drop the circuit unilaterally.
                    self.take_pending(key);
                    tracing::debug!(
                        "Giving up on RELEASE {transaction_id} on connection {connection_id}"
                    );
                    if let Some(connection) = self.connection(connection_id) {
                        Self::remove_leg_if(
                            &self.log,
                            &connection,
                            circuit,
                            DownReason::ReleaseTimeout,
                            |state| {
                                matches!(
                                    state,
                                    CircuitState::DisconnectionPending { remote } if *remote == transaction_id
                                )
                            },
                        )
                        .await;
                    }
                }
            }
        }
    }

    /// Removes a leg and unwinds whatever call state is attached to it, if that leg exists.
    async fn wipe_leg(&mut self, on: ConnectionId, circuit: VirtualCircuit, reason: DownReason) {
        let Some(connection) = self.connection(on) else {
            return;
        };
        let entry = connection.circuits.write().await.remove(&circuit);
        if let Some(entry) = entry {
            log_down(&self.log, on, circuit, &entry, reason);
            // The circuit went away on purpose, so a caller still ringing it is refused
            self.tear_down_leg(on, entry, MessageType::RejectedCircuit, reason)
                .await;
        }
    }

    /// Unwinds the call state attached to a leg that was just removed from connection
    /// `on`'s table. Cancels any pending transactions and releases or notifies the peer
    /// with the given `rejection` reason.
    async fn tear_down_leg(
        &mut self,
        on: ConnectionId,
        entry: CircuitEntry,
        rejection: MessageType,
        reason: DownReason,
    ) {
        let peer = entry
            .connection
            .upgrade()
            .filter(|peer| self.connections.contains_key(&peer.id));
        match entry.state {
            CircuitState::Connected { .. } => {
                // Tear down the peer's half of the call
                if let Some(peer) = peer {
                    self.begin_release(&peer, entry.circuit, reason).await;
                }
            }
            CircuitState::OutgoingPending { remote, .. } => {
                // The leg's owner was calling and aborts the call attempt. The callee
                // may already have accepted (its ESTABLISHED may be in flight), so
                // abort the transaction _and_ release the callee leg explicitly.
                if let Some(callee) = peer {
                    self.cancel_pending(callee.id, remote);
                    self.begin_release(&callee, entry.circuit, reason).await;
                }
            }
            CircuitState::IncomingPending { local, remote } => {
                // The leg's owner was being called, and the offered circuit is gone
                // before it answered: the call attempt fails.
                self.cancel_pending(on, remote);
                if let Some(caller) = peer {
                    Self::remove_leg_if(&self.log, &caller, entry.circuit, reason, |state| {
                        matches!(
                            state,
                            CircuitState::OutgoingPending { remote: r, .. } if *r == remote
                        )
                    })
                    .await;
                    Self::send(
                        &caller,
                        &signalling::Message::Error {
                            id: local,
                            error: rejection,
                        },
                    );
                }
            }
            CircuitState::DisconnectionPending { remote } => {
                // We were already tearing this down (e.g. a crossing release, where the
                // client's own RELEASE overtook our RELEASED). Complete the transaction.
                self.cancel_pending(on, remote);
            }
        }
    }

    /// Starts tearing down a circuit towards a client.
    /// The leg is replaced with a `DisconnectionPending` entry.
    /// This triggers sending of a RELEASE to that client.
    async fn begin_release(
        &mut self,
        target: &Arc<Connection>,
        circuit: VirtualCircuit,
        reason: DownReason,
    ) {
        let mut circuits = target.circuits.write().await;
        if matches!(
            circuits.get(&circuit).map(|entry| &entry.state),
            Some(CircuitState::DisconnectionPending { .. })
        ) {
            // A release handshake for this leg is already running.
            return;
        }

        // Accounting for disconnecting legs.
        let releasing = circuits.releasing();
        let remote_id = target.counter.fetch_add(1, Ordering::Relaxed);
        if releasing >= MAX_RELEASING_PER_CONNECTION {
            let dropped = circuits.remove(&circuit);
            drop(circuits);
            if let Some(dropped) = &dropped {
                log_down(&self.log, target.id, circuit, dropped, reason);
            }
            tracing::debug!(
                "Too many releases in flight towards {target}, dropping {circuit} unilaterally"
            );
            Self::send(
                target,
                &signalling::Message::Release {
                    id: remote_id,
                    circuit,
                },
            );
            return;
        }

        // Keep the direction of the leg being torn down for informational reasons only
        let direction = circuits
            .get(&circuit)
            .map(|entry| entry.direction)
            .unwrap_or(LegDirection::Incoming);
        let displaced = circuits.insert(
            circuit,
            CircuitEntry {
                state: CircuitState::DisconnectionPending { remote: remote_id },
                direction,
                connection: Weak::new(), // The peer is gone
                circuit,
                source: target.source, // Meaningless for a releasing leg
                established_at: Instant::now(),
                // A leg mid-release carries no call any more; the one it did
                // carry is reported as it is displaced
                call: None,
                cells: AtomicU64::new(0),
                cells_queue_full: AtomicU64::new(0),
            },
        );
        drop(circuits);
        if let Some(displaced) = &displaced {
            log_down(&self.log, target.id, circuit, displaced, reason);
        }

        let timer = self
            .timers
            .insert((target.id, remote_id), RELEASE_RETRANSMIT);
        if let Some(displaced) = self.insert_pending(
            (target.id, remote_id),
            Pending {
                kind: PendingKind::Release {
                    circuit,
                    retries_left: RELEASE_RETRIES,
                },
                timer,
            },
        ) {
            // Should never happen, but if it did, cancel the displaced transaction's
            // timer so it cannot keep retransmitting a stale RELEASE.
            self.timers.try_remove(&displaced.timer);
            tracing::error!("Duplicate pending transaction {remote_id} for {target}");
        }
        Self::send(
            target,
            &signalling::Message::Release {
                id: remote_id,
                circuit,
            },
        );
    }

    /// Looks up a pending transaction
    fn get_pending(&self, key: (ConnectionId, u32)) -> Option<&Pending> {
        self.pending.get(&key.0)?.get(&key.1)
    }

    /// Looks up a pending transaction for modification
    fn get_pending_mut(&mut self, key: (ConnectionId, u32)) -> Option<&mut Pending> {
        self.pending.get_mut(&key.0)?.get_mut(&key.1)
    }

    /// Tracks a pending transaction, returning any transaction it displaced
    fn insert_pending(&mut self, key: (ConnectionId, u32), pending: Pending) -> Option<Pending> {
        self.pending
            .entry(key.0)
            .or_default()
            .insert(key.1, pending)
    }

    /// Removes a pending transaction, leaving no empty per-connection buckets behind
    fn take_pending(&mut self, key: (ConnectionId, u32)) -> Option<Pending> {
        let bucket = self.pending.get_mut(&key.0)?;
        let pending = bucket.remove(&key.1);
        if bucket.is_empty() {
            self.pending.remove(&key.0);
        }
        pending
    }

    /// Cancels a pending transaction and its timer, if it exists
    fn cancel_pending(&mut self, connection: ConnectionId, id: u32) {
        if let Some(pending) = self.take_pending((connection, id)) {
            self.timers.try_remove(&pending.timer);
        }
    }

    /// Removes a leg if its state still matches the given predicate
    async fn remove_leg_if(
        log: &Log,
        connection: &Connection,
        circuit: VirtualCircuit,
        reason: DownReason,
        predicate: impl Fn(&CircuitState) -> bool,
    ) {
        let mut circuits = connection.circuits.write().await;
        let matches = circuits
            .get(&circuit)
            .is_some_and(|entry| predicate(&entry.state));
        if matches && let Some(entry) = circuits.remove(&circuit) {
            log_down(log, connection.id, circuit, &entry, reason);
        }
    }
}

/// Reports a leg that stopped carrying traffic. A leg with no call behind it --
/// the testing mirror, or one already mid-release -- has nothing to report, and
/// both legs of a call report separately, so a call may produce two records.
fn log_down(
    log: &Log,
    conn: ConnectionId,
    circuit: VirtualCircuit,
    entry: &CircuitEntry,
    reason: DownReason,
) {
    let Some(call) = entry.call else {
        return;
    };
    log.record(|| Record::CallDown {
        call,
        conn,
        vpi: circuit.vpi,
        vci: circuit.vci,
        direction: entry.direction.into(),
        reason,
        seconds: seconds_since(entry.established_at),
        cells: entry.cells.load(Ordering::Relaxed),
        cells_queue_full: entry.cells_queue_full.load(Ordering::Relaxed),
    });
}

/// An address that could not be parsed, as the log spells it
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02X}");
        text
    })
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use crate::connection::SourceKey;
    use atm::AtmCell;
    use atm::aal5::{Pdu, Reassembler};
    use tokio::sync::mpsc::{self, error::TryRecvError};

    use super::*;

    struct Harness {
        control: mpsc::Sender<Event>,
        events: mpsc::Sender<Event>,
    }

    struct TestClient {
        connection: Arc<Connection>,
        outbound: mpsc::Receiver<AtmCell>,
    }

    fn harness() -> Harness {
        harness_with(open_policy())
    }

    /// Most tests exercise the call mechanics themselves; run them without the
    /// exhaustion policy so any client can both place and receive calls.
    fn open_policy() -> Policy {
        Policy {
            allow_calls_to_dynamic: true,
            allow_calls_from_static: true,
            checker_reserve: 0,
        }
    }

    fn harness_with(policy: Policy) -> Harness {
        harness_full(policy, None)
    }

    fn harness_full(policy: Policy, mirror_circuit: Option<VirtualCircuit>) -> Harness {
        harness_logging(policy, mirror_circuit, Log::disabled())
    }

    fn harness_logging(
        policy: Policy,
        mirror_circuit: Option<VirtualCircuit>,
        log: Log,
    ) -> Harness {
        // SAFETY: Hash and Eq are deterministic for both the key and value types, even
        // across clones (same as the production map in main.rs).
        let (writer, reader) = unsafe { evmap::new_assert_stable() };
        let (control, control_queue) = mpsc::channel(CONTROL_QUEUE_SIZE);
        let (events, event_queue) = mpsc::channel(EVENT_QUEUE_SIZE);
        let switchboard = Switchboard::new(
            control_queue,
            event_queue,
            writer,
            reader,
            mirror_circuit,
            policy,
            log,
        );
        tokio::spawn(switchboard.run(CancellationToken::new()));
        Harness { control, events }
    }

    impl Harness {
        async fn client(&self, id: ConnectionId, number: &str) -> TestClient {
            self.client_with(id, number, AddressAssignment::Dynamic)
                .await
        }

        async fn client_with(
            &self,
            id: ConnectionId,
            number: &str,
            assignment: AddressAssignment,
        ) -> TestClient {
            // Counted on its own, like anything that is not a subscriber
            self.client_from(id, number, assignment, SourceKey::Connection(id), false)
                .await
        }

        async fn client_from(
            &self,
            id: ConnectionId,
            number: &str,
            assignment: AddressAssignment,
            source: SourceKey,
            reserved: bool,
        ) -> TestClient {
            let address = AtmAddress::new(number.parse().expect("valid test number"));
            let (outbound_tx, outbound) = mpsc::channel(64);
            let remote: SocketAddr = format!("127.0.0.1:{}", 40000 + id)
                .parse()
                .expect("valid test socket address");
            let connection = Connection::new(
                id,
                remote,
                "127.0.0.1:9000".parse().expect("valid test endpoint"),
                address,
                assignment,
                source,
                reserved,
                outbound_tx,
            );
            self.control
                .send(Event::Register {
                    connection: connection.clone(),
                })
                .await
                .expect("switchboard is running");
            TestClient {
                connection,
                outbound,
            }
        }

        async fn send(&self, client: &TestClient, message: signalling::Message) {
            self.events
                .send(Event::Message {
                    from: client.connection.id,
                    message,
                })
                .await
                .expect("switchboard is running");
        }

        async fn close(&self, client: &TestClient) {
            self.close_connection(client.connection.id).await;
        }

        async fn close_connection(&self, connection: ConnectionId) {
            self.control
                .send(Event::Closed { connection })
                .await
                .expect("switchboard is running");
        }

        async fn peer_gone(&self, on: ConnectionId, circuit: VirtualCircuit) {
            self.events
                .send(Event::PeerGone { on, circuit })
                .await
                .expect("switchboard is running");
        }

        /// Waits until the switchboard has processed all queued events.
        /// With paused time, the sleep only completes once the runtime is idle.
        async fn settle(&self) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    impl TestClient {
        fn address_field(&self) -> signalling::E191AddressField {
            self.connection.local.clone().into()
        }

        /// Receives and decodes the next signalling message sent to this client
        async fn recv(&mut self) -> signalling::Message {
            let mut reassembler = Reassembler::new();
            loop {
                let cell = self.outbound.recv().await.expect("outbound queue closed");
                assert!(cell.header().circuit().is_signalling());
                match reassembler.reassemble(&cell) {
                    None => continue,
                    Some(Pdu::Reassembled(pdu)) => {
                        return (&pdu.data[..])
                            .try_into()
                            .expect("valid signalling message");
                    }
                    Some(_) => panic!("unexpected PDU on the signalling circuit"),
                }
            }
        }

        fn assert_idle(&mut self) {
            assert!(
                matches!(self.outbound.try_recv(), Err(TryRecvError::Empty)),
                "expected no pending messages"
            );
        }

        async fn circuit_count(&self) -> usize {
            self.connection.circuits.read().await.len()
        }
    }

    /// Establishes a call and returns the circuit allocated on the callee side
    async fn connect(
        harness: &Harness,
        caller: &mut TestClient,
        callee: &mut TestClient,
        circuit: VirtualCircuit,
        id: u32,
    ) -> VirtualCircuit {
        harness
            .send(
                caller,
                signalling::Message::Establish {
                    id,
                    address: callee.address_field(),
                    circuit,
                },
            )
            .await;
        let forwarded = callee.recv().await;
        let signalling::Message::Establish {
            id: remote,
            circuit: callee_circuit,
            ..
        } = forwarded
        else {
            panic!("expected forwarded ESTABLISH, got {forwarded:?}");
        };
        harness
            .send(callee, signalling::Message::Established { id: remote })
            .await;
        assert_eq!(caller.recv().await, signalling::Message::Established { id });
        callee_circuit
    }

    /// A call from setup to teardown, as the debug log records it. This is the
    /// contract the correlation and statistics tooling reads, so the fields are
    /// checked by name rather than by shape.
    #[tokio::test]
    async fn a_call_is_logged_from_setup_to_teardown() {
        use crate::debug_log::{
            Writer,
            testing::{directory, of_kind, records, settings, start},
        };

        let directory = directory("switchboard");
        let (log, writer) = Writer::create(&directory, settings(), start())
            .await
            .expect("opens the log");
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(writer.run(shutdown.clone()));

        let harness = harness_logging(open_policy(), None, log);
        let mut alice = harness.client(1, "+49111111").await;
        let mut bob = harness.client(2, "+49222222").await;
        let circuit = VirtualCircuit { vpi: 1, vci: 100 };
        let callee_circuit = connect(&harness, &mut alice, &mut bob, circuit, 7).await;

        // Five cells on the caller's leg, as the forwarding path counts them
        alice
            .connection
            .circuits
            .read()
            .await
            .get(&circuit)
            .expect("the caller's leg")
            .cells
            .fetch_add(5, Ordering::Relaxed);

        // Alice hangs up, which takes Bob's leg down with it
        harness
            .send(&alice, signalling::Message::Release { id: 8, circuit })
            .await;
        assert_eq!(alice.recv().await, signalling::Message::Released { id: 8 });
        let signalling::Message::Release {
            id,
            circuit: released,
        } = bob.recv().await
        else {
            panic!("expected Bob to be released");
        };
        assert_eq!(released, callee_circuit);
        harness
            .send(&bob, signalling::Message::Released { id })
            .await;

        // A round trip through the same event queue, so that everything above
        // has been handled before the log is read
        harness
            .send(
                &alice,
                signalling::Message::Release {
                    id: 9,
                    circuit: VirtualCircuit { vpi: 7, vci: 77 },
                },
            )
            .await;
        assert_eq!(alice.recv().await, signalling::Message::Released { id: 9 });

        shutdown.cancel();
        task.await.expect("the writer finishes");
        let records = records(&directory);

        let [setup] = of_kind(&records, "call-setup")[..] else {
            panic!("expected one call setup in {records:#?}");
        };
        let call = setup["call"].as_u64().expect("a call ID");
        assert_eq!(setup["caller_conn"], 1);
        assert_eq!(setup["caller_vpi"], circuit.vpi);
        assert_eq!(setup["caller_vci"], circuit.vci);
        assert_eq!(setup["caller_id"], 7);
        assert_eq!(setup["callee_conn"], 2);
        assert_eq!(setup["callee_vpi"], callee_circuit.vpi);
        assert_eq!(setup["callee_vci"], callee_circuit.vci);
        // What the callee was dialled on, and the number it was shown instead
        // of the caller's own
        assert_eq!(setup["dialled"], "+49222222");
        assert_eq!(setup["presented"], "+49111111");

        let [up] = of_kind(&records, "call-up")[..] else {
            panic!("expected one call to come up in {records:#?}");
        };
        assert_eq!(up["call"].as_u64(), Some(call));

        // Both legs report, with the cells each of them put into the call
        let down = of_kind(&records, "call-down");
        assert_eq!(down.len(), 2, "expected both legs in {records:#?}");
        assert!(down.iter().all(|leg| leg["call"].as_u64() == Some(call)));
        let caller = down
            .iter()
            .find(|leg| leg["conn"] == 1)
            .expect("the caller's leg");
        assert_eq!(caller["direction"], "outgoing");
        assert_eq!(caller["reason"], "release");
        assert_eq!(caller["vci"], circuit.vci);
        assert_eq!(caller["cells"], 5);
        let callee = down
            .iter()
            .find(|leg| leg["conn"] == 2)
            .expect("the callee's leg");
        assert_eq!(callee["direction"], "incoming");
        assert_eq!(callee["vci"], callee_circuit.vci);
        assert_eq!(callee["cells"], 0);

        let _ = std::fs::remove_dir_all(&directory);
    }

    /// A call the DSLAM refuses is recorded as one, with the reason it gave
    #[tokio::test]
    async fn a_refused_call_is_logged() {
        use crate::debug_log::{
            Writer,
            testing::{directory, of_kind, records, settings, start},
        };

        let directory = directory("switchboard-refused");
        let (log, writer) = Writer::create(&directory, settings(), start())
            .await
            .expect("opens the log");
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(writer.run(shutdown.clone()));

        let harness = harness_logging(open_policy(), None, log);
        let mut alice = harness.client(1, "+49111111").await;
        let nobody = AtmAddress::new("+49999999".parse().expect("valid test number"));
        harness
            .send(
                &alice,
                signalling::Message::Establish {
                    id: 3,
                    address: nobody.into(),
                    circuit: VirtualCircuit { vpi: 2, vci: 200 },
                },
            )
            .await;
        assert_eq!(
            alice.recv().await,
            signalling::Message::Error {
                id: 3,
                error: MessageType::Unreachable,
            }
        );

        shutdown.cancel();
        task.await.expect("the writer finishes");
        let records = records(&directory);

        let [rejected] = of_kind(&records, "call-rejected")[..] else {
            panic!("expected one rejection in {records:#?}");
        };
        assert_eq!(rejected["caller_conn"], 1);
        assert_eq!(rejected["caller_id"], 3);
        assert_eq!(rejected["caller_vci"], 200);
        assert_eq!(rejected["dialled"], "+49999999");
        assert_eq!(rejected["error"], "UNREACHABLE");
        assert_eq!(rejected["by"], "dslam");
        // Nothing was set up, so there is no call to point at
        assert!(rejected.get("call").is_none());
        assert!(of_kind(&records, "call-setup").is_empty());

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[tokio::test(start_paused = true)]
    async fn establish_happy_path() {
        let harness = harness();
        let mut alice = harness.client(1, "+49111111").await;
        let mut bob = harness.client(2, "+49222222").await;
        let circuit = VirtualCircuit { vpi: 1, vci: 100 };

        harness
            .send(
                &alice,
                signalling::Message::Establish {
                    id: 7,
                    address: bob.address_field(),
                    circuit,
                },
            )
            .await;

        let forwarded = bob.recv().await;
        let signalling::Message::Establish {
            id: remote,
            address,
            circuit: bob_circuit,
        } = forwarded
        else {
            panic!("expected forwarded ESTABLISH, got {forwarded:?}");
        };
        // The forwarded request carries the caller's DSLAM-assigned source address
        assert_eq!(address, alice.address_field());
        assert!(bob_circuit.vci >= MIN_ALLOCATED_VCI);

        harness
            .send(&bob, signalling::Message::Established { id: remote })
            .await;
        assert_eq!(
            alice.recv().await,
            signalling::Message::Established { id: 7 }
        );

        // Both legs are connected and cross-linked
        {
            let circuits = alice.connection.circuits.read().await;
            let leg = circuits.get(&circuit).expect("caller leg exists");
            assert!(matches!(leg.state, CircuitState::Connected { .. }));
            assert_eq!(leg.circuit, bob_circuit);
        }
        {
            let circuits = bob.connection.circuits.read().await;
            let leg = circuits.get(&bob_circuit).expect("callee leg exists");
            assert!(matches!(leg.state, CircuitState::Connected { .. }));
            assert_eq!(leg.circuit, circuit);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn establish_error_responses() {
        let harness = harness();
        let mut alice = harness.client(1, "+49111111").await;
        let circuit = VirtualCircuit { vpi: 1, vci: 100 };

        // Unknown address
        let unknown = AtmAddress::new("+49999999".parse().expect("valid test number"));
        harness
            .send(
                &alice,
                signalling::Message::Establish {
                    id: 1,
                    address: unknown.into(),
                    circuit,
                },
            )
            .await;
        assert_eq!(
            alice.recv().await,
            signalling::Message::Error {
                id: 1,
                error: MessageType::Unreachable
            }
        );

        // Unparseable address
        harness
            .send(
                &alice,
                signalling::Message::Establish {
                    id: 2,
                    address: [0xFF; signalling::E191_ADDRESS_SIZE],
                    circuit,
                },
            )
            .await;
        assert_eq!(
            alice.recv().await,
            signalling::Message::Error {
                id: 2,
                error: MessageType::InvalidAddress
            }
        );

        // Reserved circuit (the signalling channel itself)
        harness
            .send(
                &alice,
                signalling::Message::Establish {
                    id: 3,
                    address: alice.address_field(),
                    circuit: VirtualCircuit { vpi: 0, vci: 5 },
                },
            )
            .await;
        assert_eq!(
            alice.recv().await,
            signalling::Message::Error {
                id: 3,
                error: MessageType::RejectedCircuit
            }
        );

        assert_eq!(alice.circuit_count().await, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn release_is_idempotent() {
        let harness = harness();
        let mut alice = harness.client(1, "+49111111").await;
        let circuit = VirtualCircuit { vpi: 1, vci: 100 };

        // RELEASE for a circuit that was never established is still confirmed
        // (this is what terminates client retransmissions after races)
        for id in [4, 5] {
            harness
                .send(&alice, signalling::Message::Release { id, circuit })
                .await;
            assert_eq!(alice.recv().await, signalling::Message::Released { id });
        }
    }

    #[tokio::test(start_paused = true)]
    async fn release_tears_down_both_legs() {
        let harness = harness();
        let mut alice = harness.client(1, "+49111111").await;
        let mut bob = harness.client(2, "+49222222").await;
        let circuit = VirtualCircuit { vpi: 1, vci: 100 };
        let bob_circuit = connect(&harness, &mut alice, &mut bob, circuit, 7).await;

        harness
            .send(&alice, signalling::Message::Release { id: 9, circuit })
            .await;
        assert_eq!(alice.recv().await, signalling::Message::Released { id: 9 });

        let released = bob.recv().await;
        let signalling::Message::Release {
            id: remote,
            circuit: released_circuit,
        } = released
        else {
            panic!("expected forwarded RELEASE, got {released:?}");
        };
        assert_eq!(released_circuit, bob_circuit);

        assert_eq!(alice.circuit_count().await, 0);
        harness
            .send(&bob, signalling::Message::Released { id: remote })
            .await;
        harness.settle().await;
        assert_eq!(bob.circuit_count().await, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn crossing_releases_terminate() {
        let harness = harness();
        let mut alice = harness.client(1, "+49111111").await;
        let mut bob = harness.client(2, "+49222222").await;
        let circuit = VirtualCircuit { vpi: 1, vci: 100 };
        let bob_circuit = connect(&harness, &mut alice, &mut bob, circuit, 7).await;

        // Alice hangs up...
        harness
            .send(&alice, signalling::Message::Release { id: 10, circuit })
            .await;
        assert_eq!(alice.recv().await, signalling::Message::Released { id: 10 });
        let forwarded = bob.recv().await;
        assert!(matches!(forwarded, signalling::Message::Release { .. }));

        // ...but Bob's own RELEASE crosses our RELEASE instead of confirming it
        harness
            .send(
                &bob,
                signalling::Message::Release {
                    id: 20,
                    circuit: bob_circuit,
                },
            )
            .await;
        assert_eq!(bob.recv().await, signalling::Message::Released { id: 20 });

        harness.settle().await;
        assert_eq!(alice.circuit_count().await, 0);
        assert_eq!(bob.circuit_count().await, 0);

        // The transaction is complete: no RELEASE retransmissions ever fire
        tokio::time::sleep(Duration::from_secs(15)).await;
        alice.assert_idle();
        bob.assert_idle();
    }

    #[tokio::test(start_paused = true)]
    async fn duplicate_establish_is_idempotent() {
        let harness = harness();
        let mut alice = harness.client(1, "+49111111").await;
        let mut bob = harness.client(2, "+49222222").await;
        let circuit = VirtualCircuit { vpi: 1, vci: 100 };

        // The same ESTABLISH twice (a client retransmission)
        for _ in 0..2 {
            harness
                .send(
                    &alice,
                    signalling::Message::Establish {
                        id: 7,
                        address: bob.address_field(),
                        circuit,
                    },
                )
                .await;
        }

        let first = bob.recv().await;
        let second = bob.recv().await;
        assert_eq!(first, second, "retransmission must not open a second call");
        assert_eq!(alice.circuit_count().await, 1);

        let signalling::Message::Establish { id: remote, .. } = first else {
            panic!("expected forwarded ESTABLISH, got {first:?}");
        };
        harness
            .send(&bob, signalling::Message::Established { id: remote })
            .await;
        assert_eq!(
            alice.recv().await,
            signalling::Message::Established { id: 7 }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn establish_times_out() {
        let harness = harness();
        let mut alice = harness.client(1, "+49111111").await;
        let mut bob = harness.client(2, "+49222222").await;
        let circuit = VirtualCircuit { vpi: 1, vci: 100 };

        harness
            .send(
                &alice,
                signalling::Message::Establish {
                    id: 7,
                    address: bob.address_field(),
                    circuit,
                },
            )
            .await;

        // Bob never answers: the request is retransmitted, then the call fails
        let first = bob.recv().await;
        for _ in 0..ESTABLISH_RETRIES {
            assert_eq!(
                bob.recv().await,
                first,
                "the retransmissions repeat the request"
            );
        }
        assert_eq!(
            alice.recv().await,
            signalling::Message::Error {
                id: 7,
                error: MessageType::Unreachable
            }
        );
        assert_eq!(alice.circuit_count().await, 0);

        // Bob may have accepted into the void, so his circuit is released explicitly
        let release = bob.recv().await;
        let signalling::Message::Release { id: remote, .. } = release else {
            panic!("expected RELEASE, got {release:?}");
        };
        harness
            .send(&bob, signalling::Message::Released { id: remote })
            .await;
        harness.settle().await;
        assert_eq!(bob.circuit_count().await, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn the_checker_keeps_its_reserve_when_a_callee_is_busy() {
        const RESERVE: usize = 4;
        let harness = harness_with(Policy {
            allow_calls_to_dynamic: true,
            allow_calls_from_static: true,
            checker_reserve: RESERVE,
        });
        let mut bob = harness.client(500, "+49222222").await;

        // Fill Bob right up to where the reserve starts, from enough sources
        // that nobody trips the per-source cap on the way
        let busy = MAX_INCOMING_CIRCUITS_PER_CONNECTION - RESERVE;
        let mut callers = Vec::new();
        for index in 0..busy.div_ceil(MAX_INCOMING_CIRCUITS_PER_SOURCE) {
            callers.push(
                harness
                    .client(index as u64 + 1, &format!("+4933{index:05}"))
                    .await,
            );
        }
        for index in 0..busy {
            let circuit = VirtualCircuit {
                vpi: 1 + (index / 512) as u8,
                vci: MIN_ALLOCATED_VCI + (index % 512) as u16,
            };
            let caller = &mut callers[index / MAX_INCOMING_CIRCUITS_PER_SOURCE];
            connect(&harness, caller, &mut bob, circuit, index as u32).await;
        }

        // An ordinary caller is turned away...
        let mut latecomer = harness.client(400, "+49444444").await;
        harness
            .send(
                &latecomer,
                signalling::Message::Establish {
                    id: 999,
                    address: bob.address_field(),
                    circuit: VirtualCircuit { vpi: 9, vci: 900 },
                },
            )
            .await;
        assert_eq!(
            latecomer.recv().await,
            signalling::Message::Error {
                id: 999,
                error: MessageType::Congested
            }
        );

        // ...while the checker still gets through
        let mut checker = harness
            .client_from(
                600,
                "+49666666",
                AddressAssignment::Dynamic,
                SourceKey::Connection(600),
                true,
            )
            .await;
        connect(
            &harness,
            &mut checker,
            &mut bob,
            VirtualCircuit { vpi: 9, vci: 901 },
            1,
        )
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn subscribers_share_one_allowance_across_connections() {
        let harness = harness();
        let subnet = SourceKey::Subnet("10.55.7.0".parse().expect("valid test network"));
        let mut bob = harness.client(100, "+49222222").await;

        // One subscriber dialling in on several connections still gets one allowance
        let mut callers = Vec::new();
        for index in 0..=MAX_INCOMING_CIRCUITS_PER_SOURCE {
            callers.push(
                harness
                    .client_from(
                        index as u64 + 1,
                        &format!("+4933{index:05}"),
                        AddressAssignment::Dynamic,
                        subnet,
                        false,
                    )
                    .await,
            );
        }
        for index in 0..MAX_INCOMING_CIRCUITS_PER_SOURCE {
            let circuit = VirtualCircuit {
                vpi: 1,
                vci: MIN_ALLOCATED_VCI + index as u16,
            };
            connect(&harness, &mut callers[index], &mut bob, circuit, 7).await;
        }

        // The allowance is spent, so a fresh connection from that subnet buys nothing
        harness
            .send(
                &callers[MAX_INCOMING_CIRCUITS_PER_SOURCE],
                signalling::Message::Establish {
                    id: 999,
                    address: bob.address_field(),
                    circuit: VirtualCircuit { vpi: 9, vci: 900 },
                },
            )
            .await;
        assert_eq!(
            callers[MAX_INCOMING_CIRCUITS_PER_SOURCE].recv().await,
            signalling::Message::Error {
                id: 999,
                error: MessageType::QuotaExceeded
            }
        );
        bob.assert_idle();

        // ...while a caller from outside that subnet is unaffected
        let mut checker = harness.client(500, "+49555555").await;
        connect(
            &harness,
            &mut checker,
            &mut bob,
            VirtualCircuit { vpi: 9, vci: 901 },
            1,
        )
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_fixed_number_goes_back_to_its_other_holder() {
        let harness = harness();
        // Both connections come from the same subscriber, so both are given its number
        let mut router = harness
            .client_with(1, "+49111111", AddressAssignment::Static)
            .await;
        let other = harness
            .client_with(2, "+49111111", AddressAssignment::Static)
            .await;
        let mut caller = harness.client(3, "+49222222").await;

        // The later connection holds the number, and giving it up hands it back
        harness.close(&other).await;
        harness.settle().await;

        harness
            .send(
                &caller,
                signalling::Message::Establish {
                    id: 7,
                    address: router.address_field(),
                    circuit: VirtualCircuit { vpi: 1, vci: 100 },
                },
            )
            .await;
        let forwarded = tokio::time::timeout(Duration::from_secs(5), router.recv())
            .await
            .expect("the number should still reach the router");
        assert!(
            matches!(forwarded, signalling::Message::Establish { .. }),
            "expected ESTABLISH, got {forwarded:?}"
        );
        // the router never answers here, so that attempt runs out on its own
        assert_eq!(
            caller.recv().await,
            signalling::Message::Error {
                id: 7,
                error: MessageType::Unreachable
            }
        );

        // ...and once nothing holds it any more, it stops resolving
        harness.close(&router).await;
        harness.settle().await;
        harness
            .send(
                &caller,
                signalling::Message::Establish {
                    id: 8,
                    address: router.address_field(),
                    circuit: VirtualCircuit { vpi: 2, vci: 200 },
                },
            )
            .await;
        assert_eq!(
            caller.recv().await,
            signalling::Message::Error {
                id: 8,
                error: MessageType::Unreachable
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn connected_circuits_expire() {
        let harness = harness();
        let mut alice = harness.client(1, "+49111111").await;
        let mut bob = harness.client(2, "+49222222").await;
        let circuit = VirtualCircuit { vpi: 1, vci: 100 };
        connect(&harness, &mut alice, &mut bob, circuit, 7).await;

        tokio::time::advance(CIRCUIT_LIFETIME + CIRCUIT_SWEEP_INTERVAL).await;
        harness.settle().await;

        // both halves are released, so neither side is left holding the call
        for client in [&mut alice, &mut bob] {
            let message = client.recv().await;
            assert!(
                matches!(message, signalling::Message::Release { .. }),
                "expected RELEASE, got {message:?}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn callee_rejections_are_clamped() {
        let harness = harness();
        let mut alice = harness.client(1, "+49111111").await;
        let mut bob = harness.client(2, "+49222222").await;

        // A callee rejecting with a DSLAM-only code is reported as a generic
        // refusal; one of its own codes passes through untouched.
        for (index, (sent, expected)) in [
            (MessageType::Congested, MessageType::GenericError),
            (MessageType::QuotaExceeded, MessageType::GenericError),
            (MessageType::NotPermitted, MessageType::GenericError),
            (MessageType::Unreachable, MessageType::GenericError),
            (MessageType::RejectedCircuit, MessageType::RejectedCircuit),
        ]
        .into_iter()
        .enumerate()
        {
            let id = index as u32;
            harness
                .send(
                    &alice,
                    signalling::Message::Establish {
                        id,
                        address: bob.address_field(),
                        circuit: VirtualCircuit {
                            vpi: 1,
                            vci: 100 + id as u16,
                        },
                    },
                )
                .await;
            let forwarded = bob.recv().await;
            let signalling::Message::Establish { id: remote, .. } = forwarded else {
                panic!("expected ESTABLISH, got {forwarded:?}");
            };
            harness
                .send(
                    &bob,
                    signalling::Message::Error {
                        id: remote,
                        error: sent,
                    },
                )
                .await;
            assert_eq!(
                alice.recv().await,
                signalling::Message::Error {
                    id,
                    error: expected
                },
                "{sent} relayed to the caller"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn release_retransmission_gives_up() {
        let harness = harness();
        let mut alice = harness.client(1, "+49111111").await;
        let mut bob = harness.client(2, "+49222222").await;
        let circuit = VirtualCircuit { vpi: 1, vci: 100 };
        let bob_circuit = connect(&harness, &mut alice, &mut bob, circuit, 7).await;

        harness
            .send(&alice, signalling::Message::Release { id: 9, circuit })
            .await;
        assert_eq!(alice.recv().await, signalling::Message::Released { id: 9 });

        // Bob never confirms: one initial RELEASE plus the retransmissions
        let first = bob.recv().await;
        assert!(matches!(
            first,
            signalling::Message::Release { circuit, .. } if circuit == bob_circuit
        ));
        for _ in 0..RELEASE_RETRIES {
            assert_eq!(bob.recv().await, first);
        }

        // Then the circuit is dropped unilaterally and the retransmissions stop
        tokio::time::sleep(RELEASE_RETRANSMIT + Duration::from_secs(1)).await;
        assert_eq!(bob.circuit_count().await, 0);
        bob.assert_idle();
    }

    #[tokio::test(start_paused = true)]
    async fn hairpin_call_to_self() {
        let harness = harness();
        let mut alice = harness.client(1, "+49111111").await;
        let circuit = VirtualCircuit { vpi: 1, vci: 100 };

        harness
            .send(
                &alice,
                signalling::Message::Establish {
                    id: 7,
                    address: alice.address_field(),
                    circuit,
                },
            )
            .await;

        let forwarded = alice.recv().await;
        let signalling::Message::Establish {
            id: remote,
            address,
            circuit: other,
        } = forwarded
        else {
            panic!("expected forwarded ESTABLISH, got {forwarded:?}");
        };
        assert_eq!(address, alice.address_field());
        assert_ne!(other, circuit, "hairpin legs need distinct circuits");

        harness
            .send(&alice, signalling::Message::Established { id: remote })
            .await;
        assert_eq!(
            alice.recv().await,
            signalling::Message::Established { id: 7 }
        );

        let circuits = alice.connection.circuits.read().await;
        assert_eq!(circuits.len(), 2);
        assert_eq!(circuits.get(&circuit).expect("caller leg").circuit, other);
        assert_eq!(circuits.get(&other).expect("callee leg").circuit, circuit);
    }

    #[tokio::test(start_paused = true)]
    async fn simultaneous_calls_both_ways() {
        let harness = harness();
        let mut alice = harness.client(1, "+49111111").await;
        let mut bob = harness.client(2, "+49222222").await;
        let alice_circuit = VirtualCircuit { vpi: 1, vci: 100 };
        let bob_circuit = VirtualCircuit { vpi: 2, vci: 200 };

        // Both call each other before either request is answered
        harness
            .send(
                &alice,
                signalling::Message::Establish {
                    id: 1,
                    address: bob.address_field(),
                    circuit: alice_circuit,
                },
            )
            .await;
        harness
            .send(
                &bob,
                signalling::Message::Establish {
                    id: 2,
                    address: alice.address_field(),
                    circuit: bob_circuit,
                },
            )
            .await;

        let signalling::Message::Establish { id: to_bob, .. } = bob.recv().await else {
            panic!("expected forwarded ESTABLISH for bob");
        };
        let signalling::Message::Establish { id: to_alice, .. } = alice.recv().await else {
            panic!("expected forwarded ESTABLISH for alice");
        };

        harness
            .send(&bob, signalling::Message::Established { id: to_bob })
            .await;
        harness
            .send(&alice, signalling::Message::Established { id: to_alice })
            .await;

        assert_eq!(
            alice.recv().await,
            signalling::Message::Established { id: 1 }
        );
        assert_eq!(bob.recv().await, signalling::Message::Established { id: 2 });

        // Two independent calls: each side has its own leg plus the incoming one
        assert_eq!(alice.circuit_count().await, 2);
        assert_eq!(bob.circuit_count().await, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn establish_on_occupied_circuit_wipes_old_call() {
        let harness = harness();
        let mut alice = harness.client(1, "+49111111").await;
        let mut bob = harness.client(2, "+49222222").await;
        let circuit = VirtualCircuit { vpi: 1, vci: 100 };
        let old_bob_circuit = connect(&harness, &mut alice, &mut bob, circuit, 7).await;

        // A new call (with a new ID) on the same circuit implicitly releases the old one
        harness
            .send(
                &alice,
                signalling::Message::Establish {
                    id: 8,
                    address: bob.address_field(),
                    circuit,
                },
            )
            .await;

        let release = bob.recv().await;
        let signalling::Message::Release {
            id: release_id,
            circuit: released,
        } = release
        else {
            panic!("expected RELEASE for the old call, got {release:?}");
        };
        assert_eq!(released, old_bob_circuit);
        harness
            .send(&bob, signalling::Message::Released { id: release_id })
            .await;

        let forwarded = bob.recv().await;
        let signalling::Message::Establish {
            id: remote,
            circuit: new_bob_circuit,
            ..
        } = forwarded
        else {
            panic!("expected forwarded ESTABLISH, got {forwarded:?}");
        };
        harness
            .send(&bob, signalling::Message::Established { id: remote })
            .await;
        assert_eq!(
            alice.recv().await,
            signalling::Message::Established { id: 8 }
        );

        harness.settle().await;
        assert_eq!(alice.circuit_count().await, 1);
        assert_eq!(bob.circuit_count().await, 1);
        let circuits = alice.connection.circuits.read().await;
        assert_eq!(
            circuits.get(&circuit).expect("new leg").circuit,
            new_bob_circuit
        );
    }

    #[tokio::test(start_paused = true)]
    async fn closed_connection_releases_peers() {
        let harness = harness();
        let mut alice = harness.client(1, "+49111111").await;
        let mut bob = harness.client(2, "+49222222").await;
        let circuit = VirtualCircuit { vpi: 1, vci: 100 };
        let bob_circuit = connect(&harness, &mut alice, &mut bob, circuit, 7).await;

        harness.close(&alice).await;

        // Bob is told the call is gone
        let release = bob.recv().await;
        let signalling::Message::Release {
            id: remote,
            circuit: released,
        } = release
        else {
            panic!("expected RELEASE, got {release:?}");
        };
        assert_eq!(released, bob_circuit);
        harness
            .send(&bob, signalling::Message::Released { id: remote })
            .await;
        harness.settle().await;
        assert_eq!(bob.circuit_count().await, 0);

        // Alice's address is no longer reachable
        let mut carol = harness.client(3, "+49333333").await;
        harness
            .send(
                &carol,
                signalling::Message::Establish {
                    id: 1,
                    address: alice.address_field(),
                    circuit,
                },
            )
            .await;
        assert_eq!(
            carol.recv().await,
            signalling::Message::Error {
                id: 1,
                error: MessageType::Unreachable
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn callee_disappears_mid_setup() {
        let harness = harness();
        let mut alice = harness.client(1, "+49111111").await;
        let mut bob = harness.client(2, "+49222222").await;
        let circuit = VirtualCircuit { vpi: 1, vci: 100 };

        harness
            .send(
                &alice,
                signalling::Message::Establish {
                    id: 7,
                    address: bob.address_field(),
                    circuit,
                },
            )
            .await;
        let forwarded = bob.recv().await;
        assert!(matches!(forwarded, signalling::Message::Establish { .. }));

        // Bob's connection dies before it answers
        harness.close(&bob).await;

        assert_eq!(
            alice.recv().await,
            signalling::Message::Error {
                id: 7,
                error: MessageType::Unreachable
            }
        );
        assert_eq!(alice.circuit_count().await, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn retransmitted_establish_after_connect_is_reconfirmed() {
        let harness = harness();
        let mut alice = harness.client(1, "+49111111").await;
        let mut bob = harness.client(2, "+49222222").await;
        let circuit = VirtualCircuit { vpi: 1, vci: 100 };
        connect(&harness, &mut alice, &mut bob, circuit, 7).await;

        // Alice never saw the ESTABLISHED (lost or crossed by her retransmission
        // timer) and sends the same ESTABLISH again
        harness
            .send(
                &alice,
                signalling::Message::Establish {
                    id: 7,
                    address: bob.address_field(),
                    circuit,
                },
            )
            .await;
        assert_eq!(
            alice.recv().await,
            signalling::Message::Established { id: 7 }
        );

        // The live call is untouched: Bob saw nothing, both legs stay connected
        harness.settle().await;
        bob.assert_idle();
        assert_eq!(alice.circuit_count().await, 1);
        assert_eq!(bob.circuit_count().await, 1);
        let circuits = alice.connection.circuits.read().await;
        assert!(matches!(
            circuits.get(&circuit).expect("caller leg exists").state,
            CircuitState::Connected { .. }
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn release_churn_does_not_exhaust_the_callee() {
        let harness = harness();
        let mut alice = harness.client(1, "+49111111").await;
        let mut bob = harness.client(2, "+49222222").await;
        let circuit = VirtualCircuit { vpi: 1, vci: 100 };

        // Alice churns calls on a single circuit (each new ID implicitly releases the
        // previous call); Bob answers the calls but never confirms the RELEASEs, so
        // his table accumulates legs stuck in DisconnectionPending.
        for index in 0..(2 * MAX_RELEASING_PER_CONNECTION) {
            harness
                .send(
                    &alice,
                    signalling::Message::Establish {
                        id: index as u32,
                        address: bob.address_field(),
                        circuit,
                    },
                )
                .await;
            let remote = loop {
                match bob.recv().await {
                    signalling::Message::Establish { id, .. } => break id,
                    signalling::Message::Release { .. } => continue,
                    other => panic!("unexpected message for the callee: {other:?}"),
                }
            };
            harness
                .send(&bob, signalling::Message::Established { id: remote })
                .await;
            assert_eq!(
                alice.recv().await,
                signalling::Message::Established { id: index as u32 }
            );
        }

        // The zombie legs are bounded (the cap, plus the one live call)...
        harness.settle().await;
        assert!(bob.circuit_count().await <= MAX_RELEASING_PER_CONNECTION + 1);

        // ...and, crucially, Bob can still be called
        let carol = harness.client(3, "+49333333").await;
        harness
            .send(
                &carol,
                signalling::Message::Establish {
                    id: 1,
                    address: bob.address_field(),
                    circuit,
                },
            )
            .await;
        loop {
            match bob.recv().await {
                signalling::Message::Establish { .. } => break,
                signalling::Message::Release { .. } => continue,
                other => panic!("unexpected message for the callee: {other:?}"),
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn peer_gone_then_close_releases_only_once() {
        let harness = harness();
        let mut alice = harness.client(1, "+49111111").await;
        let mut bob = harness.client(2, "+49222222").await;
        let circuit = VirtualCircuit { vpi: 1, vci: 100 };
        connect(&harness, &mut alice, &mut bob, circuit, 7).await;

        // Bob's transmit queue dies first (the data path notices and reports it),
        // then his connection is closed: both paths release Alice's leg.
        let bob_id = bob.connection.id;
        drop(bob);
        harness.peer_gone(alice.connection.id, circuit).await;
        harness.close_connection(bob_id).await;

        // Alice sees exactly one RELEASE (one transaction, not two)
        let release = alice.recv().await;
        let signalling::Message::Release { id: remote, .. } = release else {
            panic!("expected RELEASE, got {release:?}");
        };
        harness
            .send(&alice, signalling::Message::Released { id: remote })
            .await;
        harness.settle().await;
        assert_eq!(alice.circuit_count().await, 0);

        // No orphaned transaction keeps retransmitting a stale RELEASE
        tokio::time::sleep(Duration::from_secs(15)).await;
        alice.assert_idle();
    }

    #[tokio::test(start_paused = true)]
    async fn mirror_circuit_cannot_be_released() {
        let mirror = VirtualCircuit { vpi: 0, vci: 42 };
        let harness = harness_full(
            Policy {
                allow_calls_to_dynamic: true,
                allow_calls_from_static: true,
                checker_reserve: 0,
            },
            Some(mirror),
        );
        let mut alice = harness.client(1, "+49111111").await;

        // The switchboard installs the mirror leg when the connection registers
        harness.settle().await;
        assert_eq!(alice.circuit_count().await, 1);

        // The RELEASE is refused and the leg survives
        harness
            .send(
                &alice,
                signalling::Message::Release {
                    id: 3,
                    circuit: mirror,
                },
            )
            .await;
        assert_eq!(
            alice.recv().await,
            signalling::Message::Error {
                id: 3,
                error: MessageType::RejectedCircuit
            }
        );
        assert_eq!(alice.circuit_count().await, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn policy_blocks_calls_to_dynamic_numbers() {
        let harness = harness_with(Policy::default());
        let mut alice = harness.client(1, "+49111111").await;
        let mut bob = harness.client(2, "+49222222").await;
        let circuit = VirtualCircuit { vpi: 1, vci: 100 };

        // Dynamic numbers look exactly like offline numbers to callers
        harness
            .send(
                &alice,
                signalling::Message::Establish {
                    id: 7,
                    address: bob.address_field(),
                    circuit,
                },
            )
            .await;
        assert_eq!(
            alice.recv().await,
            signalling::Message::Error {
                id: 7,
                error: MessageType::Unreachable
            }
        );
        bob.assert_idle();
        assert_eq!(alice.circuit_count().await, 0);
        assert_eq!(bob.circuit_count().await, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn policy_blocks_calls_from_static_numbers() {
        let harness = harness_with(Policy::default());
        let mut alice = harness
            .client_with(1, "+49111111", AddressAssignment::Static)
            .await;
        let mut bob = harness
            .client_with(2, "+49222222", AddressAssignment::Static)
            .await;
        let circuit = VirtualCircuit { vpi: 1, vci: 100 };

        harness
            .send(
                &alice,
                signalling::Message::Establish {
                    id: 7,
                    address: bob.address_field(),
                    circuit,
                },
            )
            .await;
        assert_eq!(
            alice.recv().await,
            signalling::Message::Error {
                id: 7,
                error: MessageType::NotPermitted
            }
        );
        bob.assert_idle();
        assert_eq!(alice.circuit_count().await, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn policy_allows_dynamic_to_static_calls() {
        let harness = harness_with(Policy::default());
        let mut alice = harness.client(1, "+49111111").await;
        let mut bob = harness
            .client_with(2, "+49222222", AddressAssignment::Static)
            .await;
        let circuit = VirtualCircuit { vpi: 1, vci: 100 };

        // The intended direction (client calls service) works under the default policy
        connect(&harness, &mut alice, &mut bob, circuit, 7).await;
        assert_eq!(alice.circuit_count().await, 1);
        assert_eq!(bob.circuit_count().await, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn incoming_circuits_are_limited_per_source() {
        let harness = harness();
        let mut alice = harness.client(1, "+49111111").await;
        let mut bob = harness.client(2, "+49222222").await;

        // Alice fills exactly her per-source allowance of incoming legs at Bob
        for index in 0..MAX_INCOMING_CIRCUITS_PER_SOURCE {
            let circuit = VirtualCircuit {
                vpi: 1,
                vci: MIN_ALLOCATED_VCI + index as u16,
            };
            connect(&harness, &mut alice, &mut bob, circuit, index as u32).await;
        }

        // Her next call to Bob is refused by the per-source cap, even though Bob's total
        // incoming table is nowhere near full and Alice is under her own outgoing cap.
        harness
            .send(
                &alice,
                signalling::Message::Establish {
                    id: 999,
                    address: bob.address_field(),
                    circuit: VirtualCircuit {
                        vpi: 100,
                        vci: 5000,
                    },
                },
            )
            .await;
        assert_eq!(
            alice.recv().await,
            signalling::Message::Error {
                id: 999,
                error: MessageType::QuotaExceeded
            }
        );
        bob.assert_idle();

        // A different source can still reach Bob: the cap is per-source, not global.
        let mut carol = harness.client(3, "+49333333").await;
        connect(
            &harness,
            &mut carol,
            &mut bob,
            VirtualCircuit { vpi: 1, vci: 100 },
            1,
        )
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn establish_reusing_id_for_new_target_repoints_circuit() {
        let harness = harness();
        let mut alice = harness.client(1, "+49111111").await;
        let mut bob = harness.client(2, "+49222222").await;
        let mut carol = harness.client(3, "+49333333").await;
        let circuit = VirtualCircuit { vpi: 1, vci: 100 };

        // Alice establishes a live call to Bob with ID 7
        let bob_circuit = connect(&harness, &mut alice, &mut bob, circuit, 7).await;

        // Alice reuses ID 7 on the same circuit but names Carol. This is a *new* call, not
        // a retransmission of the Bob call: the retransmit fast-path must not confirm it
        // against Bob. The old call is released and a fresh one to Carol is set up.
        harness
            .send(
                &alice,
                signalling::Message::Establish {
                    id: 7,
                    address: carol.address_field(),
                    circuit,
                },
            )
            .await;

        // Bob's leg is torn down
        let release = bob.recv().await;
        let signalling::Message::Release {
            id: bob_release,
            circuit: released,
        } = release
        else {
            panic!("expected RELEASE for the old Bob call, got {release:?}");
        };
        assert_eq!(released, bob_circuit);
        harness
            .send(&bob, signalling::Message::Released { id: bob_release })
            .await;

        // Carol receives the new call and it completes
        let forwarded = carol.recv().await;
        let signalling::Message::Establish { id: remote, .. } = forwarded else {
            panic!("expected forwarded ESTABLISH to Carol, got {forwarded:?}");
        };
        harness
            .send(&carol, signalling::Message::Established { id: remote })
            .await;
        assert_eq!(
            alice.recv().await,
            signalling::Message::Established { id: 7 }
        );

        // Alice's circuit now points at Carol, not Bob
        harness.settle().await;
        assert_eq!(alice.circuit_count().await, 1);
        assert_eq!(carol.circuit_count().await, 1);
    }
}
