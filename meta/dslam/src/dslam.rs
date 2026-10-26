use std::{
    collections::{HashMap, HashSet},
    fs::File,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::Arc,
    time::Duration,
};

use rand::RngExt;
use serde::{Deserialize, Serialize};
use socket2::{SockRef, TcpKeepalive};
use thiserror::Error;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex, mpsc},
};
use tokio_util::sync::CancellationToken;

use crate::{
    addresses::{AtmAddress, E164_MAX_LENGTH, E164Idi},
    capture::Client,
    connection::{AddressAssignment, Connection, ConnectionId, SourceKey},
    debug_log::{Log, Record, RefusedReason, connection_record, flatten},
    flood::Monitor,
    switchboard::Event,
};

const QUEUE_SIZE: usize = 1024;

/// Maximum number of connections a single source may hold at once
pub(crate) const MAX_CONNECTIONS_PER_SOURCE: usize = 32;

// Keepalive for accepted connections, so a subscriber that vanishes without
// closing does not keep its circuits and its number
const KEEPALIVE_IDLE: Duration = Duration::from_secs(30);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
const KEEPALIVE_RETRIES: u32 = 3;
// Keepalive does not run while data is unacknowledged or the window is zero.
// Matches the keepalive budget, since it replaces the probe count when set.
const USER_TIMEOUT: Duration =
    KEEPALIVE_IDLE.saturating_add(KEEPALIVE_INTERVAL.saturating_mul(KEEPALIVE_RETRIES));

/// An ADSL DSLAM server
pub struct Server {
    /// Inbound TCP socket
    listener: TcpListener,

    /// Switchboard control channel for connection registrations and closures.
    control: mpsc::Sender<Event>,

    /// Switchboard event channel for signalling.
    events: mpsc::Sender<Event>,

    /// Packet capture client
    capture: Option<Client>,

    /// Flood detection
    monitor: Arc<Monitor>,

    /// Structured export of connection and call information
    log: Log,

    /// Next connection identifier
    id: ConnectionId,

    /// Numbering plan
    plan: NumberingPlan,

    /// The subscriber subnets circuit limits are pooled over
    subnets: Subnets,

    /// Which callers may use a callee's reserved circuits
    checker: CheckerMatch,

    /// Assigned random suffixes
    assigned: Arc<Mutex<HashSet<E164Idi>>>,

    /// Connections held per source
    held: Arc<Mutex<HashMap<SourceKey, usize>>>,
}

/// A numbering plan for the network.
///
/// Serializable as well, because the debug log carries a snapshot of the plan it
/// ran with: a log read after the game must not depend on which plan was live.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct NumberingPlan {
    pub random: RandomNumberingPlan,
    pub fixed: HashMap<IpAddr, E164Idi>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct RandomNumberingPlan {
    pub prefix: E164Idi,
    pub length: usize,
}

/// The subnets the subscribers sit in.
///
/// Circuit limits apply to a whole subnet, so a subscriber cannot widen its
/// allowance by dialling in from more addresses than the one its number is keyed
/// on. Configured on the command line, not in the numbering plan: the plan is
/// handed out, and who is exempt from a limit is nobody else's business.
pub(crate) struct Subnets {
    ipv4: u32,
    ipv6: u32,
}

/// The checker sits on 10.X.249.0/24, which is not a prefix: the second and the
/// last octet both vary, so it takes a mask to pick out.
pub(crate) const DEFAULT_CHECKER_MASK: IpAddr = IpAddr::V4(Ipv4Addr::new(255, 0, 255, 0));
pub(crate) const DEFAULT_CHECKER_PATTERN: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 249, 0));

/// Which callers may use a callee's reserved circuits: those whose address,
/// masked, equals the pattern. A mask rather than a prefix, so the checker can
/// be recognised by something other than the subnet it happens to sit in.
pub(crate) struct CheckerMatch {
    mask: IpAddr,
    pattern: IpAddr,
}

#[derive(Debug, Error)]
pub(crate) enum CheckerMatchError {
    #[error("the checker mask and pattern must both be IPv4 or both be IPv6")]
    MixedFamily,
    #[error("the checker pattern {0} has bits outside the mask {1}, so nothing can ever match it")]
    PatternOutsideMask(IpAddr, IpAddr),
}

impl CheckerMatch {
    pub fn new(mask: IpAddr, pattern: IpAddr) -> Result<Self, CheckerMatchError> {
        let matcher = Self { mask, pattern };
        match (mask, pattern) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {}
            _ => return Err(CheckerMatchError::MixedFamily),
        }
        // A pattern the mask cannot reach matches nothing, and the only symptom
        // would be the checker quietly losing its reserve.
        if !matcher.matches(pattern) {
            return Err(CheckerMatchError::PatternOutsideMask(pattern, mask));
        }
        Ok(matcher)
    }

    /// Whether an address is the checker's
    pub fn matches(&self, address: IpAddr) -> bool {
        match (self.mask, self.pattern, address) {
            (IpAddr::V4(mask), IpAddr::V4(pattern), IpAddr::V4(address)) => {
                Ipv4Addr::from(u32::from(address) & u32::from(mask)) == pattern
            }
            (IpAddr::V6(mask), IpAddr::V6(pattern), IpAddr::V6(address)) => {
                Ipv6Addr::from(u128::from(address) & u128::from(mask)) == pattern
            }
            _ => false,
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum SubnetError {
    #[error("/{0} is not a valid IPv{1} prefix length")]
    InvalidPrefix(u32, u8),
    #[error("{0} and {1} share the subnet {2}, so they would share a circuit allowance")]
    Collision(IpAddr, IpAddr, IpAddr),
}

impl Subnets {
    /// Derives the subscriber subnets from the numbering plan's fixed addresses
    pub fn new(plan: &NumberingPlan, ipv4: u32, ipv6: u32) -> Result<Self, SubnetError> {
        if ipv4 > 32 {
            return Err(SubnetError::InvalidPrefix(ipv4, 4));
        }
        if ipv6 > 128 {
            return Err(SubnetError::InvalidPrefix(ipv6, 6));
        }
        let subnets = Self { ipv4, ipv6 };

        // Two subscribers sharing a subnet would eat into each other's allowance,
        // which is near impossible to diagnose from the outside, and too short a
        // prefix collapses all of them into one. Refuse to start instead. One
        // subscriber reachable at several addresses is fine, and is how the CI
        // plan names a whole network.
        let mut networks: HashMap<IpAddr, (&E164Idi, IpAddr)> = HashMap::new();
        for (address, number) in &plan.fixed {
            let network = subnets.network(*address);
            if let Some((other_number, other)) = networks.insert(network, (number, *address))
                && other_number != number
            {
                return Err(SubnetError::Collision(other, *address, network));
            }
        }
        Ok(subnets)
    }

    /// The subnet an address sits in
    fn network(&self, address: IpAddr) -> IpAddr {
        match address {
            IpAddr::V4(address) => {
                let mask = u32::MAX.checked_shl(32 - self.ipv4).unwrap_or(0);
                IpAddr::V4(Ipv4Addr::from(u32::from(address) & mask))
            }
            IpAddr::V6(address) => {
                let mask = u128::MAX.checked_shl(128 - self.ipv6).unwrap_or(0);
                IpAddr::V6(Ipv6Addr::from(u128::from(address) & mask))
            }
        }
    }

    /// What a connection's calls are counted against on the callee.
    ///
    /// Everyone is pooled by subnet, so a caller cannot widen its allowance by
    /// dialling in from more addresses. The checker is the exception: it makes
    /// each call on a connection of its own, and pooling those would throttle it
    /// against itself.
    fn source_key(&self, remote: &SocketAddr, id: ConnectionId, reserved: bool) -> SourceKey {
        if reserved {
            SourceKey::Connection(id)
        } else {
            SourceKey::Subnet(self.network(remote.ip()))
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum NumberingPlanError {
    #[error("Invalid numbering plan: E.164 addresses would be too long")]
    TooLong,
    #[error("Failed to open numbering plan file: {0}")]
    IoError(std::io::Error),
    #[error("Failed to parse numbering plan file: {0}")]
    ParseError(serde_norway::Error),
}

impl NumberingPlan {
    /// Loads the numbering plan
    pub fn load_from_yaml(path: &Path) -> Result<Self, NumberingPlanError> {
        let file = File::open(path).map_err(NumberingPlanError::IoError)?;
        let plan: Self = serde_norway::from_reader(file).map_err(NumberingPlanError::ParseError)?;
        if plan.random.length > E164_MAX_LENGTH || plan.random.prefix.len() >= plan.random.length {
            return Err(NumberingPlanError::TooLong);
        }
        Ok(plan)
    }
}

// Maximum number of attempts to generate a unique random E.164 address
const RANDOM_RETRIES: usize = 20;

impl Server {
    /// Spins up a new DSLAM, forwarding connection and signalling events to a switchboard
    #[allow(clippy::too_many_arguments)] // every one of them is wiring, not policy
    pub fn new(
        plan: NumberingPlan,
        subnets: Subnets,
        checker: CheckerMatch,
        listener: TcpListener,
        control: mpsc::Sender<Event>,
        events: mpsc::Sender<Event>,
        monitor: Arc<Monitor>,
        log: Log,
    ) -> Self {
        Self {
            listener,
            control,
            events,
            capture: None,
            monitor,
            log,
            id: 0,
            plan,
            subnets,
            checker,
            assigned: Arc::new(Mutex::new(HashSet::new())),
            held: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Spins up a new DSLAM
    #[allow(clippy::too_many_arguments)] // every one of them is wiring, not policy
    pub async fn bind(
        plan: NumberingPlan,
        subnets: Subnets,
        checker: CheckerMatch,
        address: &SocketAddr,
        control: mpsc::Sender<Event>,
        events: mpsc::Sender<Event>,
        monitor: Arc<Monitor>,
        log: Log,
    ) -> std::io::Result<Self> {
        Ok(Self::new(
            plan,
            subnets,
            checker,
            TcpListener::bind(address).await?,
            control,
            events,
            monitor,
            log,
        ))
    }

    /// Sets the packet capture client for this DSLAM
    pub fn set_capture_client(&mut self, capture: Option<Client>) {
        self.capture = capture;
    }

    /// A connection the DSLAM would not take, as the debug log spells it
    fn refused(remote: &SocketAddr, source: SourceKey, reason: RefusedReason) -> Record {
        let (subnet, source_connection) = flatten(source);
        Record::ConnectionRefused {
            remote_ip: remote.ip(),
            remote_port: remote.port(),
            source: subnet,
            source_connection,
            reason,
        }
    }

    /// Returns the next connection ID
    fn next_id(&mut self) -> ConnectionId {
        self.id = self.id.wrapping_add(1);
        self.id
    }

    /// Returns a random address for a circuit (or connection, if need be)
    // These probably should be unique to account for client behavior that cannot handle multiple
    // connections from the same ATM address. In theory that would probably also be fine but I'd
    // like to avoid some ugly differentials there.
    async fn get_random_address(&self) -> Option<AtmAddress> {
        let mut rng = rand::rng();
        for _ in 0..RANDOM_RETRIES {
            let suffix: String = std::iter::repeat_with(|| rng.random_range('0'..='9'))
                .take(self.plan.random.length - self.plan.random.prefix.len())
                .collect();

            let combined = format!("{}{}", self.plan.random.prefix, suffix);
            let idi: E164Idi = match combined.parse() {
                Ok(idi) => idi,
                Err(error) => {
                    tracing::error!(
                        "Generated invalid random E.164 phone number {}: {}",
                        combined,
                        error
                    );
                    return None;
                }
            };

            let mut guard = self.assigned.lock().await;
            if guard.insert(idi.clone()) {
                return Some(AtmAddress::new(idi));
            }

            tracing::debug!("Address {idi} is already occupied");
        }
        tracing::warn!(
            "Failed to assign a random E.164 phone number within the assigned numbering plan"
        );
        return None;
    }

    /// Returns the assigned address for a connection
    async fn get_inbound_address_for_connection(
        &self,
        remote: &SocketAddr,
    ) -> Option<(AtmAddress, AddressAssignment)> {
        // Look up the IP in the fixed table for the vulnboxes
        if let Some(idi) = self.plan.fixed.get(&remote.ip()).cloned() {
            return Some((AtmAddress::new(idi), AddressAssignment::Static));
        }
        self.get_random_address()
            .await
            .map(|address| (address, AddressAssignment::Dynamic))
    }

    /// Counts a connection against its source's limit, returning whether it may be
    /// held. The checker is exempt, since it opens a connection per call.
    async fn claim_connection(&self, source: SourceKey, reserved: bool) -> bool {
        if reserved {
            return true;
        }
        let mut held = self.held.lock().await;
        let count = held.entry(source).or_insert(0);
        if *count >= MAX_CONNECTIONS_PER_SOURCE {
            return false;
        }
        *count += 1;
        true
    }

    /// Returns a connection to its source's limit
    async fn release_connection(
        held: Arc<Mutex<HashMap<SourceKey, usize>>>,
        source: SourceKey,
        reserved: bool,
    ) {
        if reserved {
            return;
        }
        let mut held = held.lock().await;
        match held.get_mut(&source) {
            Some(count) => {
                *count -= 1;
                if *count == 0 {
                    held.remove(&source);
                }
            }
            None => tracing::warn!("Released an unheld connection for {source:?}"),
        }
    }

    async fn release_address(assigned: Arc<Mutex<HashSet<E164Idi>>>, address: AtmAddress) {
        if !assigned.lock().await.remove(&address.idi) {
            tracing::warn!("Released unassigned address {address}");
        }
    }

    /// Enables TCP keepalive and the user timeout on an accepted connection
    fn set_keepalive(stream: &TcpStream) -> std::io::Result<()> {
        let keepalive = TcpKeepalive::new()
            .with_time(KEEPALIVE_IDLE)
            .with_interval(KEEPALIVE_INTERVAL)
            .with_retries(KEEPALIVE_RETRIES);
        let socket = SockRef::from(stream);
        socket.set_tcp_keepalive(&keepalive)?;
        socket.set_tcp_user_timeout(Some(USER_TIMEOUT))
    }

    /// Serves client connections on the ATM/TCP proxy port
    pub async fn run(&mut self, token: CancellationToken) {
        loop {
            let (stream, remote) = tokio::select! {
                _ = token.cancelled() => return,
                result = self.listener.accept() => match result {
                    Ok(incoming) => incoming,
                    Err(error) => {
                        tracing::error!("Failed to accept inbound connection: {error}");
                        tokio::select! {
                            _ = token.cancelled() => return,
                            _ = tokio::time::sleep(Duration::from_millis(100)) => continue,
                        };
                    }
                }
            };

            if let Err(error) = Self::set_keepalive(&stream) {
                tracing::warn!("Failed to enable TCP keepalive for {remote}: {error}");
            }

            // Our own end of the connection, so that the debug log names the
            // whole four-tuple a capture taken elsewhere can be matched on
            let endpoint = match stream.local_addr().or_else(|_| self.listener.local_addr()) {
                Ok(endpoint) => endpoint,
                Err(error) => {
                    tracing::warn!("Failed to read the local endpoint for {remote}: {error}");
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                }
            };

            // Grab the next connection ID, and work out what this client's
            // traffic is counted against. Both before the address assignment,
            // so that connections dropped for want of a number still count
            // towards a connection flood -- exhausting the pool is one.
            let id = self.next_id();
            let reserved = self.checker.matches(remote.ip());
            let source = self.subnets.source_key(&remote, id, reserved);
            self.monitor.connected(source);

            // Check the limit before assigning an address, so a refused connection
            // does not draw from the number pool.
            if !self.claim_connection(source, reserved).await {
                tracing::warn!(
                    "Refusing connection from {remote}: {source:?} already holds {MAX_CONNECTIONS_PER_SOURCE} connections"
                );
                self.log
                    .record(|| Self::refused(&remote, source, RefusedReason::ConnectionLimit));
                continue;
            }

            // Get the phone number for inbound "calls" to this connection, or assign a
            // random one if the configured map does not have one.
            // Dynamically assigned addresses cannot be called, so while traffic from
            // each TCP connection to the DSLAM can be correlated, traffic from separate
            // TCP connections from the same machine cannot.
            let (address, assignment) = tokio::select! {
                _ = token.cancelled() => return,
                address = self.get_inbound_address_for_connection(&remote) => match address {
                    Some(allocation) => allocation,
                    None => {
                        tracing::warn!("Dropping connection from {remote} (no assigned address)");
                        self.log
                            .record(|| Self::refused(&remote, source, RefusedReason::NoNumber));
                        Self::release_connection(self.held.clone(), source, reserved).await;
                        continue;
                    }
                }
            };

            tracing::info!(
                "New connection from {remote} (assigning ID {id} and address {address})"
            );

            // Build the connection state and transmit queue for this connection
            let (inbound, outbound) = stream.into_split();
            let (outbound_tx, outbound_rx) = mpsc::channel(QUEUE_SIZE);
            let connection = Connection::new(
                id,
                remote,
                endpoint,
                address.clone(),
                assignment,
                source,
                reserved,
                outbound_tx,
            );

            // The record every later one is keyed on: the four-tuple matches a
            // capture to this connection, and the number is what callers dial
            // to reach it (and what it presents itself as when it calls out).
            self.log.record(|| connection_record(&connection));

            // Sync that to the packet capture thread
            if let Some(client) = &self.capture {
                tokio::select! {
                    _ = token.cancelled() => return,
                    result = client.add_connection(connection.clone()) => if let Err(error) = result {
                        tracing::warn!("Failed to add connection to packet capture: {error}");
                        self.log.record(|| {
                            Self::refused(&remote, source, RefusedReason::CaptureBackpressure)
                        });
                        if assignment == AddressAssignment::Dynamic {
                            Self::release_address(self.assigned.clone(), address).await;
                        }
                        Self::release_connection(self.held.clone(), source, reserved).await;
                        continue;
                    }
                }
            }

            // Hand the connection to the switchboard, which publishes it in the
            // connection map. This must complete before the receive task is spawned, so
            // that the switchboard processes the registration before any signalling
            // from this client.
            if self
                .control
                .send(Event::Register {
                    connection: connection.clone(),
                })
                .await
                .is_err()
            {
                tracing::error!("Cannot register new connections, the switchboard is gone");
                return;
            }

            // New token to synchronize connection shutdown (as opposed to global shutdown)
            let shutdown = CancellationToken::new();

            // Spawn tasks to handle this connection
            tokio::spawn(connection.clone().outbound(
                outbound_rx,
                outbound,
                self.capture.clone(),
                shutdown.clone(),
                token.clone(),
            ));
            tokio::spawn(connection.clone().inbound(
                inbound,
                self.events.clone(),
                self.capture.clone(),
                self.monitor.clone(),
                shutdown.clone(),
                token.clone(),
            ));

            // On connection end, release the assigned address, notify the packet
            // capture, and have the switchboard unwind the connection's circuits.
            let handle = self.assigned.clone();
            let held = self.held.clone();
            let capture = self.capture.clone();
            let control = self.control.clone();
            let global_shutdown = token.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = shutdown.cancelled_owned() => {
                        // First, so the source does not wait for the capture and the
                        // switchboard below to get its connection back
                        Self::release_connection(held, source, reserved).await;
                        if let Some(client) = capture {
                            if let Err(error) = client.add_disconnect(connection.clone()).await {
                                tracing::error!("Failed to mark connection as disconnected in packet capture: {error}");
                            }
                        }
                        if assignment == AddressAssignment::Dynamic {
                            Self::release_address(handle, address).await;
                        }
                        let _ = control.send(Event::Closed { connection: connection.id }).await;
                    },
                    _ = global_shutdown.cancelled_owned() => return,
                };
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(addresses: &[&str]) -> NumberingPlan {
        NumberingPlan {
            random: RandomNumberingPlan {
                prefix: "+49 14 3272".parse().expect("valid test prefix"),
                length: 14,
            },
            fixed: addresses
                .iter()
                .enumerate()
                .map(|(index, address)| {
                    (
                        address.parse().expect("valid test address"),
                        format!("+4912{index:05}")
                            .parse()
                            .expect("valid test number"),
                    )
                })
                .collect(),
        }
    }

    #[test]
    fn subscribers_are_pooled_by_subnet() {
        let plan = plan(&["10.55.1.2", "10.55.2.2"]);
        let subnets = Subnets::new(&plan, 24, 64).expect("distinct subnets");

        // Everything in a subscriber's subnet shares its key, whichever address it is
        let vulnbox = "10.55.1.2:9100".parse().expect("valid test endpoint");
        let player = "10.55.1.57:40000".parse().expect("valid test endpoint");
        let expected = SourceKey::Subnet("10.55.1.0".parse().expect("valid test network"));
        assert_eq!(subnets.source_key(&vulnbox, 1, false), expected);
        assert_eq!(subnets.source_key(&player, 2, false), expected);

        // A neighbouring subscriber is a different key
        let other = "10.55.2.2:9100".parse().expect("valid test endpoint");
        assert_ne!(subnets.source_key(&other, 3, false), expected);

        // A caller that sits nowhere near a subscriber is pooled all the same
        let stranger = "10.99.0.5:40000".parse().expect("valid test endpoint");
        assert_eq!(
            subnets.source_key(&stranger, 7, false),
            SourceKey::Subnet("10.99.0.0".parse().expect("valid test network"))
        );

        // ...unless it is the checker, which needs a bucket per connection
        assert_eq!(
            subnets.source_key(&stranger, 7, true),
            SourceKey::Connection(7)
        );
    }

    #[test]
    fn the_checker_is_picked_out_by_mask_and_pattern() {
        // Not a prefix: this picks the same host out of every subscriber subnet
        let checker = CheckerMatch::new(
            "0.0.0.255".parse().expect("valid test mask"),
            "0.0.0.99".parse().expect("valid test pattern"),
        )
        .expect("pattern fits the mask");
        assert!(checker.matches("10.55.1.99".parse().expect("valid test address")));
        assert!(checker.matches("10.55.42.99".parse().expect("valid test address")));
        assert!(!checker.matches("10.55.1.2".parse().expect("valid test address")));

        // A v6 caller never matches a v4 match, and vice versa
        assert!(!checker.matches("::1".parse().expect("valid test address")));
    }

    #[test]
    fn an_unmatchable_checker_is_refused() {
        // The pattern has bits the mask clears, so nothing could ever match it
        assert!(matches!(
            CheckerMatch::new(
                "255.255.255.0".parse().expect("valid test mask"),
                "10.55.1.99".parse().expect("valid test pattern"),
            ),
            Err(CheckerMatchError::PatternOutsideMask(..))
        ));
        assert!(matches!(
            CheckerMatch::new(
                "255.255.255.0".parse().expect("valid test mask"),
                "::1".parse().expect("valid test pattern"),
            ),
            Err(CheckerMatchError::MixedFamily)
        ));
    }

    #[test]
    fn a_prefix_that_merges_subscribers_is_refused() {
        let plan = plan(&["10.55.1.2", "10.55.2.2"]);
        // /24 keeps them apart, /16 does not
        assert!(Subnets::new(&plan, 24, 64).is_ok());
        assert!(matches!(
            Subnets::new(&plan, 16, 64),
            Err(SubnetError::Collision(..))
        ));
    }

    #[test]
    fn one_subscriber_may_own_a_whole_subnet() {
        // How the CI plan names a network: every address, one number
        let mut plan = plan(&["172.28.5.1"]);
        let number = plan.fixed.values().next().cloned().expect("one entry");
        for address in ["172.28.5.2", "172.28.5.3"] {
            plan.fixed
                .insert(address.parse().expect("valid test address"), number.clone());
        }
        assert!(Subnets::new(&plan, 24, 64).is_ok());
    }

    /// A server on an ephemeral port, for the accounting the accept loop does
    async fn server() -> Server {
        let plan = plan(&["10.55.1.2"]);
        let subnets = Subnets::new(&plan, 24, 64).expect("distinct subnets");
        let checker = CheckerMatch::new(DEFAULT_CHECKER_MASK, DEFAULT_CHECKER_PATTERN)
            .expect("the defaults match");
        let (control, _control) = mpsc::channel(1);
        let (events, _events) = mpsc::channel(1);
        Server::bind(
            plan,
            subnets,
            checker,
            &"127.0.0.1:0".parse().expect("valid test endpoint"),
            control,
            events,
            crate::flood::Monitor::new(),
            Log::disabled(),
        )
        .await
        .expect("binds an ephemeral port")
    }

    #[tokio::test]
    async fn a_source_may_hold_only_so_many_connections() {
        let server = server().await;
        let source = SourceKey::Subnet("10.55.1.0".parse().expect("valid test network"));

        for _ in 0..MAX_CONNECTIONS_PER_SOURCE {
            assert!(server.claim_connection(source, false).await);
        }
        assert!(!server.claim_connection(source, false).await);

        // A neighbour is unaffected: the allowance is per subnet, not global
        let other = SourceKey::Subnet("10.55.2.0".parse().expect("valid test network"));
        assert!(server.claim_connection(other, false).await);

        // One that ends frees exactly one
        Server::release_connection(server.held.clone(), source, false).await;
        assert!(server.claim_connection(source, false).await);
        assert!(!server.claim_connection(source, false).await);

        // The checker is not counted
        for _ in 0..MAX_CONNECTIONS_PER_SOURCE {
            assert!(
                server
                    .claim_connection(SourceKey::Connection(7), true)
                    .await
            );
        }

        // A source that holds nothing is forgotten
        for _ in 0..MAX_CONNECTIONS_PER_SOURCE {
            Server::release_connection(server.held.clone(), source, false).await;
        }
        assert_eq!(
            server.held.lock().await.keys().copied().collect::<Vec<_>>(),
            vec![other]
        );
    }

    #[test]
    fn prefix_lengths_are_bounded() {
        let plan = plan(&["10.55.1.2"]);
        assert!(matches!(
            Subnets::new(&plan, 33, 64),
            Err(SubnetError::InvalidPrefix(33, 4))
        ));
        assert!(matches!(
            Subnets::new(&plan, 24, 129),
            Err(SubnetError::InvalidPrefix(129, 6))
        ));
        // the extremes are legal: /32 is one address, /0 is everything
        assert!(Subnets::new(&plan, 32, 128).is_ok());
        assert!(Subnets::new(&plan, 0, 0).is_ok());
    }
}
