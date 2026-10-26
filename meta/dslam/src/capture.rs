use std::{
    collections::HashMap,
    ffi::OsStr,
    fs::File,
    io::{Error, ErrorKind},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use atm::AtmCell;
use pcap_file::{
    DataLink, Endianness,
    pcapng::{
        PcapNgWriter,
        blocks::{
            enhanced_packet::{EnhancedPacketBlock, EnhancedPacketOption},
            interface_description::{InterfaceDescriptionBlock, InterfaceDescriptionOption},
            interface_statistics::{InterfaceStatisticsBlock, InterfaceStatisticsOption},
            section_header::{SectionHeaderBlock, SectionHeaderOption},
        },
    },
};
use thiserror::Error;
use tokio::sync::mpsc::{self, Receiver, Sender, error::SendTimeoutError};
use tokio_util::sync::CancellationToken;

use crate::connection::{Connection, ConnectionId};

const CAPTURE_QUEUE_SIZE: usize = 8192;

/// Direction in which the packet was going (from the point of view of the DSLAM)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Inbound,
    Outbound,
}

/// A packet
pub struct Packet {
    /// Packet data
    pub cell: AtmCell,

    /// Connection
    pub connection: Arc<Connection>,

    /// Direction of the packet
    pub direction: Direction,

    /// Timestamp of the packet
    pub timestamp: SystemTime,
}

/// A packet capture event
enum CaptureEvent {
    Packet(Packet),
    Connected(SystemTime, Arc<Connection>),
    Disconnected(SystemTime, Arc<Connection>),
}

/// A packet capture object
pub struct Capture {
    /// Receive end of the packet channel
    channel: Receiver<CaptureEvent>,

    /// Output path
    path: PathBuf,

    /// How often was the output file already rotated?
    rotations: usize,
}

/// Interface ID in a pcapng file
type InterfaceId = u32;

/// Internal packet capture state
struct CaptureState {
    interfaces: HashMap<ConnectionId, InterfaceId>,
    next_iid: InterfaceId,
}

/// Interface allocations for a packet
#[derive(Copy, Clone)]
enum InterfaceAllocation {
    New(InterfaceId),
    Existing(InterfaceId),
    None,
}

/// A packet capture client
#[derive(Clone)]
pub struct Client {
    channel: Sender<CaptureEvent>,
}

/// Errors when submitting capture events
#[derive(Debug, Error)]
pub enum ClientError {
    #[error("Event submission timed out")]
    Timeout,
    #[error("Capture channel closed")]
    Closed,
}

impl ClientError {
    /// Is this a permanent status that cannot be recovered from?
    pub const fn is_permanent(&self) -> bool {
        match self {
            ClientError::Timeout => false,
            ClientError::Closed => true,
        }
    }
}

impl Client {
    const SERVER_TIMEOUT: Duration = Duration::from_millis(100);
    const CONNECTION_TIMEOUT: Duration = Duration::from_millis(500);

    /// Adds a new connection to the packet capture
    pub async fn add_connection(&self, connection: Arc<Connection>) -> Result<(), ClientError> {
        match self
            .channel
            .send_timeout(
                CaptureEvent::Connected(SystemTime::now(), connection),
                Self::SERVER_TIMEOUT,
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(SendTimeoutError::Timeout(_)) => Err(ClientError::Timeout),
            Err(SendTimeoutError::Closed(_)) => Err(ClientError::Closed),
        }
    }

    /// Adds a disconnect entry to the packet capture
    pub async fn add_disconnect(&self, connection: Arc<Connection>) -> Result<(), ClientError> {
        match self
            .channel
            .send_timeout(
                CaptureEvent::Disconnected(SystemTime::now(), connection),
                Self::SERVER_TIMEOUT,
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(SendTimeoutError::Timeout(_)) => Err(ClientError::Timeout),
            Err(SendTimeoutError::Closed(_)) => Err(ClientError::Closed),
        }
    }

    /// Adds a packet to the packet capture
    pub async fn add_packet(&self, packet: Packet) -> Result<(), ClientError> {
        match self
            .channel
            .send_timeout(CaptureEvent::Packet(packet), Self::CONNECTION_TIMEOUT)
            .await
        {
            Ok(_) => Ok(()),
            Err(SendTimeoutError::Timeout(_)) => Err(ClientError::Timeout),
            Err(SendTimeoutError::Closed(_)) => Err(ClientError::Closed),
        }
    }
}

impl Capture {
    /// Creates a new packet capture
    pub fn new(path: PathBuf) -> (Client, Capture) {
        let (channel_tx, channel_rx) = mpsc::channel(CAPTURE_QUEUE_SIZE);

        let client = Client {
            channel: channel_tx,
        };
        let capture = Self {
            channel: channel_rx,
            path,
            rotations: 0,
        };
        (client, capture)
    }

    /// Creates the packet capture's output file at `path`
    fn create<P: AsRef<Path>>(path: P) -> std::io::Result<PcapNgWriter<File>> {
        let file = File::create_new(&path)?;
        let section = SectionHeaderBlock {
            endianness: Endianness::native(),
            options: vec![
                SectionHeaderOption::UserApplication("ATMLAB DSLAM".into()),
                SectionHeaderOption::Comment(
                    "This file contains raw ATM cells. Use the provided dissector to parse them."
                        .into(),
                ),
            ],
            ..Default::default()
        };
        PcapNgWriter::with_section_header(file, section).map_err(|error| {
            use std::io::Error;
            tracing::error!("Failed to create capture writer: {error}");
            Error::new(ErrorKind::Other, format!("{error}"))
        })
    }

    /// Rotates the packet capture's output file at `path` away, with `rotations` existing
    /// rotations. Only called from `rotate_output`.
    fn rotate_output_away(path: &Path, rotations: usize) -> std::io::Result<()> {
        let file_name = path
            .file_name()
            .map(OsStr::to_string_lossy)
            .unwrap_or_else(|| "capture".into());
        let mut target = path.with_file_name(format!("{}.{}", file_name, rotations));
        if target.exists() {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                format!(
                    "Rotating output would overwrite {}",
                    target.to_string_lossy()
                ),
            ));
        }
        for previous in (1..rotations).rev() {
            let current = path.with_file_name(format!("{}.{}", file_name, previous));
            std::fs::rename(&current, target)?;
            target = current;
        }
        std::fs::rename(&path, target)
    }

    /// Rotates the output file
    async fn rotate_output(&mut self) -> std::io::Result<PcapNgWriter<File>> {
        if self.path.exists() {
            self.rotations += 1;

            let path = self.path.clone();
            let rotations = self.rotations;
            tokio::task::spawn_blocking(move || Self::rotate_output_away(&path, rotations))
                .await??;
        }
        Self::create(&self.path)
    }

    /// Link type for our interfaces
    ///
    /// Of the ATM-related libpcap link types, none let us preserve the entire ATM cell:
    ///  - `LINKTYPE_ATM_RFC1483` expects reassembled AAL5 PDUs inside the LLC frame
    ///  - `LINKTYPE_ATM_CLIP` expects "Classical IP" packets
    ///    (an optional LLC/SNAP header plus an IP packet, both from the reassembled AAL5 payload)
    ///  - `LINKTYPE_SUNATM` at least supports individual ATM cells, but we have to strip the
    ///    header down to only VPI and VCI. This loses the PTI field, which we need to separate
    ///    OAM traffic from actual user traffic.
    ///
    /// Various other proprietary formats are not well-documented and don't result in ATM
    /// dissection (e.g., Juniper), and the dedicated "raw ATM" format did not make it in
    /// (see https://seclists.org/tcpdump/2009/q2/159).
    ///
    /// We can encapsulate (almost) a full ATM cell into an ERF record (this is the Endance
    /// Extensible Record Format, `LINKTYPE_ERF`), but we have to strip out the HEC checksum.
    /// See https://www.endace.com/erf-extensible-record-format-types.pdf for more details.
    ///
    /// However, Wireshark is not actually able to reassemble AAL5 PDUs, so we need a custom
    /// dissector anyways. That makes it very easy for us to just use `LINKTYPE_USER0` and dump raw
    /// ATM cells into the file.
    const LINK_TYPE: DataLink = DataLink::USER0;

    /// Runs the packet capture until a fatal error occurs or the shutdown token is set
    pub async fn run(mut self, global_shutdown: CancellationToken) {
        let mut writer = match Self::create(&self.path) {
            Ok(writer) => writer,
            Err(error) => {
                tracing::error!(
                    "Failed to create packet capture file at {}: {}",
                    self.path.to_string_lossy(),
                    error
                );
                return;
            }
        };

        loop {
            let mut state = CaptureState::new();

            while !state.should_rotate() {
                let event = tokio::select! {
                    _ = global_shutdown.cancelled() => return,
                    result = self.channel.recv() => match result {
                        Some(event) => event,
                        None => return,
                    }
                };

                let connection = match &event {
                    CaptureEvent::Packet(packet) => &packet.connection,
                    CaptureEvent::Connected(_, connection) => &connection,
                    CaptureEvent::Disconnected(_, connection) => &connection,
                };

                let interface = match &event {
                    CaptureEvent::Packet(_) => state.get_or_allocate_interface(connection.id),
                    CaptureEvent::Connected(_, _) => state.get_or_allocate_interface(connection.id),
                    CaptureEvent::Disconnected(_, _) => state.get_interface(connection.id),
                };

                if let InterfaceAllocation::New(_) = interface {
                    // Add an interface block for this interface ID
                    let name = format!("conn{}", connection.id);
                    let description = format!("{} on {}", connection.local, connection.remote);
                    let block = InterfaceDescriptionBlock {
                        linktype: Self::LINK_TYPE,
                        snaplen: 0,
                        options: vec![
                            InterfaceDescriptionOption::IfName(name.into()),
                            InterfaceDescriptionOption::IfDescription(description.into()),
                            // No IfTsresol, so timestamps are in microseconds.
                        ],
                    };

                    if let Err(error) = writer.write_pcapng_block(block) {
                        tracing::error!(
                            "Failed to write interface description block to file: {error}"
                        );
                        return;
                    }
                }

                // Finally, write the actual block for this event.
                // This only makes sense if we have an interface ID to reference.
                let Some(interface_id) = interface.interface_id() else {
                    if let CaptureEvent::Packet(_) = event {
                        tracing::error!("No interface ID allocated for packet.");
                        return;
                    }
                    continue;
                };

                match event {
                    CaptureEvent::Packet(packet) => {
                        // The low two bits of the flags indicate the traffic direction
                        let flags = match packet.direction {
                            Direction::Inbound => 0b01u32,
                            Direction::Outbound => 0b10u32,
                        };

                        let block = EnhancedPacketBlock {
                            interface_id,
                            timestamp: packet
                                .timestamp
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default(),
                            original_len: packet.cell.len() as u32,
                            data: packet.cell.to_vec().into(),
                            options: vec![EnhancedPacketOption::Flags(flags)],
                        };

                        if let Err(error) = writer.write_pcapng_block(block) {
                            tracing::error!("Failed to write packet to file: {error}");
                            return;
                        }
                    }
                    CaptureEvent::Connected(time, _) | CaptureEvent::Disconnected(time, _) => {
                        let now = time
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_micros() as u64;

                        let option = match event {
                            CaptureEvent::Packet(_) => unreachable!(),
                            CaptureEvent::Connected(_, _) => {
                                InterfaceStatisticsOption::IsbStartTime(now)
                            }
                            CaptureEvent::Disconnected(_, _) => {
                                InterfaceStatisticsOption::IsbEndTime(now)
                            }
                        };

                        let block = InterfaceStatisticsBlock {
                            interface_id,
                            timestamp: now,
                            options: vec![option],
                        };

                        if let Err(error) = writer.write_pcapng_block(block) {
                            tracing::error!("Failed to write connection event to file: {error}");
                            return;
                        }
                    }
                }
            }

            tracing::debug!("Rotating packet capture file");
            writer = match self.rotate_output().await {
                // Don't select! this against the token, we want a complete rotation or none
                Ok(writer) => writer,
                Err(error) => {
                    tracing::error!(
                        "Failed to rotate packet capture file at {}: {}",
                        self.path.to_string_lossy(),
                        error
                    );
                    return;
                }
            }
        }
    }
}

impl CaptureState {
    /// Creates a new capture state
    fn new() -> Self {
        Self {
            interfaces: HashMap::new(),
            next_iid: 0,
        }
    }

    /// Returns the interface ID for this connection
    fn get_interface(&self, connection: ConnectionId) -> InterfaceAllocation {
        match self.interfaces.get(&connection) {
            Some(iid) => InterfaceAllocation::Existing(*iid),
            None => InterfaceAllocation::None,
        }
    }

    /// Returns the interface ID for this connection, or allocates one if none is assigned yet
    fn get_or_allocate_interface(&mut self, connection: ConnectionId) -> InterfaceAllocation {
        match self.interfaces.get(&connection) {
            Some(iid) => InterfaceAllocation::Existing(*iid),
            None => {
                let current = self.next_iid;
                self.next_iid = self
                    .next_iid
                    .checked_add(1)
                    .expect("Out of interface IDs, and did not rotate in time.");
                self.interfaces.insert(connection, current);
                InterfaceAllocation::New(current)
            }
        }
    }

    /// Whether the capture file should be rotated
    fn should_rotate(&self) -> bool {
        self.next_iid > u32::MAX - 65535
    }
}

impl InterfaceAllocation {
    /// Returns the interface ID associated with this interface allocation
    pub fn interface_id(&self) -> Option<InterfaceId> {
        match self {
            InterfaceAllocation::New(iid) => Some(*iid),
            InterfaceAllocation::Existing(iid) => Some(*iid),
            InterfaceAllocation::None => None,
        }
    }
}
