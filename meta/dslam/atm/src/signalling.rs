#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

/// Simplified ATKLAB signalling (over AAL5 on a fixed circuit).
// I am _not_ going to try implementing Q.2931 over SSCOP again.
use bitfield::bitfield;

use crate::VirtualCircuit;

pub const E191_ADDRESS_SIZE: usize = 20;
pub type E191AddressField = [u8; E191_ADDRESS_SIZE];

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u32)]
pub enum MessageType {
    Establish = 0u32,
    Established = 1u32,
    Release = 2u32,
    Released = 3u32,
    GenericError = 10u32,
    InvalidAddress = 11u32,
    Unreachable = 12u32,
    RejectedCircuit = 13u32,
    NotPermitted = 14u32,
    QuotaExceeded = 15u32,
    Congested = 16u32,
}
impl From<MessageType> for u32 {
    fn from(value: MessageType) -> Self {
        value as Self
    }
}
impl TryFrom<u32> for MessageType {
    type Error = u32;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        let converted = match value {
            0 => Self::Establish,
            1 => Self::Established,
            2 => Self::Release,
            3 => Self::Released,
            10 => Self::GenericError,
            11 => Self::InvalidAddress,
            12 => Self::Unreachable,
            13 => Self::RejectedCircuit,
            14 => Self::NotPermitted,
            15 => Self::QuotaExceeded,
            16 => Self::Congested,
            _ => return Err(value),
        };
        assert!(
            converted as u32 == value,
            "Invalid conversion for atm::signalling::MessageType"
        );
        Ok(converted)
    }
}
impl core::fmt::Display for MessageType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MessageType::Establish => write!(f, "ESTABLISH"),
            MessageType::Established => write!(f, "ESTABLISHED"),
            MessageType::Release => write!(f, "RELEASE"),
            MessageType::Released => write!(f, "RELEASED"),
            MessageType::GenericError => write!(f, "GENERIC_ERROR"),
            MessageType::InvalidAddress => write!(f, "INVALID_ADDRESS"),
            MessageType::Unreachable => write!(f, "UNREACHABLE"),
            MessageType::RejectedCircuit => write!(f, "REJECTED_CIRCUIT"),
            MessageType::NotPermitted => write!(f, "NOT_PERMITTED"),
            MessageType::QuotaExceeded => write!(f, "QUOTA_EXCEEDED"),
            MessageType::Congested => write!(f, "CONGESTED"),
        }
    }
}
impl MessageType {
    pub fn payload_size(self) -> usize {
        match self {
            Self::Establish => E191_ADDRESS_SIZE + CIRCUIT_SIZE,
            Self::Release => CIRCUIT_SIZE,
            _ => 0,
        }
    }

    pub fn is_error(self) -> bool {
        self as u32 >= Self::GenericError as u32
    }
}

bitfield! {
    /// A signaling cell header.
    struct Header(MSB0 [u8]);
    impl Debug;
    u32;
    #[inline] pub from try_into MessageType, message_type, set_message_type: 31, 0;
    #[inline] pub id, set_id: 63, 32;
}
pub const HEADER_SIZE: usize = 8;

bitfield! {
    /// A VPI/VCI pair.
    struct CircuitTrailer(MSB0 [u8]);
    impl Debug;
    u32;
    #[inline] pub vpi, set_vpi: 31, 0;
    #[inline] pub vci, set_vci: 63, 32;
}
pub const CIRCUIT_SIZE: usize = 8;

// An ESTABLISH (type 0) message is a 20 byte E.191 address, followed by 32-bit VPI and VCI.
// A RELEASE (type 2) message is just the VPI and VCI

/// A signalling message
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Message {
    Establish {
        id: u32,
        address: E191AddressField,
        circuit: VirtualCircuit,
    },
    Established {
        id: u32,
    },
    Release {
        id: u32,
        circuit: VirtualCircuit,
    },
    Released {
        id: u32,
    },
    Error {
        id: u32,
        error: MessageType,
    },
}

/// Maximum encoded size of a signalling message
pub const MAX_MESSAGE_SIZE: usize = HEADER_SIZE + E191_ADDRESS_SIZE + CIRCUIT_SIZE;

impl Message {
    /// Returns the message type tag for this message
    pub fn message_type(&self) -> MessageType {
        match self {
            Message::Establish { .. } => MessageType::Establish,
            Message::Established { .. } => MessageType::Established,
            Message::Release { .. } => MessageType::Release,
            Message::Released { .. } => MessageType::Released,
            Message::Error { error, .. } => *error,
        }
    }

    /// Returns the message ID
    pub fn id(&self) -> u32 {
        match self {
            Message::Establish { id, .. }
            | Message::Established { id }
            | Message::Release { id, .. }
            | Message::Released { id }
            | Message::Error { id, .. } => *id,
        }
    }

    /// Returns the encoded size of this message (at most [`MAX_MESSAGE_SIZE`])
    pub fn encoded_size(&self) -> usize {
        HEADER_SIZE + self.message_type().payload_size()
    }

    /// Encodes the message into the front of `buffer`, returning the number of bytes written.
    ///
    /// Panics if `buffer` is smaller than [`Message::encoded_size`].
    pub fn write_to(&self, buffer: &mut [u8]) -> usize {
        if let Message::Error { error, .. } = self {
            debug_assert!(
                error.is_error(),
                "Message::Error must carry an error message type"
            );
        }

        {
            let mut header = Header(&mut buffer[..HEADER_SIZE]);
            header.set_message_type(self.message_type());
            header.set_id(self.id());
        }

        match self {
            Message::Establish {
                address, circuit, ..
            } => {
                buffer[HEADER_SIZE..HEADER_SIZE + E191_ADDRESS_SIZE].copy_from_slice(address);
                let mut trailer = CircuitTrailer(
                    &mut buffer[HEADER_SIZE + E191_ADDRESS_SIZE
                        ..HEADER_SIZE + E191_ADDRESS_SIZE + CIRCUIT_SIZE],
                );
                trailer.set_vpi(circuit.vpi.into());
                trailer.set_vci(circuit.vci.into());
            }
            Message::Release { circuit, .. } => {
                let mut trailer =
                    CircuitTrailer(&mut buffer[HEADER_SIZE..HEADER_SIZE + CIRCUIT_SIZE]);
                trailer.set_vpi(circuit.vpi.into());
                trailer.set_vci(circuit.vci.into());
            }
            _ => {}
        }

        self.encoded_size()
    }
}

#[derive(Debug)]
pub enum MessageParseError {
    HeaderTruncated,
    InvalidType { tag: u32 },
    WrongPayloadLength { length: usize, tag: MessageType },
    InvalidCircuit { vpi: u32, vci: u32 },
}

impl core::fmt::Display for MessageParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MessageParseError::HeaderTruncated => write!(f, "Message header is truncated"),
            MessageParseError::InvalidType { tag } => write!(f, "Invalid message type {tag}"),
            MessageParseError::WrongPayloadLength { length, tag } => {
                write!(f, "Wrong payload length {length} for message type {tag}")
            }
            MessageParseError::InvalidCircuit { vpi, vci } => {
                write!(f, "Invalid circuit {vpi}.{vci}")
            }
        }
    }
}

impl core::error::Error for MessageParseError {}

impl TryFrom<&[u8]> for Message {
    type Error = MessageParseError;

    fn try_from(value: &[u8]) -> Result<Self, <Self as TryFrom<&[u8]>>::Error> {
        if value.len() < HEADER_SIZE {
            return Err(MessageParseError::HeaderTruncated);
        }
        let (header, payload) = value.split_at(HEADER_SIZE);

        let header = Header(header);
        let message_type = header
            .message_type()
            .map_err(|tag| MessageParseError::InvalidType { tag })?;
        let id = header.id();

        if payload.len() != message_type.payload_size() {
            return Err(MessageParseError::WrongPayloadLength {
                length: payload.len(),
                tag: message_type,
            });
        }

        Ok(match message_type {
            MessageType::Establish => {
                let (address_ref, circuit_ref) = payload.split_at(E191_ADDRESS_SIZE);
                let circuit_ref = CircuitTrailer(circuit_ref);

                let mut address: E191AddressField = [0u8; _];
                address.copy_from_slice(address_ref);

                let vpi = circuit_ref.vpi();
                let vci = circuit_ref.vci();

                let Ok(vpi): Result<u8, _> = vpi.try_into() else {
                    return Err(MessageParseError::InvalidCircuit { vpi, vci });
                };
                let Ok(vci): Result<u16, _> = vci.try_into() else {
                    return Err(MessageParseError::InvalidCircuit {
                        vpi: vpi.into(),
                        vci,
                    });
                };
                let circuit = VirtualCircuit { vpi, vci };

                Message::Establish {
                    id,
                    address,
                    circuit,
                }
            }
            MessageType::Established => Message::Established { id },
            MessageType::Release => {
                let circuit_ref = CircuitTrailer(payload);

                let vpi = circuit_ref.vpi();
                let vci = circuit_ref.vci();

                let Ok(vpi): Result<u8, _> = vpi.try_into() else {
                    return Err(MessageParseError::InvalidCircuit { vpi, vci });
                };
                let Ok(vci): Result<u16, _> = vci.try_into() else {
                    return Err(MessageParseError::InvalidCircuit {
                        vpi: vpi.into(),
                        vci,
                    });
                };
                let circuit = VirtualCircuit { vpi, vci };

                Message::Release { id, circuit }
            }
            MessageType::Released => Message::Released { id },
            _ if message_type.is_error() => Message::Error {
                id,
                error: message_type,
            },
            _ => unreachable!(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(message: Message) {
        // A dirty buffer, so the test catches stale bytes that only parse by accident
        let mut buffer = [0xAAu8; MAX_MESSAGE_SIZE];
        let length = message.write_to(&mut buffer);
        assert_eq!(length, message.encoded_size());
        let parsed = Message::try_from(&buffer[..length]).expect("encoded message must parse");
        assert_eq!(parsed, message);
    }

    #[test]
    fn message_roundtrips() {
        let mut address = [0u8; E191_ADDRESS_SIZE];
        address[0] = 45;
        address[1] = 0x12;
        let circuit = VirtualCircuit { vpi: 3, vci: 1234 };

        roundtrip(Message::Establish {
            id: 7,
            address,
            circuit,
        });
        roundtrip(Message::Established { id: u32::MAX });
        roundtrip(Message::Release { id: 0, circuit });
        roundtrip(Message::Released { id: 1 });
        for error in [
            MessageType::GenericError,
            MessageType::InvalidAddress,
            MessageType::Unreachable,
            MessageType::RejectedCircuit,
        ] {
            roundtrip(Message::Error { id: 99, error });
        }
    }

    /// The wire format is big-endian ("network byte order"); clients must match this.
    #[test]
    fn wire_format_is_big_endian() {
        let mut buffer = [0u8; MAX_MESSAGE_SIZE];

        let length = Message::Released { id: 0x0102_0304 }.write_to(&mut buffer);
        assert_eq!(length, 8);
        assert_eq!(&buffer[..length], &[0, 0, 0, 3, 1, 2, 3, 4]);

        let circuit = VirtualCircuit { vpi: 1, vci: 0x0203 };
        let length = Message::Release { id: 5, circuit }.write_to(&mut buffer);
        assert_eq!(length, 16);
        assert_eq!(
            &buffer[..length],
            &[0, 0, 0, 2, 0, 0, 0, 5, 0, 0, 0, 1, 0, 0, 2, 3]
        );
    }
}
