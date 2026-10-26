#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

// Reassembly needs growable buffers even without std
extern crate alloc;

/// Data structures and constants for ATM (Asynchronous Transfer Mode) networks
use core::ops::{Deref, DerefMut};

use bitfield::bitfield;
use crc::Crc;

pub mod aal5;
pub mod oam;
pub mod signalling;

/// Size of an ATM cell
pub const ATM_CELL_SIZE: usize = 53;

/// Header size of an ATM cell
pub const ATM_HEADER_SIZE: usize = 5;

/// Payload size of an ATM cell
pub const ATM_PAYLOAD_SIZE: usize = ATM_CELL_SIZE - ATM_HEADER_SIZE;

/// An ATM cell
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct AtmCell(pub [u8; ATM_CELL_SIZE]);

impl Deref for AtmCell {
    type Target = [u8; ATM_CELL_SIZE];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for AtmCell {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Default for AtmCell {
    fn default() -> Self {
        Self([0u8; _])
    }
}

impl AtmCell {
    pub fn header(&self) -> CellHeader<&[u8]> {
        CellHeader(&self.0)
    }

    pub fn header_mut(&mut self) -> CellHeader<&mut [u8]> {
        CellHeader(&mut self.0)
    }
}

/// The ATM header checksum (HEC)
const ATM_HEC: Crc<u8> = Crc::<u8>::new(&crc::CRC_8_I_432_1);

/// A virtual circuit identifier (VPI and VCI)
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct VirtualCircuit {
    pub vpi: u8,
    pub vci: u16,
}

impl VirtualCircuit {
    /// SSCOP/Q.2931 (and other) signalling is sent on VPI 0, VCI 5
    pub fn is_signalling(&self) -> bool {
        self.vpi == 0 && self.vci == 5
    }

    /// ILMI (SNMP over ATM) is sent on VPI 0, VCI 18
    pub fn is_ilmi(&self) -> bool {
        self.vpi == 0 && self.vci == 18
    }
}

impl core::fmt::Display for VirtualCircuit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "VPI {}, VCI {}", self.vpi, self.vci)
    }
}

#[derive(Debug)]
pub enum VirtualCircuitParseError {
    Empty,
    NoSeparator,
    InvalidVpi,
    InvalidVci,
    TooManyParts,
}

impl core::fmt::Display for VirtualCircuitParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VirtualCircuitParseError::Empty => write!(f, "The empty string is not a valid VC"),
            VirtualCircuitParseError::NoSeparator => {
                write!(f, "No separator found between VPI and VCI")
            }
            VirtualCircuitParseError::InvalidVpi => write!(f, "Invalid VPI"),
            VirtualCircuitParseError::InvalidVci => write!(f, "Invalid VCI"),
            VirtualCircuitParseError::TooManyParts => write!(f, "Too many separators"),
        }
    }
}

impl core::error::Error for VirtualCircuitParseError {}

#[cfg(feature = "std")]
impl std::str::FromStr for VirtualCircuit {
    type Err = VirtualCircuitParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(VirtualCircuitParseError::Empty);
        }

        let mut iterator = s.split(&['.', ':', '/']);
        let vpi_str = iterator.next().ok_or(VirtualCircuitParseError::Empty)?;
        let vci_str = iterator
            .next()
            .ok_or(VirtualCircuitParseError::NoSeparator)?;
        if iterator.next().is_some() {
            return Err(VirtualCircuitParseError::TooManyParts);
        }

        let vpi = vpi_str
            .parse()
            .map_err(|_| VirtualCircuitParseError::InvalidVpi)?;
        let vci = vci_str
            .parse()
            .map_err(|_| VirtualCircuitParseError::InvalidVci)?;
        Ok(Self { vpi, vci })
    }
}

/// PTI codes at F5 level (I.610 table 2)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Pti {
    UserDataCell0 = 0b000,
    UserDataCell1 = 0b001,
    UserDataCellCongested0 = 0b010,
    UserDataCellCongested1 = 0b011,
    SegmentOamF5Cell = 0b100,
    EndToEndOamF5Cell = 0b101,
    ResourceManagementCell = 0b110,
    Reserved = 0b111,
}
impl From<Pti> for u8 {
    fn from(value: Pti) -> Self {
        value as Self
    }
}
impl From<u8> for Pti {
    fn from(value: u8) -> Self {
        match value {
            0b000 => Self::UserDataCell0,
            0b001 => Self::UserDataCell1,
            0b010 => Self::UserDataCellCongested0,
            0b011 => Self::UserDataCellCongested1,
            0b100 => Self::SegmentOamF5Cell,
            0b101 => Self::EndToEndOamF5Cell,
            0b110 => Self::ResourceManagementCell,
            _ => Self::Reserved,
        }
    }
}

bitfield! {
    /// An (UNI) ATM cell header. We only deal with the UNI format; the only difference to the NNI format
    /// is that in that format, the GFC field (top 4 bits of the first byte) is merged into the VPI field
    /// (for 12 instead of 8 bits).
    pub struct CellHeader(MSB0 [u8]);
    impl Debug;
    u8;
    #[inline] pub                    gfc, set_gfc:  3,  0;
    #[inline] pub                    vpi, set_vpi: 11,  4;
    #[inline] pub u16,               vci, set_vci: 27, 12;
    #[inline] pub u8, from into Pti, pti, set_pti: 30, 28;
    #[inline] pub                    clp, set_clp: 31;
    #[inline] pub                    hec, set_hec: 39, 32;
}

impl<T: AsRef<[u8]>> CellHeader<T> {
    pub fn circuit(&self) -> VirtualCircuit {
        VirtualCircuit {
            vpi: self.vpi(),
            vci: self.vci(),
        }
    }

    pub fn expected_hec(&self) -> u8 {
        ATM_HEC.checksum(&self.0.as_ref()[..4])
    }
}

impl<T: AsMut<[u8]> + AsRef<[u8]>> CellHeader<T> {
    pub fn fix_hec(&mut self) {
        self.set_hec(self.expected_hec());
    }
}
