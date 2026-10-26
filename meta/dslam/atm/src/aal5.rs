#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

/// Data structures and constants for AAL5, the ATM Adaption Layer 5
use alloc::vec::Vec;

use bitfield::bitfield;
use crc::Crc;

use crate::{ATM_HEADER_SIZE, ATM_PAYLOAD_SIZE, AtmCell, CellHeader, Pti};

/// The AAL5 trailer checksum
const AAL5_CRC: Crc<u32> = Crc::<u32>::new(&crc::CRC_32_BZIP2);

/// Trailer size for an AAL5 CPCS-PDU
pub const AAL5_TRAILER_SIZE: usize = 8;

/// Absolute maximum size of an AAL5 CPCS-PDU plus padding and trailer
/// This is an overestimate (an extra cell is added regardless of whether there is space for the
/// trailer).
pub const AAL5_MAX_SIZE: usize =
    (u16::MAX as usize).next_multiple_of(ATM_PAYLOAD_SIZE) + ATM_PAYLOAD_SIZE;

bitfield! {
    /// An AAL5 CPCS-PDU trailer.
    #[derive(Clone)]
    pub struct CpcsPduTrailer(MSB0 [u8]);
    impl Debug;
    u8;
    #[inline] pub      uu,     set_uu:      7,  0;
    #[inline] pub      cpi,    set_cpi:    15,  8;
    #[inline] pub u16, length, set_length: 31, 16;
    #[inline] pub u32, crc,    set_crc:    63, 32;
}

impl<T: AsRef<[u8]>> CpcsPduTrailer<T> {
    /// I.363.5 § 9.2.1.2 (d)
    /// "A Length field coded as zero is used for the abort function"
    pub fn is_abort(&self) -> bool {
        self.length() == 0
    }

    /// Computes the expected CRC (I.363.5 § 9.2.1.2 (f))
    /// This requires the full data, not just the trailer.
    pub fn expected_crc(cpcs_pdu: &[u8]) -> u32 {
        AAL5_CRC.checksum(&cpcs_pdu[..cpcs_pdu.len() - 4])
    }
}

impl CpcsPduTrailer<&[u8]> {
    /// Copies the data in the trailer to produce an owned copy.
    pub fn to_owned(&self) -> CpcsPduTrailer<[u8; AAL5_TRAILER_SIZE]> {
        let mut trailer = CpcsPduTrailer([0u8; AAL5_TRAILER_SIZE]);
        trailer.0.copy_from_slice(self.0);
        trailer
    }
}

impl CpcsPduTrailer<[u8; AAL5_TRAILER_SIZE]> {
    /// Computes the trailer (length and CRC) for a payload, without taking ownership of
    /// the data (see [`OwnedCpcsPdu::new`]; together with a borrowed [`CpcsPdu`], this
    /// allows segmentation without any allocation).
    /// Returns `None` if the data does not fit the 16-bit length field of the trailer.
    pub fn compute(data: &[u8], uu: u8, cpi: u8) -> Option<Self> {
        let length: u16 = data.len().try_into().ok()?;

        let mut trailer = CpcsPduTrailer([0u8; AAL5_TRAILER_SIZE]);
        trailer.set_uu(uu);
        trailer.set_cpi(cpi);
        trailer.set_length(length);

        // The CRC covers the padded payload and the first four bytes of the trailer
        // (I.363.5 § 9.2.1.2 (f)). Padding fills the last cell up to the trailer.
        let padded_len =
            (data.len() + AAL5_TRAILER_SIZE).next_multiple_of(ATM_PAYLOAD_SIZE) - AAL5_TRAILER_SIZE;
        let padding = [0u8; ATM_PAYLOAD_SIZE];
        let mut digest = AAL5_CRC.digest();
        digest.update(data);
        digest.update(&padding[..padded_len - data.len()]);
        digest.update(&trailer.0[..AAL5_TRAILER_SIZE - 4]);
        trailer.set_crc(digest.finalize());

        Some(trailer)
    }

}

impl<T: AsRef<[u8]>> core::borrow::Borrow<[u8]> for CpcsPduTrailer<T> {
    /// Borrows the raw trailer bytes, e.g. to build a borrowed [`CpcsPdu`]
    fn borrow(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// An (unpadded) AAL5 CPCS-PDU, split between payload (reference) and trailer (owned)
#[derive(Clone, Debug)]
pub struct CpcsPdu<'data> {
    pub data: &'data [u8],
    pub trailer: CpcsPduTrailer<&'data [u8]>,
}

impl<'data> CpcsPdu<'data> {
    /// Yields the ATM cells needed to transfer this CPCS-PDU, with an empty header except the AUU
    pub fn segments(&self) -> impl Iterator<Item = AtmCell> {
        CpcsPduSegmentIterator::new(&self.data, CpcsPduTrailer(self.trailer.0))
    }

    /// Transforms the CPCS-PDU into an owned copy (by copying the data), moving the trailer
    pub fn into_owned(self) -> OwnedCpcsPdu {
        OwnedCpcsPdu {
            data: self.data.to_vec(),
            trailer: self.trailer.to_owned(),
        }
    }
}

/// An owned, unpadded AAL5 CPCS-PDU, split between payload and trailer
#[derive(Clone, Debug)]
pub struct OwnedCpcsPdu {
    pub data: Vec<u8>,
    pub trailer: CpcsPduTrailer<[u8; AAL5_TRAILER_SIZE]>,
}

impl OwnedCpcsPdu {
    /// Builds a CPCS-PDU for transmission, computing the trailer (length and CRC) for the data.
    /// Returns `None` if the data does not fit the 16-bit length field of the trailer.
    pub fn new(data: Vec<u8>, uu: u8, cpi: u8) -> Option<Self> {
        let trailer = CpcsPduTrailer::compute(&data, uu, cpi)?;
        Some(Self { data, trailer })
    }

    /// Yields the ATM cells needed to transfer this CPCS-PDU, with an empty header except the AUU
    pub fn segments(&self) -> impl Iterator<Item = AtmCell> {
        CpcsPduSegmentIterator::new(&self.data, CpcsPduTrailer(&self.trailer.0))
    }
}

/// ATM cell iterator for a `CpcsPdu` or `OwnedCpcsPdu`.
pub struct CpcsPduSegmentIterator<'life> {
    data: &'life [u8],
    trailer: CpcsPduTrailer<&'life [u8]>,
    position: usize,
    trailer_sent: bool,
}

impl<'life> CpcsPduSegmentIterator<'life> {
    fn new(data: &'life [u8], trailer: CpcsPduTrailer<&'life [u8]>) -> Self {
        Self {
            data,
            trailer,
            position: 0,
            trailer_sent: false,
        }
    }
}

impl<'life> Iterator for CpcsPduSegmentIterator<'life> {
    type Item = AtmCell;

    fn next(&mut self) -> Option<Self::Item> {
        if self.trailer_sent {
            return None;
        }

        let mut cell = AtmCell::default();
        let (header, body) = (&mut cell[..]).split_at_mut(ATM_HEADER_SIZE);
        let mut header = CellHeader(header);
        header.set_pti(Pti::UserDataCell0);

        let to_copy = ATM_PAYLOAD_SIZE.min(self.data.len() - self.position);
        if to_copy > 0 {
            let cell_data = &mut body[..to_copy];
            let pdu_data = &self.data[self.position..self.position + to_copy];
            cell_data.copy_from_slice(pdu_data);
            self.position += to_copy;
        }
        if to_copy <= ATM_PAYLOAD_SIZE - AAL5_TRAILER_SIZE {
            let cell_trailer = &mut body[ATM_PAYLOAD_SIZE - AAL5_TRAILER_SIZE..];
            cell_trailer.copy_from_slice(&self.trailer.0);
            header.set_pti(Pti::UserDataCell1);
            self.trailer_sent = true;
        }
        return Some(cell);
    }
}

/// Errors that can be detected from the AAL5 trailer
#[derive(Debug)]
pub enum TrailerError {
    Truncated,
    TooMuchPadding,
    BadChecksum(u32 /* Value computed from actual data */),
}

impl core::fmt::Display for TrailerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TrailerError::Truncated => write!(f, "Truncated CPCS-PDU or missing data"),
            TrailerError::TooMuchPadding => write!(f, "Excessive padding"),
            TrailerError::BadChecksum(_) => write!(f, "Trailer checksum mismatch"),
        }
    }
}

/// Either a non-AAL5 ATM cell, or a reassembled CPCS-PDU, or a partially reassembled CPCS-PDU.
/// Or the "error states": a discarded bit of data (from too long cells etc.) or an invalid PDU.
pub enum Pdu {
    Reassembled(OwnedCpcsPdu),
    Raw(AtmCell),
    Discarded(Vec<u8>),
    Invalid(OwnedCpcsPdu, TrailerError),
}

/// An AAL5 reassembler
pub struct Reassembler {
    data: Vec<u8>,
}

impl Reassembler {
    /// Creates a new reassembler
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Reassembles a PDU starting at the current state.
    /// Finished cells or PDUs are returned, the local state will always be Partial.
    /// If the current state is a finished CPCS-PDU or raw cell, it is discarded.
    pub fn reassemble(&mut self, cell: &AtmCell) -> Option<Pdu> {
        // XXX Abort?
        let more = match cell.header().pti() {
            Pti::UserDataCell0 | Pti::UserDataCellCongested0 => true,
            Pti::UserDataCell1 | Pti::UserDataCellCongested1 => false,
            _ => return Some(Pdu::Raw(cell.clone())),
        };

        self.data.extend_from_slice(&cell[ATM_HEADER_SIZE..]);
        if self.data.len() > AAL5_MAX_SIZE {
            return Some(Pdu::Discarded(core::mem::take(&mut self.data)));
        }

        if more {
            return None;
        }

        // Compute the CRC
        let crc = CpcsPduTrailer::<&[u8]>::expected_crc(&self.data);
        let padded_len = self.data.len() - AAL5_TRAILER_SIZE;

        // Remove the trailer from the data
        let mut trailer = [0u8; AAL5_TRAILER_SIZE];
        trailer.copy_from_slice(&self.data[padded_len..]);
        let trailer = CpcsPduTrailer(trailer);

        // Build the PDU
        let mut cpcs_pdu = OwnedCpcsPdu {
            data: core::mem::take(&mut self.data),
            trailer,
        };

        // Check that we have the entire PDU
        let pdu_len: usize = cpcs_pdu
            .trailer
            .length()
            .try_into()
            .expect("u16 did not fit into usize");
        if pdu_len > cpcs_pdu.data.len() {
            return Some(Pdu::Invalid(cpcs_pdu, TrailerError::Truncated));
        }

        // Check that there is not excessive padding: the trailer sits at the very end of the
        // last cell, so payload, padding and trailer together fill a whole number of cells.
        let expected_total_len =
            (pdu_len + AAL5_TRAILER_SIZE).next_multiple_of(ATM_PAYLOAD_SIZE);
        if expected_total_len != cpcs_pdu.data.len() {
            return Some(Pdu::Invalid(cpcs_pdu, TrailerError::TooMuchPadding));
        }

        // Check the CRC
        if crc != cpcs_pdu.trailer.crc() {
            return Some(Pdu::Invalid(cpcs_pdu, TrailerError::BadChecksum(crc)));
        }

        // Remove the padding and trailer from the data
        cpcs_pdu.data.truncate(pdu_len);
        return Some(Pdu::Reassembled(cpcs_pdu));
    }
}

#[cfg(test)]
mod tests {
    use core::borrow::Borrow;

    use super::*;

    /// Segmentation and reassembly must round-trip for all padding shapes:
    /// plenty of room for the trailer, an exact fit, and a trailer that spills
    /// into an extra cell.
    #[test]
    fn segment_reassemble_roundtrip() {
        for size in [
            0usize, 1, 16, 24, 36, 39, 40, 41, 47, 48, 49, 80, 88, 95, 96, 100, 1000,
        ] {
            let data: Vec<u8> = (0..size).map(|value| value as u8).collect();
            let pdu = OwnedCpcsPdu::new(data.clone(), 0x42, 0).expect("data fits a CPCS-PDU");

            // The borrowed (allocation-free) path must produce identical cells
            let trailer =
                CpcsPduTrailer::compute(&data, 0x42, 0).expect("data fits a CPCS-PDU");
            let borrowed = CpcsPdu {
                data: &data,
                trailer: CpcsPduTrailer(trailer.borrow()),
            };
            assert!(
                pdu.segments().eq(borrowed.segments()),
                "borrowed segmentation mismatch for size {size}"
            );

            let mut reassembler = Reassembler::new();
            let mut result = None;
            let mut cells = 0;
            for cell in pdu.segments() {
                cells += 1;
                assert!(result.is_none(), "PDU of size {size} ended early");
                result = reassembler.reassemble(&cell);
            }

            let expected_cells =
                (size + AAL5_TRAILER_SIZE).next_multiple_of(ATM_PAYLOAD_SIZE) / ATM_PAYLOAD_SIZE;
            assert_eq!(cells, expected_cells, "wrong cell count for size {size}");

            match result {
                Some(Pdu::Reassembled(reassembled)) => {
                    assert_eq!(reassembled.data, data, "data mismatch for size {size}");
                    assert_eq!(reassembled.trailer.uu(), 0x42);
                    assert_eq!(reassembled.trailer.cpi(), 0);
                }
                Some(Pdu::Invalid(_, error)) => panic!("invalid PDU for size {size}: {error}"),
                Some(_) => panic!("unexpected PDU type for size {size}"),
                None => panic!("PDU of size {size} never completed"),
            }
        }
    }
}
