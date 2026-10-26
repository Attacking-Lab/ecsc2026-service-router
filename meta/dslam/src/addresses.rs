use std::{
    fmt::Display,
    ops::{Deref, DerefMut},
    str::FromStr,
};

use serde_with::{DeserializeFromStr, SerializeDisplay};
use thiserror::Error;

/// An ATM address.
/// Compare ITU-T Recommendation E.191.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[repr(C)]
pub struct AtmAddress {
    /// Address format indication (AFI)
    /// E.164 addresses use AFI 45.
    /// ICD addresses (using ISO/IEC 6523 ICDs) use AFI 47; we do not have an ICD and
    /// therefore don't support those. Similarly, ITU-IND AESAs use ITU-allocated identifiers and
    /// AFI 76, since we don't have one of those either, we don't use them.
    /// DCC addresses (using the ISO 3166 country codes) use AFI 39, and depend on the
    /// corresponding national standards, so we do not support those either.
    /// Local addresses use AFI 49. That's possible to use for us, but actual phone numbers is
    /// funnier, so we do that.
    afi: u8,
    /// Initial Domain Identifier
    /// This identifies _who_ allocates the values within the rest of the address (the
    /// domain-specific part, DSP). For us, this is an E.164 address (see below).
    pub idi: E164Idi,
    /// "High Order"-DSP
    /// This is for ASP use (i.e., for us).
    /// We still force it to zero, so we only have to deal with E.164e AESAs.
    ho_dsp: [u8; 4],
    /// End System Indicator
    /// This generally is for end customer use. We force it to zero for anonymization.
    /// E.191 does not give much guidance on this, but says it "may contain an IEEE MAC address."
    esi: [u8; 6],
    /// Selector
    /// This is "used by the end system for internal purposes". We force it to zero.
    sel: u8,
}

impl AtmAddress {
    const E164_AFI: u8 = 45;

    pub fn new(idi: E164Idi) -> Self {
        Self {
            afi: Self::E164_AFI,
            idi,
            ho_dsp: [0u8; 4],
            esi: [0u8; 6],
            sel: 0,
        }
    }

    pub fn is_nonstandard(&self) -> bool {
        self.afi != Self::E164_AFI
            || self.ho_dsp.iter().any(|b| *b != 0)
            || self.esi.iter().any(|b| *b != 0)
            || self.sel != 0
    }
}

impl Display for AtmAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.idi)?;
        if self.is_nonstandard() {
            write!(f, " (AFI {}, DSP", self.afi)?;
            for byte in self
                .ho_dsp
                .iter()
                .chain(self.esi.iter())
                .chain(std::iter::once(&self.sel))
            {
                write!(f, " {byte:02X}")?;
            }
            write!(f, ")")?;
        }
        Ok(())
    }
}

impl From<AtmAddress> for [u8; 20] {
    fn from(value: AtmAddress) -> Self {
        let mut raw = [0u8; _];
        raw[0] = value.afi;
        raw[1..9].copy_from_slice(&*value.idi);
        raw[9..13].copy_from_slice(&value.ho_dsp);
        raw[13..19].copy_from_slice(&value.esi);
        raw[19] = value.sel;
        raw
    }
}

impl<'life> TryFrom<&'life [u8]> for AtmAddress {
    type Error = &'life [u8];

    fn try_from(value: &'life [u8]) -> Result<Self, Self::Error> {
        if value.len() != ATM_ADDRESS_SIZE || value[0] != Self::E164_AFI {
            // Maybe this should have a different length.
            return Err(value);
        }
        let mut idi = [0u8; _];
        let mut ho_dsp = [0u8; _];
        let mut esi = [0u8; _];
        idi.copy_from_slice(&value[1..9]);
        ho_dsp.copy_from_slice(&value[9..13]);
        esi.copy_from_slice(&value[13..19]);
        Ok(Self {
            afi: value[0],
            idi: E164Idi(idi),
            ho_dsp,
            esi,
            sel: value[19],
        })
    }
}

pub const ATM_ADDRESS_SIZE: usize = 20;

/// The size of an E.164 address encoded inside an AESA IDI
pub const E164_ADDRESS_SIZE: usize = 8;

/// The maximum length of an E.164 address
pub const E164_MAX_LENGTH: usize = 15;

/// An E.164 address is a phone number of at most 15 digits.
/// We encode it in BCD encoding, then (always) append a semi-octet with value 0xF for padding.
/// Then, it is right-aligned in the field by padding with nulls on the left.
/// E.191 gives the following example in Figure 4:
///   +44 171 250 1234 <=> 00 04 41 71 25 01 23 4F
/// The leading + (international prefix) is not encoded, and neither are any trunking
/// prefixes (e.g., the (0) for German numbers).
/// For uniformity, we just assume this is an international number, and translate
/// only from and to strings starting with '+'.
#[derive(Clone, Debug, DeserializeFromStr, Eq, Hash, PartialEq, SerializeDisplay)]
#[repr(transparent)]
pub struct E164Idi([u8; E164_ADDRESS_SIZE]);

impl Deref for E164Idi {
    type Target = [u8; E164_ADDRESS_SIZE];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for E164Idi {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Display for E164Idi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Drop starting zeroes
        let mut chars = Vec::with_capacity(E164_MAX_LENGTH);
        'outer: for byte in self.0.iter() {
            for digit in [byte >> 4, byte & 0xf].into_iter() {
                match digit {
                    0 => {
                        if !chars.is_empty() {
                            chars.push('0');
                        }
                    } // Drop leading zeroes
                    1..=9 => chars.push(
                        char::from_digit(digit.into(), 10).expect("We just checked for 1..=9"),
                    ),
                    0xf => break 'outer,
                    _ => tracing::error!("Invalid digit in E.164 IDI: {digit:#x} {self:?}"),
                }
            }
        }
        let stringified: String = chars.into_iter().collect();
        write!(f, "+{}", stringified)
    }
}

#[derive(Debug, Error)]
pub enum E164ParseError {
    #[error("Invalid character '{0}' in address")]
    InvalidCharacter(char),
    #[error("Address was too long")]
    TooLong,
    #[error("Not an international number (no '+' prefix)")]
    NotInternational,
}

impl FromStr for E164Idi {
    type Err = E164ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut digits = Vec::with_capacity(E164_MAX_LENGTH);
        let Some(s) = s.trim_start().strip_prefix('+') else {
            return Err(E164ParseError::NotInternational);
        };

        for char in s.chars() {
            match char {
                '0'..='9' => digits.push(char.to_digit(10).expect("We just checked for 0..=9")),
                '(' | ')' | '/' | '-' => continue,
                _ if char.is_whitespace() => continue,
                _ => return Err(E164ParseError::InvalidCharacter(char)),
            }
            if digits.len() > E164_MAX_LENGTH {
                return Err(E164ParseError::TooLong);
            }
        }

        let mut address = [0u8; _];
        let left_padding = E164_MAX_LENGTH - digits.len();
        for (index, value) in digits.into_iter().enumerate() {
            let nibble = left_padding + index;
            let value = value & 0xf;
            match nibble % 2 {
                0 => address[nibble / 2] |= (value << 4) as u8,
                1 => address[nibble / 2] |= value as u8,
                _ => unreachable!(),
            }
        }
        address[E164_MAX_LENGTH / 2] |= 0xf;

        Ok(E164Idi(address))
    }
}

impl E164Idi {
    pub fn len(&self) -> usize {
        for index in 0..self.0.len() {
            match self.0[index] {
                0x00 => continue,
                0x01..=0x0f => return E164_MAX_LENGTH - (index * 2 + 1),
                _ => return E164_MAX_LENGTH - (index * 2),
            }
        }
        0
    }
}
