#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

/// ATM (F5) OAM cells
use bitfield::bitfield;

#[derive(Debug)]
#[repr(u8)]
pub enum FaultManagementFunction {
    /// Alarm Indication Signal (AIS)
    AlarmIndicationSignal = 0b0000,
    /// Remote Defect Indication (RDI)
    RemoteDefectIndication = 0b0001,
    /// Continuity Check (CC)
    ContinuityCheck = 0b0100,
    /// Loopback (LB)
    Loopback = 0b1000,
}
impl From<FaultManagementFunction> for u8 {
    fn from(value: FaultManagementFunction) -> Self {
        value as Self
    }
}

#[derive(Debug)]
#[repr(u8)]
pub enum PerformanceManagementFunction {
    /// Forward Performance Management (FPM)
    ForwardPerformanceManagement = 0b0000,
    /// Backward Reporting (BR)
    BackwardReporting = 0b0001,
}
impl From<PerformanceManagementFunction> for u8 {
    fn from(value: PerformanceManagementFunction) -> Self {
        value as Self
    }
}

#[derive(Debug)]
#[repr(u8)]
pub enum ApsCoordinationFunction {
    /// Group protection
    GroupProtection = 0b0000,
    /// Individual protection
    IndividualProtection = 0b0001,
}
impl From<ApsCoordinationFunction> for u8 {
    fn from(value: ApsCoordinationFunction) -> Self {
        value as Self
    }
}

#[derive(Debug)]
#[repr(u8)]
pub enum ActivationDeactivationFunction {
    /// FPM and associated BR
    FpmAndBr = 0b0000,
    /// Continuity check
    ContinuityCheck = 0b0001,
    /// FPM only
    FpmOnly = 0b0010,
}
impl From<ActivationDeactivationFunction> for u8 {
    fn from(value: ActivationDeactivationFunction) -> Self {
        value as Self
    }
}

#[derive(Debug)]
pub enum OamFunction {
    FaultManagement(FaultManagementFunction),
    PerformanceManagement(PerformanceManagementFunction),
    ApsCoordination(ApsCoordinationFunction),
    ActivationDeactivation(ActivationDeactivationFunction),
    SystemManagement(u8),
    Unknown(u8),
}
impl From<OamFunction> for u8 {
    fn from(value: OamFunction) -> Self {
        match value {
            OamFunction::FaultManagement(function) => 0b0001_0000u8 | u8::from(function),
            OamFunction::PerformanceManagement(function) => 0b0010_0000u8 | u8::from(function),
            OamFunction::ApsCoordination(function) => 0b0101_0000u8 | u8::from(function),
            OamFunction::ActivationDeactivation(function) => 0b1000_0000u8 | u8::from(function),
            OamFunction::SystemManagement(function) => 0b1111_0000u8 | function,
            OamFunction::Unknown(unknown) => unknown,
        }
    }
}
impl From<u8> for OamFunction {
    fn from(value: u8) -> Self {
        match value {
            0b0001_0000 => Self::FaultManagement(FaultManagementFunction::AlarmIndicationSignal),
            0b0001_0001 => Self::FaultManagement(FaultManagementFunction::RemoteDefectIndication),
            0b0001_0100 => Self::FaultManagement(FaultManagementFunction::ContinuityCheck),
            0b0001_1000 => Self::FaultManagement(FaultManagementFunction::Loopback),
            0b0010_0000 => Self::PerformanceManagement(
                PerformanceManagementFunction::ForwardPerformanceManagement,
            ),
            0b0010_0001 => {
                Self::PerformanceManagement(PerformanceManagementFunction::BackwardReporting)
            }
            0b0101_0000 => Self::ApsCoordination(ApsCoordinationFunction::GroupProtection),
            0b0101_0001 => Self::ApsCoordination(ApsCoordinationFunction::IndividualProtection),
            0b1000_0000 => Self::ActivationDeactivation(ActivationDeactivationFunction::FpmAndBr),
            0b1000_0001 => {
                Self::ActivationDeactivation(ActivationDeactivationFunction::ContinuityCheck)
            }
            0b1000_0010 => Self::ActivationDeactivation(ActivationDeactivationFunction::FpmOnly),
            _ if (value & 0b1111_0000) == 0b1111_0000 => Self::SystemManagement(value & 0b1111),
            _ => Self::Unknown(value),
        }
    }
}

bitfield! {
    /// An OAM cell header (within the ATM payload).
    pub struct Header(MSB0 [u8]);
    impl Debug;
    u8;
    // Per the spec, these are separate fields.
    #[inline] pub oam_type, set_oam_type: 3, 0;
    #[inline] pub function_type, set_function_type: 7, 4;
    // But really they ought to be treated as a single field.
    #[inline] pub from into OamFunction, oam_function, set_oam_function: 7, 0;
    // This is followed by the function-specific cell body, which is always 45 bytes long
}
