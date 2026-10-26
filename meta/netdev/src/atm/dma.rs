use bitfield::bitfield;

use crate::device::dma::DmaSafe;

/// Current owner of the descriptor
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DescriptorOwner {
    Software = 0,
    Hardware = 1,
}
impl From<u32> for DescriptorOwner {
    fn from(value: u32) -> Self {
        if value == Self::Hardware as u32 {
            Self::Hardware
        } else {
            Self::Software
        }
    }
}
impl From<DescriptorOwner> for u32 {
    fn from(value: DescriptorOwner) -> Self {
        value as Self
    }
}

bitfield! {
    /// Descriptor flags
    #[repr(transparent)]
    pub struct DmaFlags(u32);
    impl Debug;
    u32;
    #[inline] pub u32, from into DescriptorOwner, owner, set_owner: 1, 0;
}

// SAFETY: This object is #[repr(transparent)] around an u32.
unsafe impl DmaSafe for DmaFlags {}

/// A DMA descriptor
#[derive(Debug)]
#[repr(C)]
pub struct DmaDescriptor {
    /// Next DMA buffer in the chain
    pub next: u32,
    /// Flags for this buffer
    pub flags: DmaFlags,
    /// Actual data pointer for this buffer (an AtmCell)
    pub data: u32,
}

// SAFETY: This object is #[repr(C)] and consists of integers only (DmaFlags is
// #[repr(transparent)] around an u32). Any bit pattern is OK here.
unsafe impl DmaSafe for DmaDescriptor {}
