/// DMA backend for memory-mapped DMA
use std::{fs::File, mem::MaybeUninit};

use memmap2::{MmapOptions, MmapRaw};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DmaError {
    #[error("Address {0:#x} is out of bounds of memory region")]
    OutOfBounds(u64),
    #[error("Address {0:#x} is not mapped")]
    NotMapped(u64),
    #[error("Address {0:#x} is not writable")]
    NotWritable(u64),
    #[error("Address {0:#x} is not readable")]
    NotReadable(u64),
    #[error("Failed to flush memory: {0}")]
    FlushFailed(std::io::Error),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DmaMode {
    Read,
    Write,
    ReadWrite,
}

impl DmaMode {
    pub fn readable(self) -> bool {
        self == Self::Read || self == Self::ReadWrite
    }
    pub fn writable(self) -> bool {
        self == Self::Write || self == Self::ReadWrite
    }
}

#[derive(Debug)]
pub struct DmaRegion {
    pub address: u64,
    pub size: usize,
    mode: DmaMode,
    memory: MmapRaw,
}

impl DmaRegion {
    /// The first address beyond the end of the region
    #[inline]
    pub fn end(&self) -> u64 {
        self.address
            .saturating_add(self.size.try_into().unwrap_or_default())
    }

    /// Converts the raw memory address to an offset in the mapped region
    #[inline]
    fn to_offset(&self, address: u64) -> usize {
        let offset = address.wrapping_sub(self.address);
        offset as usize
    }

    /// Converts the raw memory address to a pointer in the mapped region
    #[inline]
    fn ptr_at(&self, address: u64) -> *mut u8 {
        let offset = self.to_offset(address);
        self.memory.as_mut_ptr().wrapping_byte_add(offset)
    }

    /// Flushes all writes to the memory region
    #[inline]
    fn flush(&self) -> Result<(), DmaError> {
        self.memory.flush_async().map_err(DmaError::FlushFailed)
    }

    /// Is this much memory at the given address accessible?
    #[inline]
    fn may_access(&self, address: u64, length: usize) -> bool {
        self.to_offset(address)
            .checked_add(length)
            .is_some_and(|end| end <= self.size)
    }

    /// Reads from the address, even if it is inaccessible
    /// SAFETY: If the address range is out of bounds, this will read out of bounds.
    #[inline]
    pub unsafe fn unchecked_read(&self, address: u64, data: &mut [u8]) {
        data.copy_from_slice(unsafe {
            std::slice::from_raw_parts(self.ptr_at(address) as *const u8, data.len())
        });
    }

    /// Writes to the address, even if it is inaccessible
    /// SAFETY: If the address range is out of bounds, this will write out of bounds.
    #[inline]
    pub unsafe fn unchecked_write(&self, address: u64, data: &[u8]) {
        unsafe { std::slice::from_raw_parts_mut(self.ptr_at(address), data.len()) }
            .copy_from_slice(data);
    }

    #[inline]
    /// Reads from the given address
    pub fn read(&self, address: u64, data: &mut [u8]) -> Result<usize, DmaError> {
        if !self.mode.readable() {
            Err(DmaError::NotReadable(address))
        } else if !self.may_access(address, data.len()) {
            Err(DmaError::OutOfBounds(address))
        } else {
            // SAFETY: We just checked that this read is OK.
            unsafe { self.unchecked_read(address, data) };
            Ok(data.len())
        }
    }

    #[inline]
    /// Writes to the given address
    pub fn write(&self, address: u64, data: &[u8]) -> Result<usize, DmaError> {
        if !self.mode.writable() {
            Err(DmaError::NotWritable(address))
        } else if !self.may_access(address, data.len()) {
            Err(DmaError::OutOfBounds(address))
        } else {
            // SAFETY: We just checked that this write is OK.
            unsafe { self.unchecked_write(address, data) };
            Ok(data.len())
        }
    }

    /// Creates a new DMA mapping
    pub fn new(
        address: u64,
        size: usize,
        offset: u64,
        mode: DmaMode,
        file: &File,
    ) -> std::io::Result<Self> {
        let mut options = MmapOptions::new();
        options.len(size).offset(offset);

        let memory = if mode.writable() {
            options.map_raw(file)
        } else {
            options.map_raw_read_only(file)
        }?;

        Ok(Self {
            address,
            size,
            mode,
            memory,
        })
    }
}

/// A set of all the DMA regions for a device
pub struct Dma {
    regions: Vec<DmaRegion>,
}

#[allow(unused)]
impl Dma {
    /// Creates a new set of DMA regions
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
        }
    }

    /// Adds a DMA region to the list
    pub fn add_region(&mut self, region: DmaRegion) {
        self.regions.push(region);
    }

    /// Removes a DMA region from the list
    pub fn remove_region(&mut self, address: u64, size: usize) {
        self.regions
            .retain(|region| region.address != address || region.size != size)
    }

    /// Finds the DMA region and applies the given function
    fn apply<T>(
        &self,
        address: u64,
        func: impl FnOnce(&DmaRegion) -> Result<T, DmaError>,
    ) -> Result<T, DmaError> {
        self.regions
            .iter()
            .find(|region| address >= region.address && address < region.end())
            .ok_or_else(|| DmaError::NotMapped(address))
            .and_then(func)
    }

    /// Reads from a DMA address
    pub fn read(&self, address: u64, data: &mut [u8]) -> Result<usize, DmaError> {
        self.apply(address, |region| region.read(address, data))
    }

    /// Writes to a DMA address
    pub fn write(&self, address: u64, data: &[u8]) -> Result<usize, DmaError> {
        self.apply(address, |region| region.write(address, data))
    }

    /// Reads a DMA-safe object from DMA
    pub fn read_object<T: DmaSafe>(&self, address: u64) -> Result<T, DmaError> {
        let mut object = MaybeUninit::<T>::uninit();
        // SAFETY: The user has indicated that arbitrary bit patterns are valid for this object.
        //         Additionally, this object is Sized (via DmaSafe).
        let slice = unsafe {
            std::slice::from_raw_parts_mut(object.as_mut_ptr() as *mut u8, size_of::<T>())
        };
        self.read(address, slice)?;
        // SAFETY: The user has indicated that arbitrary bit patterns are valid for this object.
        Ok(unsafe { object.assume_init() })
    }

    /// Writes a DMA-safe object to DMA
    pub fn write_object<T: DmaSafe>(&self, address: u64, object: &T) -> Result<usize, DmaError> {
        // SAFETY: The user has explicitly opted into the safety of this transmute, and the object
        //         is Sized via DmaSafe.
        let slice =
            unsafe { std::slice::from_raw_parts(object as *const T as *const u8, size_of::<T>()) };
        self.write(address, slice)
    }

    /// Flushes writes in a DMA region
    pub fn flush(&self, address: u64) -> Result<(), DmaError> {
        self.apply(address, |region| region.flush())
    }
}

/// An object that can be safely accessed via DMA
/// This implies that transmuting any correctly-sized byte buffer into this type is safe.
pub unsafe trait DmaSafe: Sized {}

// SAFETY: Integers and arrays of integers are trivially DMA-safe, since they obviously
// permit any byte pattern.
unsafe impl DmaSafe for u8 {}
unsafe impl DmaSafe for u16 {}
unsafe impl DmaSafe for u32 {}
unsafe impl DmaSafe for u64 {}
unsafe impl<const N: usize> DmaSafe for [u8; N] {}
unsafe impl<const N: usize> DmaSafe for [u16; N] {}
unsafe impl<const N: usize> DmaSafe for [u32; N] {}
unsafe impl<const N: usize> DmaSafe for [u64; N] {}
