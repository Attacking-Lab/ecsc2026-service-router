/// An ATM network device
use std::{
    ops::Range,
    sync::atomic::{AtomicU32, Ordering},
};

// The actual implementation of the device side of this, incl. MMIO layout, is in crate::atm::device
pub(crate) mod device;

// crate::atm::dma has the DMA structures etc.
pub(crate) mod dma;

// crate::atm::pci holds the vfio-user-pci PCI configuration for this device
pub mod pci;

// crate::atm::proxy proxies the ATM cells that come out of the device to the gamenet, and does the
// recieve handling.
pub(crate) mod proxy;

pub use device::AtmNetworkDevice;
pub use proxy::AtmNetworkProxy;

/// ATM cells are fixed at 5 bytes header and 48 bytes of payload.
pub type AtmCell = [u8; 53];

/// ATM addresses (AESAs) are 20 bytes long.
pub type Aesa = [u8; 20];

/// "Atomic" (not really) storage for an AESA.
/// Reads may see partial stores, but everything is thread-safe.
#[derive(Debug)]
pub(crate) struct ThreadSafeAesa([AtomicU32; 5]);

impl ThreadSafeAesa {
    const ITEM_SIZE: usize = 4;

    // The range from an AESA corresponding to an index in the atomic array
    const fn range_for(index: usize) -> Range<usize> {
        (index * Self::ITEM_SIZE)..(index * Self::ITEM_SIZE + Self::ITEM_SIZE)
    }

    /// Stores the AESA
    pub fn store(&self, aesa: &Aesa) {
        debug_assert!(
            aesa.len() == Self::ITEM_SIZE * self.0.len(),
            "ThreadSafeAesa is incorrectly sized"
        );
        let mut raw = [0u8; Self::ITEM_SIZE];
        for index in 0..self.0.len() {
            raw.copy_from_slice(&aesa[Self::range_for(index)]);
            self.0[index].store(u32::from_le_bytes(raw), Ordering::Release);
        }
    }

    /// Loads the AESA
    pub fn load(&self) -> Aesa {
        let mut aesa = [0u8; _];
        for index in 0..self.0.len() {
            let value = self.0[index].load(Ordering::Acquire);
            (&mut aesa[Self::range_for(index)]).copy_from_slice(&u32::to_le_bytes(value));
        }
        aesa
    }
}

impl Default for ThreadSafeAesa {
    fn default() -> Self {
        Self(std::array::from_fn(|_| 0.into()))
    }
}
