use std::fs::File;
use std::io::ErrorKind;

use tokio::{
    runtime::{Handle, TryCurrentError},
    sync::RwLock,
};
use vfio_bindings::bindings::vfio::{
    VFIO_IRQ_INFO_EVENTFD, VFIO_IRQ_SET_ACTION_MASK, VFIO_IRQ_SET_ACTION_TRIGGER,
    VFIO_IRQ_SET_ACTION_TYPE_MASK, VFIO_IRQ_SET_ACTION_UNMASK, VFIO_IRQ_SET_DATA_BOOL,
    VFIO_IRQ_SET_DATA_EVENTFD, VFIO_IRQ_SET_DATA_NONE, VFIO_IRQ_SET_DATA_TYPE_MASK,
    VFIO_PCI_BAR0_REGION_INDEX, VFIO_PCI_CONFIG_REGION_INDEX, VFIO_PCI_INTX_IRQ_INDEX,
    VFIO_PCI_NUM_IRQS, VFIO_PCI_NUM_REGIONS, VFIO_REGION_INFO_FLAG_READ,
    VFIO_REGION_INFO_FLAG_WRITE, vfio_region_info,
};
use vfio_user::{DmaMapFlags, IrqInfo, ServerBackend};

pub mod dma;
pub mod irq;
pub mod mmio;
pub mod third_party;

pub use crate::device::third_party::pci;

/// A device with an MMIO region, DMA access, and IRQs
pub struct Device<Mmio: mmio::Mmio + ?Sized> {
    dma: RwLock<dma::Dma>,
    irqs: RwLock<irq::Irqs>,
    irq_count: usize,
    mmio: Mmio,
}

#[allow(unused)]
impl<Mmio: mmio::Mmio> Device<Mmio> {
    /// Creates the device
    pub fn new(mmio: Mmio, irq_count: usize) -> Self {
        Self {
            dma: RwLock::new(dma::Dma::new()),
            irqs: RwLock::new(irq::Irqs::new(irq_count)),
            irq_count,
            mmio,
        }
    }

    /// Reads from a DMA address.
    pub async fn dma_read(&self, address: u64, data: &mut [u8]) -> Result<usize, dma::DmaError> {
        self.dma.read().await.read(address, data)
    }

    /// Writes to a DMA address
    pub async fn dma_write(&self, address: u64, data: &[u8]) -> Result<usize, dma::DmaError> {
        self.dma.read().await.write(address, data)
    }

    /// Reads an object from a DMA address
    pub async fn dma_read_object<T: dma::DmaSafe>(&self, address: u64) -> Result<T, dma::DmaError> {
        self.dma.read().await.read_object(address)
    }

    /// Writes an object to a DMA address
    pub async fn dma_write_object<T: dma::DmaSafe>(
        &self,
        address: u64,
        object: &T,
    ) -> Result<usize, dma::DmaError> {
        self.dma.read().await.write_object(address, object)
    }

    /// Maps a new DMA region
    pub async fn dma_map(&self, region: dma::DmaRegion) {
        self.dma.write().await.add_region(region)
    }

    /// Unmaps an existing DMA region
    pub async fn dma_unmap(&self, address: u64, size: usize) {
        self.dma.write().await.remove_region(address, size)
    }

    /// Triggers an interrupt
    pub async fn trigger_irq(&self, index: usize) -> Result<(), irq::IrqError> {
        self.irqs.read().await.trigger(index)
    }

    /// Binds an interrupt to an eventfd
    pub async fn bind_irq(&self, index: usize, fd: File) -> Result<(), irq::IrqError> {
        self.irqs.write().await.bind(index, fd)
    }

    /// Unbinds an interrupt
    pub async fn unbind_irq(&self, index: usize) -> Result<(), irq::IrqError> {
        self.irqs.write().await.unbind(index)
    }

    /// Masks an interrupt
    pub async fn mask_irq(&self, index: usize) -> Result<(), irq::IrqError> {
        self.irqs.write().await.mask(index)
    }

    /// Unmasks an interrupt
    pub async fn unmask_irq(&self, index: usize) -> Result<(), irq::IrqError> {
        self.irqs.write().await.unmask(index)
    }

    /// Unbinds all interrupts
    pub async fn unbind_all_irqs(&self) {
        self.irqs.write().await.unbind_all()
    }

    /// The number of interrupts supported by this device
    pub fn irq_count(&self) -> usize {
        self.irq_count
    }

    /// Reads from the MMIO space
    pub async fn mmio_read(&self, offset: u64, data: &mut [u8]) -> std::io::Result<()> {
        self.mmio.read(offset, data, &self).await
    }

    /// Writes to the MMIO space
    pub async fn mmio_write(&self, offset: u64, data: &[u8]) -> std::io::Result<()> {
        self.mmio.write(offset, data, &self).await
    }

    /// Resets the device (but not the DMA mapping or interrupt bindings)
    pub async fn reset(&self) {
        self.mmio.reset().await
    }

    /// Returns a reference to the user-provided MMIO space.
    #[inline]
    pub fn mmio(&self) -> &Mmio {
        &self.mmio
    }
}

/// A PCI device that exposes the MMIO region via bar 0.
/// Multiple bars are not supported here, since we don't need it;
/// generalizing this is left as an exercise to the reader.
/// This abstracts away all the (additional) vfio-user setup
/// in which we need to handle the configuration space ourselves.
pub struct PciDevice<'dev, Mmio: mmio::Mmio> {
    rt: Handle,
    pci: pci::PciConfiguration,
    dev: &'dev Device<Mmio>,
}

impl<'dev, Mmio: mmio::Mmio> PciDevice<'dev, Mmio> {
    /// Creates a new vfio-user PCI device on the given `tokio` runtime.
    pub fn with_runtime(dev: &'dev Device<Mmio>, pci: pci::PciConfiguration, rt: Handle) -> Self {
        Self { rt, pci, dev }
    }

    /// Creates a new vfio-user PCI device on the current runtime.
    pub async fn new(
        dev: &'dev Device<Mmio>,
        pci: pci::PciConfiguration,
    ) -> Result<Self, TryCurrentError> {
        Ok(Self::with_runtime(dev, pci, Handle::try_current()?))
    }

    /// The memory regions exported by this device, used for the initial vfio-user handshake
    pub fn regions(&self) -> Vec<vfio_region_info> {
        let mut regions = Vec::with_capacity(VFIO_PCI_NUM_REGIONS as usize);
        for index in 0..VFIO_PCI_NUM_REGIONS {
            let mut region = vfio_region_info {
                argsz: std::mem::size_of::<vfio_region_info>() as u32,
                index,
                ..Default::default()
            };
            match index {
                VFIO_PCI_CONFIG_REGION_INDEX => {
                    region.size = (pci::NUM_CONFIGURATION_REGISTERS * 4) as u64;
                    region.flags = VFIO_REGION_INFO_FLAG_READ | VFIO_REGION_INFO_FLAG_WRITE;
                }
                VFIO_PCI_BAR0_REGION_INDEX => {
                    region.size = <Mmio as mmio::Mmio>::SIZE as u64;
                    region.flags = VFIO_REGION_INFO_FLAG_READ | VFIO_REGION_INFO_FLAG_WRITE;
                }
                _ => {}
            };
            regions.push(region);
        }
        regions
    }

    /// List of IRQs exposed by this device, used for the initial handshake
    pub fn irqs(&self) -> Vec<IrqInfo> {
        let mut irqs = Vec::with_capacity(VFIO_PCI_NUM_IRQS as usize);
        for index in 0..VFIO_PCI_NUM_IRQS {
            let mut irq = IrqInfo {
                index,
                count: 0,
                flags: 0,
            };
            if index == VFIO_PCI_INTX_IRQ_INDEX {
                irq.count = self.dev.irq_count() as u32;
                irq.flags = VFIO_IRQ_INFO_EVENTFD;
                // To make an interrupt index maskable, set VFIO_IRQ_INFO_MASKABLE
                // (and support MASK/UNMASK IRQ actions below).
                // To auto-mask (so QEMU has to unmask it), set VFIO_IRQ_INFO_AUTOMASKED.
                // For MSI/MSI-X, you will need VFIO_IRQ_INFO_NORESIZE.
            }
            irqs.push(irq);
        }
        irqs
    }
}

impl<'dev, Mmio: mmio::Mmio> ServerBackend for PciDevice<'dev, Mmio> {
    fn region_read(
        &mut self,
        region: u32,
        offset: u64,
        data: &mut [u8],
    ) -> Result<(), std::io::Error> {
        tracing::trace!(
            "Read of {:#x} bytes from region {}, offset {:#x}",
            data.len(),
            region,
            offset
        );
        let len = data.len();
        if region == VFIO_PCI_CONFIG_REGION_INDEX {
            // We need to forward reads to the PCI configuration space.
            // (Writes are much simpler with the PCI template, incidentally).
            let mut register = offset as usize / 4;
            if len > 4 {
                // QEMU will gladly read the entire configuration space at once.
                // The example enforces alignment to four-byte boundaries here.
                if !len.is_multiple_of(4) || !offset.is_multiple_of(4) {
                    return Err(ErrorKind::InvalidInput.into());
                }
                let mut current = 0;
                while current < len {
                    let value = self.pci.read_reg(register);
                    data[current..current + 4].copy_from_slice(&value.to_le_bytes());
                    register += 1;
                    current += 4;
                }
            } else {
                // Here, we don't allow reads across register boundaries, and
                // enforce alignment to the length.
                let reg_offset = offset as usize % 4;
                if reg_offset + len > 4 || !reg_offset.is_multiple_of(len) {
                    return Err(ErrorKind::InvalidInput.into());
                }
                let value = self.pci.read_reg(register);
                data.copy_from_slice(&value.to_le_bytes()[reg_offset..reg_offset + len]);
            }
            Ok(())
        } else if region == VFIO_PCI_BAR0_REGION_INDEX {
            // This is our PCI bar, here we can do whatever we want
            self.rt.block_on(self.dev.mmio_read(offset, data))
        } else {
            // There's nothing here
            tracing::warn!(
                "Invalid read of {:#x} bytes attempted from region {} at offset {:#x}",
                data.len(),
                region,
                offset
            );
            data.fill(0xffu8);
            Ok(())
        }
    }

    fn region_write(
        &mut self,
        region: u32,
        offset: u64,
        data: &[u8],
    ) -> Result<(), std::io::Error> {
        tracing::trace!(
            "Write of {:#x} bytes to region {}, offset {:#x}",
            data.len(),
            region,
            offset
        );
        if region == VFIO_PCI_CONFIG_REGION_INDEX {
            // Update the PCI configuration
            self.pci.write_reg(offset as usize / 4, offset % 4, data);
            Ok(())
        } else if region == VFIO_PCI_BAR0_REGION_INDEX {
            // Write to our PCI bar
            self.rt.block_on(self.dev.mmio_write(offset, data))
        } else {
            // There's nothing here
            tracing::warn!(
                "Invalid write of {:#x} bytes attempted to region {} at offset {:#x}",
                data.len(),
                region,
                offset
            );
            Ok(())
        }
    }

    fn dma_map(
        &mut self,
        flags: DmaMapFlags,
        offset: u64,
        address: u64,
        size: u64,
        fd: Option<std::fs::File>,
    ) -> Result<(), std::io::Error> {
        tracing::trace!("Mapping DMA region of {size:#x} bytes at {address:#x}");

        // It is a violation of the spec to request overlapping regions.
        // We're supposed to return an error in that case but the vfio_user crate doesn't do proper
        // error handling anyways.
        // So just add it anyways and try and figure out which one to use later.
        // (I think our QEMU is well-behaved, so this is not an issue regardless)

        // vfio_user does not support VFIO_USER_DMA_{READ,WRITE} commands.
        // It might be nice to not have to use additional QEMU flags to force it to give us file
        // descriptors here, but it also doesn't matter practically.
        let Some(file) = fd else {
            tracing::warn!(
                "Attempted to map DMA region of {size:#x} bytes at {address:#x} without shared file descriptor"
            );
            return Err(ErrorKind::Unsupported.into());
        };

        let mode = if flags.contains(DmaMapFlags::READ_WRITE) {
            dma::DmaMode::ReadWrite
        } else if flags.contains(DmaMapFlags::READ) {
            dma::DmaMode::Read
        } else if flags.contains(DmaMapFlags::WRITE) {
            dma::DmaMode::Write
        } else {
            tracing::warn!(
                "Attempted to map DMA region that is neither readable nor writable, skipping it"
            );
            return Ok(());
        };

        let region = dma::DmaRegion::new(address, size as usize, offset, mode, &file)?;
        self.rt.block_on(self.dev.dma_map(region));
        Ok(())
    }

    fn dma_unmap(
        &mut self,
        flags: vfio_user::DmaUnmapFlags,
        address: u64,
        size: u64,
    ) -> Result<(), std::io::Error> {
        tracing::trace!("Unmapping DMA region of {size:#x} bytes at {address:#x}");

        if flags.bits() != 0 {
            tracing::error!(
                "Received DMA unmap command with unsupported flags {:#x}",
                flags.bits()
            );
            return Err(ErrorKind::Unsupported.into());
        }

        let Ok(size) = size.try_into() else {
            tracing::error!("Received DMA unmap command with invalid size {:#x}", size);
            return Err(ErrorKind::InvalidInput.into());
        };

        self.rt.block_on(self.dev.dma_unmap(address, size));
        Ok(())
    }

    fn reset(&mut self) -> Result<(), std::io::Error> {
        tracing::trace!("Resetting device state");
        self.rt.block_on(self.dev.reset());
        Ok(())
    }

    fn set_irqs(
        &mut self,
        index: u32,
        flags: u32,
        start: u32,
        count: u32,
        fds: Vec<std::fs::File>,
    ) -> Result<(), std::io::Error> {
        tracing::trace!(
            "Configuring {} IRQ{} starting at {}.{} with flags {:#x}",
            count,
            if count == 1 { "" } else { "s" },
            index,
            start,
            flags
        );

        fn as_usize(number: u32) -> Result<usize, std::io::Error> {
            match number.try_into() {
                Ok(number) => Ok(number),
                Err(_) => {
                    tracing::error!("Out-of-range IRQ index or count: {number}");
                    Err(ErrorKind::InvalidInput.into())
                }
            }
        }

        if index != VFIO_PCI_INTX_IRQ_INDEX {
            tracing::error!(
                "Client tried to set IRQs for IRQ index {index}, which is not supported."
            );
            return Err(ErrorKind::InvalidInput.into());
        }

        match flags & VFIO_IRQ_SET_ACTION_TYPE_MASK {
            action if action == VFIO_IRQ_SET_ACTION_MASK => {
                // None of our interrupts are maskable.
                tracing::error!("Client tried to mask unmaskable interrupts");
                return Err(ErrorKind::InvalidInput.into());
            }
            action if action == VFIO_IRQ_SET_ACTION_UNMASK => {
                // None of our interrupts are maskable.
                // Unfortunately, QEMU insists on attempting to unmask already-unmasked IRQs
                // even if they are not maskable and not auto-masked. We should be returning
                // -EINVAL here per the specification, but the crate hard-errors if we do that,
                // so we just ignore it instead.
                // The interrupt is unmasked afterwards so we might as well pretend this succeeded.
                return Ok(());
            }
            action if action == VFIO_IRQ_SET_ACTION_TRIGGER => {
                // We handle this below.
            }
            action => {
                tracing::error!("Unsupported IRQ action: {action:#x}");
                return Err(ErrorKind::Unsupported.into());
            }
        }

        match flags & VFIO_IRQ_SET_DATA_TYPE_MASK {
            data if data == VFIO_IRQ_SET_DATA_NONE => {
                // Per the kernel docs: DATA_NONE | ACTION_TRIGGER "simulate[s] hardware
                // triggering", so trigger the IRQs.
                // However, if count = 0, this disables the index as a whole instead.
                if count > 0 {
                    let start = as_usize(start)?;
                    let count = as_usize(count)?;
                    let Some(limit) = start.checked_add(count) else {
                        tracing::error!("Too many IRQs ({count} starting at {index}.{start})");
                        return Err(ErrorKind::InvalidInput.into());
                    };
                    self.rt.block_on(async {
                        for irq in start..limit {
                            if let Err(error) = self.dev.trigger_irq(irq).await {
                                match error {
                                    irq::IrqError::NotFound => {
                                        tracing::error!("Attempted to trigger invalid IRQ {irq}");
                                    }
                                    irq::IrqError::Disconnected => {
                                        // This is fine to do, just informative.
                                        tracing::debug!(
                                            "Attempted to trigger disconnected IRQ {irq}"
                                        );
                                    }
                                    irq::IrqError::Masked => {
                                        // This is fine to do, just informative.
                                        tracing::debug!("Attempted to trigger masked IRQ {irq}");
                                    }
                                    irq::IrqError::IoError(error) => {
                                        tracing::error!("Failed to trigger IRQ {irq}: {error}");
                                        return Err(error);
                                    }
                                }
                            }
                        }
                        Ok(())
                    })
                } else {
                    self.rt.block_on(self.dev.unbind_all_irqs());
                    Ok(())
                }
            }
            data if data == VFIO_IRQ_SET_DATA_BOOL => {
                // Not supported. This is filtered out by the crate already, however.
                Err(ErrorKind::Unsupported.into())
            }
            data if data == VFIO_IRQ_SET_DATA_EVENTFD => {
                // This wires up the interrupt lines.
                self.rt.block_on(async {
                    let start = as_usize(start)?;
                    let fd_count = fds.len();
                    for (fd_index, fd) in fds.into_iter().enumerate() {
                        let Some(irq) = start.checked_add(fd_index) else {
                            tracing::error!("Too many IRQ file descriptors ({} starting at {}.{})", fd_count, index, start);
                            return Err(ErrorKind::InvalidInput.into());
                        };
                        if let Err(error) = self.dev.bind_irq(irq, fd).await {
                            match error {
                                irq::IrqError::NotFound => {
                                    tracing::error!("Attempted to configure invalid IRQ {irq}");
                                },
                                irq::IrqError::Disconnected => {
                                    unreachable!("Cannot complain about a disconnected IRQ when configuring it");
                                },
                                irq::IrqError::Masked => {
                                    unreachable!("Cannot complain about a masked IRQ when configuring it");
                                },
                                irq::IrqError::IoError(error) => {
                                    tracing::error!("Failed to configure IRQ {irq}: {error}");
                                    return Err(error);
                                },
                            }
                        }
                    }
                    Ok(())
                })
            }
            data => {
                tracing::error!("Unsupported IRQ data type: {data:#x}");
                Err(ErrorKind::Unsupported.into())
            }
        }
    }
}
