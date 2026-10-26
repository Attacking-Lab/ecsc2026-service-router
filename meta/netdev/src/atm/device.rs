use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use tokio::sync::{
    Mutex,
    mpsc::{self, Sender},
};

use crate::{
    atm::{
        Aesa, AtmCell, ThreadSafeAesa,
        dma::{DescriptorOwner, DmaDescriptor},
    },
    device::{Device, dma::DmaError, mmio::Mmio},
};

#[derive(Debug)]
pub struct AtmNetworkDevice {
    /// Control register, at `MMIO_CONTROL`
    pub control: AtomicU32,

    /// Status register, at `MMIO_STATUS`
    pub status: AtomicU32,

    /// DMA address for incoming packets, at `MMIO_RX_BUFFER`
    pub rx_buffer: AtomicU32,

    /// DMA address for outgoing packets, at `MMIO_TX_BUFFER`
    pub tx_buffer: AtomicU32,

    /// ATM address at `MMIO_AESA`; read-only
    /// Only valid when connected (`STATUS_LOWER_UP` in `MMIO_STATUS`)
    pub aesa: ThreadSafeAesa,

    /// Transmission queue to the networking thread
    tx_queue: Sender<AtmCell>,

    /// Serializes `transmit`: two concurrent walks would put the same cell on the wire twice
    tx_lock: Mutex<()>,

    /// Set when `transmit` abandoned a chain because `tx_queue` was full; see `retransmit`
    tx_stalled: AtomicBool,
}

pub const MMIO_CONTROL: u64 = 0;
pub const MMIO_STATUS: u64 = 4;
pub const MMIO_RX_BUFFER: u64 = 8;
pub const MMIO_TX_BUFFER: u64 = 12;
#[allow(unused)]
pub const MMIO_IRQ_CLEAR: u64 = 16;
pub const MMIO_AESA: u64 = 20;

pub const CONTROL_RX_ENABLE: u32 = 1 << 0;
pub const CONTROL_TX_TRIGGER: u32 = 1 << 1;
pub const CONTROL_LOOPBACK: u32 = 1 << 2;

pub const STATUS_RX_LOSS: u32 = 1 << 0;
pub const STATUS_TX_LOSS: u32 = 1 << 1;
pub const STATUS_LOWER_UP: u32 = 1 << 2;

impl Mmio for AtmNetworkDevice {
    /// Size of the MMIO region
    const SIZE: usize = 0x200;

    /// Handles MMIO register reads
    ///
    /// For now, these don't have any side effects; they just report the values of the MMIO
    /// registers. Misaligned or partial reads are not supported.
    async fn read(
        &self,
        offset: u64,
        data: &mut [u8],
        _device: &Device<Self>,
    ) -> std::io::Result<()> {
        const MMIO_AESA_END: u64 = MMIO_AESA + std::mem::size_of::<Aesa>() as u64;
        let value: u32 = match offset {
            MMIO_CONTROL if data.len() == 4 => self.control.load(Ordering::Acquire),
            MMIO_STATUS if data.len() == 4 => self.status.load(Ordering::Acquire),
            MMIO_RX_BUFFER if data.len() == 4 => self.rx_buffer.load(Ordering::Acquire),
            MMIO_TX_BUFFER if data.len() == 4 => self.tx_buffer.load(Ordering::Acquire),
            // MMIO_IRQ_CLEAR: Just there to clear interrupts.
            MMIO_AESA..MMIO_AESA_END if offset + data.len() as u64 <= MMIO_AESA_END => {
                let start = (offset - MMIO_AESA) as usize;
                let end = start + data.len();
                data.copy_from_slice(&self.aesa.load()[start..end]);
                return Ok(());
            }
            _ => {
                data.fill(0xff);
                return Ok(());
            }
        };
        data.copy_from_slice(&u32::to_le_bytes(value));
        Ok(())
    }

    /// Handles MMIO register writes
    ///
    /// Only the `MMIO_CONTROL` register has any immediate side effects here.
    /// Misaligned or partial writes are not supported.
    async fn write(&self, offset: u64, data: &[u8], device: &Device<Self>) -> std::io::Result<()> {
        let value: u32 = if data.len() == 4 {
            let mut raw = [0u8; 4];
            raw.copy_from_slice(data);
            u32::from_le_bytes(raw)
        } else {
            return Ok(());
        };

        match offset {
            MMIO_CONTROL => {
                self.control
                    .store(value & !CONTROL_TX_TRIGGER, Ordering::Release);
                if value & CONTROL_TX_TRIGGER == CONTROL_TX_TRIGGER {
                    if let Err(error) = self.transmit(device).await {
                        tracing::debug!("DMA failure during cell transmission: {error}");
                    }
                }
            }
            MMIO_STATUS => {
                // The loss flags are write-1-to-clear.
                let loss = value & (STATUS_RX_LOSS | STATUS_TX_LOSS);
                self.status.fetch_and(!loss, Ordering::AcqRel);
            }
            MMIO_RX_BUFFER => {
                self.rx_buffer.store(value, Ordering::Release);
            }
            MMIO_TX_BUFFER => {
                self.tx_buffer.store(value, Ordering::Release);
            }
            // MMIO_IRQ_CLEAR: Just there to clear interrupts.
            _ => {}
        }
        Ok(())
    }

    /// Resets the device state to the default.
    async fn reset(&self) {
        self.control.store(0, Ordering::Release);
        self.rx_buffer.store(0, Ordering::Release);
        self.tx_buffer.store(0, Ordering::Release);
        // Keep the link state (the network layer will not re-set it cleanly)
        self.status.fetch_and(STATUS_LOWER_UP, Ordering::AcqRel);
    }
}

impl AtmNetworkDevice {
    /// Re-attempts a transfer that ran out of room in the transmit queue
    ///
    /// `CONTROL_TX_TRIGGER` is edge-triggered, so the guest will not trigger us again for
    /// cells it has already handed over. Calling this whenever the network side frees a slot
    /// makes the stall level-triggered instead.
    pub async fn retransmit(&self, device: &Device<Self>) {
        if !self.tx_stalled.load(Ordering::Acquire) {
            return;
        }
        if let Err(error) = self.transmit(device).await {
            tracing::debug!("DMA failure during cell retransmission: {error}");
        }
    }

    /// Transmits pending packets from DMA
    async fn transmit(&self, device: &Device<Self>) -> Result<(), DmaError> {
        // Held for the whole walk: `tx_buffer` and the flags are only consistent between
        // iterations, and `retransmit` can start a second walk at any time.
        let _guard = self.tx_lock.lock().await;
        self.tx_stalled.store(false, Ordering::Release);

        let mut desc_addr = self.tx_buffer.load(Ordering::Acquire);
        loop {
            // Read the descriptor from memory
            let desc: DmaDescriptor = device.dma_read_object(desc_addr.into()).await?;

            // If this is a hardware-owned descriptor, we need to transmit something
            // If it is software-owned, we can stop.
            if desc.flags.owner() == DescriptorOwner::Software {
                break;
            }

            // Read the actual ATM cell
            tracing::trace!(
                "Transmitting cell from {:#x} (descriptor {:#x})",
                desc.data,
                desc_addr
            );
            let cell: AtmCell = device.dma_read_object(desc.data.into()).await?;

            // Submit the cell to the transmit queue
            // The network thread will pick it up eventually
            if let Err(error) = self.tx_queue.try_send(cell) {
                match error {
                    mpsc::error::TrySendError::Full(_) => {
                        // The cell stays in its descriptor; we owe this chain another attempt.
                        self.tx_stalled.store(true, Ordering::Release);
                        tracing::warn!("Internal transmit queue is full.");
                    }
                    mpsc::error::TrySendError::Closed(_) => {
                        tracing::error!("Internal transmit queue was closed unexpectedly.");
                    }
                }
                self.status.fetch_or(STATUS_TX_LOSS, Ordering::AcqRel);
                break;
            }

            // Modify the flags of the descriptor
            let mut flags = desc.flags;
            flags.set_owner(DescriptorOwner::Software);
            device
                .dma_write_object(
                    desc_addr
                        .wrapping_add(std::mem::offset_of!(DmaDescriptor, flags) as u32)
                        .into(),
                    &flags,
                )
                .await?;

            // Update the transmit head.
            desc_addr = desc.next;
            self.tx_buffer.store(desc_addr, Ordering::Release);
        }
        Ok(())
    }

    /// Creates the full device
    pub fn new(tx_queue: Sender<AtmCell>) -> Device<Self> {
        let mmio = Self {
            control: 0.into(),
            status: 0.into(),
            rx_buffer: 0.into(),
            tx_buffer: 0.into(),
            aesa: Default::default(),
            tx_queue,
            tx_lock: Mutex::new(()),
            tx_stalled: AtomicBool::new(false),
        };
        Device::new(mmio, 1)
    }

    /// Creates the full device and leaks it to get `'static` lifetime
    pub fn create_and_leak(tx_queue: Sender<AtmCell>) -> &'static mut Device<Self> {
        Box::leak(Box::new(Self::new(tx_queue)))
    }
}
