/// IRQ backend for eventfd-triggered IRQs
use std::fs::File;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum IrqError {
    #[error("Interrupt does not exist")]
    NotFound,
    #[error("Interrupt is not wired up")]
    Disconnected,
    #[error("Interrupt is masked")]
    Masked,
    #[error("Failed to trigger interrupt: {0}")]
    IoError(std::io::Error),
}

#[derive(Debug)]
pub struct Irq {
    fd: Option<File>,
    masked: bool,
}

impl Irq {
    /// Triggers the IRQ
    pub fn trigger(&self) -> Result<(), IrqError> {
        if self.masked {
            return Err(IrqError::Masked);
        }
        // NB: This entire ugly dance is because write() requires a mutable reference (because it
        // updates the file offset), which write_at() would not. But eventfds do not support
        // seeking, nor do they support pwrite64, which is what write_at() ends up doing.
        let fd = self.fd.as_ref().ok_or(IrqError::Disconnected)?;
        nix::unistd::write(fd, &u64::to_le_bytes(1))
            .map(drop)
            .map_err(|errno| IrqError::IoError(errno.into()))
    }

    /// Binds the IRQ to a file descriptor
    pub fn bind(&mut self, fd: File) {
        self.fd = Some(fd)
    }

    /// Clears the IRQ
    pub fn unbind(&mut self) {
        self.fd = None
    }

    /// Creates a new, unbound IRQ entry
    pub fn new() -> Self {
        Self {
            fd: None,
            masked: false,
        }
    }

    /// Masks the IRQ
    pub fn mask(&mut self) {
        self.masked = true
    }

    /// Unmasks the IRQ
    pub fn unmask(&mut self) {
        self.masked = false
    }
}

#[derive(Debug)]
pub struct Irqs {
    irqs: Vec<Irq>,
}

impl Irqs {
    /// Creates an IRQ map
    pub fn new(count: usize) -> Self {
        let mut irqs = Vec::with_capacity(count);
        for _ in 0..count {
            irqs.push(Irq::new());
        }
        Self { irqs }
    }

    /// Triggers an IRQ by index
    pub fn trigger(&self, index: usize) -> Result<(), IrqError> {
        self.irqs.get(index).ok_or(IrqError::NotFound)?.trigger()
    }

    /// Binds an IRQ to a file descriptor
    pub fn bind(&mut self, index: usize, fd: File) -> Result<(), IrqError> {
        Ok(self.irqs.get_mut(index).ok_or(IrqError::NotFound)?.bind(fd))
    }

    /// Unbinds an IRQ
    pub fn unbind(&mut self, index: usize) -> Result<(), IrqError> {
        Ok(self.irqs.get_mut(index).ok_or(IrqError::NotFound)?.unbind())
    }

    /// Unbinds all IRQs
    pub fn unbind_all(&mut self) {
        for irq in self.irqs.iter_mut() {
            irq.unbind();
        }
    }

    /// Masks an interrupt
    pub fn mask(&mut self, index: usize) -> Result<(), IrqError> {
        Ok(self.irqs.get_mut(index).ok_or(IrqError::NotFound)?.mask())
    }

    /// Unmasks an interrupt
    pub fn unmask(&mut self, index: usize) -> Result<(), IrqError> {
        Ok(self.irqs.get_mut(index).ok_or(IrqError::NotFound)?.unmask())
    }
}
