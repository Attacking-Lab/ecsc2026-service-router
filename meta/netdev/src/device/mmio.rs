use crate::device::Device;

pub trait Mmio: Send + Sync {
    /// Size of the MMIO region
    const SIZE: usize;

    /// Handles an MMIO read
    async fn read(
        &self,
        offset: u64,
        data: &mut [u8],
        device: &Device<Self>,
    ) -> std::io::Result<()>;

    /// Handles an MMIO write
    async fn write(&self, offset: u64, data: &[u8], device: &Device<Self>) -> std::io::Result<()>;

    /// Handles a device reset
    async fn reset(&self);
}
