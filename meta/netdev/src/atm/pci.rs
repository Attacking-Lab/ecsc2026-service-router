use vfio_bindings::bindings::vfio::VFIO_PCI_BAR0_REGION_INDEX;

use crate::{
    atm::AtmNetworkDevice,
    device::{mmio::Mmio, pci},
};

/// Creates the PCI configuration for this ATM network device
pub fn config() -> pci::PciConfiguration {
    /// PCI device class 02 (network controller) subclasses
    /// (see https://admin.pci-ids.ucw.cz/read/PD/02)
    #[derive(Copy, Clone)]
    enum PciNetworkControllerSubclass {
        /// 02:03: ATM network controller
        AtmNetworkController = 0x03,
    }

    impl pci::PciSubclass for PciNetworkControllerSubclass {
        fn get_register_value(&self) -> u8 {
            *self as u8
        }
    }

    let mut configuration = pci::PciConfiguration::new(
        0xdff4,
        0x1337,
        pci::PciClassCode::NetworkController,
        &PciNetworkControllerSubclass::AtmNetworkController as &dyn pci::PciSubclass,
        None,
        pci::PciHeaderType::Device,
        0,
        0,
        0,
    );

    configuration
        .add_pci_bar(pci::PciBarConfiguration::new(
            VFIO_PCI_BAR0_REGION_INDEX as usize,
            <AtmNetworkDevice as Mmio>::SIZE as u64,
            pci::PciBarRegionType::Memory32BitRegion,
            pci::PciBarPrefetchable::NotPrefetchable,
        ))
        .expect("Invalid PCI configuration");

    configuration.set_irq(0, pci::PciInterruptPin::IntA);

    configuration
}
