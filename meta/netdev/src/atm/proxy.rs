use std::{sync::atomic::Ordering, time::Duration};

use socket2::{SockRef, TcpKeepalive};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::mpsc::{self, Receiver, Sender},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

use crate::{
    atm::{
        self, AtmCell, AtmNetworkDevice,
        device::{CONTROL_LOOPBACK, CONTROL_RX_ENABLE, STATUS_RX_LOSS, STATUS_TX_LOSS},
        dma::{DescriptorOwner, DmaDescriptor},
    },
    device::{Device, irq::IrqError},
};

// Dead connection detection towards the DSLAM
const KEEPALIVE_IDLE: Duration = Duration::from_secs(30);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
const KEEPALIVE_RETRIES: u32 = 3;
// Matches the keepalive budget, since it replaces the probe count when set
const USER_TIMEOUT: Duration =
    KEEPALIVE_IDLE.saturating_add(KEEPALIVE_INTERVAL.saturating_mul(KEEPALIVE_RETRIES));

/// Proxies the ATM cells between the device and the DSLAM, and does the receive handling
pub struct AtmNetworkProxy<'dev> {
    /// Remote host
    host: String,

    /// Remote port
    port: u16,

    /// The underlying device, for MMIO and DMA accesses
    dev: &'dev Device<AtmNetworkDevice>,

    /// The transmission queue ("receive side", we need to send out packets that appear here)
    for_tx: Receiver<AtmCell>,

    /// The loopback queue's transmit side
    loop_tx: Sender<AtmCell>,

    /// The loopback queue's receive side
    loop_rx: Receiver<AtmCell>,
}

impl<'dev> AtmNetworkProxy<'dev> {
    /// Creates the network side of the network device
    pub fn new(
        host: String,
        port: u16,
        dev: &'dev Device<AtmNetworkDevice>,
        tx_queue: Receiver<AtmCell>,
    ) -> Self {
        let (loop_tx, loop_rx) = mpsc::channel(tx_queue.max_capacity());
        AtmNetworkProxy {
            host,
            port,
            dev,
            for_tx: tx_queue,
            loop_tx,
            loop_rx,
        }
    }

    /// Connects to the DSLAM
    async fn connect(&self) -> std::io::Result<TcpStream> {
        let stream = TcpStream::connect((self.host.as_str(), self.port)).await?;
        stream.set_nodelay(true)?;

        // An idle connection would otherwise never notice that the DSLAM has dropped it,
        // and the user timeout covers the cases where keepalive does not run (unacknowledged
        // data in flight or a zero window).
        let keepalive = TcpKeepalive::new()
            .with_time(KEEPALIVE_IDLE)
            .with_interval(KEEPALIVE_INTERVAL)
            .with_retries(KEEPALIVE_RETRIES);
        let socket = SockRef::from(&stream);
        socket.set_tcp_keepalive(&keepalive)?;
        socket.set_tcp_user_timeout(Some(USER_TIMEOUT))?;
        Ok(stream)
    }

    /// Back off on failed connections. Returns whether we should try to reconnect.
    async fn backoff(token: &CancellationToken) -> bool {
        tokio::select! {
            _ = token.cancelled() => false,
            _ = tokio::time::sleep(Duration::from_secs(5)) => true,
        }
    }

    /// Runs the main network side loop
    pub async fn run(&mut self, token: CancellationToken) {
        while !token.is_cancelled() && !self.for_tx.is_closed() {
            // Clear "lower up" status bit
            self.dev
                .mmio()
                .status
                .fetch_and(!atm::device::STATUS_LOWER_UP, Ordering::AcqRel);

            // Connect to the DSLAM
            tracing::debug!("Connecting to the DSLAM at {}:{}", self.host, self.port);
            let mut stream = tokio::select! {
                _ = token.cancelled() => return,
                result = self.connect() => match result {
                    Ok(stream) => stream,
                    Err(error) => {
                        tracing::warn!("Failed to connect to the DSLAM at {}:{}: {}", self.host, self.port, error);
                        if Self::backoff(&token).await { continue; } else { return; }
                    },
                }
            };
            tracing::trace!("Connected to the DSLAM at {}:{}", self.host, self.port);

            // What is our address?
            let mut address = [0u8; _];
            tokio::select! {
                _ = token.cancelled() => return,
                result = stream.read_exact(&mut address[..]) => match result {
                    Ok(address) => address,
                    Err(error) => {
                        tracing::error!("Failed to receive AESA from the DSLAM at {}:{}: {}", self.host, self.port, error);
                        if Self::backoff(&token).await { continue; } else { return; }
                    },
                }
            };
            tracing::debug!("AESA is {address:?}");
            self.dev.mmio().aesa.store(&address);

            // We're back, indicate this in the status register and start processing cells
            let connected = Instant::now();
            self.dev
                .mmio()
                .status
                .fetch_or(atm::device::STATUS_LOWER_UP, Ordering::AcqRel);
            self.process(stream, token.clone()).await;

            // Back off if this failed very quickly
            if connected.elapsed() < Duration::from_secs(1) && !Self::backoff(&token).await {
                return;
            }
        }
    }

    /// Handles a DSLAM connection
    async fn process(&mut self, stream: TcpStream, token: CancellationToken) {
        let (rx, tx) = stream.into_split();
        let connection_token = CancellationToken::new();

        let rx_task = Self::receive(&self.dev, &mut self.loop_rx, rx, connection_token.clone());
        let tx_task = Self::transmit(
            &self.dev,
            &mut self.for_tx,
            &self.loop_tx,
            tx,
            connection_token.clone(),
        );
        tokio::pin!(rx_task);
        tokio::pin!(tx_task);

        tokio::select! {
            _ = &mut rx_task => {
                connection_token.cancel();
                (&mut tx_task).await;
            },
            _ = &mut tx_task => {
                connection_token.cancel();
                (&mut rx_task).await;
            },
            _ = token.cancelled() => {
                connection_token.cancel();
                (&mut rx_task).await;
                (&mut tx_task).await;
            },
        }
    }

    /// Poke the device via IRQ 0
    async fn poke(dev: &Device<AtmNetworkDevice>) {
        if let Err(error) = dev.trigger_irq(0).await {
            match error {
                IrqError::NotFound => unreachable!(), // We know this IRQ exists
                IrqError::Disconnected => {}
                IrqError::Masked => {}
                IrqError::IoError(error) => {
                    tracing::error!("Failed to trigger IRQ: {error}");
                }
            }
        }
    }

    /// The main receive loop
    async fn receive(
        dev: &Device<AtmNetworkDevice>,
        loopback: &mut Receiver<AtmCell>,
        mut from: OwnedReadHalf,
        connection: CancellationToken,
    ) {
        let mut pending: AtmCell = [0u8; _];
        let mut offset: usize = 0;
        loop {
            let cell = tokio::select! {
                _ = connection.cancelled() => return,
                result = from.read(&mut pending[offset..]) => match result {
                    // read_exact is not cancellation-safe, so we need to manually stitch
                    // the receives together instead.
                    Ok(0) => {
                        tracing::warn!("DSLAM closed the connection");
                        return; // Reconnect and try again
                    },
                    Err(error) => {
                        tracing::warn!("Failed to receive cell from DSLAM: {error}");
                        return; // Reconnect and try again
                    },
                    Ok(count) => {
                        offset += count;
                        if offset < pending.len() {
                            continue;
                        }
                        offset = 0;
                        pending
                    }
                },
                entry = loopback.recv(), if !loopback.is_closed() => match entry {
                    Some(cell) => cell,
                    None => {
                        tracing::warn!("Loopback queue closed unexpectedly");
                        continue;
                    }
                }
            };
            tracing::debug!("Receiving cell {cell:?}");

            let control = dev.mmio().control.load(Ordering::Acquire);
            if control & CONTROL_RX_ENABLE == 0 {
                tracing::debug!("Dropping cell (receipt is disabled)");
                continue;
            }

            // Grab the next DMA descriptor
            let desc_addr = dev.mmio().rx_buffer.load(Ordering::Acquire);
            let desc: DmaDescriptor = tokio::select! {
                _ = connection.cancelled() => return,
                result = dev.dma_read_object(desc_addr.into()) => match result {
                    Ok(desc) => desc,
                    Err(error) => {
                        tracing::debug!("DMA failure during cell receipt: {error}");
                        continue;
                    }
                }
            };

            if desc.flags.owner() == DescriptorOwner::Software {
                // No buffers available, just drop the packet.
                dev.mmio().status.fetch_or(STATUS_RX_LOSS, Ordering::AcqRel);

                // ... and poke the device
                tokio::select! {
                    _ = connection.cancelled() => return,
                    _ = Self::poke(dev) => {},
                };

                continue;
            };

            // This is our buffer, write the cell, then toggle the flags.
            tokio::select! {
                _ = connection.cancelled() => return,
                result = dev.dma_write(desc.data.into(), &cell) => if let Err(error) = result {
                    tracing::debug!("DMA failure during cell receipt: {error}");
                    continue;
                }
            };

            let mut flags = desc.flags;
            flags.set_owner(DescriptorOwner::Software);
            tokio::select! {
                _ = connection.cancelled() => return,
                result = dev.dma_write_object(
                    desc_addr.wrapping_add(std::mem::offset_of!(DmaDescriptor, flags) as u32).into(),
                    &flags
                ) => if let Err(error) = result {
                    tracing::debug!("DMA failure during cell receipt: {error}");
                    continue;
                }
            };

            // Update the head of the DMA chain
            dev.mmio().rx_buffer.store(desc.next, Ordering::Release);

            // Poke the device
            tokio::select! {
                _ = connection.cancelled() => return,
                _ = Self::poke(dev) => {},
            };
        }
    }

    /// The main transmit loop
    async fn transmit(
        dev: &Device<AtmNetworkDevice>,
        from: &mut Receiver<AtmCell>,
        loopback: &Sender<AtmCell>,
        mut into: OwnedWriteHalf,
        connection: CancellationToken,
    ) {
        loop {
            let cell = tokio::select! {
                _ = connection.cancelled() => return,
                head = from.recv() => match head {
                    Some(cell) => cell,
                    None => {
                        // The underlying queue went away. This is not recoverable.
                        tracing::error!("Transmit queue closed unexpectedly.");
                        return;
                    }
                }
            };
            tracing::debug!("Transmitting cell {cell:?}");

            // Taking the cell off the queue freed a slot, so let the device pick up any chain
            // it gave up on. Not cancellable: a half-finished walk would leave a descriptor
            // hardware-owned after its cell has already gone out.
            dev.mmio().retransmit(dev).await;

            let control = dev.mmio().control.load(Ordering::Acquire);
            if control & CONTROL_LOOPBACK != 0 {
                if loopback.try_send(cell).is_err() {
                    tracing::warn!("Loopback queue is full, dropping cell.");
                    dev.mmio().status.fetch_or(STATUS_TX_LOSS, Ordering::AcqRel);
                }
            } else {
                tokio::select! {
                    _ = connection.cancelled() => return,
                    result = into.write_all(&cell) => if let Err(error) = result {
                        tracing::warn!("Failed to send cell to DSLAM: {error}");
                        dev.mmio().status.fetch_or(STATUS_TX_LOSS, Ordering::AcqRel);
                        return; // Reconnect and try again
                    },
                }
            }
        }
    }
}
