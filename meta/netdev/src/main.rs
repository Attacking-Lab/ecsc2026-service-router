use clap::Parser;
use std::{
    error::Error,
    num::NonZeroUsize,
    os::unix::fs::FileTypeExt,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{signal::unix::SignalKind, sync::mpsc};
use tokio_util::sync::CancellationToken;
use vfio_user::Server;

use crate::device::PciDevice;

mod atm;
mod device;

#[derive(Parser)]
#[command(about)]
struct Cli {
    /// Gamenet connection, as `<host or address>:<port>`
    #[arg(value_parser = endpoint)]
    address: (String, u16),

    /// Unix socket to bind to
    socket: PathBuf,

    /// Queue size within the device
    #[arg(short, long, default_value = "32")]
    queue_size: NonZeroUsize,

    /// Try to remove the socket if it already exists
    #[arg(short, long)]
    force: bool,
}

fn endpoint(value: &str) -> Result<(String, u16), String> {
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| format!("no `:<port>` in `{value}`"))?;
    if host.is_empty() {
        return Err(format!("no host in `{value}`"));
    }
    let port = port
        .parse()
        .map_err(|error| format!("invalid port `{port}`: {error}"))?;
    Ok((host.to_owned(), port))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();
    let args = Cli::parse();
    let token = CancellationToken::new();

    // Try to remove the socket if it already exists.
    if args.force {
        // This is really more of a sanity thing.
        // If this fails, we'll error below anyways.
        if let Ok(metadata) = args.socket.metadata()
            && metadata.file_type().is_socket()
        {
            let _ = std::fs::remove_file(&args.socket);
        }
    }

    // Create the network device
    let (write_end, read_end) = mpsc::channel(args.queue_size.get());
    let device = atm::AtmNetworkDevice::create_and_leak(write_end);
    let (host, port) = args.address;
    let mut proxy = atm::AtmNetworkProxy::new(host, port, device, read_end);

    // Create the PCI device around it
    let mut pci = match PciDevice::new(device, atm::pci::config()).await {
        Ok(pci) => pci,
        Err(error) => {
            tracing::error!("Failed to create PCI device: {error}");
            return Err(error.into());
        }
    };
    let server = match Server::new(&args.socket, true, pci.irqs(), pci.regions()) {
        Ok(server) => server,
        Err(error) => {
            tracing::error!("Failed to create vfio-user server: {error}");
            return Err(error.into());
        }
    };

    // Run the (blocking) vfio-user server in a separate thread.
    let failed = Arc::new(AtomicBool::new(false));
    let server_token = token.clone();
    let server_failed = failed.clone();
    std::thread::spawn(move || {
        if let Err(error) = server.run(&mut pci) {
            tracing::error!("Server thread exited with an error: {error}");
            server_failed.store(true, Ordering::Release);
        }
        server_token.cancel();
    });

    let mut sigterm = match tokio::signal::unix::signal(SignalKind::terminate()) {
        Ok(signal) => signal,
        Err(error) => {
            tracing::error!("Failed to register SIGTERM handler: {error}");
            return Err(error.into());
        }
    };

    // Handle the network side of the device queues.
    // This will automatically attempt to reconnect to the network.
    let proxy_task = proxy.run(token.clone());
    tokio::pin!(proxy_task);

    tokio::select! {
        _ = token.cancelled() => {
            (&mut proxy_task).await;
        },
        _ = &mut proxy_task => if !token.is_cancelled() {
            tracing::error!("Network thread exited unexpectedly");
            failed.store(true, Ordering::Release);
        },
        _ = sigterm.recv() => {
            tracing::info!("Received SIGTERM, shutting down.");
            token.cancel();
            (&mut proxy_task).await;
        },
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received SIGINT, shutting down.");
            token.cancel();
            (&mut proxy_task).await;
        },
    };

    // I'd love to thread.join() here, but there is no way to signal the vfio_user thread.
    // Instead, just exit fully.
    let exit_code = if failed.load(Ordering::Acquire) { 1 } else { 0 };
    std::process::exit(exit_code);
}
