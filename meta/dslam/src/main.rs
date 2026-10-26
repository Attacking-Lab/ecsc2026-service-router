use std::{
    error::Error,
    net::SocketAddr,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use atm::VirtualCircuit;
use clap::Parser;
use tokio::signal::unix::SignalKind;
use tokio_util::sync::CancellationToken;

use crate::capture::Capture;
use crate::debug_log::{Budget, Limits, Log, PolicySnapshot, Settings, Start};
use crate::flood::{Export, Monitor};
use crate::switchboard::Switchboard;

mod addresses;
mod capture;
mod connection;
mod debug_log;
mod dslam;
mod flood;
mod switchboard;

#[derive(Parser)]
struct Cli {
    /// Listening address
    pub address: SocketAddr,

    /// Numbering plan configuration
    pub plan: PathBuf,

    /// Packet capture file
    #[arg(long)]
    pub capture: Option<PathBuf>,

    /// File to append flood warnings to, as JSON lines, for another container to
    /// tail. Written in addition to the log, and appended to across restarts.
    #[arg(long, value_name = "PATH")]
    pub flood_log: Option<PathBuf>,

    /// Mirror cells on this VPI/VCI for testing
    #[arg(long, value_name = "VPI:VCI")]
    pub mirror_circuit: Option<VirtualCircuit>,

    /// Allow calls to dynamically-assigned numbers (by default, only statically
    /// numbered subscribers can be called)
    #[arg(long)]
    pub allow_calls_to_dynamic: bool,

    /// Allow statically-assigned numbers to place calls (by default, they can
    /// only receive them)
    #[arg(long)]
    pub allow_calls_from_static: bool,

    /// Prefix length of the subnet a subscriber's circuit limits are pooled over
    #[arg(long, value_name = "LENGTH", default_value_t = 24)]
    pub subscriber_ipv4_prefix: u32,

    /// Same for IPv6 subscribers
    #[arg(long, value_name = "LENGTH", default_value_t = 64)]
    pub subscriber_ipv6_prefix: u32,

    /// Mask applied to a caller's address before comparing it to
    /// `--checker-pattern`; together they pick out the checker
    #[arg(long, value_name = "ADDRESS", default_value_t = dslam::DEFAULT_CHECKER_MASK)]
    pub checker_mask: std::net::IpAddr,

    /// What a masked caller address must equal to be the checker
    #[arg(long, value_name = "ADDRESS", default_value_t = dslam::DEFAULT_CHECKER_PATTERN)]
    pub checker_pattern: std::net::IpAddr,

    /// Incoming circuits held back on every subscriber for the checker, so a
    /// subscriber busy with everyone else's calls can still be scored
    #[arg(long, value_name = "COUNT", default_value_t = 48)]
    pub checker_reserve: usize,

    /// OTLP gRPC endpoint for logging
    #[arg(long)]
    pub otlp: Option<String>,

    /// Directory to write the debug log to: who connected, who called whom, and
    /// how much each of them sent, as JSON lines, for the correlation and
    /// statistics tooling. One file per run, plus a `latest.jsonl` symlink.
    ///
    /// The log names the team behind every call, which the service deliberately
    /// hides from the teams themselves. Keep the volume to the organisers.
    #[arg(long, value_name = "PATH", env = "DSLAM_DEBUG_LOG_DIR")]
    pub debug_log_dir: Option<PathBuf>,

    /// How much space the debug log may use, as a byte count with an optional
    /// K, M or G suffix. Once a run is over it, the oldest segments are deleted:
    /// the newest records are the ones someone is reading the log for. Unset
    /// keeps everything.
    #[arg(long, value_name = "SIZE", env = "DSLAM_DEBUG_LOG_BUDGET")]
    pub debug_log_budget: Option<Budget>,

    /// How often the debug log starts a new segment. A segment is closed,
    /// compressed and ready to be copied away at the end of each one, so this is
    /// how far behind a game anything reading the log elsewhere runs. Zero rolls
    /// on size alone.
    #[arg(
        long,
        value_name = "SECONDS",
        env = "DSLAM_DEBUG_LOG_SEGMENT_SECONDS",
        default_value_t = debug_log::SEGMENT_INTERVAL.as_secs(),
    )]
    pub debug_log_segment_seconds: u64,

    /// Keep closed segments as plain JSON lines instead of gzipping them. They
    /// compress about eight times, which is both what the budget holds and what
    /// has to be copied off the machine to look at.
    #[arg(long, env = "DSLAM_DEBUG_LOG_NO_COMPRESS")]
    pub debug_log_no_compress: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();
    let token = CancellationToken::new();

    // Set up logging
    #[cfg(not(feature = "opentelemetry"))]
    tracing_subscriber::fmt::init();
    #[cfg(feature = "opentelemetry")]
    {
        if let Some(endpoint) = args.otlp {
            use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
            use opentelemetry_otlp::{LogExporter, WithExportConfig};
            use opentelemetry_sdk::logs::SdkLoggerProvider;
            use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

            let otlp_exporter = LogExporter::builder()
                .with_tonic()
                .with_endpoint(endpoint)
                .build()?;
            let otel_provider = SdkLoggerProvider::builder()
                .with_batch_exporter(otlp_exporter)
                .build();
            let otel_layer = OpenTelemetryTracingBridge::new(&otel_provider);
            tracing_subscriber::registry()
                .with(EnvFilter::try_from_default_env().unwrap_or_default())
                .with(otel_layer)
                .with(tracing_subscriber::fmt::layer())
                .init();
        } else {
            tracing_subscriber::fmt::init();
        }
    }

    // Load the numbering plan
    let numbering_plan = match dslam::NumberingPlan::load_from_yaml(&args.plan) {
        Ok(plan) => plan,
        Err(error) => {
            tracing::error!("Failed to load numbering plan: {error}");
            return Err(error.into());
        }
    };

    // Set up the debug log. Like the flood export, a log that cannot be opened
    // is a misconfiguration, and refusing to start says so before a game rather
    // than during one.
    let (log, log_task) = match &args.debug_log_dir {
        Some(directory) => {
            let start = Start {
                run: format!(
                    "{}-{}",
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    std::process::id()
                ),
                segment: 0,
                trimmed: 0,
                host: std::env::var("HOSTNAME").ok(),
                pid: std::process::id(),
                version: env!("CARGO_PKG_VERSION"),
                listen: args.address.to_string(),
                // All filled in by the writer, which works the segment size
                // out from the budget
                budget: None,
                segment_limit: 0,
                segment_seconds: 0,
                compressed: false,
                policy: PolicySnapshot {
                    allow_calls_to_dynamic: args.allow_calls_to_dynamic,
                    allow_calls_from_static: args.allow_calls_from_static,
                    checker_reserve: args.checker_reserve,
                    subscriber_ipv4_prefix: args.subscriber_ipv4_prefix,
                    subscriber_ipv6_prefix: args.subscriber_ipv6_prefix,
                    checker_mask: args.checker_mask,
                    checker_pattern: args.checker_pattern,
                    mirror_circuit: args.mirror_circuit.map(|circuit| circuit.to_string()),
                },
                limits: Limits::current(),
                plan: numbering_plan.clone(),
            };
            let settings = Settings {
                budget: args.debug_log_budget,
                interval: Duration::from_secs(args.debug_log_segment_seconds),
                compress: !args.debug_log_no_compress,
            };
            match debug_log::Writer::create(directory, settings, start).await {
                Ok((log, writer)) => (log, Some(tokio::spawn(writer.run(token.clone())))),
                Err(error) => {
                    tracing::error!(
                        "Failed to open the debug log in {}: {error}",
                        directory.display()
                    );
                    return Err(error.into());
                }
            }
        }
        None => (Log::disabled(), None),
    };

    // Set up packet capture
    let client = match args.capture.map(Capture::new) {
        Some((client, capture)) => {
            // Run the capture task in the background
            tokio::spawn(capture.run(token.clone()));
            // ...and return the client
            Some(client)
        }
        None => None,
    };

    // Set up the connection map and the switchboard that owns it.
    // The switchboard serializes all signalling and circuit state changes.
    // SAFETY: Hash and Eq are deterministic for both the key and value types, even across
    // clones. This makes new_assert_stable safe, according to its documentation.
    let (writer, reader) = unsafe { evmap::new_assert_stable() };
    let (control, control_queue) = tokio::sync::mpsc::channel(switchboard::CONTROL_QUEUE_SIZE);
    let (events, event_queue) = tokio::sync::mpsc::channel(switchboard::EVENT_QUEUE_SIZE);
    let checker = match dslam::CheckerMatch::new(args.checker_mask, args.checker_pattern) {
        Ok(checker) => checker,
        Err(error) => {
            tracing::error!("Failed to set up the checker match: {error}");
            return Err(error.into());
        }
    };
    let policy = switchboard::Policy {
        allow_calls_to_dynamic: args.allow_calls_to_dynamic,
        allow_calls_from_static: args.allow_calls_from_static,
        checker_reserve: args.checker_reserve,
    };
    let switchboard = Switchboard::new(
        control_queue,
        event_queue,
        writer,
        reader,
        args.mirror_circuit,
        policy,
        log.clone(),
    );
    tokio::spawn(switchboard.run(token.clone()));

    // Set up the DSLAM
    let subnets = match dslam::Subnets::new(
        &numbering_plan,
        args.subscriber_ipv4_prefix,
        args.subscriber_ipv6_prefix,
    ) {
        Ok(subnets) => subnets,
        Err(error) => {
            tracing::error!("Failed to derive the subscriber subnets: {error}");
            return Err(error.into());
        }
    };
    // Set up flood detection, which samples and reports on its own schedule.
    // A flood log that cannot be opened is a misconfiguration, and refusing to
    // start says so before a game rather than during one.
    let monitor = Monitor::new();
    let export = match &args.flood_log {
        Some(path) => match Export::create(path).await {
            Ok(export) => Some(export),
            Err(error) => {
                tracing::error!("Failed to open the flood log {}: {error}", path.display());
                return Err(error.into());
            }
        },
        None => None,
    };
    tokio::spawn(monitor.clone().run(token.clone(), export, log.clone()));

    let mut dslam = dslam::Server::bind(
        numbering_plan,
        subnets,
        checker,
        &args.address,
        control,
        events,
        monitor,
        log,
    )
    .await?;
    dslam.set_capture_client(client);

    // Set up signal handling for shutdown
    let mut sigterm = match tokio::signal::unix::signal(SignalKind::terminate()) {
        Ok(signal) => signal,
        Err(error) => {
            tracing::error!("Failed to register SIGTERM handler: {error}");
            return Err(error.into());
        }
    };

    // Start running the DSLAM process
    let dslam_task = dslam.run(token.clone());
    tokio::pin!(dslam_task);

    tracing::info!("DSLAM is listening on {}", args.address);
    tokio::select! {
        _ = token.cancelled() => {
            (&mut dslam_task).await;
        },
        _ = &mut dslam_task => if !token.is_cancelled() {
            tracing::error!("DSLAM task exited unexpectedly.");
        },
        _ = sigterm.recv() => {
            tracing::info!("Received SIGTERM, shutting down.");
            token.cancel();
            (&mut dslam_task).await;
        },
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received SIGINT, shutting down.");
            token.cancel();
            (&mut dslam_task).await;
        },
    };

    // Let the log finish what is still queued, but not hold up the shutdown if
    // the volume it writes to has gone away
    if let Some(task) = log_task {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), task).await;
    }

    Ok(())
}
