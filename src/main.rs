mod interface;
mod net;

use std::sync::{Arc, atomic::AtomicBool};

use clap::{Parser, Subcommand};
use itertools::Itertools;
use windivert::{WinDivert, prelude::WinDivertFlags};

use crate::{
    interface::query_interfaces,
    net::{divert_handler, uninstall_windivert},
};

#[derive(Parser, Debug)]
#[clap(disable_help_flag = true)]
struct CliArgs {
    /// Interface index in Windows
    #[clap(short, long)]
    interface_idx: Option<u32>,

    /// The hostname included in the fake HTTP packet
    #[clap(short, long, default_value = "fake.domain")]
    http_hostname: String,

    /// Handle IPv4
    #[clap(short = '4', long)]
    ipv4: bool,

    /// Handle IPv6
    #[clap(short = '6', long)]
    ipv6: bool,

    /// TTL of the fake packet to send
    #[clap(short, long, default_value_t = 3)]
    ttl: u8,

    /// Threads spawned for handling packets
    #[clap(short, long, default_value_t = 2)]
    jobs: usize,

    /// Also handles forwarding traffic
    #[clap(short, long)]
    forwarding: bool,

    /// Don't auto uninstall WinDivert driver on quit
    #[clap(long)]
    no_uninstall: bool,

    #[command(subcommand)]
    command: Option<Commands>,

    #[clap(long, action = clap::ArgAction::HelpLong)]
    help: Option<bool>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List all connected interfaces with their indices in the system
    ListInterfaces,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = CliArgs::parse();

    if let Some(commands) = args.command {
        match commands {
            Commands::ListInterfaces => {
                match query_interfaces() {
                    Ok(interfaces) => {
                        println!("{}", interfaces.iter().join("\n\n"));
                    }
                    Err(err) => {
                        anyhow::bail!("Error while retrieving interface info: {err}");
                    }
                };
            }
        }
        return Ok(());
    }

    let ip_version_filter = match (args.ipv4, args.ipv6) {
        (true, false) => "ip and",
        (false, true) => "ipv6 and",
        _ => "",
    };
    let interface_filter = match args.interface_idx {
        Some(interface_idx) => format!("ifIdx == {} and", interface_idx),
        None => String::new(),
    };

    let filter = format!(
        "inbound and {} {} tcp.Syn and tcp.Ack",
        ip_version_filter, interface_filter
    );
    let cancellation_token = Arc::new(AtomicBool::new(false));

    ctrlc::set_handler({
        let cancellation_token = cancellation_token.clone();
        move || {
            if cancellation_token.load(std::sync::atomic::Ordering::SeqCst) {
                tracing::warn!("Force quitting...");
                if !args.no_uninstall {
                    uninstall_windivert().unwrap();
                }
                std::process::exit(2);
            } else {
                tracing::info!("Waiting for WinDivert to end, press Ctrl-C again to force quit");
                cancellation_token.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
    })
    .expect("Error setting Ctrl-C handler");

    let network_handle = WinDivert::network(&filter, 0, WinDivertFlags::new())?;
    let network_handle = Arc::new(network_handle);
    let threads = (0..args.jobs)
        .map(|_| {
            let http_hostname = args.http_hostname.clone();
            let network_handle = network_handle.clone();
            let cancellation_token = cancellation_token.clone();
            std::thread::spawn(move || {
                divert_handler(network_handle, http_hostname, args.ttl, cancellation_token)
            })
        })
        .collect_vec();
    tracing::info!("Started handling network traffic");

    if args.forwarding {
        let forward_handle = WinDivert::forward(&filter, 0, WinDivertFlags::new())?;
        let forward_handle = Arc::new(forward_handle);
        let forward_threads = (0..args.jobs)
            .map(|_| {
                let http_hostname = args.http_hostname.clone();
                let forward_handle = forward_handle.clone();
                let cancellation_token = cancellation_token.clone();
                std::thread::spawn(move || {
                    divert_handler(forward_handle, http_hostname, args.ttl, cancellation_token)
                })
            })
            .collect_vec();
        tracing::info!("Started handling forwarded network traffic");

        for t in forward_threads {
            let _ = t.join();
        }
    }

    for t in threads {
        let _ = t.join();
    }

    if !args.no_uninstall {
        uninstall_windivert()?
    }

    Ok(())
}
