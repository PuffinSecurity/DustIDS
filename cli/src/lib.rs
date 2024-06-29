mod app;
mod crossterm;
mod ui;

use std::{path::PathBuf, str::FromStr};
use clap::{Parser, Subcommand, CommandFactory};
use clap_complete::{generate, shells::{Bash, Fish, Zsh}};

use core::commands;
use utils::error::Result;
use utils::types::LogLevel;

use atomic_counter::{AtomicCounter, RelaxedCounter};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use std::ffi::OsString;

const TICKRATE: usize = 1000;


#[derive(Parser, Debug)]
#[command(
    name = "dust",
    author,
    about,
    long_about = "The lean industrial IDS",
    version
)]
pub struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[clap(
        name = "scan",
        about = "Scan a interface for malicious traffic",
        long_about = None, 
    )]
    Scan {
        #[arg(required = true, value_name = "INTERFACE", help = "Interface to scan")]
        iface: Option<OsString>,

        #[arg(
            value_name = "RULES-DIR",
            short, long,
            required = true,
            help = "Path to a directory holding yara rules")
        ]
        rules_dir: Option<OsString>,

        #[arg(
            value_name = "SYSLOG-SERVER",
            long,
            required = true,
            help = "[IP:PORT] of the syslog server to which send alerts")
        ]
        syslog_server: Option<OsString>,

        #[arg(
            value_name = "ANALYSIS-THREADS",
            long,
            default_value_t = 1,
            help = "Number of threads to use for analysis")
        ]
        analysis_threads: u8,

        #[arg(
            value_name = "ANALYSIS-BUFFER-SIZE",
            long,
            default_value_t = 32768,
            help = "Max number of packets to buffer for analysis")
        ]
        analysis_buffer_size: usize,

        #[arg(
            value_name = "AF-XDP",
            short, long, action,
            help = "Use AF_XDP instead of AF_PACKET (Experimental)")
        ]
        use_afxdp: bool,

        #[arg(
            value_name = "TUI",
            short, long, action,
            help = "Use Terminal User Interface")
        ]
        tui: bool,
    },
}

pub fn cli_match() -> Result<()> {
    // Parse the command line arguments
    let cli = Cli::parse();

    // Execute the subcommand
    match cli.command {
        Commands::Scan {
            iface,
            rules_dir,
            syslog_server,
            analysis_threads,
            analysis_buffer_size,
            use_afxdp,
            tui,
        } => {
            let iface = iface
                .as_deref()
                .map(|s| s.to_str().unwrap())
                .unwrap_or("lo");

            let rules_dir = rules_dir
                .as_deref()
                .map(|s| s.to_str().unwrap())
                .unwrap_or(".");

            let syslog_server = syslog_server
                .as_deref()
                .map(|s| s.to_str().unwrap())
                .unwrap_or("");

            let (mut state, handles) = core::commands::scan_interface(
                iface,
                rules_dir,
                analysis_threads as usize,
                analysis_buffer_size,
                use_afxdp,
                syslog_server).unwrap();

            if tui {
                crossterm::run(TICKRATE, state).unwrap();
            } else {
                loop {
                    std::thread::sleep(Duration::from_secs(15));//TODO 
                    state.on_tick(TICKRATE);
                    // print all state data
                    println!("Rx per sec: {:?} Total: {:?} - RX Dropped {:?} - Analysis Buffer: {:?}/{:?} - Alerts:\n {:?}",
                        state.rx_per_sec,
                        state.rx_total.get(),
                        state.rx_dropped.get(),
                        state.analysis_buffer_len.load(Ordering::Relaxed),
                        state.analysis_buffer_cap,
                        state.alerts.read().unwrap()
                    );
                    println!("rx queue: {:?}", state.rx_per_tick);
                }
            }

            for handle in handles {
                handle.join();
            }
        }
    }

    Ok(())
}
