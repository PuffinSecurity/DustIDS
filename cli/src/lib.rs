use std::{path::PathBuf, str::FromStr};
use clap::{Parser, Subcommand, CommandFactory};
use clap_complete::{generate, shells::{Bash, Fish, Zsh}};

use core::commands;
use utils::error::Result;
use utils::types::LogLevel;

use std::ffi::OsString;

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
        } => {
            let iface = iface
                .as_deref()
                .map(|s| s.to_str().unwrap())
                .unwrap_or("lo");

            let rules_dir = rules_dir
                .as_deref()
                .map(|s| s.to_str().unwrap())
                .unwrap_or(".");

            core::commands::scan_interface(iface, rules_dir).unwrap();
        }

    }

    Ok(())
}
