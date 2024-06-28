#[macro_use]
extern crate log;

pub mod commands;
pub mod analyzer_t;
pub mod debug_analyzer;
pub mod yara_analyzer;
pub mod xdpworker;
pub mod afxdp_listener;
pub mod afpacket_listener;
pub mod alerts_t;
pub mod evejson_t;
pub mod alerts;
pub mod state;
pub mod syslog_alerts;
pub mod logging;

use utils::error::Result;

pub fn start() -> Result<()> {
    // does nothing

    Ok(())
}
