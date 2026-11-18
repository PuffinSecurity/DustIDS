#[macro_use]
extern crate log;

pub mod commands;
pub mod yara_analyzer;
pub mod listener_afxdp;
pub mod listener_afpacket;
pub mod alerts;
pub mod state;
pub mod evejson_t;
pub mod syslog_alerter;

use utils::error::Result;

pub fn start() -> Result<()> {
    // does nothing

    Ok(())
}
