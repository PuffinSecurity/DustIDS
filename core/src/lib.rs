#[macro_use]
extern crate log;

pub mod commands;
pub mod analyzer_t;
pub mod debug_analyzer;
pub mod yara_analyzer;
pub mod xdpworker;
pub mod alerts;
pub mod stats;

use utils::error::Result;

pub fn start() -> Result<()> {
    // does nothing

    Ok(())
}
