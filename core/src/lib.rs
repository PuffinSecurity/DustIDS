#[macro_use]
extern crate log;

pub mod commands;
pub mod scan;
pub mod yara_helpers;
pub mod packet_analysis;
pub mod eve_alert;

use utils::error::Result;

pub mod analyzer {
    pub mod threaded_analyzer;
}

pub fn start() -> Result<()> {
    // does nothing

    Ok(())
}
