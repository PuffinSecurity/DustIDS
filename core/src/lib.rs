#[macro_use]
extern crate log;

pub mod commands;
pub mod scan;
pub mod yara_helpers;

use utils::error::Result;

pub fn start() -> Result<()> {
    // does nothing

    Ok(())
}
