use super::error;
use super::hazard;
use super::scan;

use utils::app_config::AppConfig;
use utils::error::Result;
use std::fs;
use std::path::Path;
use std::io::Read;

use yara_x_parser::SourceCode;
use yara_x::Compiler;
use yara_x::Scanner;
use yara_x::Rules;


pub fn ids() -> Result<()> {
    // Create Yara Scanner
    let mut compiler = yara_x::Compiler::new();

    let rule_dir = "rules";
    
    let entries = fs::read_dir(rule_dir)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        // Check if the path is a file and has the '.rule' extension
        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("yar") {
            println!("Added Rule File: {:?}", path);
            let mut file = fs::File::open(&path)?;
            let mut contents = String::new();
            
            // Read the file's content into a string
            file.read_to_string(&mut contents)?;
            
            // Add the file's content as a source to the compiler
            compiler.add_source(contents.as_str()).expect("Failed to add source to compiler");
        }
    }

    let rules = compiler.build();

    // Create a scanner that uses the compiled rules.
    let mut scanner = yara_x::Scanner::new(&rules);

    let _ = scan::capture_packets(&mut scanner);

    Ok(())
}

/// Show the configuration file
pub fn hazard() -> Result<()> {
    // Generate, randomly, True or False
    let random_hazard: bool = hazard::generate_hazard()?;

    if random_hazard {
        println!("You got it right!");
    } else {
        println!("You got it wrong!");
    }

    Ok(())
}

/// Show the configuration file
pub fn config() -> Result<()> {
    let config = AppConfig::fetch()?;
    println!("{:#?}", config);

    Ok(())
}

/// Simulate an error
pub fn simulate_error() -> Result<()> {
    // Log this Error simulation
    info!("We are simulating an error");

    // Simulate an error
    error::simulate_error()?;

    // We should never get here...
    Ok(())
}
