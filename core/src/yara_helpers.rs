use std::fs;
use std::path::Path;
use std::io::Read;

use yara_x_parser::SourceCode;
use yara_x::Compiler;
use yara_x::Scanner;
use yara_x::Rules;

use utils::error::Result;

pub fn compile_rules_from_dir(mut compiler: Compiler, rule_dir: &str) -> Result<Rules> {
    let files_in_path = fs::read_dir(rule_dir)?;
    
    let mut count = 0;
    for file in files_in_path {
        let file = file?;
        let path = file.path();

        // Check if the path is a file and has the '.yar' extension
        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("yar") {
            let mut file = fs::File::open(&path)?;

            // Read the file's content into a string
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;

            // Add the file's content as a source to the compiler
            if let Err(err) = compiler.add_source(contents.as_str()) {
                log::warn!("[!] Error while processing rule file: {}: {}", path.display(), err);
            }

            log::debug!("Added Rule File: {:?}", path);
        }
        count += 1;
    }
    if count == 0 {
        log::warn!("[!] No rule files found in directory: {}", rule_dir);
        return Err(utils::error::Error::new("No rule files found"));
    }

    Ok(compiler.build())
}
