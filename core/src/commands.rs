use super::scan;
use super::yara_helpers::compile_rules_from_dir;

use pnet::datalink;
use pnet::datalink::NetworkInterface;
use utils::error::Result;
use std::fs;
use std::path::Path;
use std::io::Read;
use slog::{Drain, Logger, o};
use slog_async::Async;
use slog_json::Json;
use slog_term::{FullFormat, PlainDecorator, TermDecorator};
use std::fs::OpenOptions;
use std::sync::Arc;



use yara_x::Compiler;

pub fn scan_interface(interface_name: &str, rule_dir: &str) -> Result<()> {    
    // Init EveJSON Logger
    let file_logger = {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open("json_logs.json")
            .expect("Failed to open json log file");
        let drain = Json::new(file)
            .add_default_keys()
            .build()
            .fuse();
        Async::new(drain).build().fuse()
    };
    let json_logger = Logger::root(file_logger, o!());

    // Init YARA-X Scanner
    let compiler = Compiler::new();
    let rules = compile_rules_from_dir(compiler, rule_dir).unwrap();
    let mut scanner = yara_x::Scanner::new(&rules); 

    // Get the network interface
    let all_interfaces = datalink::interfaces();
    let interface: &NetworkInterface = match all_interfaces
        .iter()
        .find(|e| e.name == interface_name) {
            Some(interface) => interface,
            None => {
                panic!("[!] No interface found matching name: {}", interface_name);
                //eprintln!("No interface found matching name: {}", interface_name);
                //return Ok(());  // Exit the function or use std::process::exit(1) to exit the program
        }
    };
        //e.is_up() && !e.is_loopback() && !e.ips.is_empty())
        //.unwrap();

    if interface.is_up() {
        log::debug!("Interface is up: {}", interface.name);
    } else {
        log::error!("Interface is down, unable to start: {}", interface.name);
        panic!("[!] Interface is down, unable to start: {}", interface.name);
    }

    // Initiate packet capture
    let _ = scan::analyze_packets(&mut scanner, interface, json_logger);

    Ok(())
}
