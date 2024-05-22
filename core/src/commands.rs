use super::scan;
use super::yara_helpers::compile_rules_from_dir;

use pnet::datalink;
use pnet::datalink::NetworkInterface;
use utils::error::Result;
use std::fs;
use std::path::Path;
use std::io::Read;

use yara_x::Compiler;

pub fn scan_interface(interface_name: &str, rule_dir: &str) -> Result<()> {    
    // Init YARA-X Scanner
    let compiler = Compiler::new();
    let rules = compile_rules_from_dir(compiler, rule_dir).unwrap();
    let mut scanner = yara_x::Scanner::new(&rules); 

    // Get the network interface
    let all_interfaces = datalink::interfaces();
    let interface: &NetworkInterface = all_interfaces
        .iter()
        .find(|e| e.name == interface_name) //e.is_up() && !e.is_loopback() && !e.ips.is_empty())
        .unwrap();

    if interface.is_up() {
        log::debug!("Interface is up: {}", interface.name);
    } else {
        log::error!("Interface is down, unable to start: {}", interface.name);
        panic!("[!] Interface is down, unable to start: {}", interface.name);
    }

    // Initiate packet capture
    let _ = scan::capture_packets(&mut scanner, interface);

    Ok(())
}
