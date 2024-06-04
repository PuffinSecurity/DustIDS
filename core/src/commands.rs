use std::cmp::min;
use std::sync::{mpsc::Sender, Arc, Mutex};
use std::thread;
use std::fs;
use std::io::Read;

use yara_x::Rules;
use yara_x::Compiler;
use super::yara_analyzer::YaraAnalyzer;
use super::yara_analyzer::compile_rules_from_dir;
use super::xdpworker;
use super::alerts;

use rebpf::{interface, libbpf};
use libbpf_sys;
use utils::error::Result;

pub fn scan_interface(interface_name: &str, rule_dir: &str) -> Result<()> {  
    // DEBUG
    //let interface_name = "lo";
    //let yara_dir = "../yaraids/rules";
    // ! DEBUG

    // Load XDP flags (Optionally, load a BPF program, but this isnt needed as long as its a IDS and not a IPS)
    let xdp_flags = libbpf::XdpFlags::UPDATE_IF_NOEXIST | libbpf::XdpFlags::DRV_MODE;
    let interface = interface::get_interface(interface_name).unwrap();
    let _ = libbpf::bpf_set_link_xdp_fd(&interface, None, xdp_flags).unwrap();

    // Initialize XDP worker
    let mut xdpanalyzer = xdpworker::XDPWorker::new( // TODO: Add rx queue as param
        interface_name.to_string(),
        xdp_flags,
        2
    );

    // Initialize alert reciever thread
    let alerts_sender = alerts::run(&alerts::AlertConfig {
        stdout: true,
        ip: "".to_string(),
        port: 0,
    });

    // Load Yara rules
    let compiler = Compiler::new();
    let rules  = compile_rules_from_dir(compiler, rule_dir);

    // Initialize analysis threads
    let yara_analyzer: YaraAnalyzer = YaraAnalyzer::new(2, Arc::new(rules), alerts_sender);

    // Run worker
    xdpanalyzer.run(yara_analyzer.frame_sender);

    //yara_analyzer.thread_handles.join();

    xdpanalyzer.disconnect();

    Ok(())
}
