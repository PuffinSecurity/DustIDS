use std::sync::{Arc, RwLock};
use yara_x::Compiler;
use super::yara_analyzer::YaraAnalyzer;
use super::yara_analyzer::compile_rules_from_dir;
use super::xdpworker;
use super::alerts;
use super::stats;
use super::afxdp_listener;
use super::afpacket_listener;

use rebpf::{interface, libbpf};
use libbpf_sys;
use utils::error::Result;

pub struct ScanResult {
    pub handles: Vec<std::thread::JoinHandle<()>>,
    pub stats: Arc<RwLock<stats::Stats>>,
}

pub fn scan_interface(interface_name: &str, rule_dir: &str) -> Result<(ScanResult)> {  
    // DEBUG
    //let interface_name = "lo";
    //let yara_dir = "../yaraids/rules";
    // ! DEBUG

    // Load XDP flags (Optionally, load a BPF program, but this isnt needed as long as its a IDS and not a IPS)
    let xdp_flags = libbpf::XdpFlags::UPDATE_IF_NOEXIST | libbpf::XdpFlags::DRV_MODE;
    let interface = interface::get_interface(interface_name).unwrap();
    let _ = libbpf::bpf_set_link_xdp_fd(&interface, None, xdp_flags).unwrap();

    // Initialize Stats
    let (stats, rx_stat_sender, alert_stat_sender) = stats::Stats::new();

    // Initialize alert reciever thread
    let alerts_sender = alerts::run(&alerts::AlertConfig {
        stdout: true,
        ip: "".to_string(),
        port: 0,
        },
        alert_stat_sender.clone()
    );

    // Load Yara rules
    let compiler = Compiler::new();
    let rules  = compile_rules_from_dir(compiler, rule_dir);

    // Initialize analysis threads
    let yara_analyzer: YaraAnalyzer = YaraAnalyzer::new(2, Arc::new(rules), alerts_sender.clone(), rx_stat_sender.clone());

    // Initialize XDP worker
    // let mut xdpanalyzer = xdpworker::XDPWorker::new( // TODO: Add rx queue as param
    //     interface_name.to_string(),
    //     xdp_flags,
    //     2,
    // );

    // Run worker
    //xdpanalyzer.run(yara_analyzer.frame_sender, rx_stat_sender.clone());

    //yara_analyzer.thread_handles.join()

    // let mut afxdp_listener = afxdp_listener::AFXDPListener::new(interface_name.to_string(), xdp_flags, 2, yara_analyzer.frame_sender.clone(), rx_stat_sender.clone());
    // let afxdp_handle = afxdp_listener.run();
    let mut afpacket_listener = afpacket_listener::AFPacketListener::new(interface_name.to_string(), yara_analyzer.frame_sender.clone(), rx_stat_sender.clone());
    let afpacket_handle = afpacket_listener.run();
    // afxdp_handle.join();
    // for handle in yara_analyzer.thread_handles {
    //     handle.join();
    // }
    //xdpanalyzer.disconnect();

    let mut all_handles = yara_analyzer.thread_handles;
    all_handles.push(afpacket_handle); 

    Ok(ScanResult {
        handles: all_handles,
        stats: stats,
    })
}
