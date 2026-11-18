use std::sync::{Arc, RwLock};
use yara_x::Compiler;
use super::yara_analyzer::YaraAnalyzer;
use super::yara_analyzer::compile_rules_from_dir;
use super::alerts;
use super::listener_afxdp;
use super::listener_afpacket;
use super::state;
use super::syslog_alerter;

use rebpf::{interface, libbpf};
use libbpf_sys;
use utils::error::Result;


pub fn scan_interface(
    interface_name: &str,
    rule_dir: &str,
    analysis_threads: usize,
    anlys_buf_size: usize,
    use_afxdp: bool,
    syslog_server: &str,
    ) -> Result<(state::State, Vec<std::thread::JoinHandle<()>>)> {
    // Load Yara rules
    let compiler = Compiler::new();
    let (rules, rule_files)  = compile_rules_from_dir(compiler, rule_dir);

    // Create crossbeam channel
    let (frame_sender, frame_receiver) = crossbeam_channel::bounded(anlys_buf_size);

    // Init Alert Handler TODO1
    // let syslog_alerter = syslog_alerter::new();


    // Initialize state // TODO For now hardcode number of queues to 1
    let (state, state_handle) = state::State::new(
        interface_name.to_string(),
        1,
        analysis_threads as u8,
        rule_files,
        frame_receiver.clone(),
        syslog_server.to_string(),
    );

    // Initialize analysis threads
    let yara_analyzer: YaraAnalyzer = YaraAnalyzer::new(
        analysis_threads,
        anlys_buf_size,
        Arc::new(rules),
        Arc::clone(&state.analyzed_total),
        state.alert_sender.clone(),
        frame_receiver.clone(),
    );

    // Join handles
    let mut all_handles = yara_analyzer.thread_handles;
    all_handles.push(state_handle);

    // Initialize listeners
    if use_afxdp {
        // Load XDP flags (Optionally, load a BPF program, but this isnt needed as long as its a IDS and not a IPS)
        let xdp_flags = libbpf::XdpFlags::UPDATE_IF_NOEXIST | libbpf::XdpFlags::DRV_MODE;
        let interface = interface::get_interface(interface_name).unwrap();
        let _ = libbpf::bpf_set_link_xdp_fd(&interface, None, xdp_flags).unwrap();

        let mut afxdp_listener = listener_afxdp::AFXDPListener::new(
            interface_name.to_string(),
            xdp_flags, 
            2,
            frame_sender.clone());
        let afpacket_handle = afxdp_listener.run(Arc::clone(&state.rx_total));
        all_handles.push(afpacket_handle);

    } else {
        let mut afpacket_listener = listener_afpacket::AFPacketListener::new(
            interface_name.to_string(),
            frame_sender.clone());
        let afpacket_handle = afpacket_listener.run(Arc::clone(&state.rx_total), Arc::clone(&state.rx_dropped));    

        all_handles.push(afpacket_handle);
    }

    Ok((
        state,
        all_handles,
    ))
}
