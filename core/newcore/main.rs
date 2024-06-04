use std::cmp::min;
use std::sync::{mpsc::Sender, Arc, Mutex};
use std::thread;
use std::fs;
use std::io::Read;
use yara_x::Compiler;
use yara_x::Rules;

use yara_analyzer::YaraAnalyzer;

use rebpf::{interface, libbpf};
use libbpf_sys;

fn main() {
    // DEBUG
    let interface_name = "lo";
    let yara_dir = "../yaraids/rules";
    let interface = interface::get_interface(interface_name).unwrap();
    let xdp_flags = libbpf::XdpFlags::UPDATE_IF_NOEXIST | libbpf::XdpFlags::DRV_MODE;
    // ! DEBUG

    // Load XDP flags (Optionally, load a BPF program, but this isnt needed as long as its a IDS and not a IPS)
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

    // Create crossbeam communication channel
    let (frame_sender, frame_receiver) = crossbeam_channel::unbounded();

    // Load Yara rules
    let compiler = Compiler::new();
    let rules  = compile_rules_from_dir(compiler, yara_dir);

    // Create Yara Analyzer
    let yara_analyzer: YaraAnalyzer = YaraAnalyzer::new(2, Arc::new(rules), frame_receiver, alerts_sender);

    // Run worker
    xdpanalyzer.run(frame_sender);

    //yara_analyzer.thread_handles.join();

    xdpanalyzer.disconnect();
}


pub fn compile_rules_from_dir(mut compiler: Compiler, rule_dir: &str) -> Rules {
    let files_in_path = fs::read_dir(rule_dir).unwrap();
    
    let mut count = 0;
    for file in files_in_path {
        let file = file.unwrap();
        let path = file.path();

        // Check if the path is a file and has the '.yar' extension
        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("yar") {
            let mut file = fs::File::open(&path).unwrap();

            // Read the file's content into a string
            let mut contents = String::new();
            file.read_to_string(&mut contents).unwrap();

            // Add the file's content as a source to the compiler
            if let Err(err) = compiler.add_source(contents.as_str()) {
                println!("[!] Error while processing rule file: {}: {}", path.display(), err);
            }

            println!("Added Rule File: {:?}", path);
        }
        count += 1;
    }
    if count == 0 {
        panic!("[!] No rule files found in directory: {}", rule_dir);
    }

    compiler.build()
}
