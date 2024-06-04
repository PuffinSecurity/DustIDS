use super::alerts::AlertMsg;
use super::analyzer_t::Analyzer;
use yara_x;
use std::fs;
use std::io::Read;
use arraydeque::{ArrayDeque, Wrapping};
use afxdp::PENDING_LEN;
use afxdp::buf_mmap::BufMmap;
use std::thread;
use std::sync::Arc;
use std::sync::Mutex;
use std::cell::RefCell;
use yara_x::Scanner;
use std::net::IpAddr;

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

use yara_x::Compiler;
use yara_x::Rules;

use hex;

//use std::sync::mpsc::Sender;
use crossbeam_channel;

use super::xdpworker::BufCustom;

pub struct YaraAnalyzer {
    pub frame_sender: crossbeam_channel::Sender<Vec<u8>>,
    pub thread_handles: Vec<thread::JoinHandle<()>>,
}

impl YaraAnalyzer {
    pub fn new(num_threads: usize, rules: Arc<yara_x::Rules>, alert_sender: crossbeam_channel::Sender<AlertMsg>) -> Self {
        // Create crossbeam channel
        let (frame_sender, frame_receiver) = crossbeam_channel::unbounded();

        // Init threads
        let mut thread_handles = Vec::new();
        for _ in 0..num_threads {
            let rules = Arc::clone(&rules);
            let sender = alert_sender.clone();
            let reciever = frame_receiver.clone();
            let handle = thread::spawn(move || {
                YaraAnalyzer::thread_run(&*rules, reciever, sender);
            });
            thread_handles.push(handle);
        }

        YaraAnalyzer {
            frame_sender,
            thread_handles
        }
    }

    pub fn thread_run(rules: &yara_x::Rules, frame_reciever: crossbeam_channel::Receiver<Vec<u8>>, alert_sender: crossbeam_channel::Sender<AlertMsg>) {
        // Init scanner
        let mut yara_scanner = Scanner::new(rules);

        // Loop over frames
        loop {
            match frame_reciever.recv() {
                Ok(frame) => {
                    let frame_slice = &frame;
                    let ethernet = EthernetPacket::new(frame_slice).unwrap();
                    analyze_ethernet_frame(&ethernet, &mut yara_scanner, &alert_sender);

                    println!("New packet processed by {:?}", thread::current().id());
                },
                _ => {},
            }
        }
    }
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

pub fn analyze_ethernet_frame(ethernet: &EthernetPacket, yara_scanner: &mut yara_x::Scanner, alert_sender: &crossbeam_channel::Sender<AlertMsg>) {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => analyze_ipv4_packet( ethernet, yara_scanner, alert_sender),
        EtherTypes::Ipv6 => analyze_ipv6_packet( ethernet, yara_scanner, alert_sender),
        //_ => analyze_raw_packet( ethernet, yara_scanner, alert_sender)
        _ => {},
    }
}

// fn analyze_raw_packet(ethernet: &EthernetPacket, yara_scanner: &mut yara_x::Scanner, alert_sender: &Sender<AlertMsg>) {
//     let results = yara_scanner.scan(ethernet.payload()).unwrap();

//     for rule in results.matching_rules() {
//         let data = json!({
//             "timestamp": "2021-08-01T00:00:00.000Z".to_string(),
//             "event_type": "alert".to_string(),
//             // "src_ip": source.to_string(),
//             // "src_port": udp.get_source(),
//             // "dest_ip": destination.to_string(),
//             // "dest_port": udp.get_destination(),
//             "protocol": "UDP".to_string(),
//             "alert": rule.identifier().to_string(),
//         });
//         println!("{}", data.to_string());
//     };
// }

fn analyze_ipv4_packet(ethernet: &EthernetPacket, yara_scanner: &mut yara_x::Scanner, alert_sender: &crossbeam_channel::Sender<AlertMsg>) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        analyze_transport_protocol(
            
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
            yara_scanner,
            alert_sender
        );
    } else {
        println!("[]: Malformed IPv4 Packet");
    }
}

fn analyze_ipv6_packet(ethernet: &EthernetPacket, yara_scanner: &mut yara_x::Scanner, alert_sender: &crossbeam_channel::Sender<AlertMsg>) {
    let header = Ipv6Packet::new(ethernet.payload());
    if let Some(header) = header {
        analyze_transport_protocol(
            
            IpAddr::V6(header.get_source()),
            IpAddr::V6(header.get_destination()),
            header.get_next_header(),
            header.payload(),
            yara_scanner,
            alert_sender
        );
    } else {
        println!("[]: Malformed IPv6 Packet");
    }
}

fn analyze_transport_protocol(
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
    yara_scanner: &mut yara_x::Scanner,
    alert_sender: &crossbeam_channel::Sender<AlertMsg>
) {
    match protocol {
        IpNextHeaderProtocols::Udp => {
            analyze_udp_packet( packet, source, destination, yara_scanner, alert_sender)
        }
        IpNextHeaderProtocols::Tcp => {
            analyze_tcp_packet( packet, source, destination, yara_scanner, alert_sender)
        }
        _ => {},
    }
}

fn analyze_udp_packet(packet: &[u8], source: IpAddr, destination: IpAddr, yara_scanner: &mut yara_x::Scanner, alert_sender: &crossbeam_channel::Sender<AlertMsg>) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        let payload = udp.payload();
        let results = yara_scanner.scan(payload).unwrap();
    
        for rule in results.matching_rules() {
            alert_sender.send(AlertMsg {
                timestamp: None,
                rule: rule.identifier().to_string(),
                src_ip: hex::encode(packet),
                src_port: "src_port".to_string(),
                dst_ip: "dst_ip".to_string(),
                dst_port: "dst_port".to_string(),
            }).unwrap();
        };
    } else {
        println!(" Malformed UDP Packet");
    }
}

fn analyze_tcp_packet(packet: &[u8], source: IpAddr, destination: IpAddr, yara_scanner: &mut yara_x::Scanner, alert_sender: &crossbeam_channel::Sender<AlertMsg>) {
    let tcp = TcpPacket::new(packet);

    if let Some(tcp) = tcp {
        let payload = tcp.payload();
        let results = yara_scanner.scan(payload).unwrap();
    
        for rule in results.matching_rules() {
            alert_sender.send(AlertMsg {
                timestamp: None,
                rule: rule.identifier().to_string(),
                src_ip: hex::encode(packet),
                src_port: "src_port".to_string(),
                dst_ip: "dst_ip".to_string(),
                dst_port: "dst_port".to_string(),
            }).unwrap();
        };
    } else {
        println!("Malformed TCP Packet");
    }
}

