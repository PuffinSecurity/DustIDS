use std::sync::mpsc::Sender;
use super::alerts::AlertMsg;
use super::analyzer_t::Analyzer;
use yara_x;
use std::fs;
use std::io::Read;
use arraydeque::{ArrayDeque, Wrapping};
use afxdp::PENDING_LEN;
use afxdp::buf_mmap::BufMmap;
use threadpool::ThreadPool;
use threadpool_scope::scope_with;
use deadpool::unmanaged::Pool;
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


use crossbeam_channel::unbounded;
use crossbeam_channel::Receiver;

use super::xdpworker::BufCustom;

pub struct YaraAnalyzer {
    pub thread_handles: Vec<thread::JoinHandle<()>>,
}

impl YaraAnalyzer {
    pub fn new(num_threads: usize, rules: Arc<yara_x::Rules>, frame_reciever: crossbeam_channel::Receiver<Vec<u8>>, alert_sender: Sender<AlertMsg>) -> Self {
        // Init threads
        let mut thread_handles = Vec::new();
        for _ in 0..num_threads {
            let rules = Arc::clone(&rules);
            let sender = alert_sender.clone();
            let reciever = frame_reciever.clone();
            let handle = thread::spawn(move || {
                YaraAnalyzer::thread_run(&*rules, reciever, sender);
            });
            thread_handles.push(handle);
        }

        YaraAnalyzer {
            thread_handles: thread_handles,
        }
    }

    pub fn thread_run(rules: &yara_x::Rules, frame_reciever: crossbeam_channel::Receiver<Vec<u8>>, alert_sender: Sender<AlertMsg>) {
        // Init scanner
        let mut yara_scanner = Scanner::new(rules);

        // Loop over frames
        loop {
            match frame_reciever.recv() {
                Ok(frame) => {
                    let frame_slice = &frame;
                    //let matches = scanner.scan(data_slice).unwrap();
                    let ethernet = EthernetPacket::new(frame_slice).unwrap();
                    analyze_ethernet_frame(&ethernet, &mut yara_scanner, &alert_sender);

                    // let ethernet = EthernetPacket::new(frame_slice).unwrap();
                    // let ip_header = Ipv4Packet::new(ethernet.payload()).unwrap();

                    // match ip_header.get_next_level_protocol() {
                    //     IpNextHeaderProtocols::Udp => {}
                    //     IpNextHeaderProtocols::Tcp => {
                    //         let tcp = TcpPacket::new(ip_header.payload());
                    //         if let Some(tcp) = tcp {
                    //             let payload = tcp.payload();
                    //             let results = yara_scanner.scan(payload).unwrap();

                    //             for rule in results.matching_rules() {
                    //                 alert_sender.send(AlertMsg {
                    //                     timestamp: None,
                    //                     rule: rule.identifier().to_string(),
                    //                     src_ip: hex::encode(frame_slice),
                    //                     src_port: "src_port".to_string(),
                    //                     dst_ip: "dst_ip".to_string(),
                    //                     dst_port: "dst_port".to_string(),
                    //                 }).unwrap();
                    //             }

                    //             if results.matching_rules().len() == 0 {
                    //                 alert_sender.send(AlertMsg {
                    //                     timestamp: None,
                    //                     rule: "NO MATCH".to_string(),
                    //                     src_ip: hex::encode(tcp.payload()),
                    //                     src_port: "".to_string(),
                    //                     dst_ip: "".to_string(),
                    //                     dst_port: "".to_string(),
                    //                 }).unwrap();
                    //             }
                    //         }
                    //     }
                    //     _ => { println!("Packet not understood"); }
                    // }

                    // for rule in matches.matching_rules() {
                    //     alert_sender.send(AlertMsg {
                    //         timestamp: None,
                    //         rule: hex::encode(data_slice),
                    //         src_ip: rule.identifier().to_string(),
                    //         src_port: "src_port".to_string(),
                    //         dst_ip: "dst_ip".to_string(),
                    //         dst_port: "dst_port".to_string(),
                    //     }).unwrap();
                    // };
                    //let matches = scanner.scan(x);
                    println!("New packet processed by {:?}", thread::current().id());
                },
                _ => {},
            }
        }
    }
}



pub fn analyze_ethernet_frame(ethernet: &EthernetPacket, yara_scanner: &mut yara_x::Scanner, alert_sender: &Sender<AlertMsg>) {
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

fn analyze_ipv4_packet(ethernet: &EthernetPacket, yara_scanner: &mut yara_x::Scanner, alert_sender: &Sender<AlertMsg>) {
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

fn analyze_ipv6_packet(ethernet: &EthernetPacket, yara_scanner: &mut yara_x::Scanner, alert_sender: &Sender<AlertMsg>) {
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
    alert_sender: &Sender<AlertMsg>
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

fn analyze_udp_packet(packet: &[u8], source: IpAddr, destination: IpAddr, yara_scanner: &mut yara_x::Scanner, alert_sender: &Sender<AlertMsg>) {
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

fn analyze_tcp_packet(packet: &[u8], source: IpAddr, destination: IpAddr, yara_scanner: &mut yara_x::Scanner, alert_sender: &Sender<AlertMsg>) {
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
