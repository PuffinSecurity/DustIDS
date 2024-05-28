extern crate pnet;

use pnet::datalink::NetworkInterface;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

use std::net::IpAddr;

use chrono::Utc;

use super::eve_alert::{Alert, EveEvent, Metadata};

pub fn analyze_ethernet_frame(interface: &NetworkInterface, ethernet: &EthernetPacket, yara_scanner: &mut yara_x::Scanner, alert_logger: &slog::Logger) {
    let interface_name = &interface.name[..];
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => analyze_ipv4_packet(interface_name, ethernet, yara_scanner, alert_logger),
        EtherTypes::Ipv6 => analyze_ipv6_packet(interface_name, ethernet, yara_scanner, alert_logger),
        //_ => analyze_raw_packet(interface_name, ethernet, yara_scanner, alert_logger)
        _ => println!(
            "[{}]: Unknown packet: {} > {}; ethertype: {:?} length: {}",
            interface_name,
            ethernet.get_source(),
            ethernet.get_destination(),
            ethernet.get_ethertype(),
            ethernet.packet().len()
        ),
    }
}

// fn analyze_raw_packet(interface_name: &str, ethernet: &EthernetPacket, yara_scanner: &mut yara_x::Scanner, alert_logger: &slog::Logger) {
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

fn analyze_ipv4_packet(interface_name: &str, ethernet: &EthernetPacket, yara_scanner: &mut yara_x::Scanner, alert_logger: &slog::Logger) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        analyze_transport_protocol(
            interface_name,
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
            yara_scanner,
            alert_logger
        );
    } else {
        println!("[{}]: Malformed IPv4 Packet", interface_name);
    }
}

fn analyze_ipv6_packet(interface_name: &str, ethernet: &EthernetPacket, yara_scanner: &mut yara_x::Scanner, alert_logger: &slog::Logger) {
    let header = Ipv6Packet::new(ethernet.payload());
    if let Some(header) = header {
        analyze_transport_protocol(
            interface_name,
            IpAddr::V6(header.get_source()),
            IpAddr::V6(header.get_destination()),
            header.get_next_header(),
            header.payload(),
            yara_scanner,
            alert_logger
        );
    } else {
        println!("[{}]: Malformed IPv6 Packet", interface_name);
    }
}

fn analyze_transport_protocol(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
    yara_scanner: &mut yara_x::Scanner,
    alert_logger: &slog::Logger
) {
    match protocol {
        IpNextHeaderProtocols::Udp => {
            analyze_udp_packet(interface_name, packet, source, destination, yara_scanner, alert_logger)
        }
        IpNextHeaderProtocols::Tcp => {
            analyze_tcp_packet(interface_name, packet, source, destination, yara_scanner, alert_logger)
        }
        _ => println!(
            "[{}]: Unknown {} packet: {} > {}; protocol: {:?} length: {}",
            interface_name,
            match source {
                IpAddr::V4(..) => "IPv4",
                _ => "IPv6",
            },
            source,
            destination,
            protocol,
            packet.len()
        ),
    }
}

fn analyze_udp_packet(interface_name: &str, packet: &[u8], source: IpAddr, destination: IpAddr, yara_scanner: &mut yara_x::Scanner, alert_logger: &slog::Logger) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        let payload = udp.payload();
        let results = yara_scanner.scan(payload).unwrap();
    
        for rule in results.matching_rules() {
            let event = EveEvent {
                timestamp: Utc::now().to_rfc3339(),
                flow_id: 1234567890,
                event_type: "alert".to_string(),
                src_ip: source.to_string(),
                src_port: udp.get_source(),
                dest_ip: destination.to_string(),
                dest_port: udp.get_destination(),
                proto: "UDP".to_string(),
                alert: Alert {
                    action: "allowed".to_string(),
                    gid: 1,
                    signature_id: 1000001,
                    rev: 1,
                    signature: "Placeholder".to_string(),
                    category: "Placeholder".to_string(),
                    severity: 1,
                    metadata: Metadata {
                        rule: rule.identifier().to_string(),
                        ruleset: rule.namespace().to_string(),
                        tags: vec!["Placeholder".to_string()],
                        mitre: vec!["Placeholder".to_string()],
                    },
                },
            };
        
            let event_json = serde_json::to_string(&event).unwrap();
            println!("{}", event_json);
        };
    } else {
        println!("[{}]: Malformed UDP Packet", interface_name);
    }
}

fn analyze_tcp_packet(interface_name: &str, packet: &[u8], source: IpAddr, destination: IpAddr, yara_scanner: &mut yara_x::Scanner, alert_logger: &slog::Logger) {
    let tcp = TcpPacket::new(packet);

    if let Some(tcp) = tcp {
        let payload = tcp.payload();
        let results = yara_scanner.scan(payload).unwrap();
    
        for rule in results.matching_rules() {
            let event = EveEvent {
                timestamp: Utc::now().to_rfc3339(),
                flow_id: 1234567890,
                event_type: "alert".to_string(),
                src_ip: source.to_string(),
                src_port: tcp.get_source(),
                dest_ip: destination.to_string(),
                dest_port: tcp.get_destination(),
                proto: "TCP".to_string(),
                alert: Alert {
                    action: "allowed".to_string(),
                    gid: 1,
                    signature_id: 1000001,
                    rev: 1,
                    signature: "Placeholder".to_string(),
                    category: "Placeholder".to_string(),
                    severity: 1,
                    metadata: Metadata {
                        rule: rule.identifier().to_string(),
                        ruleset: rule.namespace().to_string(),
                        tags: vec!["Placeholder".to_string()],
                        mitre: vec!["Placeholder".to_string()],
                    },
                },
            };
        
            let event_json = serde_json::to_string(&event).unwrap();
            println!("{}", event_json);
        };
    } else {
        println!("[{}]: Malformed TCP Packet", interface_name);
    }
}
