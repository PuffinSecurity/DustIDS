
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


pub struct ThreadedAnalyzer {
    pub alert_logger: &slog::Logger,
    pub rules: &Rules,
    workers: Option(Vec<tokio::task::JoinHandle<()>>)
}

impl ThreadedAnalyzer {
    pub fn new(alert_logger: &slog::Logger, rules: Rules) -> ThreadedAnalyzer {
        ThreadedAnalyzer {
            alert_logger,
            rules
        }
    }

    pub async fn run(interface: &NetworkInterface) ->   {
        let mut yara_scanner = yara_x::Scanner::new(&self.rules);
        let mut packet_iter = interface.iter();
        while let Some(packet) = packet_iter.next() {
            let ethernet = EthernetPacket::new(packet).unwrap();
            match ethernet.get_ethertype() {
                EtherTypes::Ipv4 => {
                    analyze_ipv4_packet(interface.name, &ethernet, &mut yara_scanner, &self.alert_logger);
                }
                EtherTypes::Ipv6 => {
                    analyze_ipv6_packet(interface.name, &ethernet, &mut yara_scanner, &self.alert_logger);
                }
                _ => {
                    println!("[{}]: Unknown packet: {:?}", interface.name, ethernet.get_ethertype());
                }
            }
        }
    }
} 