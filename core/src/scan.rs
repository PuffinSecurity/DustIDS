use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::FromPacket;
use pnet::packet::Packet;
use yara_x::Scanner;

pub fn capture_packets(scanner: &mut Scanner) {
    let all_interfaces = datalink::interfaces();

    // Search for the default interface - the one that is
    // up, not loopback and has an IP.
    let interface = all_interfaces
        .iter()
        .find(|e| e.name == "lo") //e.is_up() && !e.is_loopback() && !e.ips.is_empty())
        .unwrap();

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type: {}", &interface),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    println!("Start reading packet: ");
    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet_packet) = EthernetPacket::new(packet) {
                    println!(
                        "{} | {} => {}: {}",
                        interface.name,
                        ethernet_packet.get_destination(),
                        ethernet_packet.get_source(),
                        ethernet_packet.get_ethertype()
                    );
                    let packet = ethernet_packet.packet();
                    let payload = ethernet_packet.payload();
                    let from_packet = ethernet_packet.from_packet();

                    let results = scanner.scan(payload).unwrap();

                    for rule in results.matching_rules() {
                        println!("Matched rule: {}", rule.identifier());
                    }
                }
            }
            Err(e) => {
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}
