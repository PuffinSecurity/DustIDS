use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::NetworkInterface;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::Packet;

pub fn capture_packets(yara_scanner: &mut yara_x::Scanner, interface: &NetworkInterface) {
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type: {}", &interface),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    log::info!("Starting packet analysis on interface: {}", interface.name);
    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet_packet) = EthernetPacket::new(packet) {
                    log::debug!(
                        "{} | {} => {}: {}",
                        interface.name,
                        ethernet_packet.get_destination(),
                        ethernet_packet.get_source(),
                        ethernet_packet.get_ethertype()
                    );
                    //let packet = ethernet_packet.packet();
                    let payload = ethernet_packet.payload();
                    //let from_packet = ethernet_packet.from_packet();

                    let results = yara_scanner.scan(payload).unwrap();

                    for rule in results.matching_rules() {
                        log::info!("Matched rule: {}", rule.identifier());
                        log::debug!("Payload: {:02X?}", payload);
                    }
                }
            }
            Err(e) => {
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}
