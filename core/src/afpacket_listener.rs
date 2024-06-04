use std::cmp::{min, max};
use std::sync::{Arc, Mutex};
use num_cpus;

use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::NetworkInterface;
use pnet::packet::ethernet::EthernetPacket;


#[derive(Default, Copy, Clone, Debug)]
pub struct BufCustom {}


pub struct AFPacketListener {
    interface: NetworkInterface,
    interface_name: String,
    rx_queues: usize,

    frame_sender: crossbeam_channel::Sender<Vec<u8>>,
    rx_stats_sender: crossbeam_channel::Sender<isize>
}

impl  AFPacketListener {
    pub fn new(
        interface_name: String, 
        frame_sender: crossbeam_channel::Sender<Vec<u8>>, 
        rx_stats_sender: crossbeam_channel::Sender<isize>
    ) -> AFPacketListener 
    {
        // Find the network interface with the provided name
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .filter(|iface: &NetworkInterface| iface.name == interface_name)
            .next()
            .unwrap_or_else(|| panic!("No such network interface: {}", interface_name));

        let threads = min(max(0, 1), num_cpus::get());
        println!("AF_XDP Listener initialized with {} threads", threads);
        AFPacketListener {
            interface_name: interface_name,
            interface: interface,

            rx_queues: threads,

            frame_sender: frame_sender.clone(),
            rx_stats_sender: rx_stats_sender.clone()
        }
    }

    pub fn run(&mut self,) -> std::thread::JoinHandle<()> {
        let interface = self.interface.clone();
        let frame_sender = self.frame_sender.clone();
        let rx_stats_sender = self.rx_stats_sender.clone();

        std::thread::spawn(move || {
            // Create a channel to receive on
            let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
                Ok(Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => panic!("packetdump: unhandled channel type"),
                Err(e) => panic!("packetdump: unable to create channel: {}", e),
            };
            
            log::info!("Starting packet analysis on interface: {}", interface.name);
            loop {
                match rx.next() {
                    Ok(packet) => {
                        let payload_offset;
                        if interface.is_loopback() {
                            // The pnet code for BPF loopback adds a zero'd out Ethernet header
                            payload_offset = 14;
                        } else {
                            payload_offset = 0;
                        }
                        //frame_sender.send(packet[payload_offset..].to_vec()).unwrap();
                        rx_stats_sender.send(1).unwrap();
                    }
                    Err(e) => {
                        panic!("An error occurred while reading: {}", e);
                    }
                }
            }
        })
    }
}