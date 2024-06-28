use std::cmp::{min, max};
use std::sync::{Arc, Mutex};
use atomic_counter::{AtomicCounter, RelaxedCounter};
use num_cpus;

use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::NetworkInterface;


pub struct AFPacketListener {
    interface: NetworkInterface,
    interface_name: String,
    rx_queues: usize,

    frame_sender: crossbeam_channel::Sender<Vec<u8>>,
}

impl  AFPacketListener {
    pub fn new(
        interface_name: String, 
        frame_sender: crossbeam_channel::Sender<Vec<u8>>, 
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
        println!("[*] AF_PACKET Listener initialized with {} threads", threads);
        AFPacketListener {
            interface: interface,
            interface_name: interface_name,

            rx_queues: threads,

            frame_sender: frame_sender.clone(),
        }
    }

    pub fn run(&mut self, rx_counter: Arc<RelaxedCounter>, rx_drop_counter: Arc<RelaxedCounter>) -> std::thread::JoinHandle<()> {
        let interface = self.interface.clone();
        let frame_sender = self.frame_sender.clone();

        std::thread::spawn(move || {
            // Create a channel to receive on
            let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
                Ok(Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => panic!("[AFPACKET] Unhandled channel type"),
                Err(e) => panic!("[AFPACKET] Unable to create channel: {}", e),
            };

            info!("[AFPACKET] Starting packet analysis on interface: {}", interface.name);
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

                        match frame_sender.try_send(packet[payload_offset..].to_vec()) {
                            Ok(_) => {
                                rx_counter.inc();
                            }
                            Err(_) => {
                                rx_drop_counter.inc();
                                debug!("[AFPACKET] Analysis Buffer Full. Dropping packet.");
                            }
                        }
                    }
                    Err(e) => {
                        println!("[AFPACKET] An error occurred while reading: {}", e); // TODO: log error
                    }
                }
            }
        })
    }
}