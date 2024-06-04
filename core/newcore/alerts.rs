use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, RwLock};
use std::thread;

#[derive(Clone)]
pub struct AlertMsg {
    pub timestamp: Option<String>,
    pub rule: String,
    pub src_ip: String,
    pub src_port: String,
    pub dst_ip: String,
    pub dst_port: String,
}

pub struct AlertConfig {
    pub stdout: bool,
    pub ip: String,
    pub port: u16,
}

pub fn run(config: &AlertConfig) -> Sender<AlertMsg> {
    let (sender, receiver): (Sender<AlertMsg>, Receiver<AlertMsg>) = channel();

    thread::spawn(move || loop {
        match receiver.recv() {
            Ok(msg) => {
                println!(
                    "ALERT: {} {}:{} -> {}:{}",
                    msg.rule, msg.src_ip, msg.src_port, msg.dst_ip, msg.dst_port
                );
            }
            Err(e) => println!("An error occurred while reading: {}", e),
        }
    });
    sender
}
