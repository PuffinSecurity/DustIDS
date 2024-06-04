use std::thread;
use crossbeam_channel;

#[derive(Debug, Clone)]
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

pub fn run(config: &AlertConfig) -> crossbeam_channel::Sender<AlertMsg> {
    let (alert_sender, alert_receiver) = crossbeam_channel::unbounded::<AlertMsg>();

    thread::spawn(move || loop {
        match alert_receiver.recv() {
            Ok(msg) => {
                println!(
                    "ALERT: {} {}:{} -> {}:{}",
                    msg.rule, msg.src_ip, msg.src_port, msg.dst_ip, msg.dst_port
                );
            }
            Err(e) => println!("An error occurred while reading: {}", e),
        }
    });
    alert_sender
}
