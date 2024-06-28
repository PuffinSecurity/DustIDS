use std::thread;
use crossbeam_channel;

#[derive(Debug, Clone)]
pub struct AlertMsg {
    pub timestamp: String,
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

pub fn on_alert(msg: AlertMsg) {
    // println!(
    //     "[!!!] DETECTED: {} ",
    //     msg.rule
    // );
}
