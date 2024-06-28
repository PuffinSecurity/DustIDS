#[derive(Debug)]
pub struct AlertMsg {
    pub timestamp: String,

    pub src_ip: String,
    pub src_port: String,

    pub dst_ip: String,
    pub dst_port: String,
    
    pub rule_id: String,
    pub rule_author: String,
    pub rule_description: String,

    pub payload: [u8],
}

pub trait Alerter {
    fn on_alert(&self, msg: AlertMsg);
}