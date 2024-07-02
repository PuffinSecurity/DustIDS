#[derive(Debug, Clone)]
pub struct AlertMsg {
    pub timestamp: String,
    pub event_type: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub proto: String,
    pub rule: String,
    pub alert_metadata: serde_json::Value,
}

impl AlertMsg {
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"timestamp": "{}", "event_type": "{}", "src_ip": "{}",
            "src_port": {}, "dst_ip": "{}", "dst_port": {},
            "proto": "{}", "rule": "{}", "alert": {}}}"#,
            self.timestamp, self.event_type, self.src_ip,
            self.src_port, self.dst_ip, self.dst_port,
            self.proto, self.rule, self.alert_metadata
        )
    }
}
