pub struct EveAlertMetadata {
    pub author: String,
    pub description: String,
    pub category: String,
    pub severity: u8,
    pub uuid: String,
}

impl EveAlertMetadata {
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"author": "{}", "description": "{}",
            "category": "{}", "severity": {}, "uuid": "{}"}}"#,
            self.author, self.description,
            self.category, self.severity, self.uuid
        )
    }
}

pub struct EveAlert {
    pub timestamp: String,
    pub event_type: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub proto: String,
    pub rule: String,
    pub alert_metadata: String,
}

impl EveAlert {
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"timestamp": "{}", "event_type": "{}", "src_ip": "{}",
            "src_port": {}, "dst_ip": "{}", "dst_port": {},
            "proto": "{}", "rule": "{}", "alert_metadata": "{}"}}"#,
            self.timestamp, self.event_type, self.src_ip,
            self.src_port, self.dst_ip, self.dst_port,
            self.proto, self.rule, self.alert_metadata
        )
    }
}
