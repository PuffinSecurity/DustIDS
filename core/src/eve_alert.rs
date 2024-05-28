use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct EveEvent {
    pub timestamp: String,
    pub flow_id: u64,
    pub event_type: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dest_ip: String,
    pub dest_port: u16,
    pub proto: String, // Protocol, e.g., TCP, UDP
    pub alert: Alert,
}

#[derive(Serialize, Deserialize)]
pub struct Alert {
    pub action: String,
    pub gid: u64, // Group ID
    pub signature_id: u64,
    pub rev: u64, // Revision
    pub signature: String,
    pub category: String,
    pub severity: u8,
    pub metadata: Metadata,
}

#[derive(Serialize, Deserialize)]
pub struct Metadata {
    pub rule: String,
    pub ruleset: String,
    pub tags: Vec<String>,
    pub mitre: Vec<String>, // MITRE ATT&CK techniques
}
