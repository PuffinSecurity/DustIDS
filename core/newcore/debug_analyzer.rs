// use std::sync::mpsc::Sender;
// use super::alerts::AlertMsg;
// use super::analyzer_t::Analyzer;
// use hex;

// pub struct DebugAnalyzer {
//     pub alert_sender: Sender<AlertMsg>,
// }

// impl Analyzer for DebugAnalyzer {
//     fn analyze(&self, data: &[u8]) {
//         self.alert_sender.send(AlertMsg {
//             timestamp: None,
//             rule: "rule".to_string(),//hex::encode(data[0]),
//             src_ip: "src_ip".to_string(),
//             src_port: "src_port".to_string(),
//             dst_ip: "dst_ip".to_string(),
//             dst_port: "dst_port".to_string(),
//         }).unwrap();
//     }
// }