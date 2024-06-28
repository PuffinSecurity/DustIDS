// use syslog::{Facility, Formatter3164, Severity};
// use super::alerts_t;
// use super::evejson_t::{EveAlert, EveAlertMetadata};

// pub struct SyslogAlerter {
//     formatter: Formatter3164,
//     facility: Facility,
//     url: String,
// }

// impl SyslogAlerter {
//     pub fn new(url: String) -> SyslogAlerter {
//         SyslogAlerter {
//             formatter: Formatter3164 {
//                 facility: Facility::LOG_USER,
//                 hostname: None,
//                 process: "dust-ids".to_string(),
//                 pid: 0,
//             },
//             facility: Facility::LOG_USER,
//             url: url,
//         }
//     }
// }

// impl alerts_t::Alerter for SyslogAlerter {
//     fn on_alert(&self, eve_alert: EveAlert) {
//         let formatted = self.formatter.format(
//             self.facility,
//             Severity::LOG_ALERT,
//             eve_alert.to_json().as_str(),
//         );
//         let socket = syslog::tcp(formatted, self.url).unwrap();
//         socket.send(formatted.as_bytes()).unwrap();
//     }
// }