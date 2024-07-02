extern crate syslog_tls;

use gethostname::gethostname;
use syslog_tls::{Facility, Formatter5424, LoggerBackend, Logger, Severity, SyslogMessage};
use super::alerts::AlertMsg;


pub struct SyslogAlerter {
    syslog_server: String,
    syslog_protocol: String,
    syslog_formatter: Formatter5424
}

impl SyslogAlerter {
    pub fn new( syslog_ip_port: &str) -> SyslogAlerter {

        SyslogAlerter {
            syslog_server: syslog_ip_port.to_string(),
            syslog_protocol: "TCP".to_string(),
            syslog_formatter: Formatter5424 {
                facility: Facility::LOG_USER,
                hostname: Some(gethostname().to_string_lossy().to_string()),
                process: "dust-ids".into(),
                pid: 0,
            }
        }
    }

    pub fn on_alert(&self, alert: AlertMsg) {
        // Parse AlertMsg to EveJSON
        let msg = alert.to_json();

        let syslog_msg = SyslogMessage {
            message_level: 1,
            structured: vec![],
            message: msg,
        };

        // Send Message
        match syslog_tls::tcp(self.syslog_formatter.clone(), self.syslog_server.as_str()) {
            Err(e) => { }
            Ok(mut writer) => {
                writer.alert(syslog_msg).unwrap();
                //writer.alert(msg.as_str());
            },
        };
    }
}
