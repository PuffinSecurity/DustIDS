use utils::logger;

extern crate log;
use simplelog::{Config, TermLogger, TerminalMode, ColorChoice};
use syslog_tls::{Formatter5424, Facility};
use multi_log;
use gethostname::gethostname;

pub fn init_stdout_logger(log_level: log::Level) {
    TermLogger::init(
        log_level.to_level_filter(),
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto
    );
}

pub fn create_stdout_logger(log_level: log::Level) -> Box<dyn log::Log> {
    TermLogger::new(
        log_level.to_level_filter(),
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto
    )
}

// pub fn create_syslog_tcp_logger(server_addr: &str, log_level: log::Level) -> Box<dyn log::Log> {
//     let formatter = Formatter5424 {
//         facility: Facility::LOG_USER,
//         hostname: None,
//         process: "dust-ids".into(),
//         pid: 0,
//     };

//     Box::new(syslog_tls::tcp(formatter, server_addr).unwrap())
// }

pub fn init_syslog_tcp_logger(server_addr: &str, log_level: log::Level) {
    let hostname = gethostname().to_string_lossy().to_string();

    syslog_tls::init_tcp(server_addr, hostname, Facility::LOG_USER, log_level.to_level_filter()).unwrap();
}

// pub fn create_syslog_tls_logger(server_addr: &str, log_level: log::LevelFilter) -> Box<dyn log::Log> {
//     Box::new(simplelog::SimpleLogger::new(
//         log_level, 
//         simplelog::Config::default()))
// }

// pub fn create_file_logger() -> Box<dyn log::Log> {
//     Box::new(TermLogger::new(
//         log::LevelFilter::Warn,
//         simplelog::Config::default(),
//         simplelog::TerminalMode::Mixed,
//         simplelog::ColorChoice::Auto,
//     ))
// }

pub fn start_loggers(loggers: Vec<Box<dyn log::Log>>, level: log::Level) {
    multi_log::MultiLogger::init(loggers, level);
}

pub fn log_level_from_str(s: &str) -> log::Level {
    match s {
        "trace" => log::Level::Trace,
        "debug" => log::Level::Debug,
        "info" => log::Level::Info,
        "warn" => log::Level::Warn,
        "error" => log::Level::Error,
        _ => log::Level::Info,
    }
}