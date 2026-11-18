use std::time::Duration;
use super::alerts::AlertMsg;
use crossbeam_channel::{bounded, unbounded};
use std::sync::{Arc, RwLock};
use atomic_counter::{AtomicCounter, RelaxedCounter};
use std::thread;
use std::sync::atomic::{AtomicU32, Ordering};
use super::syslog_alerter;

#[derive(Clone)]
pub struct State {
    pub iface_name: String,
    pub iface_queues: u8,
    pub analysis_threads: u8,

    pub rule_sets: Vec<String>,
    pub syslog_server: String,

    pub alerts: Arc<RwLock<Vec<AlertMsg>>>,

    pub rx_total: Arc<RelaxedCounter>,
    pub rx_dropped: Arc<RelaxedCounter>,
    pub analyzed_total: Arc<RelaxedCounter>,
    rx_total_prev: usize,
    rx_dropped_prev: usize,
    analyzed_total_prev: usize,

    pub rx_per_sec: usize,
    pub analyzed_per_sec: usize,
    pub rx_drop_per_sec: usize,

    pub rx_per_tick: [usize; 300],
    pub rx_drop_per_tick: [usize; 300],
    pub analyzed_per_tick: [usize; 300],

    pub analysis_buffer_len: Arc<AtomicU32>,
    pub analysis_buffer_cap: usize,

    pub alert_sender: crossbeam_channel::Sender<AlertMsg>,
    alert_receiver: crossbeam_channel::Receiver<AlertMsg>,

    frame_receiver: crossbeam_channel::Receiver<Vec<u8>>,
}

impl State {
    // Constructor, initialize arrays empty and counter to 0
    pub fn new(iface_name: String, iface_queues: u8,
        analysis_threads: u8, rule_sets: Vec<String>,
        frame_receiver: crossbeam_channel::Receiver<Vec<u8>>,
        syslog_server: String) -> (State, thread::JoinHandle<()>) {

        // Init self and return sender
        let (alert_sender, alert_receiver) = unbounded::<AlertMsg>();

        // Init state
        let state = State {
            iface_name: iface_name,
            iface_queues: iface_queues,
            analysis_threads: analysis_threads,
            rule_sets: rule_sets.clone(),
            syslog_server: syslog_server.clone(),
            alerts: Arc::new(RwLock::new(Vec::new())),
            rx_total: Arc::new(RelaxedCounter::new(0)),
            rx_dropped: Arc::new(RelaxedCounter::new(0)),
            analyzed_total: Arc::new(RelaxedCounter::new(0)),

            rx_total_prev: 0,
            rx_dropped_prev: 0,
            analyzed_total_prev: 0,

            rx_per_sec: 0,
            analyzed_per_sec: 0,
            rx_drop_per_sec: 0,

            rx_per_tick: [0; 300],
            rx_drop_per_tick: [0; 300],
            analyzed_per_tick: [0; 300],
            analysis_buffer_len: Arc::new(AtomicU32::new(0)),
            analysis_buffer_cap: frame_receiver.capacity().unwrap(),
            alert_sender: alert_sender.clone(),
            alert_receiver: alert_receiver.clone(),
            frame_receiver: frame_receiver.clone(),
        };

        // Spawn a thread to listen for alerts
        let alert_receiver = alert_receiver.clone();
        let alerts_thread = state.alerts.clone();

        let handle = thread::spawn(move || loop {
            match alert_receiver.recv() {
                Ok(msg) => {
                    if !(&syslog_server as &str).is_empty() {   
                        let syslog_alerter = syslog_alerter::SyslogAlerter::new(
                            &syslog_server,
                        );

                        syslog_alerter.on_alert(msg.clone());
                    }
                    let mut alerts = alerts_thread.write().unwrap();
                    alerts.insert(0, msg);
                }
                Err(e) => println!("An error occurred while reading: {}", e),
            }
        });

        (state, handle)
    }

    // t_delta in miliseconds
    pub fn on_tick(&mut self, t_delta: usize) {
        // Calculate new time dependent stats
        let rx_diff = self.rx_total.get() - self.rx_total_prev;
        self.rx_total_prev = self.rx_total.get();
        self.rx_per_tick.rotate_right(1);
        self.rx_per_tick[0] = rx_diff;
        self.rx_per_sec = rx_diff * 1000 / t_delta;

        let rx_drop_diff = self.rx_dropped.get() - self.rx_dropped_prev;
        self.rx_dropped_prev = self.rx_dropped.get();
        self.rx_drop_per_tick.rotate_right(1);
        self.rx_drop_per_tick[0] = rx_drop_diff;
        self.rx_drop_per_sec = rx_drop_diff * 1000 / t_delta;

        let analyzed_diff = self.analyzed_total.get() - self.analyzed_total_prev;
        self.analyzed_total_prev = self.analyzed_total.get();
        self.analyzed_per_tick.rotate_right(1);
        self.analyzed_per_tick[0] = analyzed_diff;
        self.analyzed_per_sec = analyzed_diff * 1000 / t_delta;

        // Get length of analysis buffer
        self.analysis_buffer_len.store(self.frame_receiver.len() as u32, Ordering::Relaxed);
    }
}