use std::time::Duration;
use super::alerts::AlertMsg;
use crossbeam_channel::unbounded;
use std::sync::{Arc, RwLock};


#[derive(Debug)]
pub struct Stats {
    pub rx_per_sec: Vec<isize>,
    pub alerts: Vec<AlertMsg>,
    pub analysis_buffer: isize,
}

impl Stats {
    // Constructor, initialize arrays empty and counter to 0
    pub fn new() -> (Arc<RwLock<Stats>>, crossbeam_channel::Sender<isize>, crossbeam_channel::Sender<AlertMsg>) {
        // Init self and return sender
        let (alert_stat_sender, alert_stat_receiver) = unbounded();
        let (rx_stat_sender, rx_stat_receiver) = unbounded::<isize>();

        // Init stats
        let stats = Arc::new(RwLock::new(Stats {
            rx_per_sec: Vec::with_capacity(60),
            alerts: Vec::with_capacity(50),
            analysis_buffer: 0,
        }));

        // Spawn thread to update buffer
        let thread_stats = stats.clone();
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(Duration::from_millis(5000));
                let mut new_stats = thread_stats.write().unwrap();
                
                // Clean up vector elements > 60
                while new_stats.rx_per_sec.len() >= 60 {
                    new_stats.rx_per_sec.remove(0);
                    println!("Timestamp:");
                }

                // Push new element every 5 secs
                new_stats.rx_per_sec.push(0);
                println!("RX: {:?} Buffer: {:?}", new_stats.rx_per_sec, new_stats.analysis_buffer);
            }
        });

        // Spawn thread to update stats
        let thread_stats = stats.clone();
        std::thread::spawn(move || {
            loop {
                match rx_stat_receiver.recv() {
                    Ok(msg) => {
                        let mut new_stats = thread_stats.write().unwrap();
                        
                        let rx_len = new_stats.rx_per_sec.len();
                        if msg > 0 {
                            if rx_len == 0 {
                                new_stats.rx_per_sec.push(msg);
                            } else {
                                new_stats.rx_per_sec[rx_len - 1] += msg;
                            }
                        }
                        new_stats.analysis_buffer += msg;
                    }
                    Err(e) => {
                        println!("An error occurred while reading: {}", e);
                    }
                }
            }
        });

        // Spawn thread to update alerts
        let thread_alerts2 = stats.clone();
        std::thread::spawn(move || {
            loop {
                match alert_stat_receiver.recv() {
                    Ok(msg) => {
                        // Update stats
                        let mut new_stats = thread_alerts2.write().unwrap();
                        // check if capacity is reached and if its, remove the first element
                        if new_stats.alerts.len() == 50 {
                            new_stats.alerts.remove(0);
                        }
                        new_stats.alerts.push(msg);
                    }
                    Err(e) => {
                        println!("An error occurred while reading: {}", e);
                    }
                }
            }
        });

        (stats, rx_stat_sender.clone(), alert_stat_sender.clone())
    }
}