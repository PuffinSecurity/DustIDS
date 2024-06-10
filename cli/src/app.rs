use ratatui::widgets::ListState;
use core::alerts::AlertMsg;
use core::state::State;
use std::sync::{Arc, RwLock};

// const TASKS: [&str; 24] = [
//     "DNP3.yar", "EIP.yar", "FINS.yas", "ICS-Attacks.yar", "MCCONNECT.yar", "modbus.yar", "mtconnect.yar", "OPC-DA.yar", "OPC-UA.yar", "Siemens-S7.yar",
//     "SLMP.yar", "", "", "", "", "", "", "", "",
//     "", "", "", "", "",
// ];

// const LOGS: [(&str, &str); 26] = [
//     ("", ""),
//     ("Event2", "INFO"),
//     ("Event3", "CRITICAL"),
//     ("Event4", "ERROR"),
//     ("Event5", "INFO"),
//     ("Event6", "INFO"),
//     ("Event7", "WARNING"),
//     ("Event8", "INFO"),
//     ("Event9", "INFO"),
//     ("Event10", "INFO"),
//     ("Event11", "CRITICAL"),
//     ("Event12", "INFO"),
//     ("Event13", "INFO"),
//     ("Event14", "INFO"),
//     ("Event15", "INFO"),
//     ("Event16", "INFO"),
//     ("Event17", "ERROR"),
//     ("Event18", "ERROR"),
//     ("Event19", "INFO"),
//     ("Event20", "INFO"),
//     ("Event21", "WARNING"),
//     ("Event22", "INFO"),
//     ("Event23", "INFO"),
//     ("Event24", "WARNING"),
//     ("Event25", "INFO"),
//     ("Event26", "INFO"),
// ];
pub struct App<'a> {
    pub title: &'a str,
    pub should_quit: bool,
    pub state: State,
    pub tick_rate: usize,
}

impl<'a> App<'a> {
    pub fn new(title: &'a str, state: State, tick_rate: usize) -> Self {
        App {
            title,
            should_quit: false,
            state,
            tick_rate
        }
    }

    pub fn on_key(&mut self, c: char) {
        match c {
            'q' => {
                self.should_quit = true;
            }
            _ => {}
        }
    }

    pub fn on_tick(&mut self) {
        self.state.on_tick(self.tick_rate);
        // // Get data from stats
        // let state = self.state.read().unwrap();

        // self.rx_per_sec = state.rx_per_sec.iter().map(|&rx| rx as u64).collect::<Vec<u64>>().into_iter().rev().collect();

        // self.analysis_buffer = state.analysis_buffer;

        // self.alerts = state.alerts.clone();

        // self.logs = self.alerts.iter().map(|alert| (alert.timestamp.as_ref().unwrap().clone(), alert.rule.clone())).collect::<Vec<(String, String)>>();

        // // Update progress
        // self.progress = self.analysis_buffer as f64 / 32768.0;
    }
}
