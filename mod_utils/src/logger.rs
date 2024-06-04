use std::fs::{create_dir, File, OpenOptions};
use std::io::Write;

use crate::mod_utils::get_current_mod_name;

pub struct Logger {
    name: String,
    file: Option<File>,
}

impl Logger {
    pub fn new(name: &str) -> Self {
        Logger {
            name: name.to_string(),
            file: None,
        }
    }

    pub fn open(&mut self) {
        match create_dir("log") {
            Ok(_) => {}
            Err(e) => {
                eprintln!("failed to create log directory: {}", e)
            }
        }
        match OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(format!("log/{}.log", get_current_mod_name()))
        {
            Ok(file) => self.file = Some(file),
            Err(e) => eprintln!("Failed to open or create log file: {}", e),
        }
    }

    pub fn log(&mut self, message: &str) {
        if let Some(file) = &mut self.file {
            if let Err(e) = writeln!(file, ">> {} >> {}", get_current_mod_name(), message) {
                eprintln!("Failed to write to log file: {}", e);
            }
        } else {
            eprintln!("Log file is not open.");
        }
    }

    pub fn close(&mut self) {
        if let Some(file) = &mut self.file {
            self.file = None;
        }
    }
}
