use std::time::{Duration, Instant};

pub struct Timer {
    interval_ms: u64,
    first_check: bool,
    last_passed_check_time: Instant,
}

impl Timer {
    pub fn new(interval_ms: u64) -> Self {
        Timer {
            interval_ms,
            first_check: true,
            last_passed_check_time: Instant::now(),
        }
    }

    pub fn check(&mut self) -> bool {
        if self.first_check {
            self.reset();
            self.first_check = false;
        }

        let now = Instant::now();
        let diff = now - self.last_passed_check_time;

        if diff >= Duration::from_millis(self.interval_ms) {
            self.last_passed_check_time = now;
            true
        } else {
            false
        }
    }

    pub fn reset(&mut self) {
        self.last_passed_check_time = Instant::now();
    }
}
