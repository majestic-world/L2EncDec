//! Lock-free progress of one file conversion, written by the codec (possibly
//! from several worker threads) and read by the UI ticker.

use std::sync::atomic::{AtomicUsize, Ordering};

/// Work is split into equally weighted phases; each phase counts `done` units
/// out of `total`.
#[derive(Debug, Default)]
pub struct Progress {
    phase: AtomicUsize,
    phases: AtomicUsize,
    done: AtomicUsize,
    total: AtomicUsize,
}

impl Progress {
    pub fn new() -> Self {
        Self::default()
    }

    /// Starts phase `index` (0-based) of `phases`, made of `total` units.
    pub fn start_phase(&self, index: usize, phases: usize, total: usize) {
        self.done.store(0, Ordering::Relaxed);
        self.total.store(total, Ordering::Relaxed);
        self.phases.store(phases, Ordering::Relaxed);
        self.phase.store(index, Ordering::Relaxed);
    }

    pub fn advance(&self, units: usize) {
        self.done.fetch_add(units, Ordering::Relaxed);
    }

    /// Completed share of the whole conversion, in `0.0..=1.0`. Readers racing a
    /// phase switch may see a momentary dip, so the UI keeps the highest value.
    pub fn fraction(&self) -> f64 {
        let phases = self.phases.load(Ordering::Relaxed);
        if phases == 0 {
            return 0.0;
        }
        let total = self.total.load(Ordering::Relaxed);
        let done = self.done.load(Ordering::Relaxed).min(total);
        let within = if total == 0 {
            1.0
        } else {
            done as f64 / total as f64
        };
        let phase = self.phase.load(Ordering::Relaxed) as f64;
        ((phase + within) / phases as f64).min(1.0)
    }
}

#[cfg(test)]
#[path = "tests/progress.rs"]
mod tests;
