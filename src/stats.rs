//! Running statistics for a client run.

/// Streaming summary of a series (Welford mean/variance plus RFC 5905-style jitter,
/// the RMS of successive differences).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Series {
    pub n: u64,
    pub mean: f64,
    m2: f64,
    pub min: f64,
    pub max: f64,
    pub last: f64,
    jitter_sq: f64,
}

impl Series {
    pub fn push(&mut self, x: f64) {
        if self.n == 0 {
            self.min = x;
            self.max = x;
        } else {
            self.min = self.min.min(x);
            self.max = self.max.max(x);
            self.jitter_sq += (x - self.last).powi(2);
        }
        self.n += 1;
        let d = x - self.mean;
        self.mean += d / self.n as f64;
        self.m2 += d * (x - self.mean);
        self.last = x;
    }

    pub fn stddev(&self) -> f64 {
        if self.n < 2 {
            0.0
        } else {
            (self.m2 / (self.n - 1) as f64).sqrt()
        }
    }

    pub fn jitter(&self) -> f64 {
        if self.n < 2 {
            0.0
        } else {
            (self.jitter_sq / (self.n - 1) as f64).sqrt()
        }
    }

    pub fn summary(&self, unit: &str) -> String {
        if self.n == 0 {
            return "n/a".into();
        }
        format!(
            "mean {:+.3} {unit}, min {:+.3}, max {:+.3}, stddev {:.3}, jitter {:.3} (n={})",
            self.mean,
            self.min,
            self.max,
            self.stddev(),
            self.jitter(),
            self.n
        )
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct ClientStats {
    pub sent: u64,
    pub received: u64,
    pub failures: u64,
    pub timeouts: u64,
    pub nts_failures: u64,
    pub kods: u64,
    pub authenticated: u64,
    pub ke_exchanges: u64,
    pub offset_ms: Series,
    pub delay_ms: Series,
}

impl ClientStats {
    pub fn loss_percent(&self) -> f64 {
        if self.sent == 0 {
            0.0
        } else {
            100.0 * (self.sent - self.received) as f64 / self.sent as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn series_math() {
        let mut s = Series::default();
        for x in [1.0, 3.0, 2.0, 4.0] {
            s.push(x);
        }
        assert_eq!(s.n, 4);
        assert!((s.mean - 2.5).abs() < 1e-12);
        assert_eq!((s.min, s.max), (1.0, 4.0));
        assert!((s.stddev() - 1.290_994_448_7).abs() < 1e-9);
        // diffs 2, -1, 2 → sqrt((4+1+4)/3)
        assert!((s.jitter() - 3f64.sqrt()).abs() < 1e-12);
    }
}
