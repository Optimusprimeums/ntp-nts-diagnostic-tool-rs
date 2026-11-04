//! Event reporting from worker threads to the GUI or console, with optional log file.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::stats::ClientStats;

#[derive(Debug, Clone)]
pub enum Event {
    Log(String),
    Stats(ClientStats),
    ClientDone,
    ResponderStopped,
    SuiteDone { passed: usize, failed: usize },
}

type Sink = dyn Fn(Event) + Send + Sync;

/// Cheap to clone; every clone writes to the same sink and log file.
#[derive(Clone)]
pub struct Reporter {
    sink: Arc<Sink>,
    file: Arc<Mutex<Option<(PathBuf, File)>>>,
}

impl Reporter {
    pub fn new(sink: impl Fn(Event) + Send + Sync + 'static) -> Self {
        Reporter {
            sink: Arc::new(sink),
            file: Arc::new(Mutex::new(None)),
        }
    }

    /// Reporter that prints log lines to stdout (for the command-line tool).
    pub fn stdout() -> Self {
        Self::new(|ev| {
            if let Event::Log(line) = ev {
                println!("{line}");
            }
        })
    }

    pub fn set_log_file(&self, path: Option<&Path>) -> std::io::Result<()> {
        let mut slot = self.file.lock().unwrap();
        *slot = match path {
            Some(p) => Some((
                p.to_path_buf(),
                OpenOptions::new().create(true).append(true).open(p)?,
            )),
            None => None,
        };
        Ok(())
    }

    pub fn log(&self, msg: impl AsRef<str>) {
        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let line = format!("[{ts}] {}", msg.as_ref());
        let mut write_err = None;
        if let Some((path, f)) = self.file.lock().unwrap().as_mut()
            && let Err(e) = writeln!(f, "{line}")
        {
            write_err = Some(format!(
                "[ERROR] Failed to write log file {}: {e}",
                path.display()
            ));
        }
        (self.sink)(Event::Log(line));
        if let Some(e) = write_err {
            (self.sink)(Event::Log(e));
        }
    }

    pub fn emit(&self, ev: Event) {
        (self.sink)(ev);
    }
}
