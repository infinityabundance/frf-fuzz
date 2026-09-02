//! Coordinator-side worker process management.
//!
//! Spawns an instrumented fuzz-target binary as a persistent worker with
//! piped stdio and the coordinator protocol on stdin/stdout. A background
//! thread per worker reads frames and forwards them over a bounded-ish
//! channel (bounded in practice by one in-flight result per worker: the
//! worker sends a result only after finishing its batch, then waits for the
//! next order). Stderr is captured into a bounded tail for diagnostics
//! (ASan reports, panic messages).
//!
//! Worker death is detected via the reader thread hitting EOF; the
//! coordinator then checks `try_wait` and reads the shared crash ledger
//! ([`crate::execute::crash_ledger`]) to reconstruct the exact candidate.
//!
//! This module is coordinator-gated.

use crate::error::{Error, Result};
use crate::execute::crash_ledger::{CrashLedgerReader, LEDGER_LEN};
use crate::execute::protocol::{self, MsgKind};
use crate::scheduler::policy::SchedulePolicy;
use crate::scheduler::work_order::{self, Hello, WorkOrder, WorkResult};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::thread;
use std::time::Instant;

/// Environment variables the coordinator sets on every worker.
pub const ENV_LEDGER: &str = "FRF_FUZZ_LEDGER";
/// Worker lane id (u16; diagnostics — the executing lane comes from the
/// work order's coordinate).
pub const ENV_LANE: &str = "FRF_FUZZ_LANE";
/// Sanitizer mode string ("none" or "address").
pub const ENV_SANITIZER: &str = "FRF_FUZZ_SANITIZER";
/// Per-execution watchdog timeout in milliseconds.
pub const ENV_TIMEOUT_MS: &str = "FRF_FUZZ_TIMEOUT_MS";
/// Worker ordinal (diagnostics).
pub const ENV_WORKER_ID: &str = "FRF_FUZZ_WORKER_ID";
/// Optional RLIMIT_AS in MiB (0 = no limit).
pub const ENV_MEMORY_LIMIT_MB: &str = "FRF_FUZZ_MEMORY_LIMIT_MB";
/// Compare-guidance switch: "0" = coverage-only worker (Phase-8 ablation
/// arm; the worker skips cmp-ring reset/snapshot and substitution hits).
pub const ENV_CMP: &str = "FRF_FUZZ_CMP";

/// Sanitizer mode string passed via [`ENV_SANITIZER`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SanitizerMode {
    /// sancov + trace-compares, no ASan (default).
    None,
    /// AddressSanitizer (trace-compares disabled; see docs/COMPATIBILITY.md).
    Address,
}

impl SanitizerMode {
    /// The sanitizer name (`"none"` or `"address"`).
    pub fn env_value(self) -> &'static str {
        match self {
            SanitizerMode::None => "none",
            SanitizerMode::Address => "address",
        }
    }

    /// The protocol wire-mode byte.
    pub fn wire_mode(self) -> u8 {
        match self {
            SanitizerMode::None => work_order::mode::SANCOV_TRACECMP,
            SanitizerMode::Address => work_order::mode::ASAN,
        }
    }
}

/// What a worker reader thread observed.
#[derive(Debug)]
pub enum WorkerEvent {
    /// A full frame arrived (payload borrowed into an owned buffer).
    Frame(Vec<u8>),
    /// The stream ended or the worker died; the coordinator checks
    /// `try_wait` + the ledger.
    Eof,
}

/// A spawned worker.
pub struct WorkerHandle {
    child: Child,
    stdin: BufWriter<ChildStdin>,
    events: Receiver<WorkerEvent>,
    ledger: CrashLedgerReader,
    /// Highest ledger sequence already accounted for (crash attribution).
    last_seq: u64,
    /// Lane id.
    pub lane: u16,
    /// The worker's hello (mode + identity).
    pub hello: Hello,
    /// Bounded stderr tail (diagnostics). Shared with the capture thread;
    /// read on demand (e.g. after a crash).
    stderr_tail: std::sync::Arc<std::sync::Mutex<String>>,
}

/// Bound on the stderr tail kept for diagnostics.
pub const STDERR_TAIL_BYTES: usize = 16 * 1024;

impl WorkerHandle {
    /// Spawn a worker for `lane`.
    pub fn spawn(
        target_bin: &Path,
        store_root: &Path,
        lane: u16,
        policy: &SchedulePolicy,
        sanitizer: SanitizerMode,
        memory_limit_mb: u64,
    ) -> Result<WorkerHandle> {
        let ledger_path = store_root
            .join("tmp")
            .join(format!("ledger-worker-{lane}.bin"));
        // A stale ledger from a previous campaign must not be attributed to
        // this worker (the coordinator tracks seq; a fresh file is cleanest).
        if ledger_path.exists() {
            std::fs::remove_file(&ledger_path)?;
        }
        // Create + size the ledger file now so both sides map the same file.
        {
            let f = std::fs::File::options()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&ledger_path)?;
            f.set_len(LEDGER_LEN as u64)?;
        }

        let mut cmd = Command::new(target_bin);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env(ENV_LEDGER, &ledger_path)
            .env(ENV_LANE, lane.to_string())
            .env(ENV_SANITIZER, sanitizer.env_value())
            .env(ENV_TIMEOUT_MS, policy.timeout_ms.to_string())
            .env(ENV_WORKER_ID, lane.to_string())
            .env(ENV_MEMORY_LIMIT_MB, memory_limit_mb.to_string())
            .env(ENV_CMP, if policy.cmp { "1" } else { "0" });
        let mut child = cmd.spawn().map_err(|e| {
            Error::Other(format!(
                "cannot spawn worker binary {}: {e}",
                target_bin.display()
            ))
        })?;
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");

        let (tx, rx) = channel();
        // Reader thread: forwards frames, then Eof.
        thread::spawn(move || reader_loop(stdout, tx));

        // Stderr capture thread: bounded tail.
        let tail = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let tail2 = std::sync::Arc::clone(&tail);
        thread::spawn(move || stderr_loop(stderr, tail2));

        let stdin = BufWriter::new(stdin);
        let ledger = CrashLedgerReader::open(&ledger_path)?;

        // Greeting handshake: the worker sends Hello immediately.
        let _scratch: Vec<u8> = Vec::new();
        let hello_payload = match rx.recv() {
            Ok(WorkerEvent::Frame(payload)) => payload,
            Ok(WorkerEvent::Eof) => {
                let status = child.wait()?;
                return Err(Error::WorkerDied {
                    status,
                    stage: "hello",
                });
            }
            Err(e) => {
                let _ = child.kill();
                return Err(Error::Other(format!("worker channel closed: {e}")));
            }
        };
        let hello = work_order::decode_hello(&hello_payload)?;
        if hello.mode != sanitizer.wire_mode() {
            return Err(Error::Other(format!(
                "worker lane {lane} reported mode {} but {} was requested",
                hello.mode,
                sanitizer.wire_mode()
            )));
        }

        Ok(WorkerHandle {
            child,
            stdin,
            events: rx,
            ledger,
            last_seq: 0,
            lane,
            hello,
            stderr_tail: tail,
        })
    }

    /// Send a work order.
    pub fn send_order(&mut self, order: &WorkOrder) -> Result<()> {
        let payload = work_order::encode_work_order(order)?;
        protocol::write_frame(&mut self.stdin, MsgKind::WorkOrder, &payload)?;
        self.stdin.flush()?;
        Ok(())
    }

    /// Send a graceful shutdown.
    pub fn send_shutdown(&mut self) -> Result<()> {
        protocol::write_frame(&mut self.stdin, MsgKind::Shutdown, b"")?;
        self.stdin.flush()?;
        Ok(())
    }

    /// Send a heartbeat probe.
    pub fn send_heartbeat(&mut self) -> Result<()> {
        protocol::write_frame(&mut self.stdin, MsgKind::Heartbeat, b"")?;
        self.stdin.flush()?;
        Ok(())
    }

    /// Kill the worker process outright.
    pub fn kill(&mut self) -> Result<()> {
        self.child.kill()?;
        Ok(())
    }

    /// Wait for exit with a timeout; kills on timeout.
    pub fn wait_timeout(&mut self, timeout: std::time::Duration) -> Result<ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                return Ok(self.child.wait()?);
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }

    /// Poll for an event with a timeout (`Ok(None)` on timeout).
    pub fn poll_event(&mut self, timeout: std::time::Duration) -> Result<Option<WorkerEvent>> {
        poll_event(&self.events, timeout)
    }

    /// Block for the next frame/EOF from this worker.
    pub fn recv_event(&mut self) -> Result<WorkerEvent> {
        match self.events.recv() {
            Ok(e) => Ok(e),
            Err(_) => Ok(WorkerEvent::Eof), // channel closed => stream ended
        }
    }

    /// Non-blocking poll.
    pub fn try_recv_event(&mut self) -> Result<Option<WorkerEvent>> {
        match self.events.try_recv() {
            Ok(e) => Ok(Some(e)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Ok(Some(WorkerEvent::Eof)),
        }
    }

    /// Block for a result frame; the caller then decodes.
    pub fn recv_result(&mut self) -> Result<WorkResult> {
        match self.recv_event()? {
            WorkerEvent::Frame(payload) => work_order::decode_work_result(&payload),
            WorkerEvent::Eof => {
                let status = self.child.try_wait()?.unwrap_or_else(|| {
                    // The stream ended but the process is still alive (it
                    // closed stdout): treat as an abnormal end.
                    let _ = self.child.kill();
                    self.child.wait().unwrap_or_default()
                });
                Err(Error::WorkerDied {
                    status,
                    stage: "result",
                })
            }
        }
    }

    /// The worker's exit status, if it has exited.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        Ok(self.child.try_wait()?)
    }

    /// Whether the process has exited.
    pub fn is_dead(&mut self) -> Result<bool> {
        Ok(self.child.try_wait()?.is_some())
    }

    /// The crash ledger's newest valid commit (raw bytes + seq), if newer
    /// than the last accounted-for sequence.
    pub fn new_crash_commit(&mut self) -> Result<Option<(u64, [u8; 49])>> {
        let Some((seq, bytes)) = self.ledger.latest_raw()? else {
            return Ok(None);
        };
        if seq > self.last_seq {
            self.last_seq = seq;
            Ok(Some((seq, bytes)))
        } else {
            Ok(None)
        }
    }

    /// Wait for the process and return its status.
    pub fn wait(&mut self) -> Result<ExitStatus> {
        Ok(self.child.wait()?)
    }

    /// The captured stderr tail.
    pub fn stderr_tail(&self) -> String {
        self.stderr_tail
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    /// The worker's pid (diagnostics).
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// The ledger's input echo: the exact candidate bytes the worker
    /// executed before death (empty when it died before its first echo).
    pub fn ledger_echo(&self) -> Vec<u8> {
        self.ledger.echo()
    }
}

/// Read frames from the worker's stdout until EOF, forwarding each to the
/// channel. A frame error (corruption, truncation) ends the stream: the
/// coordinator treats the worker as broken and restarts it.
fn reader_loop(stdout: ChildStdout, tx: Sender<WorkerEvent>) {
    let mut reader = BufReader::new(stdout);
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match protocol::read_frame(&mut reader, &mut buf) {
            Ok(frame) => {
                if tx.send(WorkerEvent::Frame(frame.payload.to_vec())).is_err() {
                    return; // coordinator gone
                }
            }
            Err(_) => {
                let _ = tx.send(WorkerEvent::Eof);
                return;
            }
        }
    }
}

/// Capture stderr into a bounded tail (diagnostics only).
fn stderr_loop(stderr: ChildStderr, tail: std::sync::Arc<std::sync::Mutex<String>>) {
    let mut reader = BufReader::new(stderr);
    let mut buf = [0u8; 4096];
    loop {
        match reader.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                let mut t = tail.lock().unwrap();
                t.push_str(&String::from_utf8_lossy(&buf[..n]));
                if t.len() > STDERR_TAIL_BYTES {
                    let cut = t.len() - STDERR_TAIL_BYTES;
                    t.drain(..cut);
                }
            }
        }
    }
}

/// Channel timeout used by the coordinator's idle poll.
pub const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

/// A convenience poll over a worker event receiver.
pub fn poll_event(
    rx: &Receiver<WorkerEvent>,
    timeout: std::time::Duration,
) -> Result<Option<WorkerEvent>> {
    match rx.recv_timeout(timeout) {
        Ok(e) => Ok(Some(e)),
        Err(RecvTimeoutError::Timeout) => Ok(None),
        Err(RecvTimeoutError::Disconnected) => Ok(Some(WorkerEvent::Eof)),
    }
}
