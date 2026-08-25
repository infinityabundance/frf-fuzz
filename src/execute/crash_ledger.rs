//! Per-worker crash ledger.
//!
//! The worker writes its current [`MutationCoordinate`] into a shared
//! memory-mapped file immediately before executing the target. If the worker
//! dies (panic=abort, ASan finding, SIGSEGV, SIGILL, SIGABRT, OOM, target
//! abort), the coordinator maps the same file, reads the last committed
//! coordinate, reconstructs the exact candidate, records crash metadata, and
//! restarts the worker — with NO per-execution IPC round-trip
//! (docs/ARCHITECTURE.md §7, docs/INVARIANTS.md I2).
//!
//! # Crash consistency (no atomics needed)
//!
//! Two self-validating slots in a ping-pong arrangement:
//!
//! ```text
//! slot = magic(8) | seq(8) | coordinate(49) | crc(4)   (padded to 128 bytes)
//! ```
//!
//! The worker writes in the order **body (magic + seq + coordinate) then
//! CRC**, and the CRC covers the body *including the sequence number*. The
//! coordinator reads only after the worker has died (never concurrently), so
//! every observed state is either a complete commit or a prefix of one.
//!
//! Why this is crash-consistent even with plain stores (no atomics, no
//! volatile):
//!
//! * The only ordering that matters is *CRC last*. If the compiler reorders
//!   the CRC store earlier, any interleaving of a torn commit leaves a slot
//!   whose CRC was computed from the new body/seq but whose stored body/seq
//!   are old (or vice versa) — the CRC validation fails.
//! * A torn body or torn seq likewise fails CRC.
//! * Therefore the reader accepts a slot only in its fully-committed state,
//!   and the two-slot ping-pong with monotonic seq selects the newest
//!   complete commit.
//!
//! The residual risk is a torn byte that by chance preserves the CRC
//! (≈ 2⁻³² per torn byte) — the standard CRC assumption, documented in
//! docs/THREAT_MODEL.md.
//!
//! This module is fully safe Rust with a single approved unsafe zone: the
//! `memmap2::MmapOptions::map_mut` calls, which are `unsafe fn` (the mmap
//! syscall boundary). The prompt's unsafe policy admits syscall/FFI boundaries
//! "where unavoidable"; this is one. Every unsafe block carries a `// SAFETY:`
//! comment. No atomics are needed (see the crash-consistency argument above).

#![allow(unsafe_code)]

use crate::error::{Error, Result};
use crate::mutation::MutationCoordinate;
use memmap2::{MmapMut, MmapOptions};
use std::fs::File;
use std::path::Path;

/// Magic identifying a valid ledger slot.
const SLOT_MAGIC: u64 = 0x4652_465A_4C45_4447; // "FRFZLEDG"
/// Number of slots (ping-pong).
const SLOTS: usize = 2;
/// Layout: magic(8) + seq(8) + coordinate(49) + crc(4) = 69; padded to 128
/// for alignment and future growth.
const SLOT_LEN: usize = 128;
const MAGIC_OFF: usize = 0;
const SEQ_OFF: usize = 8;
const COORD_OFF: usize = 16;
const COORD_LEN: usize = 49;
const CRC_OFF: usize = COORD_OFF + COORD_LEN; // 65
/// Input echo region: `u32 len | echo bytes`, starting after both slots.
/// The worker copies the exact candidate into the shared mapping before
/// executing, so the coordinator can reproduce the exact crashing input
/// even when the mutation depended on runtime cmp feedback (which a
/// coordinate-only reconstruction cannot replay). This is one memcpy into a
/// pre-mapped region per execution — no syscall, no per-execution IPC; the
/// same shared-memory-testcase pattern AFL uses. The mapping is capped at
/// [`crate::scheduler::work_order::MAX_INPUT_LEN`].
const ECHO_OFF: usize = SLOTS * SLOT_LEN;
const ECHO_LEN_OFF: usize = ECHO_OFF;
const ECHO_BYTES_OFF: usize = ECHO_OFF + 4;
const MAX_ECHO_LEN: usize = crate::scheduler::work_order::MAX_INPUT_LEN;
/// Total ledger file size: 2 slots + 4-byte length field + echo bytes.
pub const LEDGER_LEN: usize = ECHO_BYTES_OFF + MAX_ECHO_LEN;

/// The writer side: mapped into the worker process.
pub struct CrashLedgerWriter {
    map: MmapMut,
}

/// The reader side: mapped into the coordinator process.
pub struct CrashLedgerReader {
    map: MmapMut,
}

fn open_ledger_file(path: &Path) -> Result<File> {
    let file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.set_len(LEDGER_LEN as u64)?;
    Ok(file)
}

impl CrashLedgerWriter {
    /// Open (creating if needed) the ledger at `path`.
    pub fn open(path: &Path) -> Result<CrashLedgerWriter> {
        let file = open_ledger_file(path)?;
        // SAFETY: the file was created/sized to LEDGER_LEN above, so the
        // mapping covers exactly the ledger; memmap2's safety contract is
        // satisfied (valid file, no aliasing with other mutable mappings).
        let mut map = unsafe { MmapOptions::new().len(LEDGER_LEN).map_mut(&file)? };
        // Zero-initialize on first creation so stale garbage is never valid.
        map.fill(0);
        Ok(CrashLedgerWriter { map })
    }

    /// Commit the current coordinate to the ledger. Call immediately before
    /// target execution. Order: body bytes, then CRC (see module docs).
    pub fn commit(&mut self, coord: &MutationCoordinate) {
        self.commit_raw(&coord.encode());
    }

    /// Commit raw 49 coordinate bytes (used by input-override executions,
    /// whose marker coordinate cannot round-trip through the typed enum:
    /// mutator id 0 is the override marker).
    pub fn commit_raw(&mut self, coord_bytes: &[u8; 49]) {
        // Compute slot and seq BEFORE borrowing the body mutably (borrow
        // checker: next_slot/next_seq take &self).
        let slot = self.next_slot();
        let seq = self.next_seq();
        let base = slot * SLOT_LEN;
        let body = &mut self.map[base..base + SLOT_LEN];
        // Body: magic + seq + coordinate.
        body[MAGIC_OFF..MAGIC_OFF + 8].copy_from_slice(&SLOT_MAGIC.to_le_bytes());
        body[SEQ_OFF..SEQ_OFF + 8].copy_from_slice(&seq.to_le_bytes());
        body[COORD_OFF..COORD_OFF + COORD_LEN].copy_from_slice(coord_bytes);
        // CRC last, covering the entire body including seq.
        let crc = ledger_crc(&body[..CRC_OFF]);
        body[CRC_OFF..CRC_OFF + 4].copy_from_slice(&crc.to_le_bytes());
    }

    /// Commit the exact candidate bytes into the ledger's input-echo
    /// region. Called immediately after [`Self::commit`] and immediately
    /// before execution. Refuses inputs above the echo bound (a bounded
    /// mutation engine cannot produce them, but the check is free).
    pub fn commit_echo(&mut self, input: &[u8]) -> Result<()> {
        if input.len() > MAX_ECHO_LEN {
            return Err(Error::BoundExceeded {
                what: "ledger input echo length",
                limit: MAX_ECHO_LEN as u64,
                got: input.len() as u64,
            });
        }
        let map = &mut self.map;
        map[ECHO_LEN_OFF..ECHO_LEN_OFF + 4].copy_from_slice(&(input.len() as u32).to_le_bytes());
        map[ECHO_BYTES_OFF..ECHO_BYTES_OFF + input.len()].copy_from_slice(input);
        Ok(())
    }

    /// The slot whose committed sequence is lower is overwritten next.
    fn next_slot(&self) -> usize {
        let s0 = read_seq(&self.map, 0);
        let s1 = read_seq(&self.map, 1);
        if s0 <= s1 {
            0
        } else {
            1
        }
    }

    fn next_seq(&self) -> u64 {
        let s0 = read_seq(&self.map, 0);
        let s1 = read_seq(&self.map, 1);
        s0.max(s1).wrapping_add(1)
    }
}

impl CrashLedgerReader {
    /// Open the ledger at `path` (must already exist).
    pub fn open(path: &Path) -> Result<CrashLedgerReader> {
        let file = File::options().read(true).write(true).open(path)?;
        // SAFETY: the file is LEDGER_LEN bytes (created by the writer);
        // memmap2's safety contract is satisfied.
        let map = unsafe { MmapOptions::new().len(LEDGER_LEN).map_mut(&file)? };
        Ok(CrashLedgerReader { map })
    }

    /// The input echo of the most recent commit: the exact candidate bytes
    /// the worker executed (empty when the worker died before its first
    /// echo).
    pub fn echo(&self) -> Vec<u8> {
        let len_field =
            u32::from_le_bytes(self.map[ECHO_LEN_OFF..ECHO_LEN_OFF + 4].try_into().unwrap())
                as usize;
        if len_field == 0 || len_field > MAX_ECHO_LEN {
            return Vec::new();
        }
        self.map[ECHO_BYTES_OFF..ECHO_BYTES_OFF + len_field].to_vec()
    }

    /// Read the most recently committed valid coordinate.
    ///
    /// `Ok(None)` means the ledger is empty (worker never committed — e.g. it
    /// died before its first execution). Both slots invalid with magic
    /// present is reported as an error (ledger damage), so operators can
    /// distinguish "no crash data" from "corrupt ledger file".
    pub fn latest(&self) -> Result<Option<MutationCoordinate>> {
        match self.latest_raw()? {
            None => Ok(None),
            Some((_, bytes)) => MutationCoordinate::decode(&bytes).map(Some).map_err(|e| {
                Error::Other(format!(
                    "crash ledger coordinate is not a typed coordinate (override marker?): {e}"
                ))
            }),
        }
    }

    /// Read the most recent valid commit as raw bytes (survives the override
    /// marker, which the typed decoder refuses).
    pub fn latest_raw(&self) -> Result<Option<(u64, [u8; 49])>> {
        let mut best: Option<(u64, [u8; 49])> = None;
        let mut any_magic = false;
        for slot in 0..SLOTS {
            let base = slot * SLOT_LEN;
            let body = &self.map[base..base + SLOT_LEN];
            let magic = read_magic(body);
            if magic != SLOT_MAGIC {
                continue;
            }
            any_magic = true;
            let crc = ledger_crc(&body[..CRC_OFF]);
            let stored = read_crc(body);
            if crc != stored {
                continue;
            }
            let seq = read_seq(&self.map, slot);
            let mut coord = [0u8; COORD_LEN];
            coord.copy_from_slice(&body[COORD_OFF..COORD_OFF + COORD_LEN]);
            match &best {
                Some((best_seq, _)) if *best_seq >= seq => {}
                _ => best = Some((seq, coord)),
            }
        }
        if best.is_none() && any_magic {
            return Err(Error::Other(
                "crash ledger slots present but all invalid (torn write or file damage)".into(),
            ));
        }
        Ok(best)
    }
}

fn read_magic(body: &[u8]) -> u64 {
    u64::from_le_bytes(body[MAGIC_OFF..MAGIC_OFF + 8].try_into().unwrap())
}

fn read_crc(body: &[u8]) -> u32 {
    u32::from_le_bytes(body[CRC_OFF..CRC_OFF + 4].try_into().unwrap())
}

fn read_seq(map: &MmapMut, slot: usize) -> u64 {
    let base = slot * SLOT_LEN;
    u64::from_le_bytes(map[base + SEQ_OFF..base + SEQ_OFF + 8].try_into().unwrap())
}

/// CRC-32 over the slot body up to (not including) the CRC field.
fn ledger_crc(bytes: &[u8]) -> u32 {
    crate::execute::protocol::crc32(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mutation::MutatorId;

    fn tmp_path(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("frf-fuzz-crash-ledger-tests");
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    fn coord(seed: u64, index: u64) -> MutationCoordinate {
        MutationCoordinate {
            campaign_seed: seed,
            parent_short_id: [1, 2, 3, 4, 5, 6, 7, 8],
            generation: 1,
            mutator_id: MutatorId::ByteFlip,
            lane_id: 0,
            mutation_index: index,
            probe_params: [0; 4],
        }
    }

    #[test]
    fn commit_then_read_roundtrip() {
        let path = tmp_path("roundtrip.ledger");
        let _ = std::fs::remove_file(&path);
        let mut w = CrashLedgerWriter::open(&path).unwrap();
        let c = coord(0xABCD, 42);
        w.commit(&c);
        let r = CrashLedgerReader::open(&path).unwrap();
        assert_eq!(r.latest().unwrap(), Some(c));
    }

    #[test]
    fn reader_on_fresh_ledger_returns_none() {
        let path = tmp_path("fresh.ledger");
        let _ = std::fs::remove_file(&path);
        let _w = CrashLedgerWriter::open(&path).unwrap();
        let r = CrashLedgerReader::open(&path).unwrap();
        assert_eq!(r.latest().unwrap(), None);
    }

    #[test]
    fn latest_wins_after_ping_pong() {
        let path = tmp_path("pingpong.ledger");
        let _ = std::fs::remove_file(&path);
        let mut w = CrashLedgerWriter::open(&path).unwrap();
        for i in 0..4u64 {
            w.commit(&coord(i + 1, i + 1));
        }
        let r = CrashLedgerReader::open(&path).unwrap();
        assert_eq!(r.latest().unwrap(), Some(coord(4, 4)));
    }

    #[test]
    fn torn_slot_never_wins() {
        let path = tmp_path("torn.ledger");
        let _ = std::fs::remove_file(&path);
        let mut w = CrashLedgerWriter::open(&path).unwrap();
        w.commit(&coord(1, 1)); // slot 0
        w.commit(&coord(2, 2)); // slot 1 (newer)
                                // Simulate a torn write to slot 1: corrupt the coordinate body so the
                                // CRC fails (the stored CRC no longer matches).
        let base = SLOT_LEN;
        w.map[base + COORD_OFF] ^= 0xFF;
        let r = CrashLedgerReader::open(&path).unwrap();
        // The reader must fall back to slot 0's complete commit.
        assert_eq!(r.latest().unwrap(), Some(coord(1, 1)));
    }

    #[test]
    fn both_slots_corrupt_reports_error_when_magic_present() {
        let path = tmp_path("bothcorrupt.ledger");
        let _ = std::fs::remove_file(&path);
        let mut w = CrashLedgerWriter::open(&path).unwrap();
        w.commit(&coord(1, 1));
        // Corrupt both slot bodies (magic intact, CRC broken).
        for slot in 0..SLOTS {
            let base = slot * SLOT_LEN;
            w.map[base + COORD_OFF] ^= 0x01;
        }
        let r = CrashLedgerReader::open(&path).unwrap();
        assert!(r.latest().is_err());
    }

    #[test]
    fn seq_is_monotonic() {
        let path = tmp_path("seq.ledger");
        let _ = std::fs::remove_file(&path);
        let mut w = CrashLedgerWriter::open(&path).unwrap();
        for i in 0..100u64 {
            w.commit(&coord(i, i));
            let s0 = read_seq(&w.map, 0);
            let s1 = read_seq(&w.map, 1);
            assert!(s0.max(s1) >= i, "seq must never decrease");
        }
        let r = CrashLedgerReader::open(&path).unwrap();
        assert_eq!(r.latest().unwrap(), Some(coord(99, 99)));
    }

    #[test]
    fn garbage_magic_is_ignored() {
        let path = tmp_path("garbage.ledger");
        let _ = std::fs::remove_file(&path);
        let mut w = CrashLedgerWriter::open(&path).unwrap();
        w.commit(&coord(4, 4)); // slot 0
        w.commit(&coord(5, 5)); // slot 1 (newer)
                                // Corrupt slot 0's magic: that slot becomes invisible; the reader
                                // must still return the newer valid slot.
        w.map[MAGIC_OFF] ^= 0xFF;
        let r = CrashLedgerReader::open(&path).unwrap();
        assert_eq!(r.latest().unwrap(), Some(coord(5, 5)));
    }
}
