//! The run-tape model and canonical encoding.
//!
//! Every field is bounded; every length is checked before allocation. The
//! canonical payload contains no host pathnames, wall-clock timestamps,
//! process IDs, or memory addresses (canonical identity rules,
//! docs/INVARIANTS.md I13).

use crate::error::{Error, Result};
use crate::id::ContentId;
use crate::mutation::MutationCoordinate;
use crate::scheduler::work_order::{
    CmpEventWire, MAX_CMP_EVENTS_PER_EXEC, MAX_FEATURES_PER_EXEC, MAX_INPUT_LEN,
};
use crate::target_runtime::signals::{ResidualSketch, SignalId, SignalVector, MAX_SIGNALS};

/// Version of the tape payload encoding.
pub const TAPE_VERSION: u8 = 1;

/// How the tape's candidate terminated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TerminationStatus {
    /// The target returned normally.
    Ok = 1,
    /// The worker died executing the candidate.
    Crash = 2,
    /// The watchdog aborted the candidate.
    Timeout = 3,
}

impl TerminationStatus {
    /// Decode from the wire byte.
    pub fn from_byte(b: u8) -> Option<TerminationStatus> {
        match b {
            1 => Some(TerminationStatus::Ok),
            2 => Some(TerminationStatus::Crash),
            3 => Some(TerminationStatus::Timeout),
            _ => None,
        }
    }

    /// The wire byte.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Human-readable name.
    pub const fn name(self) -> &'static str {
        match self {
            TerminationStatus::Ok => "ok",
            TerminationStatus::Crash => "crash",
            TerminationStatus::Timeout => "timeout",
        }
    }
}

/// Why a tape was written (its durable boundary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TapeSource {
    /// A seed observation.
    Seed = 1,
    /// A finding (crash/timeout; observation is None — the window never
    /// completed).
    Finding = 2,
    /// A residual admission (state feature / morphology / structured-unknown).
    Admission = 3,
    /// A counterfactual boundary witness (both sides).
    Boundary = 4,
    /// A deliberate replay session.
    Replay = 5,
}

impl TapeSource {
    /// Decode from the wire byte.
    pub fn from_byte(b: u8) -> Option<TapeSource> {
        match b {
            1 => Some(TapeSource::Seed),
            2 => Some(TapeSource::Finding),
            3 => Some(TapeSource::Admission),
            4 => Some(TapeSource::Boundary),
            5 => Some(TapeSource::Replay),
            _ => None,
        }
    }

    /// The wire byte.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Human-readable name.
    pub const fn name(self) -> &'static str {
        match self {
            TapeSource::Seed => "seed",
            TapeSource::Finding => "finding",
            TapeSource::Admission => "admission",
            TapeSource::Boundary => "boundary",
            TapeSource::Replay => "replay",
        }
    }
}

/// The recorded observation of a completed window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TapeObservation {
    /// Sorted, deduplicated packed features.
    pub features: Vec<u64>,
    /// The observed signal vector.
    pub signals: SignalVector,
    /// The child-vs-parent residual sketch (empty for seeds).
    pub sketch: ResidualSketch,
    /// Compact comparison summary.
    pub cmp_events: Vec<CmpEventWire>,
    /// Logarithmic execution-time bucket.
    pub time_bucket: u8,
}

/// The lineage context of a tape (for structural replay).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TapeLineage {
    /// The lineage root (seed ancestor) entry id.
    pub root: ContentId,
    /// The edge mutator family.
    pub mutator: u16,
}

/// A deterministic run tape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunTape {
    /// Canonical build digest (target identity + flags + toolchain).
    pub build_digest: [u8; 32],
    /// Canonical environment digest.
    pub environment_digest: [u8; 32],
    /// The exact candidate bytes.
    pub candidate: Vec<u8>,
    /// The reconstructible coordinate (None for seeds/overrides).
    pub coordinate: Option<MutationCoordinate>,
    /// Scheduler mode at tape time (0 explore, 1 amplify, 2 override).
    pub scheduler_mode: u8,
    /// Recorded observation (None when the window never completed).
    pub observation: Option<TapeObservation>,
    /// Termination status.
    pub termination: TerminationStatus,
    /// Lineage context.
    pub lineage: Option<TapeLineage>,
    /// Why the tape was written.
    pub source: TapeSource,
}

/// Canonical build digest: a deterministic function of the target identity
/// and the exact instrumented-build flags.
pub fn build_digest(
    target_name: &str,
    rustc_release: &str,
    llvm_version: &str,
    instrument_flags: &[String],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"frf-fuzz-build-v1\0");
    h.update(target_name.as_bytes());
    h.update(&[0]);
    h.update(rustc_release.as_bytes());
    h.update(&[0]);
    h.update(llvm_version.as_bytes());
    h.update(&[0]);
    for f in instrument_flags {
        h.update(f.as_bytes());
        h.update(&[0]);
    }
    *h.finalize().as_bytes()
}

/// Canonical environment digest (host-independent; no pathnames, pids, or
/// timestamps).
pub fn environment_digest(
    target_name: &str,
    rustc_release: &str,
    llvm_version: &str,
    sanitizer_mode: u8,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"frf-fuzz-env-v1\0");
    h.update(target_name.as_bytes());
    h.update(&[0]);
    h.update(rustc_release.as_bytes());
    h.update(&[0]);
    h.update(llvm_version.as_bytes());
    h.update(&[0]);
    h.update(&[sanitizer_mode]);
    *h.finalize().as_bytes()
}

fn push_obs(out: &mut Vec<u8>, obs: &TapeObservation) -> Result<()> {
    if obs.features.len() > MAX_FEATURES_PER_EXEC {
        return Err(Error::BoundExceeded {
            what: "tape features",
            limit: MAX_FEATURES_PER_EXEC as u64,
            got: obs.features.len() as u64,
        });
    }
    if obs.cmp_events.len() > MAX_CMP_EVENTS_PER_EXEC {
        return Err(Error::BoundExceeded {
            what: "tape cmp events",
            limit: MAX_CMP_EVENTS_PER_EXEC as u64,
            got: obs.cmp_events.len() as u64,
        });
    }
    out.extend_from_slice(&(obs.features.len() as u32).to_le_bytes());
    for f in &obs.features {
        out.extend_from_slice(&f.to_le_bytes());
    }
    out.extend_from_slice(&obs.signals.touched_mask().to_le_bytes());
    for i in 0..MAX_SIGNALS {
        out.extend_from_slice(&obs.signals.value(SignalId(i as u16)).to_le_bytes());
    }
    out.extend_from_slice(&obs.sketch.mag_buckets);
    out.extend_from_slice(&obs.sketch.dir_bits.to_le_bytes());
    out.extend_from_slice(&obs.sketch.touched_new.to_le_bytes());
    out.extend_from_slice(&obs.sketch.touched_lost.to_le_bytes());
    out.extend_from_slice(&(obs.cmp_events.len() as u16).to_le_bytes());
    for e in &obs.cmp_events {
        out.push(e.kind);
        out.push(e.width);
        out.extend_from_slice(&e.a.to_le_bytes());
        out.extend_from_slice(&e.b.to_le_bytes());
    }
    out.push(obs.time_bucket);
    Ok(())
}

fn take<'a>(bytes: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8]> {
    let end = pos.checked_add(n).ok_or(Error::Overflow)?;
    if end > bytes.len() {
        return Err(Error::Encoding("tape truncated"));
    }
    let out = &bytes[*pos..end];
    *pos = end;
    Ok(out)
}

fn take_obs(bytes: &[u8], pos: &mut usize) -> Result<TapeObservation> {
    let fcount = u32::from_le_bytes(take(bytes, pos, 4)?.try_into().unwrap()) as usize;
    if fcount > MAX_FEATURES_PER_EXEC {
        return Err(Error::BoundExceeded {
            what: "tape features",
            limit: MAX_FEATURES_PER_EXEC as u64,
            got: fcount as u64,
        });
    }
    let mut features = Vec::with_capacity(fcount);
    for _ in 0..fcount {
        features.push(u64::from_le_bytes(take(bytes, pos, 8)?.try_into().unwrap()));
    }
    let touched = u64::from_le_bytes(take(bytes, pos, 8)?.try_into().unwrap());
    let mut signals = SignalVector::new();
    for i in 0..MAX_SIGNALS {
        let v = u64::from_le_bytes(take(bytes, pos, 8)?.try_into().unwrap());
        if touched & (1u64 << i) != 0 {
            signals
                .observe(SignalId(i as u16), v)
                .map_err(|_| Error::Encoding("tape signal id out of range"))?;
        }
    }
    let mut sketch = ResidualSketch::zeroed();
    sketch
        .mag_buckets
        .copy_from_slice(take(bytes, pos, MAX_SIGNALS)?);
    let dir_raw: [u8; 16] = take(bytes, pos, 16)?.try_into().unwrap();
    sketch.dir_bits = u128::from_le_bytes(dir_raw);
    sketch.touched_new = u64::from_le_bytes(take(bytes, pos, 8)?.try_into().unwrap());
    sketch.touched_lost = u64::from_le_bytes(take(bytes, pos, 8)?.try_into().unwrap());
    let ccount = u16::from_le_bytes(take(bytes, pos, 2)?.try_into().unwrap()) as usize;
    if ccount > MAX_CMP_EVENTS_PER_EXEC {
        return Err(Error::BoundExceeded {
            what: "tape cmp events",
            limit: MAX_CMP_EVENTS_PER_EXEC as u64,
            got: ccount as u64,
        });
    }
    let mut cmp_events = Vec::with_capacity(ccount);
    for _ in 0..ccount {
        let kind = take(bytes, pos, 1)?[0];
        let width = take(bytes, pos, 1)?[0];
        let a = u64::from_le_bytes(take(bytes, pos, 8)?.try_into().unwrap());
        let b = u64::from_le_bytes(take(bytes, pos, 8)?.try_into().unwrap());
        cmp_events.push(CmpEventWire { kind, width, a, b });
    }
    let time_bucket = take(bytes, pos, 1)?[0];
    Ok(TapeObservation {
        features,
        signals,
        sketch,
        cmp_events,
        time_bucket,
    })
}

/// Encode a tape to its canonical payload.
pub fn encode_tape(tape: &RunTape) -> Result<Vec<u8>> {
    if tape.candidate.len() > MAX_INPUT_LEN {
        return Err(Error::BoundExceeded {
            what: "tape candidate length",
            limit: MAX_INPUT_LEN as u64,
            got: tape.candidate.len() as u64,
        });
    }
    if tape.scheduler_mode > 2 {
        return Err(Error::Encoding("tape scheduler mode out of range"));
    }
    let mut out = Vec::with_capacity(1 + 32 + 32 + 4 + 49 + 1 + 1 + 1 + 1 + 33);
    out.push(TAPE_VERSION);
    out.extend_from_slice(&tape.build_digest);
    out.extend_from_slice(&tape.environment_digest);
    out.extend_from_slice(&(tape.candidate.len() as u32).to_le_bytes());
    out.extend_from_slice(&tape.candidate);
    match tape.coordinate {
        Some(c) => {
            out.push(1);
            out.extend_from_slice(&c.encode());
        }
        None => out.push(0),
    }
    out.push(tape.scheduler_mode);
    match &tape.observation {
        Some(obs) => {
            out.push(1);
            push_obs(&mut out, obs)?;
        }
        None => out.push(0),
    }
    out.push(tape.termination.code());
    match tape.lineage {
        Some(l) => {
            out.push(1);
            out.extend_from_slice(l.root.as_bytes());
            out.extend_from_slice(&l.mutator.to_le_bytes());
        }
        None => out.push(0),
    }
    out.push(tape.source.code());
    Ok(out)
}

/// Decode a tape payload.
pub fn decode_tape(bytes: &[u8]) -> Result<RunTape> {
    let mut pos = 0usize;
    let version = take(bytes, &mut pos, 1)?[0];
    if version != TAPE_VERSION {
        return Err(Error::UnsupportedVersion {
            family: "run-tape",
            version: version as u32,
        });
    }
    let build_digest = take(bytes, &mut pos, 32)?.try_into().unwrap();
    let environment_digest = take(bytes, &mut pos, 32)?.try_into().unwrap();
    let clen = u32::from_le_bytes(take(bytes, &mut pos, 4)?.try_into().unwrap()) as usize;
    if clen > MAX_INPUT_LEN {
        return Err(Error::BoundExceeded {
            what: "tape candidate length",
            limit: MAX_INPUT_LEN as u64,
            got: clen as u64,
        });
    }
    let candidate = take(bytes, &mut pos, clen)?.to_vec();
    let coordinate = match take(bytes, &mut pos, 1)?[0] {
        0 => None,
        1 => Some(MutationCoordinate::decode(take(
            bytes,
            &mut pos,
            crate::mutation::coordinate::COORDINATE_ENCODED_LEN,
        )?)?),
        _ => return Err(Error::Encoding("tape coordinate flag invalid")),
    };
    let scheduler_mode = take(bytes, &mut pos, 1)?[0];
    if scheduler_mode > 2 {
        return Err(Error::Encoding("tape scheduler mode out of range"));
    }
    let observation = match take(bytes, &mut pos, 1)?[0] {
        0 => None,
        1 => Some(take_obs(bytes, &mut pos)?),
        _ => return Err(Error::Encoding("tape observation flag invalid")),
    };
    let termination = TerminationStatus::from_byte(take(bytes, &mut pos, 1)?[0])
        .ok_or(Error::Encoding("tape termination invalid"))?;
    let lineage = match take(bytes, &mut pos, 1)?[0] {
        0 => None,
        1 => Some(TapeLineage {
            root: ContentId::from_array(take(bytes, &mut pos, 32)?.try_into().unwrap()),
            mutator: u16::from_le_bytes(take(bytes, &mut pos, 2)?.try_into().unwrap()),
        }),
        _ => return Err(Error::Encoding("tape lineage flag invalid")),
    };
    let source = TapeSource::from_byte(take(bytes, &mut pos, 1)?[0])
        .ok_or(Error::Encoding("tape source invalid"))?;
    if pos != bytes.len() {
        return Err(Error::Encoding("tape has trailing bytes"));
    }
    Ok(RunTape {
        build_digest,
        environment_digest,
        candidate,
        coordinate,
        scheduler_mode,
        observation,
        termination,
        lineage,
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::work_order::ExecutionStatus;

    fn sample_tape() -> RunTape {
        let mut signals = SignalVector::new();
        signals.observe(SignalId(0), 7).unwrap();
        RunTape {
            build_digest: [7; 32],
            environment_digest: [9; 32],
            candidate: b"the candidate".to_vec(),
            coordinate: Some(MutationCoordinate {
                campaign_seed: 1,
                parent_short_id: [2; 8],
                generation: 3,
                mutator_id: crate::mutation::MutatorId::ByteFlip,
                lane_id: 4,
                mutation_index: 5,
                probe_params: [0; 4],
            }),
            scheduler_mode: 1,
            observation: Some(TapeObservation {
                features: vec![1, 2, 3],
                signals: signals.clone(),
                sketch: ResidualSketch::of(&SignalVector::new(), &signals),
                cmp_events: vec![CmpEventWire {
                    kind: 2,
                    width: 4,
                    a: 0xBEEF,
                    b: 0,
                }],
                time_bucket: 0,
            }),
            termination: TerminationStatus::Ok,
            lineage: Some(TapeLineage {
                root: ContentId::new(b"root"),
                mutator: 12,
            }),
            source: TapeSource::Admission,
        }
    }

    #[test]
    fn tape_roundtrip() {
        let t = sample_tape();
        let enc = encode_tape(&t).unwrap();
        let dec = decode_tape(&enc).unwrap();
        assert_eq!(dec, t);
    }

    #[test]
    fn crash_tape_roundtrip_no_observation() {
        let mut t = sample_tape();
        t.observation = None;
        t.termination = TerminationStatus::Crash;
        t.source = TapeSource::Finding;
        let dec = decode_tape(&encode_tape(&t).unwrap()).unwrap();
        assert_eq!(dec, t);
    }

    #[test]
    fn tape_rejects_malformed() {
        let enc = encode_tape(&sample_tape()).unwrap();
        assert!(decode_tape(&enc[..enc.len() - 1]).is_err());
        let mut bad = enc.clone();
        bad[0] = 99;
        assert!(matches!(
            decode_tape(&bad),
            Err(Error::UnsupportedVersion { .. })
        ));
        let mut extra = enc.clone();
        extra.push(0);
        assert!(decode_tape(&extra).is_err());
    }

    #[test]
    fn digests_are_canonical_and_distinct() {
        let flags = vec!["-Cpasses=sancov-module".to_string()];
        let a = build_digest("t", "r", "l", &flags);
        let b = build_digest("t", "r", "l", &flags);
        assert_eq!(a, b);
        let c = build_digest("t2", "r", "l", &flags);
        assert_ne!(a, c);
        let d = environment_digest("t", "r", "l", 1);
        let e = environment_digest("t", "r", "l", 2);
        assert_ne!(d, e);
        assert_eq!(d, environment_digest("t", "r", "l", 1));
    }

    #[test]
    fn termination_and_source_codes_are_stable() {
        assert_eq!(TerminationStatus::Ok.code(), 1);
        assert_eq!(TerminationStatus::Crash.code(), 2);
        assert_eq!(TerminationStatus::Timeout.code(), 3);
        assert_eq!(TapeSource::Seed.code(), 1);
        assert_eq!(TapeSource::Finding.code(), 2);
        assert_eq!(TapeSource::Admission.code(), 3);
        assert_eq!(TapeSource::Boundary.code(), 4);
        assert_eq!(TapeSource::Replay.code(), 5);
        assert_eq!(TerminationStatus::from_byte(9), None);
        assert_eq!(TapeSource::from_byte(9), None);
        let _ = ExecutionStatus::Ok; // silence unused-import style warnings
    }
}
