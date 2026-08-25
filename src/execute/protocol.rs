//! Bounded versioned binary protocol between coordinator and workers.
//!
//! Framing (all lengths little-endian):
//!
//! ```text
//! magic    [u8; 4]   = b"FRFZ"
//! major    u16       (protocol major; unknown major FAILS CLOSED)
//! minor    u16
//! kind     u8        (MsgKind)
//! length   u32       (payload length, bounded by MAX_FRAME_LEN)
//! payload  [u8; length]
//! checksum u32       (CRC-32 over magic..payload, i.e. everything before the
//!                     checksum field)
//! ```
//!
//! No JSON in the hot path. Every length is bounded before allocation;
//! hostile lengths fail without allocation. Workers and the coordinator
//! enforce the same framing, so truncation, corruption, and version skew are
//! detected identically on both sides.
//!
//! The protocol is shared by both planes: the worker binary (a fuzz target
//! built with `target-runtime`) speaks exactly this protocol.

use crate::error::{Error, Result};
use std::io::{Read, Write};

/// Protocol magic.
pub const PROTOCOL_MAGIC: [u8; 4] = *b"FRFZ";
/// Protocol major version. Bump on breaking changes; unknown majors fail
/// closed on both sides.
pub const PROTOCOL_MAJOR: u16 = 1;
/// Protocol minor version. Bump on additive changes.
pub const PROTOCOL_MINOR: u16 = 0;
/// Absolute frame length ceiling (header + payload). Bounded before any
/// allocation.
pub const MAX_FRAME_LEN: u32 = 1 << 20; // 1 MiB
/// Fixed header length: magic(4) + major(2) + minor(2) + kind(1) + len(4) +
/// checksum(4) = 17 bytes.
pub const HEADER_LEN: usize = 17;

/// Message kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgKind {
    /// Worker greeting: version identity + capabilities.
    Hello = 1,
    /// Worker capability description.
    Capabilities = 2,
    /// Coordinator -> worker work order (a batch, not a single candidate).
    WorkOrder = 3,
    /// Worker -> coordinator batch result.
    WorkResult = 4,
    /// Worker -> coordinator discovery (interesting/crash candidate).
    Discovery = 5,
    /// Liveness (low-frequency; never per-execution).
    Heartbeat = 6,
    /// Graceful shutdown.
    Shutdown = 7,
    /// Error notification.
    Error = 8,
}

impl MsgKind {
    /// Decode a kind byte.
    pub fn from_byte(b: u8) -> Option<MsgKind> {
        match b {
            1 => Some(MsgKind::Hello),
            2 => Some(MsgKind::Capabilities),
            3 => Some(MsgKind::WorkOrder),
            4 => Some(MsgKind::WorkResult),
            5 => Some(MsgKind::Discovery),
            6 => Some(MsgKind::Heartbeat),
            7 => Some(MsgKind::Shutdown),
            8 => Some(MsgKind::Error),
            _ => None,
        }
    }
}

/// One decoded frame, borrowing the receive buffer.
#[derive(Debug)]
pub struct Frame<'a> {
    /// Major version (guaranteed equal to [`PROTOCOL_MAJOR`]).
    pub major: u16,
    /// Minor version.
    pub minor: u16,
    /// Message kind.
    pub kind: MsgKind,
    /// Payload.
    pub payload: &'a [u8],
}

/// Encode a frame into `out` (appended). Bounds are checked before writing.
pub fn encode_frame(kind: MsgKind, payload: &[u8], out: &mut Vec<u8>) -> Result<()> {
    let total = HEADER_LEN
        .checked_add(payload.len())
        .ok_or(Error::Overflow)?;
    if total > MAX_FRAME_LEN as usize {
        return Err(Error::BoundExceeded {
            what: "frame length",
            limit: MAX_FRAME_LEN as u64,
            got: total as u64,
        });
    }
    let start = out.len();
    out.resize(start + HEADER_LEN, 0);
    out[start..start + 4].copy_from_slice(&PROTOCOL_MAGIC);
    out[start + 4..start + 6].copy_from_slice(&PROTOCOL_MAJOR.to_le_bytes());
    out[start + 6..start + 8].copy_from_slice(&PROTOCOL_MINOR.to_le_bytes());
    out[start + 8] = kind as u8;
    out[start + 9..start + 13].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    let crc = crc32(&out[start..]);
    out.resize(start + HEADER_LEN + payload.len() + 4, 0);
    out[start + total..start + total + 4].copy_from_slice(&crc.to_le_bytes());
    Ok(())
}

/// Write one frame to a stream (single write_all; the caller owns buffering).
pub fn write_frame<W: Write>(w: &mut W, kind: MsgKind, payload: &[u8]) -> Result<()> {
    let mut buf = Vec::with_capacity(HEADER_LEN + payload.len() + 4);
    encode_frame(kind, payload, &mut buf)?;
    w.write_all(&buf)?;
    Ok(())
}

/// Read exactly one frame from a stream. All lengths are bounded before any
/// allocation; a hostile length field fails without allocating. The payload
/// borrows `buf` (the caller's scratch buffer).
pub fn read_frame<'a, R: Read>(r: &mut R, buf: &'a mut Vec<u8>) -> Result<Frame<'a>> {
    let mut header = [0u8; HEADER_LEN];
    r.read_exact(&mut header)?;
    if header[0..4] != PROTOCOL_MAGIC {
        return Err(Error::BadMagic {
            expected: hex(&PROTOCOL_MAGIC),
            got: hex(&header[0..4]),
        });
    }
    let major = u16::from_le_bytes(header[4..6].try_into().unwrap());
    if major != PROTOCOL_MAJOR {
        // Fail closed on unknown major versions (never guess).
        return Err(Error::UnsupportedVersion {
            family: "coordinator-worker protocol",
            version: major as u32,
        });
    }
    let minor = u16::from_le_bytes(header[6..8].try_into().unwrap());
    let kind = MsgKind::from_byte(header[8]).ok_or(Error::Encoding("unknown message kind"))?;
    let len = u32::from_le_bytes(header[9..13].try_into().unwrap());
    if len > MAX_FRAME_LEN {
        return Err(Error::BoundExceeded {
            what: "frame payload length",
            limit: MAX_FRAME_LEN as u64,
            got: len as u64,
        });
    }
    let total = HEADER_LEN
        .checked_add(len as usize)
        .ok_or(Error::Overflow)?;
    // The payload is read into a scratch allocation, then validated, then
    // copied into the caller's buffer (one copy in the hot path; the caller
    // reuses `buf` across frames).
    let mut frame = Vec::with_capacity(total + 4);
    frame.extend_from_slice(&header);
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload)?;
    frame.extend_from_slice(&payload);
    let mut crc_bytes = [0u8; 4];
    r.read_exact(&mut crc_bytes)?;
    let expected_crc = u32::from_le_bytes(crc_bytes);
    let actual_crc = crc32(&frame);
    if actual_crc != expected_crc {
        return Err(Error::ChecksumMismatch);
    }
    buf.clear();
    buf.extend_from_slice(&payload);
    Ok(Frame {
        major,
        minor,
        kind,
        payload: buf.as_slice(),
    })
}

/// CRC-32 (IEEE 802.3, reflected, polynomial 0xEDB88320). Table-driven.
///
/// The table is generated by a `const fn` at compile time; no lazy init, no
/// allocation, deterministic.
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in bytes {
        let idx = ((crc ^ u32::from(b)) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC32_TABLE[idx];
    }
    !crc
}

const fn build_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

const CRC32_TABLE: [u32; 256] = build_crc32_table();

fn hex(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(HEX[(x >> 4) as usize] as char);
        s.push(HEX[(x & 0xf) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn roundtrip(kind: MsgKind, payload: &[u8]) {
        let mut buf = Vec::new();
        write_frame(&mut buf, kind, payload).unwrap();
        let mut cur = Cursor::new(buf);
        let mut scratch = Vec::new();
        let f = read_frame(&mut cur, &mut scratch).unwrap();
        assert_eq!(f.kind, kind);
        assert_eq!(f.payload, payload);
        assert_eq!(f.major, PROTOCOL_MAJOR);
        assert_eq!(f.minor, PROTOCOL_MINOR);
    }

    #[test]
    fn roundtrip_all_kinds() {
        for kind in [
            MsgKind::Hello,
            MsgKind::Capabilities,
            MsgKind::WorkOrder,
            MsgKind::WorkResult,
            MsgKind::Discovery,
            MsgKind::Heartbeat,
            MsgKind::Shutdown,
            MsgKind::Error,
        ] {
            roundtrip(kind, b"");
            roundtrip(kind, b"payload with \x00 bytes and \xff\xfe");
            roundtrip(kind, &[0u8; 4096]);
        }
    }

    #[test]
    fn crc32_known_vector() {
        // CRC-32("123456789") == 0xCBF43926 (standard check value).
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn truncation_is_rejected() {
        let mut buf = Vec::new();
        write_frame(&mut buf, MsgKind::WorkOrder, b"x").unwrap();
        for cut in 0..buf.len() {
            let mut cur = Cursor::new(&buf[..cut]);
            let mut scratch = Vec::new();
            assert!(
                read_frame(&mut cur, &mut scratch).is_err(),
                "truncated frame at {cut} bytes must fail"
            );
        }
    }

    #[test]
    fn hostile_length_is_rejected_without_allocation() {
        let mut header = [0u8; HEADER_LEN];
        header[0..4].copy_from_slice(&PROTOCOL_MAGIC);
        header[4..6].copy_from_slice(&PROTOCOL_MAJOR.to_le_bytes());
        header[6..8].copy_from_slice(&PROTOCOL_MINOR.to_le_bytes());
        header[8] = MsgKind::WorkOrder as u8;
        header[9..13].copy_from_slice(&u32::MAX.to_le_bytes());
        let mut cur = Cursor::new(header);
        let mut scratch = Vec::new();
        assert!(matches!(
            read_frame(&mut cur, &mut scratch),
            Err(Error::BoundExceeded { .. })
        ));
    }

    #[test]
    fn unknown_major_fails_closed() {
        let mut buf = Vec::new();
        write_frame(&mut buf, MsgKind::Hello, b"").unwrap();
        buf[4..6].copy_from_slice(&99u16.to_le_bytes());
        let mut cur = Cursor::new(buf);
        let mut scratch = Vec::new();
        assert!(matches!(
            read_frame(&mut cur, &mut scratch),
            Err(Error::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut buf = Vec::new();
        write_frame(&mut buf, MsgKind::Hello, b"").unwrap();
        buf[0] = b'X';
        let mut cur = Cursor::new(buf);
        let mut scratch = Vec::new();
        assert!(matches!(
            read_frame(&mut cur, &mut scratch),
            Err(Error::BadMagic { .. })
        ));
    }

    #[test]
    fn checksum_mismatch_is_rejected() {
        let mut buf = Vec::new();
        write_frame(&mut buf, MsgKind::Hello, b"payload").unwrap();
        let n = buf.len();
        buf[n - 1] ^= 0xFF; // corrupt one checksum byte
        let mut cur = Cursor::new(buf);
        let mut scratch = Vec::new();
        assert!(matches!(
            read_frame(&mut cur, &mut scratch),
            Err(Error::ChecksumMismatch)
        ));
    }

    #[test]
    fn oversize_payload_is_rejected_at_encode() {
        let payload = vec![0u8; (MAX_FRAME_LEN + 1) as usize];
        let mut out = Vec::new();
        assert!(matches!(
            encode_frame(MsgKind::WorkOrder, &payload, &mut out),
            Err(Error::BoundExceeded { .. })
        ));
    }

    #[test]
    fn unknown_kind_byte_is_rejected() {
        let mut buf = Vec::new();
        write_frame(&mut buf, MsgKind::Hello, b"").unwrap();
        buf[8] = 0xEE;
        let mut cur = Cursor::new(buf);
        let mut scratch = Vec::new();
        assert!(read_frame(&mut cur, &mut scratch).is_err());
    }

    #[test]
    fn multiple_frames_in_one_stream() {
        let mut buf = Vec::new();
        for i in 0..100u32 {
            write_frame(&mut buf, MsgKind::WorkResult, &i.to_le_bytes()).unwrap();
        }
        let mut cur = Cursor::new(buf);
        let mut scratch = Vec::new();
        for i in 0..100u32 {
            let f = read_frame(&mut cur, &mut scratch).unwrap();
            assert_eq!(f.kind, MsgKind::WorkResult);
            assert_eq!(f.payload, i.to_le_bytes());
        }
        // Stream is now exhausted.
        assert!(read_frame(&mut cur, &mut scratch).is_err());
    }
}
