//! Signal schema store objects.
//!
//! The target registers its signal names/units at setup; the worker sends
//! them in HELLO; the coordinator persists the first-seen schema as a
//! `Family::SignalSchema` object (content-addressed: identical schemas share
//! one object) and records it in campaign metadata. Reports and inspections
//! resolve signal IDs to names/units through it. The canonical encoding is
//! deterministic and bounded (≤ 64 entries; names ≤ 32 B, units ≤ 16 B).

use crate::error::{Error, Result};
use crate::scheduler::work_order::SignalDescWire;
use crate::target_runtime::signals::{
    SignalId, SignalSchema, MAX_SIGNAL_NAME_LEN, MAX_SIGNAL_UNIT_LEN,
};

/// Version of the schema-object payload.
pub const SIGNAL_SCHEMA_VERSION: u8 = 1;

/// Encode a schema to its canonical payload.
pub fn encode_signal_schema(schema: &SignalSchema) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(1 + 3 * (1 + 2 + 1 + 32 + 1 + 16));
    out.push(SIGNAL_SCHEMA_VERSION);
    out.push(schema.count);
    for (id, d) in schema.iter() {
        out.extend_from_slice(&id.id().to_le_bytes());
        out.push(d.name_len);
        out.extend_from_slice(&d.name[..d.name_len as usize]);
        out.push(d.unit_len);
        out.extend_from_slice(&d.unit[..d.unit_len as usize]);
    }
    Ok(out)
}

/// Decode a schema payload.
pub fn decode_signal_schema(bytes: &[u8]) -> Result<SignalSchema> {
    if bytes.is_empty() {
        return Err(Error::Encoding("signal-schema truncated"));
    }
    let version = bytes[0];
    if version != SIGNAL_SCHEMA_VERSION {
        return Err(Error::UnsupportedVersion {
            family: "signal-schema",
            version: version as u32,
        });
    }
    let count = bytes[1] as usize;
    if count > crate::target_runtime::signals::MAX_SIGNALS {
        return Err(Error::BoundExceeded {
            what: "schema entries",
            limit: crate::target_runtime::signals::MAX_SIGNALS as u64,
            got: count as u64,
        });
    }
    let mut schema = SignalSchema::empty();
    let mut pos = 2usize;
    let mut take = |n: usize| -> Result<&[u8]> {
        let end = pos.checked_add(n).ok_or(Error::Overflow)?;
        if end > bytes.len() {
            return Err(Error::Encoding("signal-schema truncated"));
        }
        let out = &bytes[pos..end];
        pos = end;
        Ok(out)
    };
    for _ in 0..count {
        let id = u16::from_le_bytes(take(2)?.try_into().unwrap());
        let id = SignalId::new(id).ok_or(Error::Encoding("schema signal id out of range"))?;
        let name_len = take(1)?[0] as usize;
        if name_len == 0 || name_len > MAX_SIGNAL_NAME_LEN {
            return Err(Error::BoundExceeded {
                what: "schema name length",
                limit: MAX_SIGNAL_NAME_LEN as u64,
                got: name_len as u64,
            });
        }
        let name = std::str::from_utf8(take(name_len)?)
            .map_err(|_| Error::Encoding("schema name is not UTF-8"))?;
        let unit_len = take(1)?[0] as usize;
        if unit_len > MAX_SIGNAL_UNIT_LEN {
            return Err(Error::BoundExceeded {
                what: "schema unit length",
                limit: MAX_SIGNAL_UNIT_LEN as u64,
                got: unit_len as u64,
            });
        }
        let unit = std::str::from_utf8(take(unit_len)?)
            .map_err(|_| Error::Encoding("schema unit is not UTF-8"))?;
        SignalSchema::validate(name, unit)?;
        if schema.desc(id).is_some() {
            return Err(Error::Encoding("schema contains a duplicate signal id"));
        }
        let mut desc = crate::target_runtime::signals::SignalDesc::empty();
        desc.present = true;
        desc.name_len = name.len() as u8;
        desc.name[..name.len()].copy_from_slice(name.as_bytes());
        desc.unit_len = unit.len() as u8;
        desc.unit[..unit.len()].copy_from_slice(unit.as_bytes());
        schema.set_desc(id, desc);
    }
    if pos != bytes.len() {
        return Err(Error::Encoding("signal-schema has trailing bytes"));
    }
    Ok(schema)
}

/// A renderable name for a signal given a schema (fallback: "sig#N").
pub fn signal_name(schema: Option<&SignalSchema>, id: SignalId) -> String {
    match schema.and_then(|s| s.desc(id)) {
        Some(d) => format!("{}({})", d.name_str(), d.unit_str()),
        None => format!("sig#{}", id.id()),
    }
}

/// Wire entries for storage (HELLO decode side).
pub fn wire_entries_to_schema(entries: &[SignalDescWire]) -> Result<SignalSchema> {
    crate::scheduler::work_order::wire_to_schema(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_object_roundtrip() {
        let mut schema = SignalSchema::empty();
        schema.set_desc(SignalId(0), {
            let mut d = crate::target_runtime::signals::SignalDesc::empty();
            d.present = true;
            d.name_len = 12;
            d.name[..12].copy_from_slice(b"parsed_items");
            d.unit_len = 5;
            d.unit[..5].copy_from_slice(b"count");
            d
        });
        schema.set_desc(SignalId(3), {
            let mut d = crate::target_runtime::signals::SignalDesc::empty();
            d.present = true;
            d.name_len = 5;
            d.name[..5].copy_from_slice(b"depth");
            d.unit_len = 0;
            d
        });
        let enc = encode_signal_schema(&schema).unwrap();
        let dec = decode_signal_schema(&enc).unwrap();
        assert_eq!(dec.count, 2);
        assert_eq!(dec.desc(SignalId(0)).unwrap().name_str(), "parsed_items");
        assert_eq!(dec.desc(SignalId(3)).unwrap().name_str(), "depth");
        assert_eq!(dec.desc(SignalId(3)).unwrap().unit_str(), "");
        assert_eq!(signal_name(Some(&dec), SignalId(0)), "parsed_items(count)");
        assert_eq!(signal_name(Some(&dec), SignalId(1)), "sig#1");
    }

    #[test]
    fn schema_object_rejects_malformed() {
        assert!(decode_signal_schema(&[]).is_err());
        let mut schema = SignalSchema::empty();
        schema.set_desc(SignalId(0), {
            let mut d = crate::target_runtime::signals::SignalDesc::empty();
            d.present = true;
            d.name_len = 1;
            d.name[0] = b'x';
            d.unit_len = 0;
            d
        });
        let enc = encode_signal_schema(&schema).unwrap();
        // Unknown version.
        let mut bad = enc.clone();
        bad[0] = 99;
        assert!(matches!(
            decode_signal_schema(&bad),
            Err(Error::UnsupportedVersion { .. })
        ));
        // Truncation.
        assert!(decode_signal_schema(&enc[..enc.len() - 1]).is_err());
        // Trailing bytes.
        let mut extra = enc.clone();
        extra.push(0);
        assert!(decode_signal_schema(&extra).is_err());
    }

    #[test]
    fn wire_entries_convert() {
        let entries = vec![SignalDescWire {
            id: 2,
            name: "q".into(),
            unit: "u".into(),
        }];
        let schema = wire_entries_to_schema(&entries).unwrap();
        assert_eq!(schema.count, 1);
        assert_eq!(schema.desc(SignalId(2)).unwrap().name_str(), "q");
    }
}
