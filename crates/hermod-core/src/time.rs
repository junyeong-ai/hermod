use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::error::HermodError;

/// Timestamp with RFC3339 (de)serialization.
///
/// Always UTC. Storage backends use `unix_ms()` for `INTEGER` columns.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Timestamp(OffsetDateTime);

impl Timestamp {
    pub fn now() -> Self {
        Self(OffsetDateTime::now_utc())
    }

    pub fn from_unix_ms(ms: i64) -> Result<Self, HermodError> {
        let nanos = (ms as i128)
            .checked_mul(1_000_000)
            .ok_or_else(|| HermodError::InvalidTimestamp(format!("unix ms overflow: {ms}")))?;
        OffsetDateTime::from_unix_timestamp_nanos(nanos)
            .map(Self)
            .map_err(|e| HermodError::InvalidTimestamp(e.to_string()))
    }

    pub fn unix_ms(&self) -> i64 {
        (self.0.unix_timestamp_nanos() / 1_000_000) as i64
    }

    /// Return `self` shifted by `delta_ms` milliseconds. Falls back to
    /// `self` (no shift) on overflow — appropriate for TTL math where the
    /// only practical failure mode is a centuries-long delta. **Not** for
    /// security-critical replay-window comparisons: there, do the
    /// arithmetic on `i64` returned by [`Self::unix_ms`] so an overflow
    /// surfaces as an observable rejection rather than a silent clamp.
    pub fn offset_by_ms(&self, delta_ms: i64) -> Self {
        let target = self.unix_ms().saturating_add(delta_ms);
        Self::from_unix_ms(target).unwrap_or(*self)
    }

    pub fn as_offset_date_time(&self) -> OffsetDateTime {
        self.0
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Timestamp({})",
            self.0.format(&Rfc3339).unwrap_or_default()
        )
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0
            .format(&Rfc3339)
            .map_err(|_| fmt::Error)
            .and_then(|s| write!(f, "{s}"))
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let s = self.0.format(&Rfc3339).map_err(serde::ser::Error::custom)?;
        ser.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        OffsetDateTime::parse(&s, &Rfc3339)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_json() {
        let ts = Timestamp::now();
        let s = serde_json::to_string(&ts).unwrap();
        let back: Timestamp = serde_json::from_str(&s).unwrap();
        assert_eq!(ts, back);
    }

    #[test]
    fn unix_ms_roundtrip() {
        let ts = Timestamp::from_unix_ms(1_714_000_000_000).unwrap();
        assert_eq!(ts.unix_ms(), 1_714_000_000_000);
    }

    #[test]
    fn offset_by_ms_normal_case() {
        let ts = Timestamp::from_unix_ms(1_000_000_000_000).unwrap();
        let shifted = ts.offset_by_ms(60_000);
        assert_eq!(shifted.unix_ms(), 1_000_000_060_000);
    }

    #[test]
    fn offset_by_ms_falls_back_to_self_on_overflow() {
        let ts = Timestamp::now();
        // i64::MAX milliseconds is ~292 million years — well past the
        // representable range. The helper must not panic; it should
        // simply return self.
        let shifted = ts.offset_by_ms(i64::MAX);
        assert_eq!(shifted, ts);
    }
}
