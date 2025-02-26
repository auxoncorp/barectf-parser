use crate::config::{PreferredDisplayBase, UnsignedIntegerFieldType};
use derive_more::Display;
use internment::Intern;
use num_enum::{FromPrimitive, IntoPrimitive};
use ordered_float::OrderedFloat;
use serde::{Deserialize, Serialize};

pub use event::Event;
pub use packet::{Packet, PacketContext, PacketHeader};

pub mod event;
pub mod packet;

pub type StreamId = u64;

pub type EventId = u64;

/// Timestamp in cycles
pub type Timestamp = u64;

pub type EventCount = u64;

pub type SequenceNumber = u64;

pub const CTF_MAGIC_NUMBER: u32 = 0xC1FC1FC1;

#[derive(
    Copy,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Debug,
    Display,
    IntoPrimitive,
    FromPrimitive,
    Serialize,
    Deserialize,
)]
#[repr(i32)]
pub enum LogLevel {
    #[display("EMERG")]
    Emergency = 0,
    #[display("ALERT")]
    Alert = 1,
    #[display("CRIT")]
    Critical = 2,
    #[display("ERR")]
    Error = 3,
    #[display("WARNING")]
    Warning = 4,
    #[display("NOTICE")]
    Notice = 5,
    #[display("INFO")]
    Info = 6,
    #[display("DEBUG_SYSTEM")]
    DebugSystem = 7,
    #[display("DEBUG_PROGRAM")]
    DebugProgram = 8,
    #[display("DEBUG_PROCESS")]
    DebugProcess = 9,
    #[display("DEBUG_MODULE")]
    DebugModule = 10,
    #[display("DEBUG_UNIT")]
    DebugUnit = 11,
    #[display("DEBUG_FUNCTION")]
    DebugFunction = 12,
    #[display("DEBUG_LINE")]
    DebugLine = 13,
    #[display("DEBUG")]
    Debug = 14,
    #[display("{_0}")]
    #[num_enum(catch_all)]
    Other(i32),
}

/// Stores the lower word of a [`TrackingInstant`] for
/// keeping track of timestamp rollovers.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
enum CyclesTracker {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
}

impl CyclesTracker {
    fn size_bits(&self) -> usize {
        match self {
            Self::U8(_) => 8,
            Self::U16(_) => 16,
            Self::U32(_) => 32,
            Self::U64(_) => 64,
        }
    }

    fn reset(&mut self) {
        match self {
            Self::U8(v) => {
                *v = 0;
            }
            Self::U16(v) => {
                *v = 0;
            }
            Self::U32(v) => {
                *v = 0;
            }
            Self::U64(v) => {
                *v = 0;
            }
        }
    }

    fn set(&mut self, cycles: Timestamp) {
        match self {
            Self::U8(v) => {
                *v = cycles as u8;
            }
            Self::U16(v) => *v = cycles as u16,
            Self::U32(v) => *v = cycles as u32,
            Self::U64(v) => {
                *v = cycles;
            }
        }
    }

    fn as_cycles(&self) -> u64 {
        match self {
            Self::U8(v) => *v as u64,
            Self::U16(v) => *v as u64,
            Self::U32(v) => *v as u64,
            Self::U64(v) => *v,
        }
    }

    fn is_u64(&self) -> bool {
        matches!(self, Self::U64(_))
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, thiserror::Error)]
#[error("Unsupported timestamp field time")]
pub struct UnsupportedTimestampFieldType {}

/// Instant, in cycles, that tracks rollovers.
/// Supports 8, 16, and 32 bit timestamp field types.
/// When the timestamp is a 64 bit value, then no rollover tracking is performed.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct TrackingInstant {
    lower: CyclesTracker,
    upper: u32,
}

impl TrackingInstant {
    pub fn new(
        field_type: &UnsignedIntegerFieldType,
    ) -> Result<Self, UnsupportedTimestampFieldType> {
        let lower = match field_type.field_type.size {
            8 => CyclesTracker::U8(0),
            16 => CyclesTracker::U16(0),
            32 => CyclesTracker::U32(0),
            64 => CyclesTracker::U64(0),
            _ => return Err(UnsupportedTimestampFieldType {}),
        };
        Ok(Self { lower, upper: 0 })
    }

    pub fn reset(&mut self) {
        self.lower.reset();
        self.upper = 0;
    }

    pub fn reset_to(&mut self, cycles: Timestamp, upper: u32) {
        self.lower.set(cycles);
        self.upper = upper;
    }

    pub fn elapsed(&mut self, cycles: Timestamp) -> Timestamp {
        if self.lower.is_u64() {
            self.lower.set(cycles)
        } else {
            // Check for rollover on the lower
            if cycles < self.lower.as_cycles() {
                self.upper += 1;
            }

            self.lower.set(cycles);
        }

        self.as_timestamp()
    }

    pub fn as_timestamp(&self) -> Timestamp {
        if self.lower.is_u64() {
            self.lower.as_cycles()
        } else {
            (u64::from(self.upper) << self.lower.size_bits()) | self.lower.as_cycles()
        }
    }
}

#[derive(Clone, PartialEq, PartialOrd, Hash, Debug, Serialize, Deserialize)]
pub enum PrimitiveFieldValue {
    UnsignedInteger(u64, PreferredDisplayBase),
    SignedInteger(i64, PreferredDisplayBase),
    String(String),
    F32(OrderedFloat<f32>),
    F64(OrderedFloat<f64>),
    Enumeration(i64, PreferredDisplayBase, Option<Intern<String>>),
}

#[derive(Clone, PartialEq, PartialOrd, Hash, Debug, Serialize, Deserialize)]
pub enum FieldValue {
    Primitive(PrimitiveFieldValue),
    Array(Vec<PrimitiveFieldValue>),
}

impl From<PrimitiveFieldValue> for FieldValue {
    fn from(v: PrimitiveFieldValue) -> Self {
        Self::Primitive(v)
    }
}

impl From<Vec<PrimitiveFieldValue>> for FieldValue {
    fn from(v: Vec<PrimitiveFieldValue>) -> Self {
        Self::Array(v)
    }
}

impl From<u8> for PrimitiveFieldValue {
    fn from(v: u8) -> Self {
        PrimitiveFieldValue::UnsignedInteger(v.into(), PreferredDisplayBase::default())
    }
}

impl From<u16> for PrimitiveFieldValue {
    fn from(v: u16) -> Self {
        PrimitiveFieldValue::UnsignedInteger(v.into(), PreferredDisplayBase::default())
    }
}

impl From<u32> for PrimitiveFieldValue {
    fn from(v: u32) -> Self {
        PrimitiveFieldValue::UnsignedInteger(v.into(), PreferredDisplayBase::default())
    }
}

impl From<u64> for PrimitiveFieldValue {
    fn from(v: u64) -> Self {
        PrimitiveFieldValue::UnsignedInteger(v, PreferredDisplayBase::default())
    }
}

impl From<i8> for PrimitiveFieldValue {
    fn from(v: i8) -> Self {
        PrimitiveFieldValue::SignedInteger(v.into(), PreferredDisplayBase::default())
    }
}

impl From<i16> for PrimitiveFieldValue {
    fn from(v: i16) -> Self {
        PrimitiveFieldValue::SignedInteger(v.into(), PreferredDisplayBase::default())
    }
}

impl From<i32> for PrimitiveFieldValue {
    fn from(v: i32) -> Self {
        PrimitiveFieldValue::SignedInteger(v.into(), PreferredDisplayBase::default())
    }
}

impl From<i64> for PrimitiveFieldValue {
    fn from(v: i64) -> Self {
        PrimitiveFieldValue::SignedInteger(v, PreferredDisplayBase::default())
    }
}

impl From<String> for PrimitiveFieldValue {
    fn from(v: String) -> Self {
        PrimitiveFieldValue::String(v)
    }
}

impl From<&str> for PrimitiveFieldValue {
    fn from(v: &str) -> Self {
        PrimitiveFieldValue::String(v.to_owned())
    }
}

impl From<f32> for PrimitiveFieldValue {
    fn from(v: f32) -> Self {
        PrimitiveFieldValue::F32(OrderedFloat(v))
    }
}

impl From<f64> for PrimitiveFieldValue {
    fn from(v: f64) -> Self {
        PrimitiveFieldValue::F64(OrderedFloat(v))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::config::IntegerFieldType;

    fn timestamp_ft(size_bits: usize) -> UnsignedIntegerFieldType {
        UnsignedIntegerFieldType {
            field_type: IntegerFieldType {
                size: size_bits,
                alignment: 8, // byte-packed
                preferred_display_base: Default::default(),
            },
        }
    }

    #[test]
    fn rollover_tracking_u8() {
        // 5 ticks before rollover
        let t0 = u8::MAX - 5;

        // 10 ticks after rollover
        let t1 = 10_u8;

        let mut instant = TrackingInstant::new(&timestamp_ft(8)).unwrap();
        assert_eq!(instant.elapsed(t0.into()), u64::from(t0));

        let t2 = instant.elapsed(t1.into());
        assert_eq!(u64::from(t0) + 16, t2);
    }

    #[test]
    fn rollover_tracking_u16() {
        // 5 ticks before rollover
        let t0 = u16::MAX - 5;

        // 10 ticks after rollover
        let t1 = 10_u16;

        let mut instant = TrackingInstant::new(&timestamp_ft(16)).unwrap();
        assert_eq!(instant.elapsed(t0.into()), u64::from(t0));

        let t2 = instant.elapsed(t1.into());
        assert_eq!(u64::from(t0) + 16, t2);
    }

    #[test]
    fn rollover_tracking_u32() {
        // 5 ticks before rollover
        let t0 = u32::MAX - 5;

        // 10 ticks after rollover
        let t1 = 10_u32;

        let mut instant = TrackingInstant::new(&timestamp_ft(32)).unwrap();
        assert_eq!(instant.elapsed(t0.into()), u64::from(t0));

        let t2 = instant.elapsed(t1.into());
        assert_eq!(u64::from(t0) + 16, t2);
    }

    #[test]
    fn no_rollover_tracking_u64() {
        // 5 ticks before rollover
        let t0 = u64::MAX - 5;

        // 10 ticks after rollover
        let t1 = 10_u64;

        let mut instant = TrackingInstant::new(&timestamp_ft(64)).unwrap();
        assert_eq!(instant.elapsed(t0), t0);

        let t2 = instant.elapsed(t1);
        assert_eq!(t1, t2);
    }

    #[test]
    fn unsupported_timestamp_field_type() {
        assert_eq!(
            TrackingInstant::new(&timestamp_ft(24)),
            Err(UnsupportedTimestampFieldType {})
        );
    }
}
