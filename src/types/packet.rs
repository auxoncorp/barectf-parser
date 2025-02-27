use crate::{
    config::ClockType,
    types::{Event, EventCount, FieldValue, SequenceNumber, StreamId, Timestamp},
};
use internment::Intern;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Packet {
    pub header: PacketHeader,
    pub context: PacketContext,
    pub events: Vec<Event>,
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Serialize, Deserialize)]
pub struct PacketHeader {
    /// Magic number ([`PacketHeader::MAGIC`]) specifies that this is a CTF packet.
    pub magic_number: Option<u32>,
    /// Trace UUID, used to ensure the event packet match the metadata used.
    pub trace_uuid: Option<Uuid>,
    /// Stream ID, used as reference to stream description in metadata.
    pub stream_id: StreamId,
    /// Stream name
    pub stream_name: Intern<String>,
    /// Name of this stream's default clock
    pub clock_name: Option<Intern<String>>,
    /// This stream's clock type
    pub clock_type: Option<Intern<ClockType>>,
}

impl PacketHeader {
    pub const MAGIC: u32 = 0xC1FC_1FC1;
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PacketContext {
    /// Event packet size (in bits, includes padding).
    pub packet_size_bits: usize,
    /// Event packet content size (in bits).
    pub content_size_bits: usize,
    /// Time-stamp at the beginning of the event packet.
    pub beginning_timestamp: Option<Timestamp>,
    /// Time-stamp at the end of the event packet.
    pub end_timestamp: Option<Timestamp>,
    /// Snapshot of a per-stream free-running counter,
    /// counting the number of events discarded that were supposed to be
    /// written in the stream after the last event in the event packet.
    pub events_discarded: Option<EventCount>,
    /// Per-stream event packet sequence count.
    pub sequence_number: Option<SequenceNumber>,
    /// Extra, user-defined members to be appended to this data stream type’s packet context structure field type.
    pub extra_members: Vec<(Intern<String>, FieldValue)>,
}

impl PacketContext {
    /// Event packet size (in bytes).
    pub fn packet_size(&self) -> usize {
        self.packet_size_bits >> 3
    }

    /// Event packet content size (in bytes).
    pub fn content_size(&self) -> usize {
        self.content_size_bits >> 3
    }
}
