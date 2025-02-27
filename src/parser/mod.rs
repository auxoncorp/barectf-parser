use self::types::{
    AlignedCursor, EnumerationMappings, EventHeaderParser, EventParser, EventPayloadMemberParser,
    EventPayloadParser, FieldTypeParser, PacketContextParser, PacketContextParserArgs,
    PacketHeaderParser, Size, StreamParser, StreamReader, UIntParser, UuidParser,
};
use crate::{
    config::{ClockType, Config, FieldType, NativeByteOrder},
    error::Error,
    types::{Event, EventId, LogLevel, Packet, PacketContext, PacketHeader, StreamId},
};
use bytes::{Buf, BytesMut};
use fxhash::FxHashMap;
use internment::Intern;
use itertools::Itertools;
use std::io::Read;
use tokio_util::codec::Decoder;
use tracing::{debug, warn};
use uuid::Uuid;

pub(crate) mod types;

/// A barectf CTF byte-stream parser.
#[derive(Debug)]
pub struct Parser {
    byte_order: NativeByteOrder,
    trace_uuid: Option<Uuid>,
    pkt_header: PacketHeaderParser,
    streams: FxHashMap<StreamId, StreamParser>,
    stream_clocks: FxHashMap<StreamId, Intern<String>>,
    stream_clock_types: FxHashMap<StreamId, Intern<ClockType>>,
}

impl Parser {
    pub fn new(cfg: &Config) -> Result<Self, Error> {
        // Do some basic semantic checks
        if let Some(magic_ft) = cfg.trace.typ.features.magic_field_type.as_ft() {
            if magic_ft.field_type.size != 32 {
                return Err(Error::UnsupportedFieldType(
                    "magic-field-type".to_owned(),
                    magic_ft.field_type.size,
                    magic_ft.field_type.alignment,
                ));
            }
        }

        let magic = UIntParser::from_opt_uint_ft(&cfg.trace.typ.features.magic_field_type)
            .map_err(|e| Error::unsupported_ft("magic-field-type", e))?;
        let uuid = UuidParser::from_bool_ft(cfg.trace.typ.features.uuid_field_type);
        let stream_id =
            UIntParser::from_uint_ft(&cfg.trace.typ.features.data_stream_type_id_field_type)
                .map_err(|e| Error::unsupported_ft("data-stream-type-id-field-type", e))?;
        let pkt_header = PacketHeaderParser::new(
            magic,
            uuid,
            stream_id,
            Size::from_bits(cfg.trace.typ.features.alignment())
                .ok_or_else(|| Error::unsupported_alignment("trace.type.$features"))?,
        );

        // Per-stream packet parsers
        // NOTE: barectf generates stream IDs based on alphabetical order of stream name
        let mut streams = FxHashMap::default();
        let mut stream_clocks = FxHashMap::default();
        let mut stream_clock_types = FxHashMap::default();
        for (stream_id, (stream_name, stream)) in cfg
            .trace
            .typ
            .data_stream_types
            .iter()
            .sorted_by_key(|(name, _)| name.as_str())
            .enumerate()
        {
            if let Some(default_clock) = stream.default_clock_type_name.as_ref() {
                stream_clocks.insert(stream_id as StreamId, Intern::new(default_clock.to_owned()));
                if let Some(clock_type) = cfg.trace.typ.clock_types.get(default_clock) {
                    stream_clock_types
                        .insert(stream_id as StreamId, Intern::new(clock_type.clone()));
                }
            }

            // These are required by barectf
            let packet_size = UIntParser::from_uint_ft(
                &stream.features.packet.total_size_field_type,
            )
            .map_err(|e| {
                Error::unsupported_ft(
                    format!(
                        "stream.{}.$features.packet.total-size-field-type",
                        stream_name
                    ),
                    e,
                )
            })?;
            let content_size = UIntParser::from_uint_ft(
                &stream.features.packet.content_size_field_type,
            )
            .map_err(|e| {
                Error::unsupported_ft(
                    format!(
                        "stream.{}.$features.packet.content-size-field-type",
                        stream_name
                    ),
                    e,
                )
            })?;
            let beginning_timestamp = UIntParser::from_opt_uint_ft(
                &stream.features.packet.beginning_timestamp_field_type,
            )
            .map_err(|e| {
                Error::unsupported_ft(
                    format!(
                        "stream.{}.$features.packet.beginning-timestamp-field-type",
                        stream_name
                    ),
                    e,
                )
            })?;
            let end_timestamp =
                UIntParser::from_opt_uint_ft(&stream.features.packet.end_timestamp_field_type)
                    .map_err(|e| {
                        Error::unsupported_ft(
                            format!(
                                "stream.{}.$features.packet.end-timestamp-field-type",
                                stream_name
                            ),
                            e,
                        )
                    })?;
            let events_discarded = UIntParser::from_opt_uint_ft(
                &stream
                    .features
                    .packet
                    .discarded_event_records_counter_snapshot_field_type,
            )
            .map_err(|e| {
                Error::unsupported_ft(
                    format!("stream.{}.$features.packet.discarded-event-records-counter-snapshot-field-type", stream_name),
                    e,
                )
            })?;
            let sequence_number =
                UIntParser::from_opt_uint_ft(&stream.features.packet.sequence_number_field_type)
                    .map_err(|e| {
                        Error::unsupported_ft(
                            format!(
                                "stream.{}.$features.packet.sequence-number-field-type",
                                stream_name
                            ),
                            e,
                        )
                    })?;

            let mut pc_extra_members = Vec::new();
            let pc_extra_member_alignment =
                stream.packet_context_field_type_extra_members.alignment();
            for (pc_member_name, pc_member) in stream
                .packet_context_field_type_extra_members
                .0
                .iter()
                .flat_map(|m| m.iter())
            {
                pc_extra_members.push(EventPayloadMemberParser {
                    member_name: Intern::new(pc_member_name.clone()),
                    preferred_display_base: pc_member.field_type.preferred_display_base(),
                    enum_mappings: EnumerationMappings::from_struct_ft(&pc_member.field_type),
                    value: FieldTypeParser::from_ft(&pc_member.field_type).map_err(|e| {
                        Error::unsupported_ft(
                            format!(
                                "stream.{}.packet-context-field-type-extra-members.{}",
                                stream_name, pc_member_name
                            ),
                            e,
                        )
                    })?,
                });
            }

            // Event common context
            let common_context = if let Some(cc_field_type) =
                stream.event_record_common_context_field_type.as_ref()
            {
                let mut members = Vec::new();
                for (member_name, member) in cc_field_type.members.iter().flat_map(|m| m.iter()) {
                    members.push(EventPayloadMemberParser {
                        member_name: Intern::new(member_name.clone()),
                        preferred_display_base: member.field_type.preferred_display_base(),
                        enum_mappings: EnumerationMappings::from_struct_ft(&member.field_type),
                        value: FieldTypeParser::from_ft(&member.field_type).map_err(|e| {
                            Error::unsupported_ft(
                                format!(
                                    "stream.{}.event-record-common-context-field-type.{}",
                                    stream_name, member_name
                                ),
                                e,
                            )
                        })?,
                    });
                }

                Some(EventPayloadParser {
                    alignment: Size::from_bits(cc_field_type.alignment()).ok_or_else(|| {
                        Error::unsupported_alignment(format!(
                            "stream.{}.event-record-common-context-field-type",
                            stream_name
                        ))
                    })?,
                    members,
                })
            } else {
                None
            };

            // Per-event event parsers
            // NOTE: barectf generates event IDs based on alphabetical order of event name
            let mut events = FxHashMap::default();
            for (event_id, (event_name, event)) in stream
                .event_record_types
                .iter()
                .sorted_by_key(|(name, _)| name.as_str())
                .enumerate()
            {
                let specific_context = if let Some(sc_field_type) =
                    event.specific_context_field_type.as_ref()
                {
                    let mut members = Vec::new();
                    for (member_name, member) in sc_field_type.members.iter().flat_map(|m| m.iter())
                    {
                        members.push(EventPayloadMemberParser {
                            member_name: Intern::new(member_name.clone()),
                            preferred_display_base: member.field_type.preferred_display_base(),
                            enum_mappings: EnumerationMappings::from_struct_ft(&member.field_type),
                            value: FieldTypeParser::from_ft(&member.field_type)
                                .map_err(|e| {
                                Error::unsupported_ft(
                                    format!(
                                        "stream.{}.event-record-types.{}.specific-context-field-type.{}",
                                        stream_name,
                                        event_name,
                                        member_name
                                    ),
                                    e,
                                )
                            })?,
                        });
                    }

                    Some(EventPayloadParser {
                        alignment: Size::from_bits(sc_field_type.alignment()).ok_or_else(|| {
                            Error::unsupported_alignment(format!(
                                "stream.{}.event-record-types.{}.specific-context-field-type",
                                stream_name, event_name
                            ))
                        })?,
                        members,
                    })
                } else {
                    None
                };

                let payload = if let Some(payload_field_type) = event.payload_field_type.as_ref() {
                    let mut members = Vec::new();
                    for (member_name, member) in
                        payload_field_type.members.iter().flat_map(|m| m.iter())
                    {
                        members.push(EventPayloadMemberParser {
                            member_name: Intern::new(member_name.clone()),
                            preferred_display_base: member.field_type.preferred_display_base(),
                            enum_mappings: EnumerationMappings::from_struct_ft(&member.field_type),
                            value: FieldTypeParser::from_ft(&member.field_type).map_err(|e| {
                                Error::unsupported_ft(
                                    format!(
                                        "stream.{}.event-record-types.{}.payload-field-type.{}",
                                        stream_name, event_name, member_name
                                    ),
                                    e,
                                )
                            })?,
                        });
                    }

                    Some(EventPayloadParser {
                        alignment: Size::from_bits(payload_field_type.alignment()).ok_or_else(
                            || {
                                Error::unsupported_alignment(format!(
                                    "stream.{}.event-record-types.{}.payload-field-type",
                                    stream_name, event_name
                                ))
                            },
                        )?,
                        members,
                    })
                } else {
                    None
                };

                events.insert(
                    event_id as EventId,
                    EventParser {
                        event_name: Intern::new(event_name.clone()),
                        log_level: event.log_level,
                        specific_context,
                        payload,
                    },
                );
            }

            streams.insert(
                stream_id as StreamId,
                StreamParser {
                    stream_name: Intern::new(stream_name.clone()),
                    packet_context: PacketContextParser::new(
                        PacketContextParserArgs {
                            packet_size,
                            content_size,
                            beginning_timestamp,
                            end_timestamp,
                            events_discarded,
                            sequence_number,
                            extra_members: pc_extra_members,
                            alignment: Size::from_bits(
                                stream
                                    .features
                                    .packet
                                    .alignment()
                                    .max(pc_extra_member_alignment),
                            )
                            .ok_or_else(|| {
                                Error::unsupported_alignment(format!(
                                    "stream.{}.$features.packet",
                                    stream_name
                                ))
                            })?,
                        },
                        &pkt_header.wire_size_hint,
                    ),
                    event_header: EventHeaderParser {
                        event_id: UIntParser::from_uint_ft(
                            &stream.features.event_record.type_id_field_type,
                        )
                        .map_err(|e| {
                            Error::unsupported_ft(
                                format!(
                                    "stream.{}.$features.event-record.type-id-field-type",
                                    stream_name
                                ),
                                e,
                            )
                        })?,
                        timestamp: UIntParser::from_uint_ft(
                            &stream.features.event_record.timestamp_field_type,
                        )
                        .map_err(|e| {
                            Error::unsupported_ft(
                                format!(
                                    "stream.{}.$features.event-record.timestamp-field-type",
                                    stream_name
                                ),
                                e,
                            )
                        })?,
                        alignment: Size::from_bits(stream.features.event_record.alignment())
                            .ok_or_else(|| {
                                Error::unsupported_alignment(format!(
                                    "stream.{}.$features.event-record",
                                    stream_name
                                ))
                            })?,
                    },
                    common_context,
                    events,
                },
            );
        }

        Ok(Self {
            byte_order: cfg.trace.typ.native_byte_order,
            trace_uuid: cfg.trace.typ.uuid,
            pkt_header,
            streams,
            stream_clocks,
            stream_clock_types,
        })
    }

    pub fn into_packet_decoder(self) -> PacketDecoder {
        PacketDecoder {
            parser: self,
            state: PacketDecoderState::Header,
        }
    }

    pub fn parse<R: Read>(&self, r: &mut R) -> Result<Packet, Error> {
        let mut r = StreamReader::new(self.byte_order, r);

        let header = self.parse_header(&mut r)?;

        // Stream-specific from here on
        let stream = self
            .streams
            .get(&header.stream_id)
            .ok_or(Error::UndefinedStreamId(header.stream_id))?;

        let context = Self::parse_packet_context(stream, &mut r)?;

        let events = Self::parse_events(stream, &context, &mut r)?;

        Ok(Packet {
            header,
            context,
            events,
        })
    }

    fn parse_header<R: Read>(&self, r: &mut StreamReader<R>) -> Result<PacketHeader, Error> {
        // Align for packet header structure
        r.align_to(self.pkt_header.alignment)?;

        // Parse the header
        let magic = self
            .pkt_header
            .magic
            .as_ref()
            .map(|p| p.parse(r))
            .transpose()?
            .map(|m| m as u32);
        let trace_uuid = self
            .pkt_header
            .uuid
            .as_ref()
            .map(|p| p.parse(r))
            .transpose()?;
        let stream_id = self.pkt_header.stream_id.parse(r)?;
        debug!(stream_id, ?magic, ?trace_uuid, "Parsed packet header");
        if let Some(m) = magic {
            if m != PacketHeader::MAGIC {
                warn!(
                    "Invalid packet header magic number 0x{m:X} (expected 0x{:X})",
                    PacketHeader::MAGIC
                );
            }
        }
        if let (Some(uuid), Some(schema_uuid)) = (trace_uuid.as_ref(), self.trace_uuid.as_ref()) {
            if uuid != schema_uuid {
                warn!(
                    trace_uuid = %uuid,
                    %schema_uuid, "Trace type UUID doesn't match"
                );
            }
        }

        // Ensure the wire size hint is aligned with reality
        debug_assert_eq!(
            r.cursor_bits(),
            self.pkt_header.wire_size_hint.cursor_bits()
        );

        let stream = self
            .streams
            .get(&stream_id)
            .ok_or(Error::UndefinedStreamId(stream_id))?;

        Ok(PacketHeader {
            magic_number: magic,
            trace_uuid,
            stream_id,
            stream_name: stream.stream_name,
            clock_name: self.stream_clocks.get(&stream_id).copied(),
            clock_type: self.stream_clock_types.get(&stream_id).copied(),
        })
    }

    fn parse_packet_context<R: Read>(
        stream: &StreamParser,
        r: &mut StreamReader<R>,
    ) -> Result<PacketContext, Error> {
        // Align for packet context structure
        r.align_to(stream.packet_context.alignment)?;

        // Parse packet context
        let pkt_size_bits = stream.packet_context.packet_size.parse(r)?;
        let content_size_bits = stream.packet_context.content_size.parse(r)?;
        let beginning_timestamp = stream
            .packet_context
            .beginning_timestamp
            .as_ref()
            .map(|p| p.parse(r))
            .transpose()?;
        let end_timestamp = stream
            .packet_context
            .end_timestamp
            .as_ref()
            .map(|p| p.parse(r))
            .transpose()?;
        let events_discarded = stream
            .packet_context
            .events_discarded
            .as_ref()
            .map(|p| p.parse(r))
            .transpose()?;
        let sequence_number = stream
            .packet_context
            .sequence_number
            .as_ref()
            .map(|p| p.parse(r))
            .transpose()?;

        // Align for and read each extra member
        let mut extra_members = Vec::new();
        for member in stream.packet_context.extra_members.iter() {
            let val = member.parse(r)?;
            extra_members.push((member.member_name, val));
        }

        debug!(
            packet_size = pkt_size_bits,
            content_size = content_size_bits,
            ?events_discarded,
            ?sequence_number,
            "Parsed packet context"
        );
        // Ensure the wire size hint is aligned with reality
        debug_assert_eq!(
            r.cursor_bits(),
            stream.packet_context.wire_size_hint.cursor_bits()
        );

        Ok(PacketContext {
            packet_size_bits: pkt_size_bits as _,
            content_size_bits: content_size_bits as _,
            beginning_timestamp,
            end_timestamp,
            events_discarded,
            sequence_number,
            extra_members,
        })
    }

    fn parse_events<R: Read>(
        stream: &StreamParser,
        packet_context: &PacketContext,
        r: &mut StreamReader<R>,
    ) -> Result<Vec<Event>, Error> {
        let mut events = Vec::new();

        // Read until we reach the end of the actual packet content
        loop {
            // Align for header structure
            r.align_to(stream.event_header.alignment)?;

            // Parse event header structure
            let event_id = stream.event_header.event_id.parse(r)?;
            let timestamp = stream.event_header.timestamp.parse(r)?;
            debug!(event_id, timestamp, "Parsed event header");

            // Align for common context structure
            // Common context
            let mut common_context = Vec::new();
            if let Some(p) = stream.common_context.as_ref() {
                // Align for common context structure
                r.align_to(p.alignment)?;

                // Align for and read each member
                for member in p.members.iter() {
                    let val = member.parse(r)?;
                    common_context.push((member.member_name, val));
                }
            }

            // Event-specific from here on
            let event = stream
                .events
                .get(&event_id)
                .ok_or(Error::UndefinedEventId(event_id))?;

            // Specific context
            let mut specific_context = Vec::new();
            if let Some(p) = event.specific_context.as_ref() {
                // Align for specific context structure
                r.align_to(p.alignment)?;

                // Align for and read each member
                for member in p.members.iter() {
                    let val = member.parse(r)?;
                    specific_context.push((member.member_name, val));
                }
            }

            // Payload
            let mut payload = Vec::new();
            if let Some(p) = event.payload.as_ref() {
                // Align for payload structure
                r.align_to(p.alignment)?;

                // Align for and read each member
                for member in p.members.iter() {
                    let val = member.parse(r)?;
                    payload.push((member.member_name, val));
                }
            }

            events.push(Event {
                id: event_id,
                name: event.event_name,
                timestamp,
                log_level: event.log_level.map(LogLevel::from),
                specific_context,
                common_context,
                payload,
            });

            // Done with actual packet data, may still be residual bits to skip over
            debug_assert!(r.cursor_bits() <= packet_context.content_size_bits);
            if r.cursor_bits() == packet_context.content_size_bits {
                break;
            }
        }

        // Skip the remaining in the packet
        let remaining_bits = packet_context.packet_size_bits - packet_context.content_size_bits;
        if remaining_bits != 0 {
            let remaining_bytes = remaining_bits >> 3;
            for _ in 0..remaining_bytes {
                // No need to maintain alignment/etc, we're done with the reader
                r.inner.read_u8()?;
            }
        }

        Ok(events)
    }
}

/// A barectf CTF byte-stream decoder.
#[derive(Debug)]
pub struct PacketDecoder {
    parser: Parser,
    state: PacketDecoderState,
}

#[derive(Debug)]
enum PacketDecoderState {
    Header,
    PacketContext(PacketHeader, AlignedCursor),
    Events(PacketHeader, PacketContext, AlignedCursor),
}

impl Decoder for PacketDecoder {
    type Item = Packet;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Loop until we've got a full packet or need more data
        loop {
            match std::mem::replace(&mut self.state, PacketDecoderState::Header) {
                PacketDecoderState::Header => {
                    if src.len() < self.parser.pkt_header.wire_size_hint.cursor_bytes() {
                        // Not enough data for header
                        self.state = PacketDecoderState::Header;
                        return Ok(None);
                    }

                    let mut src_reader = src.reader();
                    let mut r = StreamReader::new(self.parser.byte_order, &mut src_reader);
                    let header = self.parser.parse_header(&mut r)?;
                    let cursor = r.into_cursor();

                    self.state = PacketDecoderState::PacketContext(header, cursor);
                }
                PacketDecoderState::PacketContext(header, cursor) => {
                    // Stream-specific from here on
                    let stream = self
                        .parser
                        .streams
                        .get(&header.stream_id)
                        .ok_or(Error::UndefinedStreamId(header.stream_id))?;

                    let context_bytes_remaining =
                        stream.packet_context.wire_size_hint.cursor_bytes() - cursor.cursor_bytes();
                    if src.len() < context_bytes_remaining {
                        // Not enough data for context
                        self.state = PacketDecoderState::PacketContext(header, cursor);
                        return Ok(None);
                    }

                    let mut src_reader = src.reader();
                    let mut r = StreamReader::new_with_cursor(
                        self.parser.byte_order,
                        cursor,
                        &mut src_reader,
                    );

                    let packet_context = Parser::parse_packet_context(stream, &mut r)?;
                    let cursor = r.into_cursor();

                    self.state = PacketDecoderState::Events(header, packet_context, cursor);
                }
                PacketDecoderState::Events(header, packet_context, cursor) => {
                    let remaining_bytes = packet_context.packet_size() - cursor.cursor_bytes();
                    if src.len() < remaining_bytes {
                        // Not enough data for the remaining payload
                        self.state = PacketDecoderState::Events(header, packet_context, cursor);
                        return Ok(None);
                    }

                    let stream = self
                        .parser
                        .streams
                        .get(&header.stream_id)
                        .ok_or(Error::UndefinedStreamId(header.stream_id))?;

                    let mut src_reader = src.reader();
                    let mut r = StreamReader::new_with_cursor(
                        self.parser.byte_order,
                        cursor,
                        &mut src_reader,
                    );

                    let events = Parser::parse_events(stream, &packet_context, &mut r)?;

                    let pkt = Packet {
                        header,
                        context: packet_context,
                        events,
                    };
                    self.state = PacketDecoderState::Header;
                    return Ok(Some(pkt));
                }
            }
        }
    }
}
