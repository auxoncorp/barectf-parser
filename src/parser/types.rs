use crate::{
    config::{
        EnumerationFieldTypeMappingSequence, FeaturesUnsignedIntegerFieldType, FieldType,
        NativeByteOrder, PreferredDisplayBase, PrimitiveFieldType, StructureMemberFieldType,
        UnsignedIntegerFieldType,
    },
    error::Error,
    types::{EventId, FieldValue, PrimitiveFieldValue},
};
use byteordered::{byteorder::ReadBytesExt, ByteOrdered, Endianness};
use fxhash::FxHashMap;
use internment::Intern;
use uuid::Uuid;

#[derive(Debug)]
pub struct PacketHeaderParser {
    pub magic: Option<UIntParser>,
    pub uuid: Option<UuidParser>,
    pub stream_id: UIntParser,
    pub alignment: Size,
    pub wire_size_hint: AlignedCursor,
}

impl PacketHeaderParser {
    pub fn new(
        magic: Option<UIntParser>,
        uuid: Option<UuidParser>,
        stream_id: UIntParser,
        alignment: Size,
    ) -> Self {
        let mut wire_size_hint = AlignedCursor::default();

        // Align for packet header structure
        wire_size_hint.align_to(alignment);

        // Add fields
        if let Some(f) = magic.as_ref() {
            wire_size_hint.aligned_increment(f.desc());
        }
        if uuid.is_some() {
            // This is a 16 byte-packed static array
            wire_size_hint.align_to(Size::Bits8);
            wire_size_hint.increment(Size::Bits64);
            wire_size_hint.increment(Size::Bits64);
        }
        wire_size_hint.aligned_increment(stream_id.desc());

        Self {
            magic,
            uuid,
            stream_id,
            alignment,
            wire_size_hint,
        }
    }
}

#[derive(Debug)]
pub struct PacketContextParserArgs {
    pub packet_size: UIntParser,
    pub content_size: UIntParser,
    pub beginning_timestamp: Option<UIntParser>,
    pub end_timestamp: Option<UIntParser>,
    pub events_discarded: Option<UIntParser>,
    pub sequence_number: Option<UIntParser>,
    pub extra_members: Vec<EventPayloadMemberParser>,
    pub alignment: Size,
}

#[derive(Debug)]
pub struct PacketContextParser {
    pub packet_size: UIntParser,
    pub content_size: UIntParser,
    pub beginning_timestamp: Option<UIntParser>,
    pub end_timestamp: Option<UIntParser>,
    pub events_discarded: Option<UIntParser>,
    pub sequence_number: Option<UIntParser>,
    pub extra_members: Vec<EventPayloadMemberParser>,
    pub alignment: Size,
    pub wire_size_hint: AlignedCursor,
}

impl PacketContextParser {
    pub fn new(args: PacketContextParserArgs, packet_header_cursor: &AlignedCursor) -> Self {
        let mut wire_size_hint = *packet_header_cursor;

        // Align for packet context structure
        wire_size_hint.align_to(args.alignment);

        // Add fields
        wire_size_hint.aligned_increment(args.packet_size.desc());
        wire_size_hint.aligned_increment(args.content_size.desc());
        if let Some(f) = args.beginning_timestamp.as_ref() {
            wire_size_hint.aligned_increment(f.desc());
        }
        if let Some(f) = args.end_timestamp.as_ref() {
            wire_size_hint.aligned_increment(f.desc());
        }
        if let Some(f) = args.events_discarded.as_ref() {
            wire_size_hint.aligned_increment(f.desc());
        }
        if let Some(f) = args.sequence_number.as_ref() {
            wire_size_hint.aligned_increment(f.desc());
        }

        // Add extra members
        for extra_member in args.extra_members.iter() {
            wire_size_hint.aligned_increment(extra_member.value.desc());
        }

        Self {
            packet_size: args.packet_size,
            content_size: args.content_size,
            beginning_timestamp: args.beginning_timestamp,
            end_timestamp: args.end_timestamp,
            events_discarded: args.events_discarded,
            sequence_number: args.sequence_number,
            extra_members: args.extra_members,
            alignment: args.alignment,
            wire_size_hint,
        }
    }
}

#[derive(Debug)]
pub struct StreamParser {
    pub stream_name: Intern<String>,
    pub packet_context: PacketContextParser,
    pub event_header: EventHeaderParser,
    pub common_context: Option<EventPayloadParser>,
    pub events: FxHashMap<EventId, EventParser>,
}

#[derive(Debug)]
pub struct EventHeaderParser {
    pub event_id: UIntParser,
    pub timestamp: UIntParser,
    pub alignment: Size,
}

#[derive(Debug)]
pub struct EventParser {
    pub event_name: Intern<String>,
    pub log_level: Option<i32>,
    pub specific_context: Option<EventPayloadParser>,
    pub payload: Option<EventPayloadParser>,
}

#[derive(Debug)]
pub struct EventPayloadParser {
    pub alignment: Size,
    pub members: Vec<EventPayloadMemberParser>,
}

#[derive(Debug)]
pub struct EnumerationMappings(pub Vec<(Intern<String>, Vec<EnumerationFieldTypeMappingSequence>)>);

impl EnumerationMappings {
    pub(crate) fn from_struct_ft(ft: &StructureMemberFieldType) -> Option<Self> {
        match ft {
            StructureMemberFieldType::UnsignedEnumeration(t)
            | StructureMemberFieldType::SignedEnumeration(t) => {
                let mut mappings = Vec::new();
                for (label, seq) in t.mappings.iter() {
                    mappings.push((Intern::new(label.clone()), seq.clone()));
                }
                Some(Self(mappings))
            }
            _ => None,
        }
    }

    pub fn label(&self, v: i64) -> Option<Intern<String>> {
        self.0
            .iter()
            .find_map(|(label, values)| values.iter().any(|s| s.contains(v)).then_some(*label))
    }
}

#[derive(Debug)]
pub struct EventPayloadMemberParser {
    pub member_name: Intern<String>,
    pub preferred_display_base: Option<PreferredDisplayBase>,
    pub enum_mappings: Option<EnumerationMappings>,
    pub value: FieldTypeParser,
}

impl EventPayloadMemberParser {
    pub fn parse<T: ReadBytesExt>(&self, r: &mut StreamReader<T>) -> Result<FieldValue, Error> {
        // Parse the value, add preferred display base, if any
        let val = match self.value.parse(r)? {
            FieldValue::Primitive(PrimitiveFieldValue::UnsignedInteger(v, _)) => {
                FieldValue::Primitive(PrimitiveFieldValue::UnsignedInteger(
                    v,
                    self.preferred_display_base.unwrap_or_default(),
                ))
            }
            FieldValue::Primitive(PrimitiveFieldValue::SignedInteger(v, _)) => {
                FieldValue::Primitive(PrimitiveFieldValue::SignedInteger(
                    v,
                    self.preferred_display_base.unwrap_or_default(),
                ))
            }
            val => val,
        };

        // Attempt to extract an enum value label, if any
        if let Some(mappings) = &self.enum_mappings {
            match val {
                // NOTE: we always convert unsigned enums to signed
                FieldValue::Primitive(PrimitiveFieldValue::UnsignedInteger(v, pdb)) => {
                    Ok(FieldValue::Primitive(PrimitiveFieldValue::Enumeration(
                        v as i64,
                        pdb,
                        mappings.label(v as i64),
                    )))
                }
                FieldValue::Primitive(PrimitiveFieldValue::SignedInteger(v, pdb)) => {
                    Ok(FieldValue::Primitive(PrimitiveFieldValue::Enumeration(
                        v,
                        pdb,
                        mappings.label(v),
                    )))
                }
                val => Ok(val),
            }
        } else {
            Ok(val)
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Size {
    Bits8,
    Bits16,
    Bits32,
    Bits64,
}

impl Size {
    pub fn from_bits(bits: usize) -> Option<Self> {
        Some(match bits {
            8 => Self::Bits8,
            16 => Self::Bits16,
            32 => Self::Bits32,
            64 => Self::Bits64,
            _ => return None,
        })
    }

    fn bits(&self) -> usize {
        match self {
            Self::Bits8 => 8,
            Self::Bits16 => 16,
            Self::Bits32 => 32,
            Self::Bits64 => 64,
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct FieldDesc {
    pub size: Size,
    pub alignment: Size,
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, thiserror::Error)]
#[error("Unsupported field type (width {0}, alignment {1})")]
pub struct FieldUnsupportedError(pub usize, pub usize);

impl FieldDesc {
    pub fn from_ft<T: FieldType>(ft: &T) -> Result<Self, FieldUnsupportedError> {
        if let (Some(size), Some(alignment)) =
            (Size::from_bits(ft.size()), Size::from_bits(ft.alignment()))
        {
            Ok(Self { size, alignment })
        } else {
            Err(FieldUnsupportedError(ft.size(), ft.alignment()))
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct UuidParser {}

impl UuidParser {
    pub fn from_bool_ft(uuid_field_type: bool) -> Option<Self> {
        uuid_field_type.then_some(Self {})
    }

    pub fn parse<T: ReadBytesExt>(&self, r: &mut StreamReader<T>) -> Result<Uuid, Error> {
        r.align_to(Size::Bits8)?;
        let mut bytes = [0_u8; 16];
        for b in bytes.iter_mut() {
            *b = r.read_u8(Size::Bits8)?;
        }
        Ok(Uuid::from_bytes(bytes))
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct UIntParser(FieldDesc);

impl UIntParser {
    pub fn from_uint_ft(ft: &UnsignedIntegerFieldType) -> Result<Self, FieldUnsupportedError> {
        Ok(Self(FieldDesc::from_ft(&ft.field_type)?))
    }

    pub fn from_opt_uint_ft(
        ft: &FeaturesUnsignedIntegerFieldType,
    ) -> Result<Option<Self>, FieldUnsupportedError> {
        match ft {
            FeaturesUnsignedIntegerFieldType::False(_) => Ok(None),
            FeaturesUnsignedIntegerFieldType::UnsignedInteger(uint) => {
                Ok(Some(Self::from_uint_ft(uint)?))
            }
        }
    }

    pub fn desc(&self) -> &FieldDesc {
        &self.0
    }

    pub fn parse<T: ReadBytesExt>(&self, r: &mut StreamReader<T>) -> Result<u64, Error> {
        Ok(match self.desc().size {
            Size::Bits8 => r.read_u8(self.desc().alignment)?.into(),
            Size::Bits16 => r.read_u16(self.desc().alignment)?.into(),
            Size::Bits32 => r.read_u32(self.desc().alignment)?.into(),
            Size::Bits64 => r.read_u64(self.desc().alignment)?,
        })
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum PrimitiveFieldTypeParser {
    UInt(FieldDesc),
    Int(FieldDesc),
    String(FieldDesc),
    Real(FieldDesc),
    UEnum(FieldDesc),
    Enum(FieldDesc),
}

impl PrimitiveFieldTypeParser {
    pub fn from_ft(ft: &PrimitiveFieldType) -> Result<Self, FieldUnsupportedError> {
        let desc = FieldDesc::from_ft(ft)?;
        Ok(match ft {
            PrimitiveFieldType::UnsignedInteger(_) => Self::UInt(desc),
            PrimitiveFieldType::SignedInteger(_) => Self::Int(desc),
            PrimitiveFieldType::String => Self::String(desc),
            PrimitiveFieldType::Real(_) => Self::Real(desc),
            PrimitiveFieldType::UnsignedEnumeration(_) => Self::UEnum(desc),
            PrimitiveFieldType::SignedEnumeration(_) => Self::Enum(desc),
        })
    }

    pub fn desc(&self) -> &FieldDesc {
        match self {
            Self::UInt(t)
            | Self::Int(t)
            | Self::String(t)
            | Self::Real(t)
            | Self::UEnum(t)
            | Self::Enum(t) => t,
        }
    }

    pub fn parse<T: ReadBytesExt>(
        &self,
        r: &mut StreamReader<T>,
    ) -> Result<PrimitiveFieldValue, Error> {
        Ok(match self {
            Self::UInt(desc) | Self::UEnum(desc) => match desc.size {
                Size::Bits8 => r.read_u8(desc.alignment)?.into(),
                Size::Bits16 => r.read_u16(desc.alignment)?.into(),
                Size::Bits32 => r.read_u32(desc.alignment)?.into(),
                Size::Bits64 => r.read_u64(desc.alignment)?.into(),
            },
            Self::Int(desc) | Self::Enum(desc) => match desc.size {
                Size::Bits8 => r.read_i8(desc.alignment)?.into(),
                Size::Bits16 => r.read_i16(desc.alignment)?.into(),
                Size::Bits32 => r.read_i32(desc.alignment)?.into(),
                Size::Bits64 => r.read_i64(desc.alignment)?.into(),
            },
            Self::String(_) => r.read_string()?.into(),
            Self::Real(desc) => match desc.size {
                Size::Bits32 => r.read_f32(desc.alignment)?.into(),
                Size::Bits64 => r.read_f64(desc.alignment)?.into(),
                _ => return Err(Error::InvalidFloatSize(desc.size.bits())),
            },
        })
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum FieldTypeParser {
    Primitive(PrimitiveFieldTypeParser),
    StaticArray(usize, PrimitiveFieldTypeParser),
    DynamicArray(PrimitiveFieldTypeParser),
}

impl FieldTypeParser {
    pub fn from_ft(ft: &StructureMemberFieldType) -> Result<Self, FieldUnsupportedError> {
        let desc = FieldDesc::from_ft(ft)?;

        Ok(match ft {
            StructureMemberFieldType::UnsignedInteger(_) => {
                Self::Primitive(PrimitiveFieldTypeParser::UInt(desc))
            }
            StructureMemberFieldType::SignedInteger(_) => {
                Self::Primitive(PrimitiveFieldTypeParser::Int(desc))
            }
            StructureMemberFieldType::String => {
                Self::Primitive(PrimitiveFieldTypeParser::String(desc))
            }
            StructureMemberFieldType::Real(_) => {
                Self::Primitive(PrimitiveFieldTypeParser::Real(desc))
            }
            StructureMemberFieldType::UnsignedEnumeration(_) => {
                Self::Primitive(PrimitiveFieldTypeParser::UEnum(desc))
            }
            StructureMemberFieldType::SignedEnumeration(_) => {
                Self::Primitive(PrimitiveFieldTypeParser::Enum(desc))
            }
            StructureMemberFieldType::StaticArray(ft) => Self::StaticArray(
                ft.length,
                PrimitiveFieldTypeParser::from_ft(&ft.element_field_type)?,
            ),
            StructureMemberFieldType::DynamicArray(ft) => {
                Self::DynamicArray(PrimitiveFieldTypeParser::from_ft(&ft.element_field_type)?)
            }
        })
    }

    pub fn desc(&self) -> &FieldDesc {
        match self {
            Self::Primitive(t) => t.desc(),
            Self::StaticArray(_len, t) => t.desc(),
            Self::DynamicArray(t) => t.desc(),
        }
    }

    pub fn parse<T: ReadBytesExt>(&self, r: &mut StreamReader<T>) -> Result<FieldValue, Error> {
        match self {
            Self::Primitive(p) => Ok(p.parse(r)?.into()),
            Self::StaticArray(len, p) => {
                // Align for field
                r.align_to(p.desc().alignment)?;

                // Align for and read elements
                let mut arr = Vec::new();
                for _ in 0..*len {
                    arr.push(p.parse(r)?);
                }
                Ok(FieldValue::Array(arr))
            }
            Self::DynamicArray(p) => {
                // NOTE: the u32 len field is always byte-packed

                // Align for and read len
                let len = r.read_u32(Size::Bits8)?;

                // Align for field
                r.align_to(p.desc().alignment)?;

                // Align for and read elements
                let mut arr = Vec::new();
                for _ in 0..len {
                    arr.push(p.parse(r)?);
                }
                Ok(FieldValue::Array(arr))
            }
        }
    }
}

/// Used by the [`StreamReader`] and wire size helper utilities.
/// The [`StreamReader`] uses this do to sync IO reads, where alignment
/// is handled on the fly.
/// The [`Parser`] also maintains additional packet header and per-stream
/// packet context [`AlignedCursor`]'s to provided a way to know how
/// many bytes to expect so we can implement a `tokio_util::codec::Decoder`
/// for async streams.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
pub struct AlignedCursor {
    bit_index: usize,
}

impl AlignedCursor {
    pub fn cursor_bits(&self) -> usize {
        self.bit_index
    }

    pub fn cursor_bytes(&self) -> usize {
        self.bit_index >> 3
    }

    /// Returns the amount of padding the cursor moved by (bits)
    pub fn align_to(&mut self, align: Size) -> usize {
        let align_bits = align.bits();
        debug_assert!(align_bits % 8 == 0);

        // Compute the next alignment/padding
        let next_index = (self.bit_index + (align_bits - 1)) & (!align_bits + 1);
        tracing::trace!(align = align_bits, index = self.bit_index, next_index,);
        debug_assert!(next_index % 8 == 0);

        // Offset the cursor if necessary
        let padding = next_index - self.bit_index;
        self.bit_index += padding;
        padding
    }

    /// Align to the given bit alignment and increment the cursor by size bits
    pub fn aligned_increment(&mut self, desc: &FieldDesc) {
        let _padding = self.align_to(desc.alignment);
        self.increment(desc.size);
    }

    /// Increment the cursor by size bits
    pub fn increment(&mut self, size: Size) {
        self.bit_index += size.bits();
    }
}

#[derive(Debug)]
pub struct StreamReader<T> {
    pub inner: ByteOrdered<T, Endianness>,
    pub cursor: AlignedCursor,
}

impl<T> StreamReader<T>
where
    T: ReadBytesExt,
{
    pub fn new(byte_order: NativeByteOrder, r: T) -> Self {
        Self::new_with_cursor(byte_order, AlignedCursor::default(), r)
    }

    pub fn new_with_cursor(byte_order: NativeByteOrder, cursor: AlignedCursor, r: T) -> Self {
        Self {
            inner: ByteOrdered::runtime(r, byte_order.into()),
            cursor,
        }
    }

    pub fn into_cursor(self) -> AlignedCursor {
        let StreamReader { inner: _, cursor } = self;
        cursor
    }

    pub fn cursor_bits(&self) -> usize {
        self.cursor.cursor_bits()
    }

    pub fn align_to(&mut self, align: Size) -> Result<(), Error> {
        // Read padding, if any, 1 byte at a time
        let padding = self.cursor.align_to(align);
        let padding_bytes = padding >> 3;
        for _ in 0..padding_bytes {
            let _ = self.inner.read_u8()?;
        }
        Ok(())
    }

    pub fn read_u8(&mut self, align: Size) -> Result<u8, Error> {
        self.align_to(align)?;
        let val = self.inner.read_u8()?;
        self.cursor.increment(Size::Bits8);
        Ok(val)
    }

    pub fn read_i8(&mut self, align: Size) -> Result<i8, Error> {
        self.align_to(align)?;
        let val = self.inner.read_i8()?;
        self.cursor.increment(Size::Bits8);
        Ok(val)
    }

    pub fn read_u16(&mut self, align: Size) -> Result<u16, Error> {
        self.align_to(align)?;
        let val = self.inner.read_u16()?;
        self.cursor.increment(Size::Bits16);
        Ok(val)
    }

    pub fn read_i16(&mut self, align: Size) -> Result<i16, Error> {
        self.align_to(align)?;
        let val = self.inner.read_i16()?;
        self.cursor.increment(Size::Bits16);
        Ok(val)
    }

    pub fn read_u32(&mut self, align: Size) -> Result<u32, Error> {
        self.align_to(align)?;
        let val = self.inner.read_u32()?;
        self.cursor.increment(Size::Bits32);
        Ok(val)
    }

    pub fn read_i32(&mut self, align: Size) -> Result<i32, Error> {
        self.align_to(align)?;
        let val = self.inner.read_i32()?;
        self.cursor.increment(Size::Bits32);
        Ok(val)
    }

    pub fn read_f32(&mut self, align: Size) -> Result<f32, Error> {
        self.align_to(align)?;
        let val = self.inner.read_f32()?;
        self.cursor.increment(Size::Bits32);
        Ok(val)
    }

    pub fn read_u64(&mut self, align: Size) -> Result<u64, Error> {
        self.align_to(align)?;
        let val = self.inner.read_u64()?;
        self.cursor.increment(Size::Bits64);
        Ok(val)
    }

    pub fn read_i64(&mut self, align: Size) -> Result<i64, Error> {
        self.align_to(align)?;
        let val = self.inner.read_i64()?;
        self.cursor.increment(Size::Bits64);
        Ok(val)
    }

    pub fn read_f64(&mut self, align: Size) -> Result<f64, Error> {
        self.align_to(align)?;
        let val = self.inner.read_f64()?;
        self.cursor.increment(Size::Bits64);
        Ok(val)
    }

    pub fn read_string(&mut self) -> Result<String, Error> {
        let mut cstr = Vec::new();
        self.align_to(Size::Bits8)?;
        loop {
            let b = self.inner.read_u8()?;
            self.cursor.increment(Size::Bits8);
            if b == 0 {
                break;
            }
            cstr.push(b);
        }
        Ok(String::from_utf8_lossy(&cstr).to_string())
    }
}
