use byteordered::Endianness;
use serde::{Deserialize, Deserializer, Serialize};
use serde_yaml::Value;
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeByteOrder {
    #[serde(alias = "little")]
    #[serde(alias = "le")]
    LittleEndian,
    #[serde(alias = "big")]
    #[serde(alias = "be")]
    BigEndian,
}

impl From<NativeByteOrder> for Endianness {
    fn from(value: NativeByteOrder) -> Self {
        match value {
            NativeByteOrder::LittleEndian => Endianness::Little,
            NativeByteOrder::BigEndian => Endianness::Big,
        }
    }
}

#[derive(
    Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default, Deserialize, Serialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum PreferredDisplayBase {
    #[serde(alias = "bin")]
    Binary,
    #[serde(alias = "oct")]
    Octal,
    #[default]
    #[serde(alias = "dec")]
    Decimal,
    #[serde(alias = "hex")]
    Hexadecimal,
}

/// Integer field type objects are the types of integer data fields, found in data streams.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct IntegerFieldType {
    /// Size of this field type’s instances (bits).
    pub size: usize,
    /// Alignment of the first bit of this field type’s instances within a CTF packet (bits).
    #[serde(default = "default_alignment_bits")]
    pub alignment: usize,
    /// The preferred base (radix) to use when displaying this field type’s instances.
    #[serde(default)]
    pub preferred_display_base: PreferredDisplayBase,
}

impl FieldType for IntegerFieldType {
    fn size(&self) -> usize {
        self.size
    }

    fn alignment(&self) -> usize {
        self.alignment
    }

    fn preferred_display_base(&self) -> Option<PreferredDisplayBase> {
        Some(self.preferred_display_base)
    }
}

/// Integer field type objects are the types of integer data fields, found in data streams.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[serde(tag = "class", rename = "unsigned-integer")]
pub struct UnsignedIntegerFieldType {
    #[serde(flatten)]
    pub field_type: IntegerFieldType,
}

/// Integer field type objects are the types of integer data fields, found in data streams.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[serde(tag = "class", rename = "signed-integer")]
pub struct SignedIntegerFieldType {
    #[serde(flatten)]
    pub field_type: IntegerFieldType,
}

/// A real field type object is the type of floating point number data fields, found in data streams.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RealFieldType {
    /// Size of this field type’s instances (bits).
    pub size: usize,
    /// Alignment of the first bit of this field type’s instances within a CTF packet (bits).
    #[serde(default = "default_alignment_bits")]
    pub alignment: usize,
}

impl FieldType for RealFieldType {
    fn size(&self) -> usize {
        self.size
    }

    fn alignment(&self) -> usize {
        self.alignment
    }

    fn preferred_display_base(&self) -> Option<PreferredDisplayBase> {
        None
    }
}

/// Mapping sequence type of enumeration field types.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[serde(untagged)]
pub enum EnumerationFieldTypeMappingSequence {
    InclusiveRange(i64, i64),
    Value(i64),
}

impl EnumerationFieldTypeMappingSequence {
    /// Returns true if the mapping sequence element contains the value
    pub fn contains(&self, value: i64) -> bool {
        match self {
            Self::InclusiveRange(min, max) => (value >= *min) && (value <= *max),
            Self::Value(v) => *v == value,
        }
    }
}

/// Enumeration field type objects are the types of enumeration data fields, found in data streams.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct EnumerationFieldType {
    /// Size of this field type’s instances (bits).
    pub size: usize,
    /// Alignment of the first bit of this field type’s instances within a CTF packet (bits).
    #[serde(default = "default_alignment_bits")]
    pub alignment: usize,
    /// The preferred base (radix) to use when displaying this field type’s instances.
    #[serde(default)]
    pub preferred_display_base: PreferredDisplayBase,
    /// Mappings of this enumeration field type.
    pub mappings: BTreeMap<String, Vec<EnumerationFieldTypeMappingSequence>>,
}

impl FieldType for EnumerationFieldType {
    fn size(&self) -> usize {
        self.size
    }

    fn alignment(&self) -> usize {
        self.alignment
    }

    fn preferred_display_base(&self) -> Option<PreferredDisplayBase> {
        Some(self.preferred_display_base)
    }
}

/// Primitive field types supported by [`StaticArrayFieldType`] and [`DynamicArrayFieldType`].
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[serde(tag = "class")]
pub enum PrimitiveFieldType {
    UnsignedInteger(IntegerFieldType),
    SignedInteger(IntegerFieldType),
    String,
    Real(RealFieldType),
    UnsignedEnumeration(EnumerationFieldType),
    SignedEnumeration(EnumerationFieldType),
}

impl FieldType for PrimitiveFieldType {
    fn size(&self) -> usize {
        match self {
            Self::UnsignedInteger(t) | Self::SignedInteger(t) => t.size,
            Self::UnsignedEnumeration(t) | Self::SignedEnumeration(t) => t.size,
            Self::Real(t) => t.size,
            Self::String => 8,
        }
    }

    fn alignment(&self) -> usize {
        match self {
            Self::UnsignedInteger(t) | Self::SignedInteger(t) => t.alignment,
            Self::UnsignedEnumeration(t) | Self::SignedEnumeration(t) => t.alignment,
            Self::Real(t) => t.alignment,
            Self::String => 8,
        }
    }

    fn preferred_display_base(&self) -> Option<PreferredDisplayBase> {
        Some(match self {
            Self::UnsignedInteger(t) | Self::SignedInteger(t) => t.preferred_display_base,
            Self::UnsignedEnumeration(t) | Self::SignedEnumeration(t) => t.preferred_display_base,
            Self::String | Self::Real(_) => return None,
        })
    }
}

/// A static array field type object is the type of static array data fields, found in data streams.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct StaticArrayFieldType {
    /// Number of elements in this field type’s instances.
    pub length: usize,
    /// Type of each element (data fields) in this field type’s instances.
    pub element_field_type: PrimitiveFieldType,
}

impl FieldType for StaticArrayFieldType {
    fn size(&self) -> usize {
        self.element_field_type.size()
    }

    fn alignment(&self) -> usize {
        self.element_field_type.alignment()
    }

    fn preferred_display_base(&self) -> Option<PreferredDisplayBase> {
        self.element_field_type.preferred_display_base()
    }
}

/// A dynamic array field type object is the type of dynamic (variable-length) array data fields, found in data streams.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DynamicArrayFieldType {
    /// Type of each element (data fields) in this field type’s instances.
    pub element_field_type: PrimitiveFieldType,
}

impl FieldType for DynamicArrayFieldType {
    fn size(&self) -> usize {
        self.element_field_type.size()
    }

    fn alignment(&self) -> usize {
        self.element_field_type.alignment()
    }

    fn preferred_display_base(&self) -> Option<PreferredDisplayBase> {
        self.element_field_type.preferred_display_base()
    }
}

/// Field types supported by [`StructureFieldTypeMember`]
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[serde(tag = "class")]
pub enum StructureMemberFieldType {
    UnsignedInteger(IntegerFieldType),
    SignedInteger(IntegerFieldType),
    String,
    Real(RealFieldType),
    UnsignedEnumeration(EnumerationFieldType),
    SignedEnumeration(EnumerationFieldType),
    StaticArray(StaticArrayFieldType),
    DynamicArray(DynamicArrayFieldType),
}

impl FieldType for StructureMemberFieldType {
    fn size(&self) -> usize {
        match self {
            Self::UnsignedInteger(t) | Self::SignedInteger(t) => t.size,
            Self::UnsignedEnumeration(t) | Self::SignedEnumeration(t) => t.size,
            Self::Real(t) => t.size,
            Self::String => 8, // Min size bits
            Self::StaticArray(t) => t.size(),
            Self::DynamicArray(t) => t.size(),
        }
    }

    fn alignment(&self) -> usize {
        match self {
            Self::UnsignedInteger(t) | Self::SignedInteger(t) => t.alignment,
            Self::UnsignedEnumeration(t) | Self::SignedEnumeration(t) => t.alignment,
            Self::Real(t) => t.alignment,
            Self::String => 8,
            Self::StaticArray(t) => t.alignment(),
            Self::DynamicArray(t) => t.alignment(),
        }
    }

    fn preferred_display_base(&self) -> Option<PreferredDisplayBase> {
        Some(match self {
            Self::UnsignedInteger(t) | Self::SignedInteger(t) => t.preferred_display_base,
            Self::UnsignedEnumeration(t) | Self::SignedEnumeration(t) => t.preferred_display_base,
            Self::StaticArray(t) => return t.preferred_display_base(),
            Self::DynamicArray(t) => return t.preferred_display_base(),
            Self::String | Self::Real(_) => return None,
        })
    }
}

/// A member within a structure field type object.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct StructureFieldTypeMember {
    /// Member’s field type.
    pub field_type: StructureMemberFieldType,
}

/// A structure field type object is the type of structure data fields, found in data streams.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[serde(tag = "class", rename = "structure")]
pub struct StructureFieldType {
    /// Minimum alignment of the first bit of this field type’s instances within a CTF packet (bits).
    #[serde(default = "default_struct_min_alignment")]
    pub minimum_alignment: usize,
    /// Members of this structure field type.
    pub members: Vec<BTreeMap<String, StructureFieldTypeMember>>,
}

impl StructureFieldType {
    /// Return the largest alignment of the event payload members (bits)
    pub(crate) fn alignment(&self) -> usize {
        self.members
            .iter()
            .flat_map(|m| m.values())
            .map(|ftm| ftm.field_type.alignment())
            .max()
            .unwrap_or_else(default_alignment_bits)
    }
}

/// Field type for `$features` fields that can either be set to `false` or
/// an [`UnsignedIntegerFieldType`]
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[serde(untagged)]
pub enum FeaturesUnsignedIntegerFieldType {
    #[serde(deserialize_with = "de_false")]
    False(bool),
    UnsignedInteger(UnsignedIntegerFieldType),
}

impl FeaturesUnsignedIntegerFieldType {
    /// Return the alignment of the field type (bits)
    pub(crate) fn alignment(&self) -> usize {
        match self {
            Self::False(_) => 0,
            Self::UnsignedInteger(ft) => ft.field_type.alignment,
        }
    }

    pub(crate) fn as_ft(&self) -> Option<&UnsignedIntegerFieldType> {
        match self {
            FeaturesUnsignedIntegerFieldType::False(_) => None,
            FeaturesUnsignedIntegerFieldType::UnsignedInteger(ft) => Some(ft),
        }
    }
}

/// Offset information of a clock type’s instances.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClockTypeOffset {
    /// Offset in seconds.
    pub seconds: i64,
    /// Offset in cycles.
    pub cycles: u64,
}

/// A clock type object is the type of data stream clocks.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClockType {
    /// Frequency of instances (Hz).
    pub frequency: u64,
    /// Offset of instances.
    pub offset: Option<ClockTypeOffset>,
    /// True if the origin of instances is the Unix epoch.
    pub origin_is_unix_epoch: bool,
    /// Precision of instances (cycles).
    pub precision: u64,
    /// Clock type’s UUID.
    pub uuid: Option<Uuid>,
    /// Clock type’s description.
    pub description: Option<String>,
    /// Return C type of the clock source function for this clock type.
    #[serde(alias = "$c-type")]
    pub c_type: String,
}

/// An event record type object is the type of an event record.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct EventRecordType {
    /// Numeric log level of this event record type’s instances.
    pub log_level: Option<i32>,
    /// Specific context field type of this event record type.
    pub specific_context_field_type: Option<StructureFieldType>,
    /// Payload field type of this event record type.
    pub payload_field_type: Option<StructureFieldType>,
}

/// The packet features of a data stream type object.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DataStreamTypePacketFeatures {
    /// Type of packet context’s total size field.
    pub total_size_field_type: UnsignedIntegerFieldType,
    /// Type of packet context’s content size field.
    pub content_size_field_type: UnsignedIntegerFieldType,
    /// Type of packet context’s beginning timestamp field.
    pub beginning_timestamp_field_type: FeaturesUnsignedIntegerFieldType,
    /// Type of packet context’s end timestamp field.
    pub end_timestamp_field_type: FeaturesUnsignedIntegerFieldType,
    /// Type of packet context’s discarded event record counter snapshot field.
    pub discarded_event_records_counter_snapshot_field_type: FeaturesUnsignedIntegerFieldType,
    /// Type of packet context’s sequence number field.
    pub sequence_number_field_type: FeaturesUnsignedIntegerFieldType,
}

impl DataStreamTypePacketFeatures {
    /// Return the largest alignment of the CTF packet context (bits)
    pub(crate) fn alignment(&self) -> usize {
        let aligns = [
            self.total_size_field_type.field_type.alignment,
            self.content_size_field_type.field_type.alignment,
            self.beginning_timestamp_field_type.alignment(),
            self.end_timestamp_field_type.alignment(),
            self.discarded_event_records_counter_snapshot_field_type
                .alignment(),
            self.sequence_number_field_type.alignment(),
        ];
        *aligns.iter().max().unwrap() // SAFETY: always non-empty
    }
}

/// The event records features of a data stream type object.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DataStreamTypeEventRecordFeatures {
    /// Type of event header’s event record type ID field.
    pub type_id_field_type: UnsignedIntegerFieldType,
    /// Type of event header’s timestamp field.
    pub timestamp_field_type: UnsignedIntegerFieldType,
}

impl DataStreamTypeEventRecordFeatures {
    /// Return the largest alignment of the CTF event header (bits)
    pub(crate) fn alignment(&self) -> usize {
        let aligns = [
            self.type_id_field_type.field_type.alignment,
            self.timestamp_field_type.field_type.alignment,
        ];
        *aligns.iter().max().unwrap() // SAFETY: always non-empty
    }
}

/// The features of a data stream type object.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DataStreamTypeFeatures {
    /// Features related to CTF packets.
    pub packet: DataStreamTypePacketFeatures,
    /// Features related to CTF event records.
    pub event_record: DataStreamTypeEventRecordFeatures,
}

/// Extra, user-defined members to be appended to a packet context structure field type.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PacketContextExtraMembers(pub Vec<BTreeMap<String, StructureFieldTypeMember>>);

impl PacketContextExtraMembers {
    /// Return the largest alignment of the event payload members (bits)
    pub(crate) fn alignment(&self) -> usize {
        self.0
            .iter()
            .flat_map(|m| m.values())
            .map(|ftm| ftm.field_type.alignment())
            .max()
            .unwrap_or_else(default_alignment_bits)
    }
}

/// A data stream type object is the type of a data stream.
/// A data stream type describes everything a CTF consumer needs to decode its instances (data streams).
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DataStreamType {
    /// If this property is true, then this data stream type is its trace type's default data stream type.
    #[serde(alias = "$is-default")]
    pub is_default: bool,
    /// Name of the clock type which describes the default clock of this data stream type’s instances.
    #[serde(alias = "$default-clock-type-name")]
    pub default_clock_type_name: Option<String>,
    /// Features of this data stream type’s instances.
    #[serde(alias = "$features")]
    pub features: DataStreamTypeFeatures,
    /// Extra, user-defined members to be appended to this data stream type’s packet context structure field type.
    #[serde(default)]
    pub packet_context_field_type_extra_members: PacketContextExtraMembers,
    /// Event record common context field type of this data stream type.
    pub event_record_common_context_field_type: Option<StructureFieldType>,
    /// Event record types of this data stream type.
    pub event_record_types: BTreeMap<String, EventRecordType>,
}

/// The features of a trace type object.
/// As of barectf 3.1, each feature controls whether or not some information will
/// be part of the header of each CTF packet which the generated tracer produces.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TraceTypeFeatures {
    /// Type of packet header’s magic number field.
    pub magic_field_type: FeaturesUnsignedIntegerFieldType,
    /// Type of packet header’s trace type UUID field.
    pub uuid_field_type: bool,
    /// Type of packet header’s data stream type ID field.
    pub data_stream_type_id_field_type: UnsignedIntegerFieldType,
}

impl TraceTypeFeatures {
    /// Return the largest alignment of the CTF packet header (bits)
    pub(crate) fn alignment(&self) -> usize {
        let aligns = [
            self.magic_field_type.alignment(),
            // uuid is always byte-packed
            self.uuid_field_type
                .then(default_alignment_bits)
                .unwrap_or(0),
            self.data_stream_type_id_field_type.field_type.alignment,
        ];
        *aligns.iter().max().unwrap() // SAFETY: always non-empty
    }
}

/// A trace type object is the type of a trace object.
/// A trace type describes everything a CTF consumer needs to decode all the trace’s data streams.
/// A trace type object is only found as the type property of a trace object.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TraceType {
    /// Native byte order of the system which produces this trace type’s instance’s data streams.
    pub native_byte_order: NativeByteOrder,
    /// UUID of this trace type.
    pub uuid: Option<Uuid>,
    /// Features of this trace type’s instance (trace).
    #[serde(alias = "$features")]
    pub features: TraceTypeFeatures,
    /// Clock type store for this trace type.
    pub clock_types: BTreeMap<String, ClockType>,
    /// Data stream types of this trace type.
    pub data_stream_types: BTreeMap<String, DataStreamType>,
}

/// A trace object represents a CTF trace.
#[derive(Clone, Eq, PartialEq, PartialOrd, Hash, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Trace {
    /// This trace’s environment variables.
    pub environment: BTreeMap<String, Value>,
    /// Type of this trace (metadata part).
    #[serde(alias = "type")]
    pub typ: TraceType,
}

/// The code generation options of a configuration object.
#[derive(Clone, Eq, PartialEq, PartialOrd, Hash, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CodeGenerationOptions {
    /// Prefix of any C file which barectf generates.
    pub file_name: String,
    /// Prefix of any public C identifier which barectf generates.
    pub identifier: String,
}

impl Default for CodeGenerationOptions {
    fn default() -> Self {
        Self {
            file_name: "barectf".to_owned(),
            identifier: "barectf_".to_owned(),
        }
    }
}

/// The C header generation options of a configuration object.
#[derive(Clone, Eq, PartialEq, PartialOrd, Hash, Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct HeaderGenerationOptions {
    /// If this property is true, then barectf generates a public C
    /// preprocessor definition named `_BARECTF_IDENTIFIER_PREFIX`
    /// which is set to the configuration’s identifier prefix.
    pub identifier_prefix_definition: bool,
    /// If this property is true, then barectf generates a public C
    /// preprocessor definition named `_BARECTF_DEFAULT_DATA_STREAM_TYPE_NAME`
    /// which is set to the name of the trace type’s default data stream type.
    pub default_data_stream_type_name_definition: bool,
}

/// The options of a configuration object.
#[derive(Clone, Eq, PartialEq, PartialOrd, Hash, Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Options {
    /// Code generation options.
    pub code_generation: CodeGenerationOptions,
    /// C header generation options.
    pub header: HeaderGenerationOptions,
}

/// The barectf configuration object.
///
/// This can be constructed from the effective configuration yaml file.
/// See <https://barectf.org/docs/barectf/3.1/cli/usage.html#show-effective-configuration-command>
/// for more information on generating the configuration file.
#[derive(Clone, Eq, PartialEq, PartialOrd, Hash, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    /// Configuration options.
    #[serde(default)]
    pub options: Options,
    /// Configuration’s trace.
    pub trace: Trace,
}

pub(crate) trait FieldType {
    /// Return the size of this field type’s instances (bits).
    fn size(&self) -> usize;

    /// Return the alignment of the field type (bits)
    fn alignment(&self) -> usize;

    /// Return the preferred base (radix) to use when displaying this field type’s instances.
    fn preferred_display_base(&self) -> Option<PreferredDisplayBase>;
}

/// Alignment of the first bit of a field type’s instances within a CTF packet (bits).
/// NOTE: 8 if the size property is a multiple of 8, or 1 otherwise.
/// But we don't support bit-packed types, this is always 8
const fn default_alignment_bits() -> usize {
    8
}

/// Minimum alignment of the first bit of this field type’s instances within a CTF packet (bits).
const fn default_struct_min_alignment() -> usize {
    1
}

fn de_false<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    if bool::deserialize(deserializer)? {
        Err(serde::de::Error::invalid_value(
            serde::de::Unexpected::Bool(true),
            &"the `false` boolean",
        ))
    } else {
        Ok(false)
    }
}
