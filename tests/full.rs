use barectf_parser::*;
use internment::Intern;
use pretty_assertions::assert_eq;
use test_log::test;
use tokio_stream::StreamExt;
use tokio_util::codec::FramedRead;
use uuid::Uuid;

const CFG: &str = "test_resources/fixtures/full/effective_config.yaml";
const STREAM: &str = "test_resources/fixtures/full/trace/stream";

fn config() -> Config {
    let cfg_str = std::fs::read_to_string(CFG).unwrap();
    serde_yaml::from_str(&cfg_str).unwrap()
}

#[test]
fn full_trace_sync() {
    let cfg = config();
    let parser = Parser::new(&cfg).unwrap();
    let mut stream = std::fs::File::open(STREAM).unwrap();

    let pkt0 = parser.parse(&mut stream).unwrap();
    let pkt1 = parser.parse(&mut stream).unwrap();
    let next = parser.parse(&mut stream);
    assert!(next.is_err()); // EOF

    check_packet_header(&pkt0.header);
    check_packet_context(&pkt0.context, 1928, 0, 5, 0);
    check_event_0(pkt0.events.first());
    check_event_1(pkt0.events.get(1));
    check_event_2(pkt0.events.get(2));
    check_event_3(pkt0.events.get(3));
    check_event_4(pkt0.events.get(4));
    assert!(pkt0.events.get(5).is_none());

    check_packet_header(&pkt1.header);
    check_packet_context(&pkt1.context, 672, 5, 5, 1);
    check_event_5(pkt1.events.first());
    assert!(pkt1.events.get(1).is_none());
}

#[test(tokio::test)]
async fn full_trace_async() {
    let cfg = config();
    let parser = Parser::new(&cfg).unwrap();
    let stream = tokio::fs::File::open(STREAM).await.unwrap();
    let decoder = parser.into_packet_decoder();
    let mut reader = FramedRead::new(stream, decoder);

    let pkt0 = reader.next().await.unwrap().unwrap();
    let pkt1 = reader.next().await.unwrap().unwrap();
    let next = reader.next().await;
    assert!(next.is_none());

    check_packet_header(&pkt0.header);
    check_packet_context(&pkt0.context, 1928, 0, 5, 0);
    check_event_0(pkt0.events.first());
    check_event_1(pkt0.events.get(1));
    check_event_2(pkt0.events.get(2));
    check_event_3(pkt0.events.get(3));
    check_event_4(pkt0.events.get(4));
    assert!(pkt0.events.get(5).is_none());

    check_packet_header(&pkt1.header);
    check_packet_context(&pkt1.context, 672, 5, 5, 1);
    check_event_5(pkt1.events.first());
    assert!(pkt1.events.get(1).is_none());
}

fn check_packet_header(h: &PacketHeader) {
    let uuid = Uuid::parse_str("79e49040-21b5-42d4-a83b-646f78666b62").unwrap();
    assert_eq!(
        h,
        &PacketHeader {
            magic_number: PacketHeader::MAGIC.into(),
            trace_uuid: uuid.into(),
            stream_id: 0,
            stream_name: Intern::new("default".to_owned()),
            clock_name: Intern::new("default".to_owned()).into(),
            clock_type: Intern::new(ClockType {
                frequency: 1000000000,
                offset: None,
                origin_is_unix_epoch: false,
                precision: 1,
                uuid: Some(Uuid::parse_str("9168b5fb-9d29-4fa5-810f-714601309ffd").unwrap()),
                description: Some("timer clock".to_lowercase()),
                c_type: "uint64_t".to_owned(),
            })
            .into(),
        }
    );
}

fn check_packet_context(
    c: &PacketContext,
    size_bits: usize,
    beg_ts: Timestamp,
    end_ts: Timestamp,
    sn: SequenceNumber,
) {
    assert_eq!(
        c,
        &PacketContext {
            packet_size_bits: 2048,
            content_size_bits: size_bits,
            beginning_timestamp: beg_ts.into(),
            end_timestamp: end_ts.into(),
            events_discarded: 0.into(),
            sequence_number: sn.into(),
            extra_members: vec![(
                Intern::new("pc".to_owned()),
                PrimitiveFieldValue::from(22_u32).into()
            )],
        }
    );
}

fn check_event_0(e: Option<&Event>) {
    assert_eq!(
        e,
        Some(&Event {
            id: 4,
            name: Intern::new("init".to_owned()),
            timestamp: 0,
            log_level: None,
            common_context: vec![(
                Intern::new("ercc".to_owned()),
                PrimitiveFieldValue::from(98_u32).into()
            )],
            specific_context: vec![(
                Intern::new("cpu_id".to_owned()),
                PrimitiveFieldValue::from(1_i32).into()
            )],
            payload: vec![(
                Intern::new("version".to_owned()),
                PrimitiveFieldValue::from("1.0.0").into()
            )],
        })
    );
}

fn check_event_1(e: Option<&Event>) {
    assert_eq!(
        e,
        Some(&Event {
            id: 3,
            name: Intern::new("foobar".to_owned()),
            timestamp: 1,
            log_level: LogLevel::Critical.into(),
            common_context: vec![(
                Intern::new("ercc".to_owned()),
                PrimitiveFieldValue::from(97_u32).into()
            )],
            specific_context: vec![],
            payload: vec![
                (
                    Intern::new("val".to_owned()),
                    PrimitiveFieldValue::from(3_u32).into()
                ),
                (
                    Intern::new("val2".to_owned()),
                    PrimitiveFieldValue::from(21_u32).into()
                ),
            ],
        })
    );
}

fn check_event_2(e: Option<&Event>) {
    assert_eq!(
        e,
        Some(&Event {
            id: 2,
            name: Intern::new("floats".to_owned()),
            timestamp: 2,
            log_level: LogLevel::Warning.into(),
            common_context: vec![(
                Intern::new("ercc".to_owned()),
                PrimitiveFieldValue::from(96_u32).into()
            )],
            specific_context: vec![],
            payload: vec![
                (
                    Intern::new("f32".to_owned()),
                    PrimitiveFieldValue::from(1.1_f32).into()
                ),
                (
                    Intern::new("f64".to_owned()),
                    PrimitiveFieldValue::from(2.2_f64).into()
                ),
            ],
        })
    );
}

fn check_event_3(e: Option<&Event>) {
    assert_eq!(
        e,
        Some(&Event {
            id: 1,
            name: Intern::new("enums".to_owned()),
            timestamp: 3,
            log_level: None,
            common_context: vec![(
                Intern::new("ercc".to_owned()),
                PrimitiveFieldValue::from(95_u32).into()
            )],
            specific_context: vec![],
            payload: vec![
                (
                    Intern::new("foo".to_owned()),
                    PrimitiveFieldValue::Enumeration(
                        0,
                        PreferredDisplayBase::Decimal,
                        Intern::new("A".to_owned()).into()
                    )
                    .into()
                ),
                (
                    Intern::new("bar".to_owned()),
                    PrimitiveFieldValue::Enumeration(
                        -1,
                        PreferredDisplayBase::Decimal,
                        Intern::new("C".to_owned()).into()
                    )
                    .into()
                ),
                (
                    Intern::new("biz".to_owned()),
                    PrimitiveFieldValue::Enumeration(
                        19,
                        PreferredDisplayBase::Decimal,
                        Intern::new("RUNNING".to_owned()).into()
                    )
                    .into()
                ),
                (
                    Intern::new("baz".to_owned()),
                    PrimitiveFieldValue::Enumeration(
                        200,
                        PreferredDisplayBase::Hexadecimal,
                        Intern::new("on/off".to_owned()).into()
                    )
                    .into()
                ),
            ],
        })
    );
}

fn check_event_4(e: Option<&Event>) {
    assert_eq!(
        e,
        Some(&Event {
            id: 0,
            name: Intern::new("arrays".to_owned()),
            timestamp: 4,
            log_level: None,
            common_context: vec![(
                Intern::new("ercc".to_owned()),
                PrimitiveFieldValue::from(94_u32).into()
            )],
            specific_context: vec![],
            payload: vec![
                (
                    Intern::new("foo".to_owned()),
                    vec![
                        PrimitiveFieldValue::from(1_u32),
                        PrimitiveFieldValue::from(2_u32),
                        PrimitiveFieldValue::from(3_u32),
                        PrimitiveFieldValue::from(4_u32),
                    ]
                    .into()
                ),
                (
                    Intern::new("bar".to_owned()),
                    vec![
                        PrimitiveFieldValue::from("b0"),
                        PrimitiveFieldValue::from("b1"),
                        PrimitiveFieldValue::from("b2"),
                    ]
                    .into()
                ),
            ],
        })
    );
}

fn check_event_5(e: Option<&Event>) {
    assert_eq!(
        e,
        Some(&Event {
            id: 5,
            name: Intern::new("shutdown".to_owned()),
            timestamp: 5,
            log_level: None,
            common_context: vec![(
                Intern::new("ercc".to_owned()),
                PrimitiveFieldValue::from(93_u32).into()
            )],
            specific_context: vec![],
            payload: vec![],
        })
    );
}
