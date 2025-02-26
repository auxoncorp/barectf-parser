use barectf_parser::*;
use internment::Intern;
use pretty_assertions::assert_eq;
use test_log::test;
use tokio_stream::StreamExt;
use tokio_util::codec::FramedRead;

const CFG: &str = "test_resources/fixtures/simple/effective_config.yaml";
const STREAM: &str = "test_resources/fixtures/simple/trace/stream";

fn config() -> Config {
    let cfg_str = std::fs::read_to_string(CFG).unwrap();
    serde_yaml::from_str(&cfg_str).unwrap()
}

#[test]
fn simple_trace_sync() {
    let cfg = config();
    let parser = Parser::new(&cfg).unwrap();
    let mut stream = std::fs::File::open(STREAM).unwrap();

    let pkt = parser.parse(&mut stream).unwrap();
    let next = parser.parse(&mut stream);
    assert!(next.is_err()); // EOF

    check_simple_packet(pkt);
}

#[test(tokio::test)]
async fn simple_trace_async() {
    let cfg = config();
    let parser = Parser::new(&cfg).unwrap();
    let stream = tokio::fs::File::open(STREAM).await.unwrap();
    let decoder = parser.into_packet_decoder();
    let mut reader = FramedRead::new(stream, decoder);

    let pkt = reader.next().await.unwrap().unwrap();
    let next = reader.next().await;
    assert!(next.is_none());

    check_simple_packet(pkt);
}

fn check_simple_packet(pkt: Packet) {
    assert_eq!(
        pkt.header,
        PacketHeader {
            magic_number: None,
            trace_uuid: None,
            stream_id: 0,
            stream_name: Intern::new("stream_a".to_owned()),
            clock_name: Intern::new("timer".to_owned()).into(),
        }
    );
    assert_eq!(
        pkt.context,
        PacketContext {
            packet_size_bits: 4096,
            content_size_bits: 320,
            beginning_timestamp: None,
            end_timestamp: None,
            events_discarded: None,
            sequence_number: None,
            extra_members: vec![],
        }
    );
    assert_eq!(
        pkt.events.first(),
        Some(&Event {
            id: 0,
            name: Intern::new("init".to_owned()),
            timestamp: 0,
            log_level: None,
            common_context: vec![],
            specific_context: vec![],
            payload: vec![],
        })
    );
    assert_eq!(
        pkt.events.get(1),
        Some(&Event {
            id: 1,
            name: Intern::new("shutdown".to_owned()),
            timestamp: 1,
            log_level: None,
            common_context: vec![],
            specific_context: vec![],
            payload: vec![],
        })
    );
}
