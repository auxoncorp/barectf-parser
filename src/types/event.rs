use crate::types::{EventId, FieldValue, LogLevel, Timestamp};
use internment::Intern;
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Event {
    pub id: EventId,
    pub name: Intern<String>,
    pub timestamp: Timestamp,
    pub log_level: Option<LogLevel>,
    pub common_context: Vec<(Intern<String>, FieldValue)>,
    pub specific_context: Vec<(Intern<String>, FieldValue)>,
    pub payload: Vec<(Intern<String>, FieldValue)>,
}
