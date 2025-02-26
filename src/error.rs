use crate::{
    parser::types::FieldUnsupportedError,
    types::{EventId, StreamId},
};
use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Attempted to parse an invalid float size ({0})")]
    InvalidFloatSize(usize),

    #[error("Unsupported field type '{0}' (size {1}, alignment {2})")]
    UnsupportedFieldType(String, usize, usize),

    #[error("Unsupported alignment '{0}'")]
    UnsupportedAlignment(String),

    #[error("Encountered a CTF stream ID ({0}) that's not defined in the schema")]
    UndefinedStreamId(StreamId),

    #[error("Encountered a CTF event ID ({0}) that's not defined in the schema")]
    UndefinedEventId(EventId),

    #[error(
        "Encountered and IO error while reading the input stream ({})",
        .0.kind()
    )]
    Io(#[from] io::Error),
}

impl Error {
    pub(crate) fn unsupported_ft<S: AsRef<str>>(f: S, ft: FieldUnsupportedError) -> Self {
        Error::UnsupportedFieldType(f.as_ref().to_owned(), ft.0, ft.1)
    }

    pub(crate) fn unsupported_alignment<S: AsRef<str>>(f: S) -> Self {
        Error::UnsupportedAlignment(f.as_ref().to_owned())
    }
}
