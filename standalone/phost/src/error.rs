use std::{error, fmt};

#[derive(Debug)]
pub enum Error {
    BlockHashNotFound,
    BlockNotFound,
    EventNotFound,
    NoSetIdAtBlock,
    SearchSetIdChangeInEmptyRange,
    FailedToDecode,
    FailedToCallRegisterWorker,
    FailedToCallResetWorker,
    ComputeWorkerNotEnabled,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BlockHashNotFound => write!(f, "block hash not found"),
            Error::BlockNotFound => write!(f, "block not found"),
            Error::EventNotFound => write!(f, "event not found"),
            Error::NoSetIdAtBlock => write!(f, "SetId not found at block"),
            Error::SearchSetIdChangeInEmptyRange => write!(f, "list of known blocks is empty"),
            Error::FailedToDecode => write!(f, "failed to decode"),
            Error::FailedToCallRegisterWorker => write!(f, "failed to call register_worker"),
            Error::FailedToCallResetWorker => write!(f, "failed to call reset_worker"),
            Error::ComputeWorkerNotEnabled => write!(f, "compute worker not enabled"),
        }
    }
}

impl error::Error for Error {}
