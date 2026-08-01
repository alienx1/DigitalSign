use thiserror::Error;

#[derive(Debug, Error)]
pub enum DomainError {
    #[error("invalid signature position: {0}")]
    InvalidPosition(String),
}
