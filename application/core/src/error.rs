use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("key generation failed: {0}")]
    KeyGeneration(String),
    #[error("signing failed: {0}")]
    Signing(String),
}
