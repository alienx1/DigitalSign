pub mod commands;

pub use commands::{
    pdf_locker_command, LockAlgorithmDto, LockOpenerDto, LockPdfError, LockPdfRequestModel,
    LockPdfResult,
};

use application_core::CoreError;
use domain::{KeyPair, LockAlgorithm, LockedDocument, UnsignedDocument};

/// The "lock pdf" use case, called by handler/ds.
pub trait LockPdfUseCase: Send + Sync {
    fn execute(
        &self,
        document: UnsignedDocument,
        openers: Vec<KeyPair>,
        algorithm: LockAlgorithm,
    ) -> Result<LockedDocument, CoreError>;
}
