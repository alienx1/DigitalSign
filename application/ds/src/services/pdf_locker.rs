use crate::features::pdf_locker::LockPdfUseCase;
use application_core::{CoreError, PdfLocker};
use domain::{KeyPair, LockAlgorithm, LockedDocument, UnsignedDocument};
use std::sync::Arc;

pub struct LockPdfService {
    locker: Arc<dyn PdfLocker>,
}

impl LockPdfService {
    pub fn new(locker: Arc<dyn PdfLocker>) -> Self {
        Self { locker }
    }
}

impl LockPdfUseCase for LockPdfService {
    fn execute(
        &self,
        document: UnsignedDocument,
        openers: Vec<KeyPair>,
        algorithm: LockAlgorithm,
    ) -> Result<LockedDocument, CoreError> {
        self.locker.lock(&document, &openers, algorithm)
    }
}
