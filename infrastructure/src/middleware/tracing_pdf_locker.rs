use application_core::{CoreError, PdfLocker};
use domain::{KeyPair, LockAlgorithm, LockedDocument, UnsignedDocument};

/// Wraps any `PdfLocker` with an audit-trail log — every locking operation
/// must be traceable. Logs only the opener count and cipher, never the
/// resulting passwords (they're national IDs — PII).
pub struct TracingPdfLocker<L> {
    inner: L,
}

impl<L: PdfLocker> TracingPdfLocker<L> {
    pub fn new(inner: L) -> Self {
        Self { inner }
    }
}

impl<L: PdfLocker> PdfLocker for TracingPdfLocker<L> {
    fn lock(
        &self,
        document: &UnsignedDocument,
        openers: &[KeyPair],
        algorithm: LockAlgorithm,
    ) -> Result<LockedDocument, CoreError> {
        tracing::info!(openers = openers.len(), ?algorithm, "locking pdf");
        let result = self.inner.lock(document, openers, algorithm);
        if let Err(e) = &result {
            tracing::error!(error = %e, "pdf locking failed");
        }
        result
    }
}
