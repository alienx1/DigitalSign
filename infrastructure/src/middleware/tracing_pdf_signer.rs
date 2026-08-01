use application_core::{CoreError, PdfSigner};
use domain::{SignatureSpec, SignedDocument, UnsignedDocument};

/// Wraps any `PdfSigner` with an audit-trail log — every signing operation
/// must be traceable.
pub struct TracingPdfSigner<S> {
    inner: S,
}

impl<S: PdfSigner> TracingPdfSigner<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S: PdfSigner> PdfSigner for TracingPdfSigner<S> {
    fn sign(
        &self,
        document: &UnsignedDocument,
        signatures: &[SignatureSpec],
    ) -> Result<SignedDocument, CoreError> {
        let pages: Vec<u32> = signatures.iter().map(|s| s.position.page).collect();
        tracing::info!(count = signatures.len(), ?pages, "signing pdf");
        let result = self.inner.sign(document, signatures);
        if let Err(e) = &result {
            tracing::error!(error = %e, "pdf signing failed");
        }
        result
    }
}
