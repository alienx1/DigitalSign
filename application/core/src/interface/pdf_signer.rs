use crate::CoreError;
use domain::{SignatureSpec, SignedDocument, UnsignedDocument};

/// Driven port: embeds one or more PAdES signatures — each with its own
/// signing key and page position — into a PDF via incremental update.
/// `lock_with_national_id`, if true, password-protects the document (using
/// the first signature's own national ID, read from its certificate) before
/// any signing happens.
pub trait PdfSigner: Send + Sync {
    fn sign(
        &self,
        document: &UnsignedDocument,
        signatures: &[SignatureSpec],
        lock_with_national_id: bool,
    ) -> Result<SignedDocument, CoreError>;
}
