use crate::CoreError;
use domain::{SignatureSpec, SignedDocument, UnsignedDocument};

/// Driven port: embeds one or more PAdES signatures — each with its own
/// signing key and page position — into a PDF via incremental update.
pub trait PdfSigner: Send + Sync {
    fn sign(
        &self,
        document: &UnsignedDocument,
        signatures: &[SignatureSpec],
    ) -> Result<SignedDocument, CoreError>;
}
