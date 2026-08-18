use crate::CoreError;
use domain::{LockAlgorithm, SignatureSpec, SignedDocument, UnsignedDocument};

/// Driven port: embeds one or more PAdES signatures — each with its own
/// signing key and page position — into a PDF via incremental update.
/// `lock`, if given, password-protects the document (using the first
/// signature's own national ID, read from its certificate) with the chosen
/// algorithm before any signing happens.
pub trait PdfSigner: Send + Sync {
    fn sign(
        &self,
        document: &UnsignedDocument,
        signatures: &[SignatureSpec],
        lock: Option<LockAlgorithm>,
    ) -> Result<SignedDocument, CoreError>;
}
