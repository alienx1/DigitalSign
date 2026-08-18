use crate::CoreError;
use domain::{SignatureSpec, SignedDocument, UnsignedDocument};

/// Driven port: embeds one or more PAdES signatures — each with its own
/// signing key and page position — into a PDF via incremental update.
/// `document_password`, if given, is the password already protecting
/// `document` (see `PdfLocker` — a document is locked BEFORE it's signed,
/// never after, since encryption changes the very bytes a signature
/// digests), needed here only so this call's own newly-appended objects
/// get encrypted the same way as the rest of the file.
pub trait PdfSigner: Send + Sync {
    fn sign(
        &self,
        document: &UnsignedDocument,
        signatures: &[SignatureSpec],
        document_password: Option<&str>,
    ) -> Result<SignedDocument, CoreError>;
}
