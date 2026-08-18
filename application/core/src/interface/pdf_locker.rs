use crate::CoreError;
use domain::{KeyPair, LockAlgorithm, LockedDocument, UnsignedDocument};

/// Driven port: password-protects a PDF (ISO 32000-1 §7.6 Standard Security
/// Handler) using national IDs read out of up to two signers' own
/// certificates as the opening password(s) — not accepted as separate
/// fields, so a caller can't lock a document with an identity that isn't
/// actually vouching for it.
///
/// The Standard Security Handler has exactly two independent password
/// slots (owner + user), never more, regardless of cipher — so `openers`
/// must have 1 or 2 entries: the first becomes the user password, a second
/// (if given) becomes the owner password; with only one, it's used for
/// both slots. More than two openers is a request error, not something
/// this can approximate — there is no third slot to add.
pub trait PdfLocker: Send + Sync {
    fn lock(
        &self,
        document: &UnsignedDocument,
        openers: &[KeyPair],
        algorithm: LockAlgorithm,
    ) -> Result<LockedDocument, CoreError>;
}
