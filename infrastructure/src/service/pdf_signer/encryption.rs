// PDF "open password" protection, applied BEFORE any PAdES signing — order
// matters: PDF Standard Security Handler encryption changes the raw bytes of
// every string/stream in the file, so it must happen first and the
// signatures must be computed over the already-encrypted document, not the
// other way around (a document encrypted after signing would invalidate
// every existing signature's digest).
//
// The owner and user password are set to the same value (matching this
// service's Java predecessor's pattern of locking a signed PDF with the
// signer's birthdate) — both open the file for viewing here, since nothing
// in this service relies on the weaker, non-cryptographic PDF permission
// bits (`Permissions`) for actually restricting what a viewer can do.

use application_core::CoreError;
use lopdf::encryption::{EncryptionState, EncryptionVersion, Permissions};
use lopdf::Document;

fn err(msg: impl std::fmt::Display) -> CoreError {
    CoreError::Signing(msg.to_string())
}

/// Encrypts `bytes` (a plain, not-yet-signed PDF) with `password`, returning
/// the new, fully self-contained encrypted PDF bytes. Every signature added
/// afterward (see `incremental.rs`'s `password` parameter) must reopen this
/// with the same password so newly-appended objects get encrypted the same
/// way.
pub fn encrypt_with_password(bytes: &[u8], password: &str) -> Result<Vec<u8>, CoreError> {
    let mut doc = Document::load_mem(bytes).map_err(|e| err(format!("invalid PDF: {e}")))?;

    let state: EncryptionState = EncryptionVersion::V2 {
        document: &doc,
        owner_password: password,
        user_password: password,
        key_length: 128,
        permissions: Permissions::all(),
    }
    .try_into()
    .map_err(|e| err(format!("failed to build PDF encryption state: {e}")))?;

    doc.encrypt(&state)
        .map_err(|e| err(format!("failed to encrypt PDF: {e}")))?;

    let mut encrypted = Vec::new();
    doc.save_to(&mut encrypted)
        .map_err(|e| err(format!("failed to save encrypted PDF: {e}")))?;
    Ok(encrypted)
}
