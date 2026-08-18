// PDF "open password" protection, applied BEFORE any PAdES signing — order
// matters: PDF Standard Security Handler encryption changes the raw bytes of
// every string/stream in the file, so it must happen first and the
// signatures must be computed over the already-encrypted document, not the
// other way around (a document encrypted after signing would invalidate
// every existing signature's digest). See `PdfLocker`/`pdf_locker.rs` — this
// is now a standalone step (`POST /ds/lock`), run before `/ds/sign` rather
// than triggered by a flag on it.
//
// `user_password` and `owner_password` may differ (unlike this feature's
// first release, which set both to the same value) — the Standard Security
// Handler has exactly these two independent slots, so two different signers'
// national IDs can each open the file. Nothing in this service relies on the
// weaker, non-cryptographic PDF permission bits (`Permissions`) for actually
// restricting what a viewer can do.

use application_core::CoreError;
use domain::LockAlgorithm;
use lopdf::encryption::crypt_filters::{Aes128CryptFilter, CryptFilter};
use lopdf::encryption::{EncryptionState, EncryptionVersion, Permissions};
use lopdf::Document;
use std::collections::BTreeMap;
use std::sync::Arc;

fn err(msg: impl std::fmt::Display) -> CoreError {
    CoreError::Signing(msg.to_string())
}

const STANDARD_CRYPT_FILTER_NAME: &[u8] = b"StdCF";

/// Encrypts `bytes` (a plain, not-yet-signed PDF) with `user_password` and
/// `owner_password` using `algorithm`, returning the new, fully
/// self-contained encrypted PDF bytes. Every signature added afterward (see
/// `incremental.rs`'s `password` parameter) must reopen this with EITHER
/// password — both derive the same underlying file encryption key, so which
/// one a caller has on hand doesn't matter — so newly-appended objects get
/// encrypted the same way. `lopdf` recovers which cipher was used from the
/// `/Encrypt` dictionary itself, so the algorithm doesn't need to be
/// threaded through separately.
pub fn encrypt_with_passwords(
    bytes: &[u8],
    user_password: &str,
    owner_password: &str,
    algorithm: LockAlgorithm,
) -> Result<Vec<u8>, CoreError> {
    let mut doc = Document::load_mem(bytes).map_err(|e| err(format!("invalid PDF: {e}")))?;

    let state: EncryptionState = match algorithm {
        LockAlgorithm::Rc4_128 => EncryptionVersion::V2 {
            document: &doc,
            owner_password,
            user_password,
            key_length: 128,
            permissions: Permissions::all(),
        }
        .try_into()
        .map_err(|e| err(format!("failed to build PDF encryption state: {e}")))?,
        LockAlgorithm::Aes128 => {
            let crypt_filter: Arc<dyn CryptFilter> = Arc::new(Aes128CryptFilter);
            EncryptionVersion::V4 {
                document: &doc,
                encrypt_metadata: true,
                crypt_filters: BTreeMap::from([(STANDARD_CRYPT_FILTER_NAME.to_vec(), crypt_filter)]),
                stream_filter: STANDARD_CRYPT_FILTER_NAME.to_vec(),
                string_filter: STANDARD_CRYPT_FILTER_NAME.to_vec(),
                owner_password,
                user_password,
                permissions: Permissions::all(),
            }
            .try_into()
            .map_err(|e| err(format!("failed to build PDF encryption state: {e}")))?
        }
        // Deliberately rejected, not implemented: verified (independently,
        // via a from-scratch Python AES-256-CBC decrypt against the derived
        // file encryption key — not just re-using lopdf's own code) that the
        // *cryptography* lopdf 0.44.0 (the latest available) produces here
        // is byte-correct — the exact same key correctly decrypts both
        // strings and streams by hand. Yet real-world viewers (confirmed
        // with Poppler's pdfinfo/pdftotext, which back many PDF readers)
        // reliably fail to read the resulting file, silently producing
        // garbage content instead of an error. This points to a structural
        // /Encrypt-dictionary-level incompatibility in lopdf's V5/R6 writer
        // that's beyond what's safe to patch around here — shipping it would
        // mean handing callers PDFs that are cryptographically fine but
        // practically unopenable. Revisit once lopdf publishes a fix.
        LockAlgorithm::Aes256 => {
            return Err(err(
                "AES-256 is not currently offered: verified (via an independent decrypt) that \
                 the underlying lopdf 0.44.0 crate produces cryptographically correct but \
                 real-world-unreadable output for this cipher (confirmed against Poppler's \
                 pdfinfo/pdftotext) — use aes128 or rc4128 instead",
            ));
        }
    };

    doc.encrypt(&state)
        .map_err(|e| err(format!("failed to encrypt PDF: {e}")))?;

    let mut encrypted = Vec::new();
    doc.save_to(&mut encrypted)
        .map_err(|e| err(format!("failed to save encrypted PDF: {e}")))?;
    Ok(encrypted)
}
