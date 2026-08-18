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
use domain::LockAlgorithm;
use lopdf::encryption::crypt_filters::{Aes128CryptFilter, Aes256CryptFilter, CryptFilter};
use lopdf::encryption::{EncryptionState, EncryptionVersion, Permissions};
use lopdf::Document;
use std::collections::BTreeMap;
use std::sync::Arc;

fn err(msg: impl std::fmt::Display) -> CoreError {
    CoreError::Signing(msg.to_string())
}

const STANDARD_CRYPT_FILTER_NAME: &[u8] = b"StdCF";

/// Encrypts `bytes` (a plain, not-yet-signed PDF) with `password` using
/// `algorithm`, returning the new, fully self-contained encrypted PDF bytes.
/// Every signature added afterward (see `incremental.rs`'s `password`
/// parameter) must reopen this with the same password so newly-appended
/// objects get encrypted the same way — `lopdf` recovers which cipher was
/// used from the `/Encrypt` dictionary itself, so the algorithm doesn't need
/// to be threaded through separately.
pub fn encrypt_with_password(
    bytes: &[u8],
    password: &str,
    algorithm: LockAlgorithm,
) -> Result<Vec<u8>, CoreError> {
    let mut doc = Document::load_mem(bytes).map_err(|e| err(format!("invalid PDF: {e}")))?;

    let state: EncryptionState = match algorithm {
        LockAlgorithm::Rc4_128 => EncryptionVersion::V2 {
            document: &doc,
            owner_password: password,
            user_password: password,
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
                owner_password: password,
                user_password: password,
                permissions: Permissions::all(),
            }
            .try_into()
            .map_err(|e| err(format!("failed to build PDF encryption state: {e}")))?
        }
        LockAlgorithm::Aes256 => {
            let crypt_filter: Arc<dyn CryptFilter> = Arc::new(Aes256CryptFilter);
            let mut file_encryption_key = [0u8; 32];
            openssl::rand::rand_bytes(&mut file_encryption_key)
                .map_err(|e| err(format!("failed to generate AES-256 file key: {e}")))?;
            EncryptionVersion::V5 {
                encrypt_metadata: true,
                crypt_filters: BTreeMap::from([(STANDARD_CRYPT_FILTER_NAME.to_vec(), crypt_filter)]),
                file_encryption_key: &file_encryption_key,
                stream_filter: STANDARD_CRYPT_FILTER_NAME.to_vec(),
                string_filter: STANDARD_CRYPT_FILTER_NAME.to_vec(),
                owner_password: password,
                user_password: password,
                permissions: Permissions::all(),
            }
            .try_into()
            .map_err(|e| err(format!("failed to build PDF encryption state: {e}")))?
        }
    };

    doc.encrypt(&state)
        .map_err(|e| err(format!("failed to encrypt PDF: {e}")))?;

    let mut encrypted = Vec::new();
    doc.save_to(&mut encrypted)
        .map_err(|e| err(format!("failed to save encrypted PDF: {e}")))?;
    Ok(encrypted)
}
