use super::pdf_signer::{encryption, pkcs12};
use application_core::{CoreError, PdfLocker};
use domain::{KeyPair, LockAlgorithm, LockedDocument, UnsignedDocument};

/// PDF Standard Security Handler locking (ISO 32000-1 §7.6), reusing the
/// `encryption`/`pkcs12` helpers written for `LopdfPdfSigner` — the actual
/// cipher work is identical, only which password(s) get set differs.
pub struct LopdfPdfLocker;

impl LopdfPdfLocker {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LopdfPdfLocker {
    fn default() -> Self {
        Self::new()
    }
}

impl PdfLocker for LopdfPdfLocker {
    fn lock(
        &self,
        document: &UnsignedDocument,
        openers: &[KeyPair],
        algorithm: LockAlgorithm,
    ) -> Result<LockedDocument, CoreError> {
        if openers.is_empty() || openers.len() > 2 {
            return Err(CoreError::Signing(format!(
                "PDF Standard Security Handler supports exactly 1 or 2 opening passwords \
                 (user + owner) — got {} openers",
                openers.len()
            )));
        }

        let mut national_ids = Vec::with_capacity(openers.len());
        for (i, opener) in openers.iter().enumerate() {
            let (_, cert, _) = pkcs12::unpack(&opener.pkcs12_der, &opener.derived_key)?;
            let national_id = pkcs12::national_id(&cert).ok_or_else(|| {
                CoreError::Signing(format!(
                    "opener {i}'s certificate carries no national ID \
                     (subject.serialNumber = \"IDC-<13 digits>\", as /ds/keypair sets)"
                ))
            })?;
            national_ids.push(national_id);
        }

        let user_password = national_ids[0].clone();
        let owner_password = national_ids.get(1).cloned().unwrap_or_else(|| user_password.clone());

        let bytes = encryption::encrypt_with_passwords(
            &document.bytes,
            &user_password,
            &owner_password,
            algorithm,
        )?;

        Ok(LockedDocument {
            bytes,
            user_password,
            owner_password,
        })
    }
}
