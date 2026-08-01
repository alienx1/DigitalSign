mod appearance;
mod cades;
mod image;
mod incremental;
mod pkcs12;

use application_core::{CoreError, PdfSigner};
use domain::{SignatureSpec, SignedDocument, UnsignedDocument};

/// PAdES signing (CMS via openssl + PDF incremental update via lopdf), one
/// signature per entry in `signatures` — each carries its own key and page
/// position, applied in the given (array) order: signature N's incremental
/// update builds on top of signature N-1's output.
pub struct LopdfPdfSigner;

impl PdfSigner for LopdfPdfSigner {
    fn sign(
        &self,
        document: &UnsignedDocument,
        signatures: &[SignatureSpec],
    ) -> Result<SignedDocument, CoreError> {
        let mut bytes = document.bytes.clone();
        for spec in signatures {
            bytes = incremental::sign_one(&bytes, spec)?;
        }
        Ok(SignedDocument { bytes })
    }
}
