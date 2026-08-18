mod appearance;
mod cades;
pub(crate) mod encryption;
mod image;
mod incremental;
pub(crate) mod pkcs12;
mod tsa;

pub use tsa::TsaConfig;

use application_core::{CoreError, PdfSigner};
use domain::{SignatureSpec, SignedDocument, UnsignedDocument};
use incremental::DocMdpPermission;

/// PAdES signing (CMS via openssl + PDF incremental update via lopdf), one
/// signature per entry in `signatures` — each carries its own key and page
/// position, applied in the given (array) order: signature N's incremental
/// update builds on top of signature N-1's output. The first signature also
/// certifies the document (DocMDP): if it's the only one, no further changes
/// are permitted afterward; if more follow in this same request, it permits
/// exactly that (form fill-in + additional signatures), nothing else.
///
/// `tsa`, if given, is used to RFC-3161-timestamp every signature (PAdES-B-T)
/// — a TSA that's down or errors fails the whole request rather than
/// silently falling back to an untimestamped (PAdES-B-B) signature: this is
/// only ever configured because the caller wants B-T, so a caller relying on
/// it should find out immediately if that guarantee couldn't be met, not
/// discover a quietly-downgraded signature later.
pub struct LopdfPdfSigner {
    tsa: Option<TsaConfig>,
}

impl LopdfPdfSigner {
    pub fn new(tsa: Option<TsaConfig>) -> Self {
        Self { tsa }
    }
}

impl PdfSigner for LopdfPdfSigner {
    fn sign(
        &self,
        document: &UnsignedDocument,
        signatures: &[SignatureSpec],
        document_password: Option<&str>,
    ) -> Result<SignedDocument, CoreError> {
        let mut bytes = document.bytes.clone();
        for (i, spec) in signatures.iter().enumerate() {
            let docmdp = (i == 0).then(|| {
                if signatures.len() == 1 {
                    DocMdpPermission::NoChanges
                } else {
                    DocMdpPermission::FormFillingAndSigning
                }
            });
            bytes = incremental::sign_one(&bytes, spec, docmdp, self.tsa.as_ref(), document_password)?;
        }
        Ok(SignedDocument { bytes })
    }
}
