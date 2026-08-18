mod appearance;
mod cades;
mod encryption;
mod image;
mod incremental;
mod pkcs12;
mod tsa;

pub use tsa::TsaConfig;

use application_core::{CoreError, PdfSigner};
use domain::{LockAlgorithm, SignatureSpec, SignedDocument, UnsignedDocument};
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
        lock: Option<LockAlgorithm>,
    ) -> Result<SignedDocument, CoreError> {
        let mut bytes = document.bytes.clone();

        // Encryption (the PDF "open password") must happen BEFORE any
        // signing — see `encryption.rs`'s module doc for why the order can't
        // be reversed. The password is the FIRST signature's own national
        // ID, read back out of its certificate (see `pkcs12::national_id`)
        // rather than accepted as a separate request field, so a caller
        // can't lock the document with an identity that isn't actually
        // vouching for it.
        let password = if let Some(algorithm) = lock {
            let first = signatures.first().ok_or_else(|| {
                CoreError::Signing("lock requires at least one signature".into())
            })?;
            let (_, cert, _) = pkcs12::unpack(&first.key.pkcs12_der, &first.key.derived_key)?;
            let national_id = pkcs12::national_id(&cert).ok_or_else(|| {
                CoreError::Signing(
                    "lock requires the first signature's certificate to carry \
                     a national ID (subject.serialNumber = \"IDC-<13 digits>\", as /ds/keypair sets)"
                        .into(),
                )
            })?;
            bytes = encryption::encrypt_with_password(&bytes, &national_id, algorithm)?;
            Some(national_id)
        } else {
            None
        };

        for (i, spec) in signatures.iter().enumerate() {
            let docmdp = (i == 0).then(|| {
                if signatures.len() == 1 {
                    DocMdpPermission::NoChanges
                } else {
                    DocMdpPermission::FormFillingAndSigning
                }
            });
            bytes = incremental::sign_one(&bytes, spec, docmdp, self.tsa.as_ref(), password.as_deref())?;
        }
        Ok(SignedDocument { bytes })
    }
}
