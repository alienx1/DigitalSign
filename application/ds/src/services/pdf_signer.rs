use crate::features::pdf_signer::SignPdfUseCase;
use application_core::{CoreError, PdfSigner};
use domain::{SignatureSpec, SignedDocument, UnsignedDocument};
use std::sync::Arc;

pub struct SignPdfService {
    signer: Arc<dyn PdfSigner>,
}

impl SignPdfService {
    pub fn new(signer: Arc<dyn PdfSigner>) -> Self {
        Self { signer }
    }
}

impl SignPdfUseCase for SignPdfService {
    fn execute(
        &self,
        document: UnsignedDocument,
        signatures: Vec<SignatureSpec>,
        document_password: Option<&str>,
    ) -> Result<SignedDocument, CoreError> {
        self.signer.sign(&document, &signatures, document_password)
    }
}
