pub mod commands;

pub use commands::{
    pdf_signer_command, PdfSignerRequestModel, SignPdfError, SignaturePlacementDto,
    UserSignatureDto,
};

use application_core::CoreError;
use domain::{SignatureSpec, SignedDocument, UnsignedDocument};

/// The "sign pdf" use case, called by handler/ds.
pub trait SignPdfUseCase: Send + Sync {
    fn execute(
        &self,
        document: UnsignedDocument,
        signatures: Vec<SignatureSpec>,
        lock_with_national_id: bool,
    ) -> Result<SignedDocument, CoreError>;
}
