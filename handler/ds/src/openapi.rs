use crate::routes::keypair::__path_generate_keypair;
use crate::routes::lock::__path_lock_pdf;
use crate::routes::ocsp::__path_ocsp_responder;
use crate::routes::sign::__path_sign_pdf;
use application_ds::features::key_generator::{
    KeyAlgorithmDto, KeyGeneratorRequestModel, KeyGeneratorResponseModel,
};
use application_ds::features::pdf_locker::{LockAlgorithmDto, LockOpenerDto, LockPdfRequestModel};
use application_ds::features::pdf_signer::{
    PdfSignerRequestModel, SignaturePlacementDto, UserSignatureDto,
};
use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
use utoipa::{Modify, OpenApi};

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "api_key",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("X-API-Key"))),
            );
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    info(title = "DigitalSign API", description = "PDF key generation and PAdES signing"),
    paths(generate_keypair, sign_pdf, lock_pdf, ocsp_responder),
    components(schemas(
        KeyGeneratorRequestModel,
        KeyGeneratorResponseModel,
        KeyAlgorithmDto,
        PdfSignerRequestModel,
        UserSignatureDto,
        SignaturePlacementDto,
        LockPdfRequestModel,
        LockOpenerDto,
        LockAlgorithmDto
    )),
    tags(
        (name = "ds", description = "DigitalSign signing endpoints"),
        (name = "ocsp", description = "OCSP responder for this service's own root CA")
    ),
    modifiers(&SecurityAddon)
)]
pub struct ApiDoc;
