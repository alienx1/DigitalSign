use crate::routes::keypair::__path_generate_keypair;
use crate::routes::sign::__path_sign_pdf;
use application_ds::features::key_generator::{KeyGeneratorRequestModel, KeyGeneratorResponseModel};
use application_ds::features::pdf_signer::{PdfSignerRequestModel, SignatureSpecDto};
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
    paths(generate_keypair, sign_pdf),
    components(schemas(
        KeyGeneratorRequestModel,
        KeyGeneratorResponseModel,
        PdfSignerRequestModel,
        SignatureSpecDto
    )),
    tags((name = "ds", description = "DigitalSign signing endpoints")),
    modifiers(&SecurityAddon)
)]
pub struct ApiDoc;
