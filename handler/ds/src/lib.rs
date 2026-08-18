mod openapi;
mod routes;

use actix_web::{web, Scope};
use application_ds::{GenerateKeyPairUseCase, SignPdfUseCase};
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use std::sync::Arc;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

pub fn scope(
    keypair_use_case: Arc<dyn GenerateKeyPairUseCase>,
    sign_use_case: Arc<dyn SignPdfUseCase>,
    max_json_body_bytes: usize,
) -> Scope {
    web::scope("/ds")
        .app_data(web::JsonConfig::default().limit(max_json_body_bytes))
        .app_data(web::Data::new(keypair_use_case))
        .app_data(web::Data::new(sign_use_case))
        .route(
            "/keypair",
            web::post().to(routes::keypair::generate_keypair),
        )
        .route("/sign", web::post().to(routes::sign::sign_pdf))
}

/// Mounted top-level, deliberately NOT under `/ds` (so it never picks up
/// `ApiKeyAuth`) — an OCSP responder must be reachable by any relying party
/// checking a certificate we issued, not just callers with our API key.
pub fn ocsp_scope(root_key: PKey<Private>, root_cert: X509) -> Scope {
    web::scope("/ocsp")
        .app_data(web::Data::new(root_key))
        .app_data(web::Data::new(root_cert))
        .route("", web::post().to(routes::ocsp::ocsp_responder))
}

/// Serves Swagger UI at `/swagger-ui/` and the raw spec at `/api-docs/openapi.json`.
/// Not behind `ApiKeyAuth` — it only wraps the `/ds` scope, not this service.
pub fn swagger_ui() -> SwaggerUi {
    SwaggerUi::new("/swagger-ui/{_:.*}")
        .url("/api-docs/openapi.json", openapi::ApiDoc::openapi())
}
