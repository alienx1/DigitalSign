use actix_web::{web, HttpResponse};
use application_ds::features::key_generator::{
    key_generator_command, KeyGeneratorRequestModel, KeyGeneratorResponseModel,
};
use application_ds::GenerateKeyPairUseCase;
use std::sync::Arc;

#[utoipa::path(
    post,
    path = "/ds/keypair",
    request_body = KeyGeneratorRequestModel,
    responses(
        (status = 200, description = "Key pair generated", body = KeyGeneratorResponseModel),
        (status = 401, description = "Missing or invalid API key"),
        (status = 500, description = "Key generation failed"),
    ),
    security(("api_key" = [])),
    tag = "ds",
)]
pub async fn generate_keypair(
    use_case: web::Data<Arc<dyn GenerateKeyPairUseCase>>,
    req: web::Json<KeyGeneratorRequestModel>,
) -> HttpResponse {
    match key_generator_command(use_case.get_ref().as_ref(), req.into_inner()) {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}
