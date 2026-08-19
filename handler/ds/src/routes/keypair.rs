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
    let use_case = use_case.get_ref().clone();
    let req = req.into_inner();

    // Rsa2048/3072/4096 keygen (plus the cert/PKCS#12 build around it) is
    // CPU-bound and can take seconds — run it on actix-web's blocking thread
    // pool so it doesn't stall this worker's ability to service other
    // connections in the meantime.
    match web::block(move || key_generator_command(use_case.as_ref(), req)).await {
        Ok(Ok(response)) => HttpResponse::Ok().json(response),
        Ok(Err(e)) => HttpResponse::InternalServerError().body(e.to_string()),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}
