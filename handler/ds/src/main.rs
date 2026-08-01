use actix_web::{App, HttpServer};
use application_ds::{GenerateKeyPairService, SignPdfService};
use infrastructure::{
    build_self_signed_ca, ApiKeyAuth, LopdfPdfSigner, OpensslKeyGenerator, TracingKeyGenerator,
    TracingPdfSigner,
};
use openssl::pkey::PKey;
use std::sync::Arc;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();

    let api_key = std::env::var("API_KEY").expect("API_KEY must be set");
    let max_json_body_bytes: usize = std::env::var("MAX_JSON_BODY_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(25 * 1024 * 1024);

    // The root CA that issues every generated signer certificate — one shared
    // issuer for verifiers to trust, instead of every signer's own
    // self-signed cert. Its key/identity are entirely config-driven (never a
    // literal in source) so which key or domain backs it can always change.
    let root_ca_key_path =
        std::env::var("ROOT_CA_KEY_PATH").expect("ROOT_CA_KEY_PATH must be set");
    let root_ca_cn = std::env::var("ROOT_CA_CN").expect("ROOT_CA_CN must be set");
    let root_ca_validity_days: u32 = std::env::var("ROOT_CA_VALIDITY_DAYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3650);

    let root_key_pem = std::fs::read(&root_ca_key_path)
        .unwrap_or_else(|e| panic!("failed to read ROOT_CA_KEY_PATH ({root_ca_key_path}): {e}"));
    let root_key =
        PKey::private_key_from_pem(&root_key_pem).expect("ROOT_CA_KEY_PATH is not a valid PEM private key");
    let root_cert = build_self_signed_ca(&root_key, &root_ca_cn, root_ca_validity_days)
        .expect("failed to build self-signed root CA certificate");

    let keypair_use_case = Arc::new(GenerateKeyPairService::new(Arc::new(
        TracingKeyGenerator::new(OpensslKeyGenerator::new(root_key, root_cert)),
    )));
    let sign_use_case = Arc::new(SignPdfService::new(Arc::new(TracingPdfSigner::new(
        LopdfPdfSigner,
    ))));

    let host = std::env::var("APP_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port: u16 = std::env::var("APP_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    tracing::info!("starting DigitalSign service on {host}:{port}");

    HttpServer::new(move || {
        App::new()
            .service(
                handler_ds::scope(
                    keypair_use_case.clone(),
                    sign_use_case.clone(),
                    max_json_body_bytes,
                )
                .wrap(ApiKeyAuth::new(api_key.clone())),
            )
            .service(handler_ds::swagger_ui())
    })
    .bind((host.as_str(), port))?
    .run()
    .await
}
