use actix_web::middleware::from_fn;
use actix_web::{App, HttpServer};
use application_ds::{GenerateKeyPairService, LockPdfService, SignPdfService};
use infrastructure::{
    build_self_signed_ca, request_log, ApiKeyAuth, LopdfPdfLocker, LopdfPdfSigner,
    OpensslKeyGenerator, TracingKeyGenerator, TracingPdfLocker, TracingPdfSigner, TsaConfig,
};
use openssl::pkey::PKey;
use std::sync::Arc;
use std::time::Duration;

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

    // Cloned before both are moved into OpensslKeyGenerator — the OCSP
    // responder also needs to sign responses as this same root CA.
    let ocsp_root_key = root_key.clone();
    let ocsp_root_cert = root_cert.clone();

    let keypair_use_case = Arc::new(GenerateKeyPairService::new(Arc::new(
        TracingKeyGenerator::new(OpensslKeyGenerator::new(root_key, root_cert)),
    )));

    // RFC 3161 timestamping (PAdES-B-T) — off unless TSA_ENABLED=true, and
    // flipping it on/off or pointing it at a different TSA is purely a
    // config change, no code/redeploy needed. TSA_URL stays in `.env` either
    // way, so turning it back on later doesn't mean re-typing the URL. See
    // `TsaConfig`'s doc comment (`infrastructure::LopdfPdfSigner`) for why a
    // TSA failure fails the whole signing request instead of silently
    // downgrading to PAdES-B-B.
    let tsa_enabled = std::env::var("TSA_ENABLED")
        .ok()
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let tsa_config = if tsa_enabled {
        let url = std::env::var("TSA_URL")
            .ok()
            .filter(|s| !s.is_empty())
            .expect("TSA_ENABLED=true but TSA_URL is unset/empty");
        let timeout_secs: u64 = std::env::var("TSA_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10);
        Some(TsaConfig {
            url,
            timeout: Duration::from_secs(timeout_secs),
        })
    } else {
        None
    };
    if let Some(tsa) = &tsa_config {
        tracing::info!(url = %tsa.url, timeout_secs = tsa.timeout.as_secs(), "RFC 3161 timestamping enabled");
    } else {
        tracing::info!("RFC 3161 timestamping disabled (TSA_ENABLED not true)");
    }

    let sign_use_case = Arc::new(SignPdfService::new(Arc::new(TracingPdfSigner::new(
        LopdfPdfSigner::new(tsa_config),
    ))));
    let lock_use_case = Arc::new(LockPdfService::new(Arc::new(TracingPdfLocker::new(
        LopdfPdfLocker::new(),
    ))));

    let host = std::env::var("APP_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port: u16 = std::env::var("APP_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    tracing::info!("starting DigitalSign service on {host}:{port}");

    HttpServer::new(move || {
        App::new()
            .wrap(from_fn(request_log))
            .service(
                handler_ds::scope(
                    keypair_use_case.clone(),
                    sign_use_case.clone(),
                    lock_use_case.clone(),
                    max_json_body_bytes,
                )
                .wrap(ApiKeyAuth::new(api_key.clone())),
            )
            .service(handler_ds::ocsp_scope(
                ocsp_root_key.clone(),
                ocsp_root_cert.clone(),
            ))
            .service(handler_ds::swagger_ui())
    })
    .bind((host.as_str(), port))?
    .run()
    .await
}
