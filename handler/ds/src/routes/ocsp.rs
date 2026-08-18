use actix_web::{web, HttpResponse};
use infrastructure::{build_ocsp_response, malformed_ocsp_request_response, parse_ocsp_request};
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;

/// Deliberately NOT behind `ApiKeyAuth` (see `handler_ds::ocsp_route`) — any
/// relying party validating a certificate we issued needs to reach this
/// without our API key, same as a public CA's OCSP endpoint.
#[utoipa::path(
    post,
    path = "/ocsp",
    request_body(content = Vec<u8>, description = "DER-encoded OCSPRequest", content_type = "application/ocsp-request"),
    responses(
        (status = 200, description = "DER-encoded OCSPResponse (RFC 6960) — `malformedRequest` if the request didn't parse", content_type = "application/ocsp-response"),
        (status = 500, description = "Response generation failed"),
    ),
    tag = "ocsp",
)]
pub async fn ocsp_responder(
    root_key: web::Data<PKey<Private>>,
    root_cert: web::Data<X509>,
    body: web::Bytes,
) -> HttpResponse {
    let cert_ids = match parse_ocsp_request(&body) {
        Ok(ids) if !ids.is_empty() => ids,
        _ => {
            return HttpResponse::Ok()
                .content_type("application/ocsp-response")
                .body(malformed_ocsp_request_response());
        }
    };

    match build_ocsp_response(root_key.get_ref(), root_cert.get_ref(), &cert_ids) {
        Ok(resp) => HttpResponse::Ok()
            .content_type("application/ocsp-response")
            .body(resp),
        Err(e) => {
            tracing::error!(error = %e, "OCSP response generation failed");
            HttpResponse::InternalServerError().body(e.to_string())
        }
    }
}
