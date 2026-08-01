use actix_web::{web, HttpResponse};
use application_ds::features::pdf_signer::{pdf_signer_command, PdfSignerRequestModel, SignPdfError};
use application_ds::SignPdfUseCase;
use std::sync::Arc;

const RESPONSE_BOUNDARY: &str = "----DigitalSignBoundary7f3a9c2e1b4d6f8a0c5e2b9d";

#[utoipa::path(
    post,
    path = "/ds/sign",
    request_body = PdfSignerRequestModel,
    responses(
        (status = 200, description = "Signed PDF wrapped in a multipart/form-data body (single part `signed_pdf`, filename `signed.pdf`)", content_type = "multipart/form-data"),
        (status = 400, description = "Malformed request (bad base64, see body for details)"),
        (status = 401, description = "Missing or invalid API key"),
        (status = 500, description = "Signing failed"),
    ),
    security(("api_key" = [])),
    tag = "ds",
)]
pub async fn sign_pdf(
    use_case: web::Data<Arc<dyn SignPdfUseCase>>,
    req: web::Json<PdfSignerRequestModel>,
) -> HttpResponse {
    let signed_bytes = match pdf_signer_command(use_case.get_ref().as_ref(), req.into_inner()) {
        Ok(bytes) => bytes,
        Err(SignPdfError::InvalidBase64 { field, source }) => {
            return HttpResponse::BadRequest().body(format!("invalid {field}: {source}"))
        }
        Err(SignPdfError::Signing(e)) => {
            return HttpResponse::InternalServerError().body(e.to_string())
        }
    };

    let mut body = Vec::with_capacity(signed_bytes.len() + 256);
    body.extend_from_slice(format!("--{RESPONSE_BOUNDARY}\r\n").as_bytes());
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"signed_pdf\"; filename=\"signed.pdf\"\r\n",
    );
    body.extend_from_slice(b"Content-Type: application/pdf\r\n\r\n");
    body.extend_from_slice(&signed_bytes);
    body.extend_from_slice(format!("\r\n--{RESPONSE_BOUNDARY}--\r\n").as_bytes());

    HttpResponse::Ok()
        .content_type(format!("multipart/form-data; boundary={RESPONSE_BOUNDARY}"))
        .body(body)
}
