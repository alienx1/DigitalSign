use actix_web::{web, HttpResponse};
use application_ds::features::pdf_locker::{pdf_locker_command, LockPdfError, LockPdfRequestModel};
use application_ds::LockPdfUseCase;
use serde::Serialize;
use std::sync::Arc;
use utoipa::ToSchema;

const RESPONSE_BOUNDARY: &str = "----DigitalSignBoundary7f3a9c2e1b4d6f8a0c5e2b9d";

/// Returned as the `passwords` JSON part of `/ds/lock`'s multipart response
/// — the caller needs these to open the file (and to pass one back into
/// `/ds/sign`'s `document_password` before signing it).
#[derive(Serialize, ToSchema)]
struct LockPasswords {
    user_password: String,
    owner_password: String,
}

#[utoipa::path(
    post,
    path = "/ds/lock",
    request_body = LockPdfRequestModel,
    responses(
        (status = 200, description = "Locked PDF wrapped in a multipart/form-data body: part `locked_pdf` (filename `locked.pdf`) and part `passwords` (JSON, see `LockPasswords`)", content_type = "multipart/form-data"),
        (status = 400, description = "Malformed request (bad base64, wrong number of openers, missing national ID — see body for details)"),
        (status = 401, description = "Missing or invalid API key"),
        (status = 500, description = "Locking failed"),
    ),
    security(("api_key" = [])),
    tag = "ds",
)]
pub async fn lock_pdf(
    use_case: web::Data<Arc<dyn LockPdfUseCase>>,
    req: web::Json<LockPdfRequestModel>,
) -> HttpResponse {
    let result = match pdf_locker_command(use_case.get_ref().as_ref(), req.into_inner()) {
        Ok(result) => result,
        Err(LockPdfError::InvalidBase64 { field, source }) => {
            tracing::warn!(field, %source, "lock request rejected: invalid base64");
            return HttpResponse::BadRequest().body(format!("invalid {field}: {source}"));
        }
        Err(LockPdfError::Locking(e)) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    let passwords = LockPasswords {
        user_password: result.user_password,
        owner_password: result.owner_password,
    };
    let passwords_json = match serde_json::to_vec(&passwords) {
        Ok(json) => json,
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    let mut body = Vec::with_capacity(result.bytes.len() + passwords_json.len() + 512);
    body.extend_from_slice(format!("--{RESPONSE_BOUNDARY}\r\n").as_bytes());
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"locked_pdf\"; filename=\"locked.pdf\"\r\n",
    );
    body.extend_from_slice(b"Content-Type: application/pdf\r\n\r\n");
    body.extend_from_slice(&result.bytes);
    body.extend_from_slice(format!("\r\n--{RESPONSE_BOUNDARY}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"passwords\"\r\n");
    body.extend_from_slice(b"Content-Type: application/json\r\n\r\n");
    body.extend_from_slice(&passwords_json);
    body.extend_from_slice(format!("\r\n--{RESPONSE_BOUNDARY}--\r\n").as_bytes());

    HttpResponse::Ok()
        .content_type(format!("multipart/form-data; boundary={RESPONSE_BOUNDARY}"))
        .body(body)
}
