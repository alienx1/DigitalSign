use crate::features::pdf_signer::SignPdfUseCase;
use application_core::CoreError;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use domain::{KeyPair, SignaturePosition, SignatureSpec, UnsignedDocument};
use serde::Deserialize;
use thiserror::Error;
use utoipa::ToSchema;

#[derive(Deserialize, ToSchema)]
pub struct SignaturePlacementDto {
    pub page: u32,
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
    #[serde(default)]
    pub image_base64: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct UserSignatureDto {
    pub p12_asn1_base64: String,
    pub derived_key: String,
    pub signatures: Vec<SignaturePlacementDto>,
}

#[derive(Deserialize, ToSchema)]
pub struct PdfSignerRequestModel {
    pub document_base64: String,
    pub users: Vec<UserSignatureDto>,
    /// The password already protecting `document_base64`, if it was locked
    /// beforehand via `POST /ds/lock` — either the `user_password` or
    /// `owner_password` that call returned both work here. Needed only so
    /// this request's own newly-appended signature objects get encrypted
    /// the same way as the rest of the file; omit for a plain document.
    #[serde(default)]
    pub document_password: Option<String>,
}

#[derive(Debug, Error)]
pub enum SignPdfError {
    #[error("invalid {field}: {source}")]
    InvalidBase64 {
        field: &'static str,
        source: base64::DecodeError,
    },
    #[error(transparent)]
    Signing(#[from] CoreError),
}

pub fn pdf_signer_command(
    use_case: &dyn SignPdfUseCase,
    req: PdfSignerRequestModel,
) -> Result<Vec<u8>, SignPdfError> {
    let document_bytes =
        BASE64
            .decode(req.document_base64)
            .map_err(|source| SignPdfError::InvalidBase64 {
                field: "document_base64",
                source,
            })?;
    let document = UnsignedDocument {
        bytes: document_bytes,
    };

    let mut signatures = Vec::new();
    for user in req.users {
        let pkcs12_der =
            BASE64
                .decode(user.p12_asn1_base64)
                .map_err(|source| SignPdfError::InvalidBase64 {
                    field: "p12_asn1_base64",
                    source,
                })?;
        let key = KeyPair {
            pkcs12_der,
            derived_key: user.derived_key,
        };

        for placement in user.signatures {
            let image = match placement.image_base64 {
                Some(b64) if !b64.is_empty() => Some(BASE64.decode(b64).map_err(|source| {
                    SignPdfError::InvalidBase64 {
                        field: "image_base64",
                        source,
                    }
                })?),
                _ => None,
            };

            signatures.push(SignatureSpec {
                position: SignaturePosition {
                    page: placement.page,
                    x: placement.x,
                    y: placement.y,
                    width: placement.width,
                    height: placement.height,
                },
                key: key.clone(),
                image,
            });
        }
    }

    let signed = use_case.execute(document, signatures, req.document_password.as_deref())?;
    Ok(signed.bytes)
}
