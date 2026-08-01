use crate::features::pdf_signer::SignPdfUseCase;
use application_core::CoreError;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use domain::{KeyPair, SignaturePosition, SignatureSpec, UnsignedDocument};
use serde::Deserialize;
use thiserror::Error;
use utoipa::ToSchema;

#[derive(Deserialize, ToSchema)]
pub struct SignatureSpecDto {
    pub page: u32,
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
    pub p12_asn1_base64: String,
    pub derived_key: String,
    #[serde(default)]
    pub image_base64: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct PdfSignerRequestModel {
    pub document_base64: String,
    pub signatures: Vec<SignatureSpecDto>,
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

    let mut signatures = Vec::with_capacity(req.signatures.len());
    for spec in req.signatures {
        let pkcs12_der =
            BASE64
                .decode(spec.p12_asn1_base64)
                .map_err(|source| SignPdfError::InvalidBase64 {
                    field: "p12_asn1_base64",
                    source,
                })?;
        let image = match spec.image_base64 {
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
                page: spec.page,
                x: spec.x,
                y: spec.y,
                width: spec.width,
                height: spec.height,
            },
            key: KeyPair {
                pkcs12_der,
                derived_key: spec.derived_key,
            },
            image,
        });
    }

    let signed = use_case.execute(document, signatures)?;
    Ok(signed.bytes)
}
