use crate::features::pdf_signer::SignPdfUseCase;
use application_core::CoreError;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use domain::{KeyPair, LockAlgorithm, SignaturePosition, SignatureSpec, UnsignedDocument};
use serde::Deserialize;
use thiserror::Error;
use utoipa::ToSchema;

/// Wire representation of `domain::LockAlgorithm` for `/ds/sign`'s
/// `lock_algorithm` field. `Rc4128` is the default, matching
/// `LockAlgorithm::default()`, so requests written before this field existed
/// (which only ever set `lock_with_national_id: true`) keep behaving exactly
/// as before.
#[derive(Clone, Copy, Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LockAlgorithmDto {
    #[default]
    Rc4128,
    Aes128,
    Aes256,
}

impl From<LockAlgorithmDto> for LockAlgorithm {
    fn from(dto: LockAlgorithmDto) -> Self {
        match dto {
            LockAlgorithmDto::Rc4128 => LockAlgorithm::Rc4_128,
            LockAlgorithmDto::Aes128 => LockAlgorithm::Aes128,
            LockAlgorithmDto::Aes256 => LockAlgorithm::Aes256,
        }
    }
}

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
    /// If true, password-protects the signed PDF (open password) using the
    /// FIRST user's own national ID — read back out of their certificate's
    /// `serialNumber` (`IDC-<13 digits>`, as `/ds/keypair` sets it), not
    /// accepted as a separate field here. Encryption happens before signing,
    /// so every embedded signature still validates once the file is opened
    /// with that password. Fails the request if the first user's
    /// certificate doesn't carry a national ID in that form (e.g. an
    /// externally-supplied p12).
    #[serde(default)]
    pub lock_with_national_id: bool,
    /// Cipher for the open-password protection above, when
    /// `lock_with_national_id` is true. Defaults to `rc4128` (this feature's
    /// original, and only, cipher) so existing callers are unaffected;
    /// `aes128`/`aes256` are stronger and preferred for anything new.
    #[serde(default)]
    pub lock_algorithm: LockAlgorithmDto,
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

    let lock = req.lock_with_national_id.then(|| req.lock_algorithm.into());
    let signed = use_case.execute(document, signatures, lock)?;
    Ok(signed.bytes)
}
