use crate::features::pdf_locker::LockPdfUseCase;
use application_core::CoreError;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use domain::{KeyPair, LockAlgorithm, UnsignedDocument};
use serde::Deserialize;
use thiserror::Error;
use utoipa::ToSchema;

/// Wire representation of `domain::LockAlgorithm`. `Rc4128` is the default —
/// this feature's original cipher — so a request that omits this field
/// keeps behaving predictably; `aes128`/`aes256` are stronger and preferred
/// for anything new.
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

/// One signer whose own national ID (read out of their certificate, not
/// accepted as a separate field) becomes an opening password — see
/// `LockPdfRequestModel::users`.
#[derive(Deserialize, ToSchema)]
pub struct LockOpenerDto {
    pub p12_asn1_base64: String,
    pub derived_key: String,
}

#[derive(Deserialize, ToSchema)]
pub struct LockPdfRequestModel {
    pub document_base64: String,
    /// 1 or 2 signers whose own national ID becomes an opening password:
    /// the first becomes the PDF's user password, a second (if given)
    /// becomes the owner password — both independently open the file. The
    /// Standard Security Handler has exactly these two slots, so more than
    /// two entries is rejected (400), not approximated.
    pub users: Vec<LockOpenerDto>,
    #[serde(default)]
    pub lock_algorithm: LockAlgorithmDto,
}

/// `document_base64`'s locked bytes, plus the password(s) that will open
/// it — handed back so the caller doesn't have to re-derive them.
pub struct LockPdfResult {
    pub bytes: Vec<u8>,
    pub user_password: String,
    pub owner_password: String,
}

#[derive(Debug, Error)]
pub enum LockPdfError {
    #[error("invalid {field}: {source}")]
    InvalidBase64 {
        field: &'static str,
        source: base64::DecodeError,
    },
    #[error(transparent)]
    Locking(#[from] CoreError),
}

pub fn pdf_locker_command(
    use_case: &dyn LockPdfUseCase,
    req: LockPdfRequestModel,
) -> Result<LockPdfResult, LockPdfError> {
    let document_bytes =
        BASE64
            .decode(req.document_base64)
            .map_err(|source| LockPdfError::InvalidBase64 {
                field: "document_base64",
                source,
            })?;
    let document = UnsignedDocument {
        bytes: document_bytes,
    };

    let mut openers = Vec::new();
    for user in req.users {
        let pkcs12_der =
            BASE64
                .decode(user.p12_asn1_base64)
                .map_err(|source| LockPdfError::InvalidBase64 {
                    field: "p12_asn1_base64",
                    source,
                })?;
        openers.push(KeyPair {
            pkcs12_der,
            derived_key: user.derived_key,
        });
    }

    let locked = use_case.execute(document, openers, req.lock_algorithm.into())?;
    Ok(LockPdfResult {
        bytes: locked.bytes,
        user_password: locked.user_password,
        owner_password: locked.owner_password,
    })
}
