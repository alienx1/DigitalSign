use crate::features::key_generator::models::KeyGeneratorResponseModel;
use crate::features::key_generator::GenerateKeyPairUseCase;
use application_core::CoreError;
use base64::{engine::general_purpose::STANDARD, Engine};
use domain::{KeyAlgorithm, SignerIdentity};
use serde::Deserialize;
use utoipa::ToSchema;

/// `ecdsa_p256` is this service's original default. The `rsaNNNN` variants
/// exist for ETDA ขมธอ. 15-2566 compliance — that subscriber certificate
/// profile specifies RSA of at least 2048 bits for a natural person
/// certificate, not ECDSA.
#[derive(Deserialize, ToSchema, Clone, Copy, Default)]
#[serde(rename_all = "snake_case")]
pub enum KeyAlgorithmDto {
    #[default]
    EcdsaP256,
    Rsa2048,
    Rsa3072,
    Rsa4096,
}

impl From<KeyAlgorithmDto> for KeyAlgorithm {
    fn from(dto: KeyAlgorithmDto) -> Self {
        match dto {
            KeyAlgorithmDto::EcdsaP256 => KeyAlgorithm::EcdsaP256,
            KeyAlgorithmDto::Rsa2048 => KeyAlgorithm::Rsa { bits: 2048 },
            KeyAlgorithmDto::Rsa3072 => KeyAlgorithm::Rsa { bits: 3072 },
            KeyAlgorithmDto::Rsa4096 => KeyAlgorithm::Rsa { bits: 4096 },
        }
    }
}

#[derive(Deserialize, ToSchema)]
pub struct KeyGeneratorRequestModel {
    pub first_name: String,
    pub last_name: String,
    pub birth_day: u8,
    pub birth_month: u8,
    pub birth_year: u16,
    /// ISO 3166-1 alpha-2 country code (e.g. "TH", "US").
    pub country: String,
    /// Government-issued national ID number.
    pub national_id: String,
    /// Caller-supplied PKCS#12 password. Takes precedence over `aes_key` if
    /// both are given. Omit both to let the server generate one.
    #[serde(default)]
    pub passphrase: Option<String>,
    /// Alternative to `passphrase` — same effect, different name for callers
    /// that think of it as a raw key rather than a human passphrase.
    #[serde(default)]
    pub aes_key: Option<String>,
    /// Signing key algorithm. Defaults to `ecdsa_p256` for backward
    /// compatibility; use an `rsaNNNN` variant for ETDA-profile compliance.
    #[serde(default)]
    pub key_algorithm: KeyAlgorithmDto,
}

pub fn key_generator_command(
    use_case: &dyn GenerateKeyPairUseCase,
    req: KeyGeneratorRequestModel,
) -> Result<KeyGeneratorResponseModel, CoreError> {
    let protection = req.passphrase.or(req.aes_key);
    let identity = SignerIdentity {
        first_name: req.first_name,
        last_name: req.last_name,
        birth_day: req.birth_day,
        birth_month: req.birth_month,
        birth_year: req.birth_year,
        country: req.country,
        national_id: req.national_id,
    };

    let key = use_case.execute(identity, protection, req.key_algorithm.into())?;
    let derived_key_bytes: Vec<u8> = key.derived_key.chars().map(|c| c as u8).collect();
    Ok(KeyGeneratorResponseModel {
        p12_asn1_base64: STANDARD.encode(&key.pkcs12_der),
        derived_key_base64: STANDARD.encode(&derived_key_bytes),
        derived_key: key.derived_key,
    })
}
