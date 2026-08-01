use crate::features::key_generator::models::KeyGeneratorResponseModel;
use crate::features::key_generator::GenerateKeyPairUseCase;
use application_core::CoreError;
use base64::{engine::general_purpose::STANDARD, Engine};
use domain::SignerIdentity;
use serde::Deserialize;
use utoipa::ToSchema;

#[derive(Deserialize, ToSchema)]
pub struct KeyGeneratorRequestModel {
    pub first_name: String,
    pub last_name: String,
    pub birth_day: u8,
    pub birth_month: u8,
    pub birth_year: u16,
    /// ISO 3166-1 alpha-2 country code (e.g. "TH", "US").
    pub country: String,
    /// Caller-supplied PKCS#12 password. Takes precedence over `aes_key` if
    /// both are given. Omit both to let the server generate one.
    #[serde(default)]
    pub passphrase: Option<String>,
    /// Alternative to `passphrase` — same effect, different name for callers
    /// that think of it as a raw key rather than a human passphrase.
    #[serde(default)]
    pub aes_key: Option<String>,
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
    };

    let key = use_case.execute(identity, protection)?;
    Ok(KeyGeneratorResponseModel {
        p12_asn1_base64: STANDARD.encode(&key.pkcs12_der),
        derived_key: key.derived_key,
    })
}
