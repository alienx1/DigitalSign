use serde::Serialize;
use utoipa::ToSchema;

#[derive(Serialize, ToSchema)]
pub struct KeyGeneratorResponseModel {
    pub p12_asn1_base64: String,
    pub derived_key: String,
    /// `derived_key`'s raw bytes, base64-encoded — safe to copy/paste or log
    /// without the control/non-ASCII bytes getting mangled.
    pub derived_key_base64: String,
}
