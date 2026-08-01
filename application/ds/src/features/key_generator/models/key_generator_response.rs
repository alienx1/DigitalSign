use serde::Serialize;
use utoipa::ToSchema;

#[derive(Serialize, ToSchema)]
pub struct KeyGeneratorResponseModel {
    pub p12_asn1_base64: String,
    pub derived_key: String,
}
