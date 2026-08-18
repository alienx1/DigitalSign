// RFC 3161 timestamping (PAdES-B-T) — after a signature's CMS SignedData is
// finalized, hash the signature value, ask a Time Stamping Authority to sign
// that hash + the current time, and embed the resulting TimeStampToken as an
// unsigned attribute on the same SignerInfo (per RFC 5126/ETSI CAdES-T,
// which PAdES-B-T inherits). Configured via `TSA_URL` (see `main.rs`) — unset
// means no timestamp is requested at all, matching this service's existing
// pattern of config-driven, all-or-nothing external integrations
// (`ROOT_CA_KEY_PATH` et al.).
//
// Request/response ASN.1 is hand-built via `yasna`, same as `ocsp.rs` and
// for the same reason: this is client-side RFC 3161, which openssl-rs's
// `ts` module (nonexistent — there's no `openssl::ts` binding at all, safe
// or raw) doesn't cover. The one detail that mattered and was verified
// empirically rather than assumed — how to embed the resulting token into
// the CMS SignerInfo as an unsigned attribute — lives in `cades.rs`.

use application_core::CoreError;
use openssl::hash::{hash, MessageDigest};
use std::time::Duration;
use yasna::models::ObjectIdentifier;

const OID_SHA256: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];

fn tsa_err(msg: impl Into<String>) -> CoreError {
    CoreError::Signing(msg.into())
}

/// Where to send timestamp requests, and how long to wait. Constructed once
/// at startup from `TSA_URL`/`TSA_TIMEOUT_SECS` — see `main.rs`.
#[derive(Clone)]
pub struct TsaConfig {
    pub url: String,
    pub timeout: Duration,
}

fn build_query(message_digest: &[u8]) -> Vec<u8> {
    yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_i64(1); // version
            writer.next().write_sequence(|writer| {
                // messageImprint
                writer.next().write_sequence(|writer| {
                    writer.next().write_oid(&ObjectIdentifier::from_slice(OID_SHA256));
                    writer.next().write_null();
                });
                writer.next().write_bytes(message_digest);
            });
            // reqPolicy, nonce: omitted (both OPTIONAL) — this service
            // doesn't need replay protection against its own TSA request,
            // and has no particular policy OID to demand.
            writer.next().write_bool(true); // certReq: ask the TSA to embed its signing cert
        })
    })
}

/// `status` field of `PKIStatusInfo` — RFC 3161 §2.4.2. Only `granted` and
/// `grantedWithMods` come with a usable `timeStampToken`.
fn status_is_usable(status: i64) -> bool {
    status == 0 || status == 1
}

/// Parses a `TimeStampResp`, returning the raw `TimeStampToken` bytes
/// (the *complete* DER TLV, tag and length included — verified empirically
/// against a real TSA response that this is exactly what `cades.rs` needs to
/// embed unchanged, not just the SEQUENCE's content).
fn parse_response(der: &[u8]) -> Result<Vec<u8>, CoreError> {
    let (status, token) = yasna::parse_der(der, |reader| {
        reader.read_sequence(|reader| {
            let status = reader.next().read_sequence(|reader| {
                let status = reader.next().read_i64()?;
                reader.read_optional(|r| r.read_der())?; // statusString
                reader.read_optional(|r| r.read_der())?; // failInfo
                Ok(status)
            })?;
            let token = reader.read_optional(|r| r.read_der())?;
            Ok((status, token))
        })
    })
    .map_err(|e| tsa_err(format!("invalid TSA response: {e:?}")))?;

    if !status_is_usable(status) {
        return Err(tsa_err(format!("TSA rejected timestamp request (status {status})")));
    }
    token.ok_or_else(|| tsa_err("TSA response granted but carried no timeStampToken"))
}

/// Requests a timestamp over `signature_der` (the CMS signature VALUE bytes,
/// not the original document) from the configured TSA, returning the raw
/// `TimeStampToken` bytes ready for `cades.rs` to embed.
pub fn request_timestamp(config: &TsaConfig, signature_der: &[u8]) -> Result<Vec<u8>, CoreError> {
    let digest = hash(MessageDigest::sha256(), signature_der)
        .map_err(|e| tsa_err(format!("failed to hash signature for timestamping: {e}")))?;
    let query = build_query(&digest);

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(config.timeout))
        .build()
        .into();
    let mut response = agent
        .post(&config.url)
        .header("Content-Type", "application/timestamp-query")
        .send(&query[..])
        .map_err(|e| tsa_err(format!("TSA request to {} failed: {e}", config.url)))?;

    if !response.status().is_success() {
        return Err(tsa_err(format!(
            "TSA at {} returned HTTP {}",
            config.url,
            response.status()
        )));
    }

    let body = response
        .body_mut()
        .read_to_vec()
        .map_err(|e| tsa_err(format!("failed to read TSA response body: {e}")))?;

    parse_response(&body)
}
