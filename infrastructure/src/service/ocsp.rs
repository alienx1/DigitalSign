// A minimal RFC 6960 OCSP responder for this service's own root CA.
//
// openssl-rs's `ocsp` module only wraps the *client* side of OCSP (building
// requests, verifying/reading responses) — there is no binding, safe or raw
// FFI, for parsing an incoming request or constructing+signing a response.
// So this module hand-encodes the handful of ASN.1 structures RFC 6960
// actually needs, via `yasna` (a small, safe DER reader/writer), reusing
// openssl only for hashing and generic signing (the same primitives
// `cades.rs` already uses for CMS).
//
// The exact tagging below (which fields are EXPLICIT vs IMPLICIT) was not
// guessed from the RFC text — it was verified by building a real request
// with `openssl ocsp`, generating a real signed response for our actual root
// CA with `openssl ocsp -index ... -CA ... -rsigner ...`, and inspecting the
// byte structure with `openssl asn1parse`. `nextUpdate` and the request-side
// `Extensions` are intentionally never written/read: they're OPTIONAL, and
// skipping them avoids encoding a tag whose exact form wasn't verified this
// way.
//
// No revocation database exists (this service persists nothing — see
// SCOPE.md), so this responder can only ever answer `good` (matches a cert
// this CA issued) or `unknown` (does not) — never `revoked`.

use application_core::CoreError;
use openssl::hash::{hash, MessageDigest};
use openssl::pkey::{Id, PKey, Private};
use openssl::sign::Signer;
use openssl::x509::X509;
use yasna::models::ObjectIdentifier;
use yasna::Tag;

const OID_SHA1: &[u64] = &[1, 3, 14, 3, 2, 26];
const OID_SHA256: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];
const OID_PKIX_OCSP_BASIC: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 48, 1, 1];
const OID_SHA256_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 11];
const OID_ECDSA_WITH_SHA256: &[u64] = &[1, 2, 840, 10045, 4, 3, 2];

fn asn1_err(msg: impl Into<String>) -> CoreError {
    CoreError::Signing(msg.into())
}

/// One `CertID` read out of an incoming `OCSPRequest`'s `requestList`.
pub struct RequestedCertId {
    hash_algorithm: ObjectIdentifier,
    issuer_name_hash: Vec<u8>,
    issuer_key_hash: Vec<u8>,
    serial_number: Vec<u8>,
}

fn digest_for_oid(oid: &ObjectIdentifier) -> Result<MessageDigest, CoreError> {
    match oid.components().as_slice() {
        c if c == OID_SHA1 => Ok(MessageDigest::sha1()),
        c if c == OID_SHA256 => Ok(MessageDigest::sha256()),
        _ => Err(asn1_err("unsupported OCSP CertID hash algorithm")),
    }
}

/// Parses an `OCSPRequest` (RFC 6960 §4.1.1), returning every `CertID` in its
/// `requestList`. Ignores `version`/`requestorName`/all `Extensions`/the
/// optional request signature — none of them affect what status we'd return.
pub fn parse_request(der: &[u8]) -> Result<Vec<RequestedCertId>, CoreError> {
    yasna::parse_der(der, |reader| {
        reader.read_sequence(|reader| {
            let cert_ids = reader.next().read_sequence(|reader| {
                // version [0] EXPLICIT Version DEFAULT v1
                reader.read_optional(|r| r.read_tagged(Tag::context(0), |r| r.read_i64()))?;
                // requestorName [1] EXPLICIT GeneralName OPTIONAL
                reader.read_optional(|r| r.read_tagged(Tag::context(1), |r| r.read_der()))?;
                // requestList SEQUENCE OF Request
                let mut ids: Vec<RequestedCertId> = Vec::new();
                reader.next().read_sequence_of(|r| {
                    let cert_id = r.read_sequence(|r| {
                        // reqCert CertID
                        let cert_id = r.next().read_sequence(|r| {
                            let hash_algorithm = r.next().read_sequence(|r| {
                                let oid = r.next().read_oid()?;
                                r.read_optional(|r2| r2.read_der())?; // parameters
                                Ok(oid)
                            })?;
                            let issuer_name_hash = r.next().read_bytes()?;
                            let issuer_key_hash = r.next().read_bytes()?;
                            let (serial_number, _positive) = r.next().read_bigint_bytes()?;
                            Ok(RequestedCertId {
                                hash_algorithm,
                                issuer_name_hash,
                                issuer_key_hash,
                                serial_number,
                            })
                        })?;
                        // singleRequestExtensions [0] EXPLICIT Extensions OPTIONAL
                        r.read_optional(|r2| r2.read_tagged(Tag::context(0), |r3| r3.read_der()))?;
                        Ok(cert_id)
                    })?;
                    ids.push(cert_id);
                    Ok(())
                })?;
                // requestExtensions [2] EXPLICIT Extensions OPTIONAL
                reader.read_optional(|r| r.read_tagged(Tag::context(2), |r| r.read_der()))?;
                Ok(ids)
            })?;
            // optionalSignature [0] EXPLICIT Signature OPTIONAL
            reader.read_optional(|r| r.read_tagged(Tag::context(0), |r| r.read_der()))?;
            Ok(cert_ids)
        })
    })
    .map_err(|e| asn1_err(format!("invalid OCSP request: {e:?}")))
}

/// Whether `cert_id` is asking about a certificate issued by `issuer` — i.e.
/// whether its `issuerNameHash`/`issuerKeyHash` (computed with whatever
/// digest the requester specified) match `issuer`'s subject name and public
/// key. RFC 5280 §4.2.1.2 method 1's keyHash: SHA-x over the `subjectPublicKey`
/// BIT STRING's content octets, excluding the unused-bits count byte.
fn matches_issuer(cert_id: &RequestedCertId, issuer: &X509) -> Result<bool, CoreError> {
    let digest = digest_for_oid(&cert_id.hash_algorithm)?;

    let name_der = issuer
        .subject_name()
        .to_der()
        .map_err(|e| asn1_err(format!("failed to encode issuer name: {e}")))?;
    let expected_name_hash =
        hash(digest, &name_der).map_err(|e| asn1_err(format!("hash failed: {e}")))?;

    let spki_der = issuer
        .public_key()
        .map_err(|e| asn1_err(format!("failed to read issuer public key: {e}")))?
        .public_key_to_der()
        .map_err(|e| asn1_err(format!("failed to encode issuer public key: {e}")))?;
    let key_bits = yasna::parse_der(&spki_der, |reader| {
        reader.read_sequence(|reader| {
            reader.next().read_der()?; // AlgorithmIdentifier
            let (bytes, _bit_len) = reader.next().read_bitvec_bytes()?;
            Ok(bytes)
        })
    })
    .map_err(|e| asn1_err(format!("invalid SubjectPublicKeyInfo: {e:?}")))?;
    let expected_key_hash =
        hash(digest, &key_bits).map_err(|e| asn1_err(format!("hash failed: {e}")))?;

    Ok(cert_id.issuer_name_hash == *expected_name_hash
        && cert_id.issuer_key_hash == *expected_key_hash)
}

fn write_cert_id(writer: &mut yasna::DERWriterSeq, cert_id: &RequestedCertId) {
    writer.next().write_sequence(|writer| {
        writer.next().write_sequence(|writer| {
            writer.next().write_oid(&cert_id.hash_algorithm);
            writer.next().write_null();
        });
        writer.next().write_bytes(&cert_id.issuer_name_hash);
        writer.next().write_bytes(&cert_id.issuer_key_hash);
        writer.next().write_bigint_bytes(&cert_id.serial_number, true);
    });
}

/// Builds a signed, successful `OCSPResponse` (RFC 6960 §4.2.1) — `good` for
/// every requested `CertID` that matches `responder` (our root CA), `unknown`
/// for anything else. Signed by `responder_key`/`responder_cert` directly
/// (the CA signs its own OCSP responses — no separate delegated signer).
pub fn build_response(
    responder_key: &PKey<Private>,
    responder_cert: &X509,
    requested: &[RequestedCertId],
) -> Result<Vec<u8>, CoreError> {
    let produced_at = format_generalized_time(chrono::Utc::now());

    let responder_name_der = responder_cert
        .subject_name()
        .to_der()
        .map_err(|e| asn1_err(format!("failed to encode responder name: {e}")))?;

    let mut matches = Vec::with_capacity(requested.len());
    for cert_id in requested {
        matches.push(matches_issuer(cert_id, responder_cert)?);
    }

    let tbs_response_data = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            // responderID, byName [1] EXPLICIT Name — re-verified by
            // re-parsing a real openssl-generated response's raw bytes with
            // `openssl asn1parse`: `cont[1]` constructed wraps a NESTED,
            // separately-tagged SEQUENCE (Name's own tag, untouched) — two
            // tag layers, i.e. EXPLICIT, not one (which a first pass here
            // wrongly assumed from `asn1parse`'s indentation, and which
            // `openssl ocsp`'s offline verifier caught immediately: "no
            // matching choice type: Type=OCSP_RESPID").
            writer
                .next()
                .write_tagged(Tag::context(1), |writer| writer.write_der(&responder_name_der));
            writer.next().write_generalized_time(&parse_generalized_time(&produced_at));
            writer.next().write_sequence(|writer| {
                for (cert_id, is_good) in requested.iter().zip(&matches) {
                    writer.next().write_sequence(|writer| {
                        write_cert_id(writer, cert_id);
                        // certStatus: good [0] IMPLICIT NULL, unknown [2] IMPLICIT NULL —
                        // both verified as primitive, zero-length context tags.
                        let status_tag = if *is_good { 0 } else { 2 };
                        writer
                            .next()
                            .write_tagged_implicit(Tag::context(status_tag), |writer| writer.write_null());
                        writer.next().write_generalized_time(&parse_generalized_time(&produced_at));
                        // nextUpdate and singleExtensions intentionally omitted (both OPTIONAL).
                    });
                }
            });
            // responseExtensions [1] EXPLICIT Extensions OPTIONAL — omitted.
        })
    });

    let digest = MessageDigest::sha256();
    let mut signer = Signer::new(digest, responder_key)
        .map_err(|e| asn1_err(format!("failed to init OCSP response signer: {e}")))?;
    signer
        .update(&tbs_response_data)
        .map_err(|e| asn1_err(format!("failed to hash OCSP response: {e}")))?;
    let signature = signer
        .sign_to_vec()
        .map_err(|e| asn1_err(format!("failed to sign OCSP response: {e}")))?;

    let sig_alg_oid = match responder_key.id() {
        Id::RSA => OID_SHA256_WITH_RSA,
        Id::EC => OID_ECDSA_WITH_SHA256,
        other => {
            return Err(asn1_err(format!(
                "unsupported OCSP responder key type: {other:?}"
            )))
        }
    };
    let has_null_params = responder_key.id() == Id::RSA;

    let responder_cert_der = responder_cert
        .to_der()
        .map_err(|e| asn1_err(format!("failed to encode responder cert: {e}")))?;

    let signature_bit_len = signature.len() * 8;
    let basic_response = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_der(&tbs_response_data);
            writer.next().write_sequence(|writer| {
                writer.next().write_oid(&ObjectIdentifier::from_slice(sig_alg_oid));
                if has_null_params {
                    writer.next().write_null();
                }
            });
            writer.next().write_bitvec_bytes(&signature, signature_bit_len);
            // certs [0] EXPLICIT SEQUENCE OF Certificate — include our own
            // cert so a verifier doesn't need it out-of-band.
            writer.next().write_tagged(Tag::context(0), |writer| {
                writer.write_sequence(|writer| {
                    writer.next().write_der(&responder_cert_der);
                });
            });
        })
    });

    let ocsp_response = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_enum(0); // responseStatus: successful
            writer.next().write_tagged(Tag::context(0), |writer| {
                writer.write_sequence(|writer| {
                    writer.next().write_oid(&ObjectIdentifier::from_slice(OID_PKIX_OCSP_BASIC));
                    writer.next().write_bytes(&basic_response);
                });
            });
        })
    });

    Ok(ocsp_response)
}

/// Builds a `malformedRequest` `OCSPResponse` — just the bare
/// `responseStatus`, no `responseBytes` (per RFC 6960, only present on a
/// `successful` response).
pub fn malformed_request_response() -> Vec<u8> {
    yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_enum(1); // malformedRequest
        })
    })
}

/// `produced_at`/`this_update` need the same GeneralizedTime string in every
/// `SingleResponse` plus the top-level `producedAt` — formatted once via
/// `format_generalized_time` (matching how the rest of this crate handles
/// time, e.g. `incremental.rs`'s `format_pdf_date`), then parsed back into
/// yasna's own `time`-crate-backed `GeneralizedTime` type to write it.
fn parse_generalized_time(s: &str) -> yasna::models::GeneralizedTime {
    // `s` is always produced by `format_generalized_time` just below, so
    // this parse cannot fail in practice.
    yasna::models::GeneralizedTime::parse(s.as_bytes()).expect("self-formatted GeneralizedTime")
}

/// Formats a UTC time as an ASN.1 `GeneralizedTime` string (`YYYYMMDDHHMMSSZ`).
fn format_generalized_time(now: chrono::DateTime<chrono::Utc>) -> String {
    format!("{}Z", now.format("%Y%m%d%H%M%S"))
}
