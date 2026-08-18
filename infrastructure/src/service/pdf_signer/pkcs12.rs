use application_core::CoreError;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::stack::Stack;
use openssl::x509::X509;

/// Signing key, leaf certificate, and any bundled CA chain certs (the issuing
/// root, if the bundle was built by `OpensslKeyGenerator`).
type UnpackedPkcs12 = (PKey<Private>, X509, Option<Stack<X509>>);

/// Unpacks a caller-supplied PKCS#12 bundle into its signing key, leaf
/// certificate, and any additional CA chain certs bundled alongside it (the
/// issuing root, if the bundle was built by `OpensslKeyGenerator`).
pub fn unpack(pkcs12_der: &[u8], derived_key: &str) -> Result<UnpackedPkcs12, CoreError> {
    let pkcs12 = Pkcs12::from_der(pkcs12_der)
        .map_err(|e| CoreError::Signing(format!("invalid PKCS#12 bundle: {e}")))?;
    let parsed = pkcs12
        .parse2(derived_key)
        .map_err(|e| CoreError::Signing(format!("could not open PKCS#12 (wrong derived_key?): {e}")))?;
    let pkey = parsed
        .pkey
        .ok_or_else(|| CoreError::Signing("PKCS#12 bundle has no private key".into()))?;
    let cert = parsed
        .cert
        .ok_or_else(|| CoreError::Signing("PKCS#12 bundle has no certificate".into()))?;
    Ok((pkey, cert, parsed.ca))
}

/// Extracts the certificate's commonName, for the text-only signature appearance fallback.
pub fn common_name(cert: &X509) -> String {
    cert.subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .and_then(|entry| entry.data().to_string().ok())
        .unwrap_or_else(|| "Unknown signer".to_string())
}

/// Extracts the 13-digit national ID from the certificate's `serialNumber`
/// subject attribute, if it's in the `IDC-<13 digits>` form `/ds/keypair`
/// writes there (see `key_generator.rs`) — `None` for any cert lacking that
/// attribute or not in that format (e.g. an externally-supplied p12).
pub fn national_id(cert: &X509) -> Option<String> {
    let value = cert
        .subject_name()
        .entries_by_nid(openssl::nid::Nid::SERIALNUMBER)
        .next()
        .and_then(|entry| entry.data().to_string().ok())?;
    let digits = value.strip_prefix("IDC-")?;
    (digits.len() == 13 && digits.bytes().all(|b| b.is_ascii_digit())).then(|| digits.to_string())
}
