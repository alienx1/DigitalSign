use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier};
use openssl::x509::{X509Name, X509};

/// Builds a fresh self-signed CA certificate (`CA:TRUE`, `keyCertSign`/`cRLSign`)
/// for the given key pair — used to issue per-signer certificates instead of
/// each one being self-signed, so verifiers only need to trust one root
/// instead of every individual signer's own certificate.
///
/// This does *not* make the resulting chain publicly trusted (that requires
/// the root's cert to actually be in a verifier's trust store) — it just
/// gives every signer cert a shared, single issuer to distribute and trust
/// once, which is a prerequisite for that.
pub fn build_self_signed(
    key: &PKey<Private>,
    common_name: &str,
    validity_days: u32,
) -> Result<X509, ErrorStack> {
    let mut name_builder = X509Name::builder()?;
    name_builder.append_entry_by_text("CN", common_name)?;
    let name = name_builder.build();

    let mut builder = X509::builder()?;
    builder.set_version(2)?;

    let mut serial = BigNum::new()?;
    serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
    let serial = serial.to_asn1_integer()?;
    builder.set_serial_number(&serial)?;

    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(key)?;

    let not_before = Asn1Time::days_from_now(0)?;
    builder.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(validity_days)?;
    builder.set_not_after(&not_after)?;

    builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
    builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;
    let ski = SubjectKeyIdentifier::new().build(&builder.x509v3_context(None, None))?;
    builder.append_extension(ski)?;

    builder.sign(key, MessageDigest::sha256())?;
    Ok(builder.build())
}
