use super::tsa::{self, TsaConfig};
use application_core::CoreError;
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::cms::{CMSOptions, CmsContentInfo};
use openssl::error::ErrorStack;
use openssl::pkey::{HasPrivate, PKeyRef};
use openssl::stack::StackRef;
use openssl::x509::{X509, X509Ref};
use openssl_sys as ffi;
use std::ffi::CString;
use std::os::raw::{c_int, c_uint, c_void};
use std::ptr;

/// Add the signer with the CAdES ESS `signing-certificate-v2` signed
/// attribute (binds a hash of the signing cert into what's signed, so a
/// certificate substituted after the fact is detectable) — required by
/// PAdES-BES/ETSI EN 319 122 and flagged by strict validators (e.g. the EU
/// DSS validator behind verifysignature.eu) as "The signed attribute:
/// 'signing-certificate' is absent!" otherwise.
///
/// The safe `openssl` crate's `CmsContentInfo::sign` wraps only the one-shot
/// `CMS_sign()` C call, which has no way to request this — its `CMSOptions`
/// bitflags don't expose OpenSSL's `CMS_CADES` flag at all (`openssl-sys`
/// doesn't even declare the constant). Building it requires the lower-level
/// `CMS_sign(..., CMS_PARTIAL)` → `CMS_add1_signer(..., CMS_CADES)` →
/// `CMS_final(...)` sequence instead, which isn't exposed by the safe crate
/// either — hence the raw FFI here.
const CMS_PARTIAL: c_uint = 0x4000;
const CMS_CADES: c_uint = 0x100000;

// Not declared by `openssl-sys`; only ever used as an opaque pointer here, so
// an empty enum (the standard opaque-FFI-type idiom) is all that's needed.
enum CmsSignerInfo {}

extern "C" {
    fn CMS_add1_signer(
        cms: *mut ffi::CMS_ContentInfo,
        signcert: *mut ffi::X509,
        pkey: *mut ffi::EVP_PKEY,
        md: *const ffi::EVP_MD,
        flags: c_uint,
    ) -> *mut CmsSignerInfo;

    fn CMS_add1_cert(cms: *mut ffi::CMS_ContentInfo, cert: *mut ffi::X509) -> c_int;

    fn CMS_final(
        cms: *mut ffi::CMS_ContentInfo,
        data: *mut ffi::BIO,
        dcont: *mut ffi::BIO,
        flags: c_uint,
    ) -> c_int;

    // For reading back the just-computed signature value (to hash and send
    // to a TSA) and for embedding its answer as an unsigned attribute — both
    // absent from openssl-sys, same as everything above.
    fn CMS_SignerInfo_get0_signature(si: *mut CmsSignerInfo) -> *mut ffi::ASN1_OCTET_STRING;
    fn CMS_unsigned_add1_attr(si: *mut CmsSignerInfo, attr: *mut ffi::X509_ATTRIBUTE) -> c_int;
    fn OBJ_txt2obj(s: *const std::os::raw::c_char, no_name: c_int) -> *mut ffi::ASN1_OBJECT;
}

/// id-aa-signatureTimeStampToken (RFC 5126 / ETSI EN 319 122's CAdES-T
/// unsigned attribute) — verified empirically (see `tsa.rs`'s module doc)
/// that embedding a real TSA's `TimeStampToken` here means passing its
/// *complete* DER bytes (tag + length + content) unchanged as `bytes`, with
/// `atrtype = V_ASN1_SEQUENCE`: `X509_ATTRIBUTE_create_by_OBJ`'s handling of
/// aggregate types is an opaque embed, not a re-wrap — passing just the
/// SEQUENCE's content (stripping its own header first, the natural-looking
/// choice) silently produces a corrupt attribute instead of an error.
const OID_SIGNATURE_TIMESTAMP_TOKEN: &str = "1.2.840.113549.1.9.16.2.14";

fn err() -> CoreError {
    CoreError::Signing(format!("CMS signing failed: {}", ErrorStack::get()))
}

/// `chain` — additional certs (e.g. the issuing root CA) to embed in the CMS
/// certificate set alongside the signer's own, so a verifier can build the
/// full chain instead of only ever seeing the leaf. `tsa`, if given, RFC
/// 3161-timestamps this signature (PAdES-B-T) — see `tsa.rs`.
pub fn sign<T>(
    cert: &X509Ref,
    pkey: &PKeyRef<T>,
    chain: &StackRef<X509>,
    data: &[u8],
    tsa_config: Option<&TsaConfig>,
) -> Result<CmsContentInfo, CoreError>
where
    T: HasPrivate,
{
    let base_flags = (CMSOptions::DETACHED | CMSOptions::BINARY).bits();

    unsafe {
        // 1. Empty SignedData shell — no signer yet (PARTIAL defers CMS_final's
        // usual all-in-one signer-adding step so we can pass CMS_CADES below).
        let cms_ptr = ffi::CMS_sign(
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            base_flags | CMS_PARTIAL,
        );
        if cms_ptr.is_null() {
            return Err(err());
        }
        let cms = CmsContentInfo::from_ptr(cms_ptr);

        // 2. Add the real signer with CADES — this is what makes OpenSSL embed
        // the ESS signing-certificate-v2 attribute automatically.
        let si = CMS_add1_signer(
            cms.as_ptr(),
            cert.as_ptr(),
            pkey.as_ptr(),
            ffi::EVP_sha256(),
            base_flags | CMS_CADES,
        );
        if si.is_null() {
            return Err(err());
        }

        // 3. Embed the issuing chain (e.g. the root CA) alongside the leaf so
        // a verifier isn't left with only the signer's own certificate.
        for ca_cert in chain {
            if CMS_add1_cert(cms.as_ptr(), ca_cert.as_ptr()) != 1 {
                return Err(err());
            }
        }

        // 4. Feed the detached content through a memory BIO and finalize —
        // this computes message-digest/signing-time attrs, the digest over
        // `data`, and the signature over the finished signedAttrs.
        let data_bio = ffi::BIO_new_mem_buf(data.as_ptr() as *const _, data.len() as c_int);
        if data_bio.is_null() {
            return Err(err());
        }
        let rc = CMS_final(cms.as_ptr(), data_bio, ptr::null_mut(), base_flags);
        ffi::BIO_free_all(data_bio);
        if rc != 1 {
            return Err(err());
        }

        // 5. RFC 3161 timestamp, if requested — must come after CMS_final:
        // the TSA timestamps THIS signature's actual value, which only
        // exists once finalization has computed it.
        if let Some(tsa_config) = tsa_config {
            let sig_octet_string = CMS_SignerInfo_get0_signature(si);
            if sig_octet_string.is_null() {
                return Err(err());
            }
            let sig_len = ffi::ASN1_STRING_length(sig_octet_string as *const _);
            let sig_ptr = ffi::ASN1_STRING_get0_data(sig_octet_string as *const _);
            let signature_der = std::slice::from_raw_parts(sig_ptr, sig_len as usize);

            let token = tsa::request_timestamp(tsa_config, signature_der)?;

            let oid_cstr = CString::new(OID_SIGNATURE_TIMESTAMP_TOKEN)
                .expect("static OID string has no NUL byte");
            let obj = OBJ_txt2obj(oid_cstr.as_ptr(), 1);
            if obj.is_null() {
                return Err(err());
            }
            const V_ASN1_SEQUENCE: c_int = 16;
            let attr = ffi::X509_ATTRIBUTE_create_by_OBJ(
                ptr::null_mut(),
                obj,
                V_ASN1_SEQUENCE,
                token.as_ptr() as *const c_void,
                token.len() as c_int,
            );
            if attr.is_null() {
                return Err(err());
            }
            if CMS_unsigned_add1_attr(si, attr) != 1 {
                return Err(err());
            }
        }

        Ok(cms)
    }
}
