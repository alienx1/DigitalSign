use application_core::CoreError;
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::cms::{CMSOptions, CmsContentInfo};
use openssl::error::ErrorStack;
use openssl::pkey::{HasPrivate, PKeyRef};
use openssl::stack::StackRef;
use openssl::x509::{X509, X509Ref};
use openssl_sys as ffi;
use std::os::raw::{c_int, c_uint};
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
}

fn err() -> CoreError {
    CoreError::Signing(format!("CMS signing failed: {}", ErrorStack::get()))
}

/// `chain` — additional certs (e.g. the issuing root CA) to embed in the CMS
/// certificate set alongside the signer's own, so a verifier can build the
/// full chain instead of only ever seeing the leaf.
pub fn sign<T>(
    cert: &X509Ref,
    pkey: &PKeyRef<T>,
    chain: &StackRef<X509>,
    data: &[u8],
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

        Ok(cms)
    }
}
