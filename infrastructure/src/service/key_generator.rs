use application_core::{CoreError, KeyGenerator};
use domain::{KeyAlgorithm, KeyPair, SignerIdentity};
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::pkey::{PKey, Private};
use openssl::rand::rand_bytes;
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::x509::extension::{BasicConstraints, KeyUsage};
use openssl::x509::{X509Name, X509};

/// ETDA ขมธอ. 15-2566's subscriber certificate profile requires RSA of at
/// least this many bits for a natural person certificate.
const MIN_RSA_BITS: u32 = 2048;

const DERIVED_KEY_LEN: usize = 32;
const PBKDF2_ITERATIONS: usize = 100_000;

fn keygen_err(e: ErrorStack) -> CoreError {
    CoreError::KeyGeneration(e.to_string())
}

/// Every `u8` maps 1:1 onto a Latin-1 Unicode scalar value, so this turns raw
/// random bytes directly into a string without any base64 padding/charset.
fn bytes_to_raw_string(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

/// Stretches caller-supplied input material (a passphrase or raw key) into a
/// proper 256-bit key via PBKDF2-HMAC-SHA256, so weak input never becomes the
/// literal PKCS#12 password.
///
/// Rejection-samples the salt: `Pkcs12Builder::build2` turns the password into
/// a `CString` internally and *panics* (`CString::new().unwrap()`) if it
/// contains an embedded NUL byte. With 32 uniformly random bytes that's a
/// ~12% chance per key — not a corner case, it will happen in production.
fn derive_key(seed: &str) -> Result<String, CoreError> {
    loop {
        let mut salt = [0u8; 16];
        rand_bytes(&mut salt).map_err(keygen_err)?;
        let mut derived = [0u8; DERIVED_KEY_LEN];
        pbkdf2_hmac(
            seed.as_bytes(),
            &salt,
            PBKDF2_ITERATIONS,
            MessageDigest::sha256(),
            &mut derived,
        )
        .map_err(keygen_err)?;
        if !derived.contains(&0u8) {
            return Ok(bytes_to_raw_string(&derived));
        }
    }
}

/// Same NUL-byte hazard as [`derive_key`], for the no-`protection`-supplied path.
fn random_key() -> Result<String, CoreError> {
    loop {
        let mut secret = [0u8; DERIVED_KEY_LEN];
        rand_bytes(&mut secret).map_err(keygen_err)?;
        if !secret.contains(&0u8) {
            return Ok(bytes_to_raw_string(&secret));
        }
    }
}

/// Generates a signer key pair (ECDSA P-256, or RSA >= 2048 bits per
/// `KeyAlgorithm`) and issues an X.509 certificate for it via OpenSSL, signed
/// by a single shared root CA (so verifiers trust one root instead of every
/// individual signer's own certificate) — with the signer's name, birthdate,
/// and national ID baked into the certificate subject. National ID goes in
/// `serialNumber` as `IDC-<13 digits>`, per ETDA ขมธอ. 15-2566's subscriber
/// certificate profile (which also specifies RSA >= 2048 bits for a natural
/// person subscriber key — `KeyAlgorithm::EcdsaP256` remains the default for
/// backward compatibility, since that profile is a non-binding recommendation).
pub struct OpensslKeyGenerator {
    root_key: PKey<Private>,
    root_cert: X509,
}

impl OpensslKeyGenerator {
    pub fn new(root_key: PKey<Private>, root_cert: X509) -> Self {
        Self { root_key, root_cert }
    }
}

impl KeyGenerator for OpensslKeyGenerator {
    fn generate(
        &self,
        identity: &SignerIdentity,
        protection: Option<&str>,
        algorithm: KeyAlgorithm,
    ) -> Result<KeyPair, CoreError> {
        // openssl's Pkcs12Builder::name() panics on an embedded NUL byte
        // (CString::new().unwrap() internally), and a JSON string field can
        // legally contain one. Reject up front instead of crashing the worker.
        if identity.first_name.contains('\0') || identity.last_name.contains('\0') {
            return Err(CoreError::KeyGeneration(
                "first_name/last_name must not contain a NUL byte".into(),
            ));
        }
        if identity.country.len() != 2 || !identity.country.bytes().all(|b| b.is_ascii_uppercase()) {
            return Err(CoreError::KeyGeneration(
                "country must be a 2-letter uppercase ISO 3166-1 alpha-2 code (e.g. \"TH\")".into(),
            ));
        }
        if identity.national_id.len() != 13 || !identity.national_id.bytes().all(|b| b.is_ascii_digit()) {
            return Err(CoreError::KeyGeneration(
                "national_id must be exactly 13 ASCII digits (Thai national ID format)".into(),
            ));
        }
        if let KeyAlgorithm::Rsa { bits } = algorithm {
            if bits < MIN_RSA_BITS {
                return Err(CoreError::KeyGeneration(format!(
                    "rsa key size must be at least {MIN_RSA_BITS} bits (ETDA ขมธอ. 15-2566 minimum for a natural person certificate)"
                )));
            }
        }

        let pkey = match algorithm {
            KeyAlgorithm::EcdsaP256 => {
                let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(keygen_err)?;
                let ec_key = EcKey::generate(&group).map_err(keygen_err)?;
                PKey::from_ec_key(ec_key).map_err(keygen_err)?
            }
            KeyAlgorithm::Rsa { bits } => {
                let rsa = Rsa::generate(bits).map_err(keygen_err)?;
                PKey::from_rsa(rsa).map_err(keygen_err)?
            }
        };

        let mut name_builder = X509Name::builder().map_err(keygen_err)?;
        name_builder
            .append_entry_by_text("C", &identity.country)
            .map_err(keygen_err)?;
        name_builder
            .append_entry_by_text(
                "CN",
                &format!("{} {}", identity.first_name, identity.last_name),
            )
            .map_err(keygen_err)?;
        name_builder
            .append_entry_by_text("GN", &identity.first_name)
            .map_err(keygen_err)?;
        name_builder
            .append_entry_by_text("SN", &identity.last_name)
            .map_err(keygen_err)?;
        // ETDA ขมธอ. 15-2566 §4.1 (Subscriber Certificate Profile v2.0) specifies
        // subject.serialNumber as the identity-linking field, formatted
        // "IDC-<13-digit national ID>" for a natural person. Birthdate moves
        // to `description` to make room — ETDA's profile doesn't reserve
        // serialNumber for it, that was this service's own earlier choice.
        name_builder
            .append_entry_by_text("serialNumber", &format!("IDC-{}", identity.national_id))
            .map_err(keygen_err)?;
        name_builder
            .append_entry_by_text(
                "description",
                &format!(
                    "{:04}{:02}{:02}",
                    identity.birth_year, identity.birth_month, identity.birth_day
                ),
            )
            .map_err(keygen_err)?;
        let name = name_builder.build();

        let mut builder = X509::builder().map_err(keygen_err)?;
        builder.set_version(2).map_err(keygen_err)?;

        let mut serial = BigNum::new().map_err(keygen_err)?;
        serial
            .rand(159, MsbOption::MAYBE_ZERO, false)
            .map_err(keygen_err)?;
        let serial = serial.to_asn1_integer().map_err(keygen_err)?;
        builder.set_serial_number(&serial).map_err(keygen_err)?;

        builder.set_subject_name(&name).map_err(keygen_err)?;
        builder
            .set_issuer_name(self.root_cert.subject_name())
            .map_err(keygen_err)?;
        builder.set_pubkey(&pkey).map_err(keygen_err)?;

        let not_before = Asn1Time::days_from_now(0).map_err(keygen_err)?;
        builder.set_not_before(&not_before).map_err(keygen_err)?;
        let not_after = Asn1Time::days_from_now(3650).map_err(keygen_err)?;
        builder.set_not_after(&not_after).map_err(keygen_err)?;

        builder
            .append_extension(BasicConstraints::new().critical().build().map_err(keygen_err)?)
            .map_err(keygen_err)?;
        builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .digital_signature()
                    .non_repudiation()
                    .build()
                    .map_err(keygen_err)?,
            )
            .map_err(keygen_err)?;

        builder
            .sign(&self.root_key, MessageDigest::sha256())
            .map_err(keygen_err)?;
        let certificate = builder.build();

        let derived_key = match protection {
            Some(seed) => derive_key(seed)?,
            None => random_key()?,
        };

        let mut ca_stack = Stack::new().map_err(keygen_err)?;
        ca_stack.push(self.root_cert.clone()).map_err(keygen_err)?;

        let mut pkcs12_builder = Pkcs12::builder();
        pkcs12_builder
            .name(&format!("{} {}", identity.first_name, identity.last_name))
            .pkey(&pkey)
            .cert(&certificate)
            .ca(ca_stack);
        let pkcs12 = pkcs12_builder.build2(&derived_key).map_err(keygen_err)?;
        let pkcs12_der = pkcs12.to_der().map_err(keygen_err)?;

        Ok(KeyPair {
            pkcs12_der,
            derived_key,
        })
    }
}
