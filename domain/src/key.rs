/// A signing identity, packaged as a password-protected PKCS#12 bundle
/// (private key + certificate) plus the key needed to open it.
pub struct KeyPair {
    pub pkcs12_der: Vec<u8>,
    pub derived_key: String,
}
