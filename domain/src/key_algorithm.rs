/// Signing key algorithm to generate for a signer identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAlgorithm {
    /// ECDSA P-256 — this service's original default.
    EcdsaP256,
    /// RSA with the given modulus size in bits. ETDA ขมธอ. 15-2566's
    /// subscriber certificate profile requires RSA of at least 2048 bits
    /// for a natural person certificate.
    Rsa { bits: u32 },
}

impl Default for KeyAlgorithm {
    fn default() -> Self {
        KeyAlgorithm::EcdsaP256
    }
}
