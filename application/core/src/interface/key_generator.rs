use crate::CoreError;
use domain::{KeyPair, SignerIdentity};

/// Driven port: produces a new signing identity (private key + certificate)
/// for the given signer. `protection`, if given, is used as the PKCS#12
/// password instead of generating a random one.
pub trait KeyGenerator: Send + Sync {
    fn generate(&self, identity: &SignerIdentity, protection: Option<&str>) -> Result<KeyPair, CoreError>;
}
