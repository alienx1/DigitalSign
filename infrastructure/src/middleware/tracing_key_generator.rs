use application_core::{CoreError, KeyGenerator};
use domain::{KeyPair, SignerIdentity};

/// Wraps any `KeyGenerator` with an audit-trail log — key generation is a
/// security-relevant event that must be traceable.
pub struct TracingKeyGenerator<G> {
    inner: G,
}

impl<G: KeyGenerator> TracingKeyGenerator<G> {
    pub fn new(inner: G) -> Self {
        Self { inner }
    }
}

impl<G: KeyGenerator> KeyGenerator for TracingKeyGenerator<G> {
    fn generate(&self, identity: &SignerIdentity, protection: Option<&str>) -> Result<KeyPair, CoreError> {
        let result = self.inner.generate(identity, protection);
        match &result {
            Ok(_) => tracing::info!(
                first_name = %identity.first_name,
                last_name = %identity.last_name,
                caller_supplied_protection = protection.is_some(),
                "key pair generated"
            ),
            Err(e) => tracing::error!(error = %e, "key generation failed"),
        }
        result
    }
}
