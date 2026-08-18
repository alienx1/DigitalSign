use crate::features::key_generator::GenerateKeyPairUseCase;
use application_core::{CoreError, KeyGenerator};
use domain::{KeyAlgorithm, KeyPair, SignerIdentity};
use std::sync::Arc;

pub struct GenerateKeyPairService {
    generator: Arc<dyn KeyGenerator>,
}

impl GenerateKeyPairService {
    pub fn new(generator: Arc<dyn KeyGenerator>) -> Self {
        Self { generator }
    }
}

impl GenerateKeyPairUseCase for GenerateKeyPairService {
    fn execute(
        &self,
        identity: SignerIdentity,
        protection: Option<String>,
        algorithm: KeyAlgorithm,
    ) -> Result<KeyPair, CoreError> {
        self.generator.generate(&identity, protection.as_deref(), algorithm)
    }
}
