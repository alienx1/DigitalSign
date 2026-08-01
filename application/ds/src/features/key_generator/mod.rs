pub mod commands;
pub mod models;

pub use commands::{key_generator_command, KeyGeneratorRequestModel};
pub use models::KeyGeneratorResponseModel;

use application_core::CoreError;
use domain::{KeyPair, SignerIdentity};

/// The "generate key pair" use case, called by handler/ds.
/// `protection`, if given, is used as the PKCS#12 password instead of
/// generating a random one.
pub trait GenerateKeyPairUseCase: Send + Sync {
    fn execute(&self, identity: SignerIdentity, protection: Option<String>) -> Result<KeyPair, CoreError>;
}
