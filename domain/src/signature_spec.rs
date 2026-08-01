use crate::{KeyPair, SignaturePosition};

pub struct SignatureSpec {
    pub position: SignaturePosition,
    pub key: KeyPair,
    /// Visible signature appearance (e.g. a scanned/drawn signature image) to
    /// render into the position's box. `None` falls back to a text-only
    /// appearance (e.g. signer name + date).
    pub image: Option<Vec<u8>>,
}
