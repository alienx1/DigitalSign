/// PDF "open password" encryption algorithm for `PdfSigner::sign`'s `lock`
/// parameter (see `SignatureSpec`'s sibling concept `KeyAlgorithm` for the
/// analogous choice on the signing key itself).
///
/// `Rc4_128` is the default for backward compatibility with this feature's
/// first release, which only ever offered RC4 (a fixed-length-preserving
/// stream cipher, which is *why* it was first — the signing pipeline's
/// reserve-then-patch `/Contents` scheme needs a predictable size). AES
/// support came after that constraint was worked around (see
/// `infrastructure`'s `encryption.rs`/`incremental.rs`) — prefer `Aes128` or
/// `Aes256` for anything new; RC4 is a broken cipher kept only so existing
/// callers who already pass `lock_with_national_id: true` don't silently
/// change behavior.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockAlgorithm {
    Rc4_128,
    Aes128,
    Aes256,
}

impl Default for LockAlgorithm {
    fn default() -> Self {
        LockAlgorithm::Rc4_128
    }
}
