/// PDF "open password" encryption algorithm for `PdfLocker::lock`'s
/// `algorithm` parameter (see `SignatureSpec`'s sibling concept
/// `KeyAlgorithm` for the analogous choice on the signing key itself).
///
/// `Rc4_128` is the default for backward compatibility with this feature's
/// first release, which only ever offered RC4 (a fixed-length-preserving
/// stream cipher, which is *why* it was first — the signing pipeline's
/// reserve-then-patch `/Contents` scheme needs a predictable size). AES
/// support came after that constraint was worked around (see
/// `infrastructure`'s `encryption.rs`/`incremental.rs`) — prefer `Aes128`
/// for anything new; RC4 is a broken cipher kept only so existing callers
/// who already pass `lock_with_national_id: true` don't silently change
/// behavior.
///
/// `Aes256` is currently REJECTED at the infrastructure layer
/// (`encryption.rs`), not offered: the underlying `lopdf` 0.44.0 (latest
/// available) produces V5/R6-encrypted PDFs that are cryptographically
/// correct — verified independently, byte-for-byte, outside of lopdf's own
/// code — yet unreadable by real-world viewers (confirmed against
/// Poppler's `pdfinfo`/`pdftotext`). The variant is kept so this can be
/// re-enabled without a wire-format break once that's fixed upstream.
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
