pub struct UnsignedDocument {
    pub bytes: Vec<u8>,
}

pub struct SignedDocument {
    pub bytes: Vec<u8>,
}

/// A PDF locked with the ISO 32000-1 §7.6 Standard Security Handler.
/// `user_password` and `owner_password` are handed back to the caller
/// rather than silently kept server-side — the Standard Security Handler
/// has exactly these two independent opening passwords, so returning both
/// is how a caller learns what will actually open the file (they aren't
/// necessarily equal — see `PdfLocker`).
pub struct LockedDocument {
    pub bytes: Vec<u8>,
    pub user_password: String,
    pub owner_password: String,
}
