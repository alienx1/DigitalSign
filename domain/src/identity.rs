pub struct SignerIdentity {
    pub first_name: String,
    pub last_name: String,
    pub birth_day: u8,
    pub birth_month: u8,
    pub birth_year: u16,
    /// ISO 3166-1 alpha-2 country code (e.g. "TH", "US"), baked into the
    /// certificate subject's `C` attribute.
    pub country: String,
}
