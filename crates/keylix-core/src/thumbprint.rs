use core::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

/// A SHA-256 RFC 7638 `JWK` thumbprint.
///
/// The raw value is public-key-derived but is intentionally redacted from
/// `Debug` output because it is a stable correlator. Call [`Self::to_base64url`]
/// when an explicit protocol or evidence surface needs the value.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct JwkThumbprint([u8; 32]);

impl JwkThumbprint {
    pub(crate) const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw SHA-256 thumbprint bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Encodes the thumbprint as unpadded base64url for `cnf.jkt`-style use.
    #[must_use]
    pub fn to_base64url(self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }
}

impl fmt::Debug for JwkThumbprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JwkThumbprint([redacted])")
    }
}
