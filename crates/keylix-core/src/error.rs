use core::fmt;

/// Errors produced while parsing or validating a public `P-256` `JWK`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum JwkError {
    /// The input was not valid JSON or contained ambiguous duplicate fields.
    InvalidJson,
    /// The JWK key type was not `EC`.
    UnsupportedKeyType,
    /// The JWK curve was not `P-256`.
    UnsupportedCurve,
    /// Private key material was present in a public-key input.
    PrivateKeyMaterial,
    /// A coordinate was not canonical unpadded base64url.
    InvalidCoordinateEncoding {
        /// The rejected coordinate name (`x` or `y`).
        coordinate: &'static str,
    },
    /// A decoded coordinate was not exactly 32 bytes.
    InvalidCoordinateLength {
        /// The rejected coordinate name (`x` or `y`).
        coordinate: &'static str,
    },
    /// The coordinates did not encode a valid public point on `P-256`.
    InvalidPublicPoint,
}

impl fmt::Display for JwkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson => formatter.write_str("invalid JWK JSON"),
            Self::UnsupportedKeyType => formatter.write_str("unsupported JWK key type"),
            Self::UnsupportedCurve => formatter.write_str("unsupported JWK curve"),
            Self::PrivateKeyMaterial => {
                formatter.write_str("private key material is not permitted in a public JWK")
            }
            Self::InvalidCoordinateEncoding { coordinate } => {
                write!(
                    formatter,
                    "invalid base64url encoding for JWK coordinate {coordinate}"
                )
            }
            Self::InvalidCoordinateLength { coordinate } => {
                write!(
                    formatter,
                    "invalid byte length for JWK coordinate {coordinate}"
                )
            }
            Self::InvalidPublicPoint => formatter.write_str("invalid P-256 public key point"),
        }
    }
}

impl std::error::Error for JwkError {}
