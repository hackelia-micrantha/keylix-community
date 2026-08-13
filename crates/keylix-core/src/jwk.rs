use core::fmt;

use aws_lc_rs::{
    digest,
    signature::{ECDSA_P256_SHA256_FIXED, ParsedPublicKey},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error as _, IgnoredAny},
    ser::SerializeStruct,
};

use crate::{JwkError, JwkThumbprint};

const COORDINATE_BYTES: usize = 32;
const UNCOMPRESSED_POINT_BYTES: usize = 1 + (COORDINATE_BYTES * 2);

/// A validated public `EC` `P-256` JSON Web Key.
///
/// Coordinates are decoded into fixed-size byte arrays and validated as an
/// uncompressed `P-256` public point before this type can be constructed.
/// Optional JWK metadata is intentionally not retained because RFC 7638
/// excludes it from thumbprint calculation.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicP256Jwk {
    x: [u8; COORDINATE_BYTES],
    y: [u8; COORDINATE_BYTES],
}

impl PublicP256Jwk {
    /// Parses and validates a public `P-256` JWK from JSON.
    ///
    /// Unknown optional JWK members are ignored. A `d` member is rejected even
    /// when its JSON value is `null`, because this type is a public-key-only
    /// boundary.
    ///
    /// # Errors
    ///
    /// Returns [`JwkError`] for malformed/ambiguous JSON, unsupported key or
    /// curve identifiers, non-canonical coordinates, private key material, or
    /// coordinates that do not encode a valid `P-256` public point.
    pub fn from_json(input: &str) -> Result<Self, JwkError> {
        let wire =
            serde_json::from_str::<PublicP256JwkWire>(input).map_err(|_| JwkError::InvalidJson)?;
        Self::from_wire(&wire)
    }

    /// Returns the validated affine `x` coordinate bytes.
    #[must_use]
    pub const fn x_bytes(&self) -> &[u8; COORDINATE_BYTES] {
        &self.x
    }

    /// Returns the validated affine `y` coordinate bytes.
    #[must_use]
    pub const fn y_bytes(&self) -> &[u8; COORDINATE_BYTES] {
        &self.y
    }

    /// Computes the SHA-256 RFC 7638 thumbprint for this JWK.
    #[must_use]
    pub fn thumbprint(&self) -> JwkThumbprint {
        let canonical = self.canonical_thumbprint_input();
        let value = digest::digest(&digest::SHA256, canonical.as_bytes());
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(value.as_ref());
        JwkThumbprint::new(bytes)
    }

    fn from_wire(wire: &PublicP256JwkWire) -> Result<Self, JwkError> {
        if wire.private_member.0 {
            return Err(JwkError::PrivateKeyMaterial);
        }
        if wire.kty != "EC" {
            return Err(JwkError::UnsupportedKeyType);
        }
        if wire.crv != "P-256" {
            return Err(JwkError::UnsupportedCurve);
        }

        let x = decode_coordinate("x", &wire.x)?;
        let y = decode_coordinate("y", &wire.y)?;
        validate_public_point(&x, &y)?;

        Ok(Self { x, y })
    }

    fn canonical_thumbprint_input(&self) -> String {
        let x = URL_SAFE_NO_PAD.encode(self.x);
        let y = URL_SAFE_NO_PAD.encode(self.y);
        format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#)
    }
}

impl fmt::Debug for PublicP256Jwk {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicP256Jwk")
            .field("kty", &"EC")
            .field("crv", &"P-256")
            .field("coordinates", &"[redacted public key coordinates]")
            .finish()
    }
}

impl Serialize for PublicP256Jwk {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let x = URL_SAFE_NO_PAD.encode(self.x);
        let y = URL_SAFE_NO_PAD.encode(self.y);
        let mut state = serializer.serialize_struct("PublicP256Jwk", 4)?;
        state.serialize_field("kty", "EC")?;
        state.serialize_field("crv", "P-256")?;
        state.serialize_field("x", &x)?;
        state.serialize_field("y", &y)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for PublicP256Jwk {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = PublicP256JwkWire::deserialize(deserializer)?;
        Self::from_wire(&wire).map_err(D::Error::custom)
    }
}

#[derive(Deserialize)]
struct PublicP256JwkWire {
    kty: String,
    crv: String,
    x: String,
    y: String,
    #[serde(default, rename = "d")]
    private_member: PrivateMemberPresence,
}

#[derive(Default)]
struct PrivateMemberPresence(bool);

impl<'de> Deserialize<'de> for PrivateMemberPresence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let _ignored = IgnoredAny::deserialize(deserializer)?;
        Ok(Self(true))
    }
}

fn decode_coordinate(
    coordinate: &'static str,
    encoded: &str,
) -> Result<[u8; COORDINATE_BYTES], JwkError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| JwkError::InvalidCoordinateEncoding { coordinate })?;
    let bytes: [u8; COORDINATE_BYTES] = decoded
        .try_into()
        .map_err(|_| JwkError::InvalidCoordinateLength { coordinate })?;

    if URL_SAFE_NO_PAD.encode(bytes) != encoded {
        return Err(JwkError::InvalidCoordinateEncoding { coordinate });
    }

    Ok(bytes)
}

fn validate_public_point(
    x: &[u8; COORDINATE_BYTES],
    y: &[u8; COORDINATE_BYTES],
) -> Result<(), JwkError> {
    let mut point = [0_u8; UNCOMPRESSED_POINT_BYTES];
    point[0] = 0x04;
    point[1..=COORDINATE_BYTES].copy_from_slice(x);
    point[(COORDINATE_BYTES + 1)..].copy_from_slice(y);

    ParsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
        .map(|_| ())
        .map_err(|_| JwkError::InvalidPublicPoint)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_7515_X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
    const RFC_7515_Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";
    const RFC_7515_PUBLIC_THUMBPRINT: &str = "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U";

    fn public_jwk_json(extra: &str) -> String {
        format!(r#"{{"kty":"EC","crv":"P-256","x":"{RFC_7515_X}","y":"{RFC_7515_Y}"{extra}}}"#)
    }

    #[test]
    fn rfc_7515_public_key_has_expected_rfc_7638_thumbprint() -> Result<(), JwkError> {
        let jwk = PublicP256Jwk::from_json(&public_jwk_json(""))?;
        assert_eq!(jwk.thumbprint().to_base64url(), RFC_7515_PUBLIC_THUMBPRINT);
        Ok(())
    }

    #[test]
    fn optional_members_do_not_change_thumbprint() -> Result<(), JwkError> {
        let plain = PublicP256Jwk::from_json(&public_jwk_json(""))?;
        let decorated = PublicP256Jwk::from_json(&public_jwk_json(
            r#", "kid":"example", "alg":"ES256", "use":"sig""#,
        ))?;
        assert_eq!(plain.thumbprint(), decorated.thumbprint());
        Ok(())
    }

    #[test]
    fn member_order_and_whitespace_do_not_change_thumbprint() -> Result<(), JwkError> {
        let canonical = PublicP256Jwk::from_json(&public_jwk_json(""))?;
        let reordered = PublicP256Jwk::from_json(&format!(
            "{{\n  \"y\": \"{RFC_7515_Y}\",\n  \"x\": \"{RFC_7515_X}\",\n  \"kty\": \"EC\",\n  \"crv\": \"P-256\"\n}}"
        ))?;

        assert_eq!(canonical.thumbprint(), reordered.thumbprint());
        Ok(())
    }

    #[test]
    fn serialization_emits_public_required_members_only() -> Result<(), JwkError> {
        let jwk = PublicP256Jwk::from_json(&public_jwk_json(""))?;
        let serialized = serde_json::to_string(&jwk).map_err(|_| JwkError::InvalidJson)?;
        let reparsed = PublicP256Jwk::from_json(&serialized)?;

        assert_eq!(jwk, reparsed);
        assert!(!serialized.contains("\"d\""));
        assert!(serialized.contains("\"kty\":\"EC\""));
        assert!(serialized.contains("\"crv\":\"P-256\""));
        Ok(())
    }

    #[test]
    fn rejects_private_member_even_when_null() {
        assert_eq!(
            PublicP256Jwk::from_json(&public_jwk_json(r#", "d":null"#)),
            Err(JwkError::PrivateKeyMaterial)
        );
    }

    #[test]
    fn rejects_duplicate_required_member() {
        let json = format!(
            r#"{{"kty":"EC","crv":"P-256","x":"{RFC_7515_X}","x":"{RFC_7515_X}","y":"{RFC_7515_Y}"}}"#
        );
        assert_eq!(PublicP256Jwk::from_json(&json), Err(JwkError::InvalidJson));
    }

    #[test]
    fn rejects_missing_required_member() {
        let missing_y = format!(r#"{{"kty":"EC","crv":"P-256","x":"{RFC_7515_X}"}}"#);
        assert_eq!(
            PublicP256Jwk::from_json(&missing_y),
            Err(JwkError::InvalidJson)
        );
    }

    #[test]
    fn rejects_wrong_key_type_and_curve() {
        let wrong_type = public_jwk_json("").replace("\"EC\"", "\"RSA\"");
        let wrong_curve = public_jwk_json("").replace("\"P-256\"", "\"P-384\"");

        assert_eq!(
            PublicP256Jwk::from_json(&wrong_type),
            Err(JwkError::UnsupportedKeyType)
        );
        assert_eq!(
            PublicP256Jwk::from_json(&wrong_curve),
            Err(JwkError::UnsupportedCurve)
        );
    }

    #[test]
    fn rejects_malformed_coordinate_encoding() {
        let malformed = public_jwk_json("").replace(RFC_7515_X, "***");
        assert_eq!(
            PublicP256Jwk::from_json(&malformed),
            Err(JwkError::InvalidCoordinateEncoding { coordinate: "x" })
        );
    }

    #[test]
    fn rejects_noncanonical_or_wrong_length_coordinates() {
        let padded_x = format!("{RFC_7515_X}=");
        let padded = public_jwk_json("").replace(RFC_7515_X, &padded_x);
        let short = public_jwk_json("").replace(RFC_7515_X, "AA");

        assert_eq!(
            PublicP256Jwk::from_json(&padded),
            Err(JwkError::InvalidCoordinateEncoding { coordinate: "x" })
        );
        assert_eq!(
            PublicP256Jwk::from_json(&short),
            Err(JwkError::InvalidCoordinateLength { coordinate: "x" })
        );
    }

    #[test]
    fn rejects_invalid_public_point() {
        const ZERO_COORDINATE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let json = format!(
            r#"{{"kty":"EC","crv":"P-256","x":"{ZERO_COORDINATE}","y":"{ZERO_COORDINATE}"}}"#
        );
        assert_eq!(
            PublicP256Jwk::from_json(&json),
            Err(JwkError::InvalidPublicPoint)
        );
    }

    #[test]
    fn debug_output_does_not_expose_coordinates_or_thumbprint() -> Result<(), JwkError> {
        let jwk = PublicP256Jwk::from_json(&public_jwk_json(""))?;
        let thumbprint = jwk.thumbprint();
        let jwk_debug = format!("{jwk:?}");
        let thumbprint_debug = format!("{thumbprint:?}");

        assert!(!jwk_debug.contains(RFC_7515_X));
        assert!(!jwk_debug.contains(RFC_7515_Y));
        assert!(!thumbprint_debug.contains(&thumbprint.to_base64url()));
        Ok(())
    }
}
