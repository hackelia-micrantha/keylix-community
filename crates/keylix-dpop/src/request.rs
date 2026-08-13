use core::fmt;
use std::net::Ipv6Addr;

use crate::{DpopError, DpopNonce};

const MAX_TARGET_BYTES: usize = 2_048;
const MAX_METHOD_BYTES: usize = 64;

/// A trusted, normalized external HTTP(S) request target used for `DPoP` binding.
///
/// This type deliberately does not inspect forwarding headers. Host integrations
/// must first establish the externally visible target according to their direct
/// or trusted-proxy deployment policy and then construct this value.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct EffectiveRequestTarget(String);

impl EffectiveRequestTarget {
    /// Parses and normalizes an absolute HTTP(S) URI for `DPoP` `htu` comparison.
    ///
    /// Query and fragment components are removed. Scheme/host case, default
    /// ports, percent-encoding of unreserved characters, and dot segments are
    /// normalized according to the v0.1 request-target contract.
    ///
    /// # Errors
    ///
    /// Returns [`DpopError::InvalidRequestTarget`] for malformed, ambiguous, or
    /// unsupported targets.
    pub fn parse(input: &str) -> Result<Self, DpopError> {
        normalize_http_uri(input).map(Self)
    }

    /// Returns the normalized target string used for protocol comparison.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for EffectiveRequestTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EffectiveRequestTarget([redacted])")
    }
}

/// `DPoP` request context shared by proof construction and strict verification.
///
/// When `access_token` is present, the proof is treated as a protected-resource
/// proof and must contain a matching `ath`. When `nonce` is present, builders
/// include it and verifiers require an exact match.
pub struct DpopRequest<'a> {
    method: &'a str,
    target: &'a EffectiveRequestTarget,
    access_token: Option<&'a [u8]>,
    nonce: Option<&'a DpopNonce>,
}

impl<'a> DpopRequest<'a> {
    /// Creates a request context without an access token or required nonce.
    ///
    /// # Errors
    ///
    /// Returns [`DpopError::InvalidMethod`] when `method` is not a bounded HTTP
    /// token.
    pub fn new(method: &'a str, target: &'a EffectiveRequestTarget) -> Result<Self, DpopError> {
        validate_method(method)?;
        Ok(Self {
            method,
            target,
            access_token: None,
            nonce: None,
        })
    }

    /// Adds the exact access-token bytes presented on a protected-resource request.
    #[must_use]
    pub const fn with_access_token(mut self, access_token: &'a [u8]) -> Self {
        self.access_token = Some(access_token);
        self
    }

    /// Adds the nonce that should be included or required for this server context.
    #[must_use]
    pub const fn with_nonce(mut self, nonce: &'a DpopNonce) -> Self {
        self.nonce = Some(nonce);
        self
    }

    pub(crate) const fn method(&self) -> &str {
        self.method
    }

    pub(crate) const fn target(&self) -> &EffectiveRequestTarget {
        self.target
    }

    pub(crate) const fn access_token(&self) -> Option<&[u8]> {
        self.access_token
    }

    pub(crate) const fn nonce(&self) -> Option<&DpopNonce> {
        self.nonce
    }
}

impl fmt::Debug for DpopRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DpopRequest")
            .field("method", &self.method)
            .field("target", &"[redacted]")
            .field("has_access_token", &self.access_token.is_some())
            .field("has_nonce", &self.nonce.is_some())
            .finish()
    }
}

fn validate_method(method: &str) -> Result<(), DpopError> {
    if method.is_empty()
        || method.len() > MAX_METHOD_BYTES
        || !method.bytes().all(is_http_token_byte)
    {
        return Err(DpopError::InvalidMethod);
    }
    Ok(())
}

const fn is_http_token_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
            | b'0'..=b'9'
            | b'A'..=b'Z'
            | b'a'..=b'z'
    )
}

fn normalize_http_uri(input: &str) -> Result<String, DpopError> {
    if input.is_empty()
        || input.len() > MAX_TARGET_BYTES
        || !input.is_ascii()
        || input.bytes().any(|byte| byte <= 0x20 || byte == 0x7f)
    {
        return Err(DpopError::InvalidRequestTarget);
    }

    let scheme_end = input.find(':').ok_or(DpopError::InvalidRequestTarget)?;
    let raw_scheme = &input[..scheme_end];
    let scheme = if raw_scheme.eq_ignore_ascii_case("https") {
        "https"
    } else if raw_scheme.eq_ignore_ascii_case("http") {
        "http"
    } else {
        return Err(DpopError::InvalidRequestTarget);
    };

    let remainder = input
        .get((scheme_end + 1)..)
        .ok_or(DpopError::InvalidRequestTarget)?;
    let after_slashes = remainder
        .strip_prefix("//")
        .ok_or(DpopError::InvalidRequestTarget)?;
    let authority_end = find_first(after_slashes, &['/', '?', '#']).unwrap_or(after_slashes.len());
    let authority = &after_slashes[..authority_end];
    let suffix = &after_slashes[authority_end..];
    if authority.is_empty() || authority.contains('@') {
        return Err(DpopError::InvalidRequestTarget);
    }

    let (host, port) = normalize_authority(authority, scheme)?;
    let path_end = find_first(suffix, &['?', '#']).unwrap_or(suffix.len());
    let raw_path = &suffix[..path_end];
    if !raw_path.is_empty() && !raw_path.starts_with('/') {
        return Err(DpopError::InvalidRequestTarget);
    }

    let percent_normalized =
        normalize_percent_encoding(if raw_path.is_empty() { "/" } else { raw_path })?;
    let path = remove_dot_segments(&percent_normalized);
    let mut normalized = String::with_capacity(input.len());
    normalized.push_str(scheme);
    normalized.push_str("://");
    normalized.push_str(&host);
    if let Some(port) = port {
        normalized.push(':');
        normalized.push_str(&port.to_string());
    }
    normalized.push_str(if path.is_empty() { "/" } else { &path });
    Ok(normalized)
}

fn normalize_authority(authority: &str, scheme: &str) -> Result<(String, Option<u16>), DpopError> {
    let (host, port) = if authority.starts_with('[') {
        let close = authority.find(']').ok_or(DpopError::InvalidRequestTarget)?;
        let literal = &authority[1..close];
        let ipv6 = literal
            .parse::<Ipv6Addr>()
            .map_err(|_| DpopError::InvalidRequestTarget)?;
        let tail = &authority[(close + 1)..];
        let port = if tail.is_empty() {
            None
        } else {
            Some(parse_port(
                tail.strip_prefix(':')
                    .ok_or(DpopError::InvalidRequestTarget)?,
            )?)
        };
        (format!("[{ipv6}]"), port)
    } else {
        if authority.contains(['[', ']']) || authority.matches(':').count() > 1 {
            return Err(DpopError::InvalidRequestTarget);
        }
        let (raw_host, port) = match authority.rsplit_once(':') {
            Some((host, raw_port)) => (host, Some(parse_port(raw_port)?)),
            None => (authority, None),
        };
        if raw_host.is_empty() {
            return Err(DpopError::InvalidRequestTarget);
        }
        (normalize_reg_name_host(raw_host)?, port)
    };

    let port = match (scheme, port) {
        ("http", Some(80)) | ("https", Some(443)) => None,
        (_, value) => value,
    };
    Ok((host, port))
}

fn normalize_reg_name_host(raw_host: &str) -> Result<String, DpopError> {
    let normalized = normalize_percent_encoding(raw_host)?;
    normalize_percent_encoding(&normalized.to_ascii_lowercase())
}

fn parse_port(raw_port: &str) -> Result<u16, DpopError> {
    if raw_port.is_empty() || !raw_port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(DpopError::InvalidRequestTarget);
    }
    raw_port
        .parse::<u16>()
        .map_err(|_| DpopError::InvalidRequestTarget)
}

fn normalize_percent_encoding(input: &str) -> Result<String, DpopError> {
    let bytes = input.as_bytes();
    let mut output = String::with_capacity(input.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            output.push(char::from(bytes[index]));
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err(DpopError::InvalidRequestTarget);
        }
        let high = hex_value(bytes[index + 1]).ok_or(DpopError::InvalidRequestTarget)?;
        let low = hex_value(bytes[index + 2]).ok_or(DpopError::InvalidRequestTarget)?;
        let value = (high << 4) | low;
        if is_unreserved(value) {
            output.push(char::from(value));
        } else {
            output.push('%');
            output.push(hex_upper(high));
            output.push(hex_upper(low));
        }
        index += 3;
    }
    Ok(output)
}

const fn is_unreserved(byte: u8) -> bool {
    matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~')
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn hex_upper(value: u8) -> char {
    char::from(match value {
        0..=9 => b'0' + value,
        _ => b'A' + (value - 10),
    })
}

fn remove_dot_segments(path: &str) -> String {
    let mut input = path.to_owned();
    let mut output = String::with_capacity(path.len());

    while !input.is_empty() {
        if input.starts_with("../") {
            input.drain(..3);
        } else if input.starts_with("./") {
            input.drain(..2);
        } else if input.starts_with("/./") {
            input.replace_range(..3, "/");
        } else if input == "/." {
            input.replace_range(..2, "/");
        } else if input.starts_with("/../") {
            input.replace_range(..4, "/");
            remove_last_segment(&mut output);
        } else if input == "/.." {
            input.replace_range(..3, "/");
            remove_last_segment(&mut output);
        } else if input == "." || input == ".." {
            input.clear();
        } else {
            let segment_end = if let Some(stripped) = input.strip_prefix('/') {
                stripped
                    .find('/')
                    .map_or(input.len(), |position| position + 1)
            } else {
                input.find('/').unwrap_or(input.len())
            };
            output.push_str(&input[..segment_end]);
            input.drain(..segment_end);
        }
    }

    output
}

fn remove_last_segment(output: &mut String) {
    if let Some(position) = output.rfind('/') {
        output.truncate(position);
    } else {
        output.clear();
    }
}

fn find_first(input: &str, needles: &[char]) -> Option<usize> {
    input
        .char_indices()
        .find_map(|(index, value)| needles.contains(&value).then_some(index))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_rfc3986_http_target_components() -> Result<(), DpopError> {
        let target = EffectiveRequestTarget::parse(
            "HTTPS://Example.COM:443/a/./b/../%7ec?ignored=1#fragment",
        )?;
        assert_eq!(target.as_str(), "https://example.com/a/~c");
        Ok(())
    }

    #[test]
    fn preserves_reserved_percent_encoding_and_trailing_slash_distinction() -> Result<(), DpopError>
    {
        let encoded = EffectiveRequestTarget::parse("https://example.com/a%2fb")?;
        let slash = EffectiveRequestTarget::parse("https://example.com/a/b")?;
        let trailing = EffectiveRequestTarget::parse("https://example.com/a/b/")?;
        assert_eq!(encoded.as_str(), "https://example.com/a%2Fb");
        assert_ne!(encoded, slash);
        assert_ne!(slash, trailing);
        Ok(())
    }

    #[test]
    fn normalizes_host_case_and_percent_escape_case() -> Result<(), DpopError> {
        let target = EffectiveRequestTarget::parse("https://ExAmPle%2f.COM/a")?;
        assert_eq!(target.as_str(), "https://example%2F.com/a");
        Ok(())
    }

    #[test]
    fn normalizes_empty_path_and_default_http_port() -> Result<(), DpopError> {
        let target = EffectiveRequestTarget::parse("http://EXAMPLE.com:80?x=1")?;
        assert_eq!(target.as_str(), "http://example.com/");
        Ok(())
    }

    #[test]
    fn validates_and_canonicalizes_bracketed_ipv6() -> Result<(), DpopError> {
        let target = EffectiveRequestTarget::parse("https://[2001:0DB8:0:0:0:0:0:1]:443/a")?;
        assert_eq!(target.as_str(), "https://[2001:db8::1]/a");
        Ok(())
    }

    #[test]
    fn rejects_ambiguous_or_unsupported_targets() {
        for value in [
            "ftp://example.com/a",
            "https://user@example.com/a",
            "https://example.com/%zz",
            "https://example.com:99999/a",
            "https://2001:db8::1/a",
            "https://[not-an-ip]/a",
            "https://example].com/a",
        ] {
            assert_eq!(
                EffectiveRequestTarget::parse(value),
                Err(DpopError::InvalidRequestTarget)
            );
        }
    }

    #[test]
    fn method_validation_preserves_case_for_exact_binding() -> Result<(), DpopError> {
        let target = EffectiveRequestTarget::parse("https://example.com/")?;
        let upper = DpopRequest::new("GET", &target)?;
        let lower = DpopRequest::new("get", &target)?;
        assert_ne!(upper.method(), lower.method());
        assert!(matches!(
            DpopRequest::new("bad method", &target),
            Err(DpopError::InvalidMethod)
        ));
        Ok(())
    }
}
