//! Framework-neutral HTTP request-target adapters for Keylix.
//!
//! The `DPoP` core deliberately never trusts forwarding headers. This crate keeps
//! that trust decision in an adapter layer: direct deployments provide trusted
//! request parts explicitly, while proxy-aware deployments inject an immediate-
//! peer trust policy and opt into exactly one forwarding-header family.

#![forbid(unsafe_code)]

use core::fmt;

use keylix_dpop::EffectiveRequestTarget;

const MAX_FORWARDING_VALUE_BYTES: usize = 1_024;
const MAX_EXTERNAL_PATH_BYTES: usize = 2_048;

/// Forwarding-header convention accepted by a trusted-proxy resolver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyHeaderFamily {
    /// RFC 7239-style `Forwarded: proto=...;host=...` metadata.
    Forwarded,
    /// Single-valued `X-Forwarded-Proto` and `X-Forwarded-Host` metadata.
    XForwarded,
}

/// Framework- or deployment-owned decision about whether an immediate peer is trusted.
///
/// Implementations can use a socket address, mTLS identity, workload identity,
/// gateway attestation, or another host-specific peer type. Keylix does not infer
/// trust from the presence of forwarding headers.
pub trait ProxyTrust<P> {
    /// Returns true only when the immediate peer is authorized to supply external-target metadata.
    fn is_trusted_proxy(&self, peer: &P) -> bool;
}

/// Raw forwarding metadata observed by the HTTP framework.
///
/// The resolver rejects mixed header families and multi-hop values. Values are
/// intentionally not exposed through `Debug` to avoid accidentally reflecting
/// attacker-controlled request metadata into diagnostics.
#[derive(Clone, Copy, Default)]
pub struct ForwardingHeaders<'a> {
    forwarded: Option<&'a str>,
    x_forwarded_proto: Option<&'a str>,
    x_forwarded_host: Option<&'a str>,
}

impl<'a> ForwardingHeaders<'a> {
    /// Creates an empty forwarding-header set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            forwarded: None,
            x_forwarded_proto: None,
            x_forwarded_host: None,
        }
    }

    /// Adds one framework-coalesced `Forwarded` header value.
    #[must_use]
    pub const fn with_forwarded(mut self, value: &'a str) -> Self {
        self.forwarded = Some(value);
        self
    }

    /// Adds one framework-coalesced `X-Forwarded-Proto` value.
    #[must_use]
    pub const fn with_x_forwarded_proto(mut self, value: &'a str) -> Self {
        self.x_forwarded_proto = Some(value);
        self
    }

    /// Adds one framework-coalesced `X-Forwarded-Host` value.
    #[must_use]
    pub const fn with_x_forwarded_host(mut self, value: &'a str) -> Self {
        self.x_forwarded_host = Some(value);
        self
    }
}

impl fmt::Debug for ForwardingHeaders<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ForwardingHeaders")
            .field("has_forwarded", &self.forwarded.is_some())
            .field("has_x_forwarded_proto", &self.x_forwarded_proto.is_some())
            .field("has_x_forwarded_host", &self.x_forwarded_host.is_some())
            .finish()
    }
}

/// Fail-closed errors produced while establishing a trusted external request target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HttpTargetError {
    /// Proxy-aware mode was selected but the immediate peer was not trusted.
    UntrustedProxy,
    /// Required forwarding metadata was absent.
    MissingForwardingMetadata,
    /// More than one forwarding family or hop was supplied.
    AmbiguousForwardingMetadata,
    /// Forwarding metadata was malformed or outside the supported v0.1 profile.
    InvalidForwardingMetadata,
    /// Trusted request parts could not form a valid HTTP(S) effective target.
    InvalidRequestTarget,
}

impl fmt::Display for HttpTargetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UntrustedProxy => "immediate peer is not a trusted proxy",
            Self::MissingForwardingMetadata => "required forwarding metadata is missing",
            Self::AmbiguousForwardingMetadata => "forwarding metadata is ambiguous",
            Self::InvalidForwardingMetadata => "forwarding metadata is invalid",
            Self::InvalidRequestTarget => "trusted request target is invalid",
        })
    }
}

impl std::error::Error for HttpTargetError {}

/// Resolves a directly observed external request target.
///
/// No forwarding headers are accepted by this API. The host must supply the
/// externally visible scheme, authority, and path/query from directly trusted
/// request/server context.
///
/// # Errors
///
/// Returns [`HttpTargetError::InvalidRequestTarget`] if the supplied trusted
/// parts do not form a valid absolute HTTP(S) target.
pub fn resolve_direct_target(
    scheme: &str,
    authority: &str,
    external_path_and_query: &str,
) -> Result<EffectiveRequestTarget, HttpTargetError> {
    build_target(scheme, authority, external_path_and_query)
}

/// Resolves an external target only after an injected immediate-peer trust check.
pub struct TrustedProxyTargetResolver<T> {
    trust: T,
    family: ProxyHeaderFamily,
}

impl<T> TrustedProxyTargetResolver<T> {
    /// Creates a resolver for one explicitly selected forwarding-header family.
    #[must_use]
    pub const fn new(trust: T, family: ProxyHeaderFamily) -> Self {
        Self { trust, family }
    }
}

impl<T> fmt::Debug for TrustedProxyTargetResolver<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedProxyTargetResolver")
            .field("family", &self.family)
            .field("trust", &"[host policy]")
            .finish()
    }
}

impl<T> TrustedProxyTargetResolver<T> {
    /// Resolves a single-hop trusted-proxy target.
    ///
    /// `external_path_and_query` must already represent the externally visible
    /// path/query according to the deployment. The generic adapter does not guess
    /// path-rewrite behavior from proxy headers.
    ///
    /// # Errors
    ///
    /// Fails closed when the immediate peer is untrusted, forwarding families are
    /// mixed, multiple hops are present, required metadata is missing, metadata is
    /// malformed, or the reconstructed target is not valid HTTP(S).
    pub fn resolve<P>(
        &self,
        peer: &P,
        external_path_and_query: &str,
        headers: &ForwardingHeaders<'_>,
    ) -> Result<EffectiveRequestTarget, HttpTargetError>
    where
        T: ProxyTrust<P>,
    {
        if !self.trust.is_trusted_proxy(peer) {
            return Err(HttpTargetError::UntrustedProxy);
        }

        let (scheme, authority) = match self.family {
            ProxyHeaderFamily::Forwarded => resolve_forwarded(headers)?,
            ProxyHeaderFamily::XForwarded => resolve_x_forwarded(headers)?,
        };
        build_target(scheme, authority, external_path_and_query)
    }
}

fn resolve_forwarded<'a>(
    headers: &'a ForwardingHeaders<'a>,
) -> Result<(&'a str, &'a str), HttpTargetError> {
    if headers.x_forwarded_proto.is_some() || headers.x_forwarded_host.is_some() {
        return Err(HttpTargetError::AmbiguousForwardingMetadata);
    }
    let raw = headers
        .forwarded
        .ok_or(HttpTargetError::MissingForwardingMetadata)?;
    parse_single_forwarded(raw)
}

fn resolve_x_forwarded<'a>(
    headers: &'a ForwardingHeaders<'a>,
) -> Result<(&'a str, &'a str), HttpTargetError> {
    if headers.forwarded.is_some() {
        return Err(HttpTargetError::AmbiguousForwardingMetadata);
    }
    let proto = headers
        .x_forwarded_proto
        .ok_or(HttpTargetError::MissingForwardingMetadata)?;
    let host = headers
        .x_forwarded_host
        .ok_or(HttpTargetError::MissingForwardingMetadata)?;
    Ok((
        single_forwarding_value(proto)?,
        single_forwarding_value(host)?,
    ))
}

fn parse_single_forwarded(raw: &str) -> Result<(&str, &str), HttpTargetError> {
    let raw = checked_forwarding_value(raw)?;
    if raw.contains(',') || raw.contains(['"', '\\']) {
        return Err(HttpTargetError::AmbiguousForwardingMetadata);
    }

    let mut proto = None;
    let mut host = None;
    for parameter in raw.split(';') {
        let parameter = trim_ows(parameter);
        let (name, value) = parameter
            .split_once('=')
            .ok_or(HttpTargetError::InvalidForwardingMetadata)?;
        let name = trim_ows(name);
        let value = trim_ows(value);
        if name.is_empty()
            || value.is_empty()
            || !name.bytes().all(is_header_token_byte)
            || value.bytes().any(is_invalid_header_value_byte)
        {
            return Err(HttpTargetError::InvalidForwardingMetadata);
        }
        if name.eq_ignore_ascii_case("proto") {
            if proto.replace(value).is_some() {
                return Err(HttpTargetError::AmbiguousForwardingMetadata);
            }
        } else if name.eq_ignore_ascii_case("host") && host.replace(value).is_some() {
            return Err(HttpTargetError::AmbiguousForwardingMetadata);
        }
    }

    Ok((
        proto.ok_or(HttpTargetError::MissingForwardingMetadata)?,
        host.ok_or(HttpTargetError::MissingForwardingMetadata)?,
    ))
}

fn single_forwarding_value(raw: &str) -> Result<&str, HttpTargetError> {
    let value = checked_forwarding_value(raw)?;
    if value.contains(',') {
        return Err(HttpTargetError::AmbiguousForwardingMetadata);
    }
    if value.bytes().any(is_invalid_header_value_byte) {
        return Err(HttpTargetError::InvalidForwardingMetadata);
    }
    Ok(value)
}

fn checked_forwarding_value(raw: &str) -> Result<&str, HttpTargetError> {
    if raw.is_empty() || raw.len() > MAX_FORWARDING_VALUE_BYTES || !raw.is_ascii() {
        return Err(HttpTargetError::InvalidForwardingMetadata);
    }
    let trimmed = trim_ows(raw);
    if trimmed.is_empty() {
        return Err(HttpTargetError::InvalidForwardingMetadata);
    }
    Ok(trimmed)
}

fn build_target(
    scheme: &str,
    authority: &str,
    external_path_and_query: &str,
) -> Result<EffectiveRequestTarget, HttpTargetError> {
    if scheme.is_empty()
        || scheme.len() > MAX_FORWARDING_VALUE_BYTES
        || authority.is_empty()
        || authority.len() > MAX_FORWARDING_VALUE_BYTES
        || external_path_and_query.is_empty()
        || external_path_and_query.len() > MAX_EXTERNAL_PATH_BYTES
        || !scheme.is_ascii()
        || !authority.is_ascii()
        || !external_path_and_query.is_ascii()
        || !external_path_and_query.starts_with('/')
        || external_path_and_query.contains('#')
        || authority.contains(['/', '?', '#'])
        || scheme.bytes().any(is_invalid_header_value_byte)
        || authority.bytes().any(is_invalid_header_value_byte)
        || external_path_and_query
            .bytes()
            .any(is_invalid_request_target_byte)
    {
        return Err(HttpTargetError::InvalidRequestTarget);
    }

    let mut absolute = String::with_capacity(
        scheme.len() + authority.len() + external_path_and_query.len() + "://".len(),
    );
    absolute.push_str(scheme);
    absolute.push_str("://");
    absolute.push_str(authority);
    absolute.push_str(external_path_and_query);
    EffectiveRequestTarget::parse(&absolute).map_err(|_| HttpTargetError::InvalidRequestTarget)
}

fn trim_ows(value: &str) -> &str {
    value.trim_matches(|character| matches!(character, ' ' | '\t'))
}

const fn is_invalid_header_value_byte(byte: u8) -> bool {
    byte <= 0x20 || byte == 0x7f
}

const fn is_invalid_request_target_byte(byte: u8) -> bool {
    byte <= 0x20 || byte == 0x7f
}

const fn is_header_token_byte(byte: u8) -> bool {
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
