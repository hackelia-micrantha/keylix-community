//! Trusted HTTP request-target conformance and adversarial coverage.

use keylix_dpop::{
    AwsLcP256Signer, Clock, DpopError, DpopPortError, DpopProofBuilder, DpopRequest, DpopVerifier,
    InMemoryReplayStore, RandomProofIdGenerator, UnverifiedDpopProof, VerificationPolicy,
};
use keylix_http::{
    ForwardingHeaders, HttpTargetError, ProxyHeaderFamily, ProxyTrust, TrustedProxyTargetResolver,
    resolve_direct_target,
};

#[derive(Clone, Copy)]
struct FixedClock(i64);

impl Clock for FixedClock {
    fn unix_seconds(&self) -> Result<i64, DpopPortError> {
        Ok(self.0)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Peer(&'static str);

struct AllowPeer(&'static str);

impl ProxyTrust<Peer> for AllowPeer {
    fn is_trusted_proxy(&self, peer: &Peer) -> bool {
        peer.0 == self.0
    }
}

#[test]
fn kx_dpop_009_direct_and_trusted_proxy_resolve_same_external_target()
-> Result<(), Box<dyn std::error::Error>> {
    let direct = resolve_direct_target("HTTPS", "API.EXAMPLE.COM:443", "/a/../rpc?ignored=yes")?;
    assert_eq!(direct.as_str(), "https://api.example.com/rpc");

    let resolver =
        TrustedProxyTargetResolver::new(AllowPeer("proxy-a"), ProxyHeaderFamily::XForwarded);
    let headers = ForwardingHeaders::new()
        .with_x_forwarded_proto("https")
        .with_x_forwarded_host("api.example.com:443");
    let proxied = resolver.resolve(&Peer("proxy-a"), "/rpc?ignored=yes", &headers)?;

    assert_eq!(proxied, direct);
    Ok(())
}

#[test]
fn kx_dpop_009_untrusted_peer_cannot_spoof_forwarded_target() {
    let resolver =
        TrustedProxyTargetResolver::new(AllowPeer("trusted-proxy"), ProxyHeaderFamily::XForwarded);
    let hostile = ForwardingHeaders::new()
        .with_x_forwarded_proto("https")
        .with_x_forwarded_host("attacker.example");

    assert!(matches!(
        resolver.resolve(&Peer("internet-client"), "/rpc", &hostile),
        Err(HttpTargetError::UntrustedProxy)
    ));
}

#[test]
fn kx_dpop_009_ambiguous_or_multi_hop_forwarding_fails_closed() {
    let peer = Peer("proxy-a");
    let x_resolver =
        TrustedProxyTargetResolver::new(AllowPeer("proxy-a"), ProxyHeaderFamily::XForwarded);

    let multi_hop = ForwardingHeaders::new()
        .with_x_forwarded_proto("https, http")
        .with_x_forwarded_host("api.example.com, internal.example");
    assert!(matches!(
        x_resolver.resolve(&peer, "/rpc", &multi_hop),
        Err(HttpTargetError::AmbiguousForwardingMetadata)
    ));

    let mixed = ForwardingHeaders::new()
        .with_forwarded("proto=https;host=api.example.com")
        .with_x_forwarded_proto("https")
        .with_x_forwarded_host("api.example.com");
    assert!(matches!(
        x_resolver.resolve(&peer, "/rpc", &mixed),
        Err(HttpTargetError::AmbiguousForwardingMetadata)
    ));

    let forwarded_resolver =
        TrustedProxyTargetResolver::new(AllowPeer("proxy-a"), ProxyHeaderFamily::Forwarded);
    let forwarded_multi = ForwardingHeaders::new()
        .with_forwarded("proto=https;host=api.example.com, proto=http;host=internal.example");
    assert!(matches!(
        forwarded_resolver.resolve(&peer, "/rpc", &forwarded_multi),
        Err(HttpTargetError::AmbiguousForwardingMetadata)
    ));

    let duplicate =
        ForwardingHeaders::new().with_forwarded("proto=https;proto=http;host=api.example.com");
    assert!(matches!(
        forwarded_resolver.resolve(&peer, "/rpc", &duplicate),
        Err(HttpTargetError::AmbiguousForwardingMetadata)
    ));
}

#[test]
fn kx_dpop_009_resolved_external_target_drives_htu_verification()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = AwsLcP256Signer::generate()?;
    let clock = FixedClock(1_700_000_000);
    let ids = RandomProofIdGenerator;
    let client_target = resolve_direct_target("https", "api.example.com", "/rpc?client=1")?;
    let client_request = DpopRequest::new("POST", &client_target)?;
    let proof = DpopProofBuilder::new(&signer, &clock, &ids).build(&client_request)?;
    let parsed = UnverifiedDpopProof::parse(proof.as_header_value())?;
    let verifier = DpopVerifier::new(&clock, VerificationPolicy::default());

    let resolver =
        TrustedProxyTargetResolver::new(AllowPeer("proxy-a"), ProxyHeaderFamily::Forwarded);
    let correct =
        ForwardingHeaders::new().with_forwarded("for=192.0.2.1;proto=https;host=api.example.com");
    let external_target = resolver.resolve(&Peer("proxy-a"), "/rpc?proxy=ignored", &correct)?;
    let server_request = DpopRequest::new("POST", &external_target)?;
    let replay = InMemoryReplayStore::new(clock, 8)?;
    verifier.verify(&parsed, &server_request, &replay)?;

    let wrong = ForwardingHeaders::new().with_forwarded("proto=https;host=evil.example");
    let wrong_target = resolver.resolve(&Peer("proxy-a"), "/rpc", &wrong)?;
    let wrong_request = DpopRequest::new("POST", &wrong_target)?;
    let wrong_replay = InMemoryReplayStore::new(clock, 8)?;
    assert!(matches!(
        verifier.verify(&parsed, &wrong_request, &wrong_replay),
        Err(DpopError::TargetMismatch)
    ));
    Ok(())
}

#[test]
fn kx_dpop_009_authority_delimiter_injection_fails_closed() {
    let peer = Peer("proxy-a");
    let resolver =
        TrustedProxyTargetResolver::new(AllowPeer("proxy-a"), ProxyHeaderFamily::XForwarded);

    for hostile_host in [
        "api.example.com/attacker-path",
        "api.example.com?attacker-query",
        "api.example.com#attacker-fragment",
    ] {
        let headers = ForwardingHeaders::new()
            .with_x_forwarded_proto("https")
            .with_x_forwarded_host(hostile_host);
        assert!(matches!(
            resolver.resolve(&peer, "/rpc", &headers),
            Err(HttpTargetError::InvalidRequestTarget)
        ));
    }

    let forwarded =
        TrustedProxyTargetResolver::new(AllowPeer("proxy-a"), ProxyHeaderFamily::Forwarded);
    let headers =
        ForwardingHeaders::new().with_forwarded("proto=https;host=api.example.com/attacker-path");
    assert!(matches!(
        forwarded.resolve(&peer, "/rpc", &headers),
        Err(HttpTargetError::InvalidRequestTarget)
    ));
}
