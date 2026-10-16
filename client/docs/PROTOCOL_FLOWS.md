# Protocol Flows

> **Keylix Client scope.** Covers mobile/desktop SDK flows (bootstrap, attestation, token binding, nonce retry) only. The canonical protocol-level flows live in the public [`keylix-community`](https://github.com/hackelia-micrantha/keylix-community) repository: [docs/PROTOCOL_FLOWS.md](https://github.com/hackelia-micrantha/keylix-community/blob/main/docs/PROTOCOL_FLOWS.md). On any conflict, the public canonical source governs.

**Status:** design phase — initial baseline.

This document defines the normative protocol flows for Keylix Client, showing the exact message sequencing between the mobile SDK, the Digitalis attestation backend, the authorization server (AS), and the resource server (RS).

## 1. Bootstrap Flow (with Attestation)

The full high-assurance bootstrap flow. This is the "happy path" when attestation is required.

```mermaid
sequenceDiagram
    participant App as Mobile App
    participant SDK as Keylix Client
    participant Attestor as Platform Attestor<br/>(App Attest / Play Integrity)
    participant DI as Digitalis Backend
    participant KS as Secure Hardware<br/>(Enclave / StrongBox)

    App->>SDK: bootstrap(config { attestationRequired: true })

    Note over SDK: state = KEY_GENERATION

    SDK->>KS: generateKeyPair(alias: "dpop-proof-key")
    KS-->>SDK: KeyReference(alias)

    SDK->>KS: exportPublicKeyJwk(keyRef)
    KS-->>SDK: Jwk { kty, crv, x, y }

    Note over SDK: compute RFC 7638 thumbprint (jkt)

    Note over SDK: state = ATTESTING

    SDK->>DI: POST /verify<br/>{ contract_version, sdk_version, project_id }

    DI-->>SDK: { attestation_challenge: nonce, ttl }

    Note over SDK: bind attestation to the DPoP key

    SDK->>Attestor: generateAttestation(challenge, dpopPublicKey)
    Note right of Attestor: Android: setAttestationChallenge(publicKey)<br/>iOS: clientDataHash = SHA-256(publicKey)
    Attestor->>KS: create attestation evidence bound to existing key
    KS-->>Attestor: attestation artifact (cert chain / assertion)
    Attestor-->>SDK: attestation_token

    SDK->>DI: POST /verify<br/>{ attestation: attestation_token,<br/>  key_thumbprint: jkt }

    DI->>DI: verify evidence<br/>check key in attestation<br/>matches presented key<br/>evaluate policy

    alt verdict = ALLOW
        DI-->>SDK: { verdict: ALLOW, ttl: 1800, config_ref }

        Note over SDK: state = TRUSTED_ACTIVE

        SDK-->>App: BootstrapResult.Success(<br/>  keyThumbprint: jkt,<br/>  hardwareBacked: true,<br/>  attestation: ALLOW )

    else verdict = DENY
        DI-->>SDK: { verdict: DENY, reason: POLICY_DENIED }

        SDK->>KS: deleteKey(keyRef)
        Note over SDK: key destroyed; cannot be used

        SDK-->>App: BootstrapResult.Failure(<br/>  AttestationError.verdictDenied )
    end
```

## 2. Bootstrap Flow (without Attestation)

The standard bootstrap flow when attestation is not required. Faster, but lower assurance.

```mermaid
sequenceDiagram
    participant App as Mobile App
    participant SDK as Keylix Client
    participant KS as Secure Hardware

    App->>SDK: bootstrap(config { attestationRequired: false })

    Note over SDK: state = KEY_GENERATION

    KS->>KS: check secure hardware availability

    alt secure hardware available
        SDK->>KS: generateKeyPair(alias)
        KS-->>SDK: KeyReference
        SDK-->>App: BootstrapResult.Success(<br/>  keyThumbprint,<br/>  hardwareBacked: true )

    else secure hardware unavailable (ADR KXC-0005)
        SDK-->>App: BootstrapResult.HardwareUnavailable

        App->>App: prompt user for consent to software key

        alt user consents
            App->>SDK: bootstrapSoftwareFallback()
            SDK->>SW: generateSoftwareKeyPair()
            SW-->>SDK: KeyReference
            SDK-->>App: BootstrapResult.Success(<br/>  keyThumbprint,<br/>  hardwareBacked: false,<br/>  degraded: true )
        else user declines
            SDK-->>App: BootstrapResult.Failure(<br/>  KeyGenerationError.secureHardwareUnavailable )
        end
    end
```

## 3. Token Request Flow (OAuth + DPoP)

The flow where the mobile app obtains a DPoP-bound access token from the authorization server.

```mermaid
sequenceDiagram
    participant App as Mobile App
    participant SDK as Keylix Client
    participant AS as Authorization Server
    participant KS as Secure Hardware

    Note over App,AS: Step 1: Authorization Code Exchange

    App->>AS: GET /authorize?<br/>response_type=code<br/>&client_id=...<br/>&redirect_uri=...<br/>&code_challenge=... (PKCE)

    Note over AS: user authenticates

    AS-->>App: 302 redirect: authorization_code

    Note over App,AS: Step 2: Token Request with DPoP

    App->>SDK: createProof(ProofRequest(<br/>  method: "POST",<br/>  url: "https://as.example.com/token"<br/>))

    SDK->>KS: sign(jws_input, keyRef)
    KS-->>SDK: raw_signature

    SDK->>SDK: assemble JWS: header.payload.signature
    SDK-->>App: ProofResult.Success(proofJwt)

    App->>AS: POST /token<br/>grant_type=authorization_code<br/>&code=...<br/>&redirect_uri=...<br/>&code_verifier=... (PKCE)<br/>&client_id=...<br/><br/>DPoP: proofJwt

    Note over AS: validate DPoP proof<br/>validate auth code<br/>validate PKCE

    alt token request success
        AS-->>App: 200 OK<br/>{ token_type: "DPoP",<br/>  access_token: "eyJ...",<br/>  refresh_token: "eyJ...",<br/>  expires_in: 3600 }<br/>DPoP-Nonce: "nonce-value"

        App->>SDK: storeAccessToken(token, keyRef)
        App->>SDK: handleNonceResponse(nonce: "nonce-value", scope: AS)

        Note over SDK: NonceStore.asNonce = "nonce-value"
    else nonce required
        AS-->>App: 400 Bad Request<br/>{ error: "use_dpop_nonce" }
        App->>SDK: handleNonceChallenge(nonce, error)

        SDK->>SDK: NonceStore.asNonce = nonce
        SDK->>App: ProofResult.NonceRequired(nonce, error)
    end
```

## 4. Protected Resource Request Flow

The flow for making an API call with a DPoP-bound access token.

```mermaid
sequenceDiagram
    participant App as Mobile App
    participant SDK as Keylix Client
    participant RS as Resource Server
    participant KS as Secure Hardware

    App->>SDK: createProof(ProofRequest(<br/>  method: "GET",<br/>  url: "https://api.example.com/resource",<br/>  accessToken: "eyJ..." (optional),<br/>  nonce: NonceStore.rsNonce ))

    SDK->>SDK: compute ath = base64url(sha256(accessToken))
    SDK->>SDK: build JWS input with htm, htu, iat, jti, ath?, nonce?

    SDK->>KS: sign(jws_input, keyRef)
    KS-->>SDK: raw_signature

    SDK->>SDK: assemble JWS
    SDK-->>App: ProofResult.Success(proofJwt)

    App->>RS: GET /resource<br/>Authorization: DPoP eyJ...<br/>DPoP: proofJwt

    Note over RS: verify DPoP proof<br/>verify access token binding<br/>check cnf.jkt matches<br/>check replay

    alt request success
        RS-->>App: 200 OK { resource }
    else nonce required
        RS-->>App: 401 Unauthorized<br/>WWW-Authenticate: DPoP error="use_dpop_nonce"<br/>DPoP-Nonce: "new-nonce"

        App->>SDK: handleNonceChallenge(nonce: "new-nonce", scope: RS)
        SDK->>SDK: NonceStore.rsNonce = "new-nonce"
        SDK-->>App: ProofResult.NonceRequired(nonce, error)
    else token expired
        RS-->>App: 401 Unauthorized<br/>{ error: "invalid_token" }
        Note over App: initiate token refresh
    end
```

## 5. Nonce Retry Flow

The retry flow when the server requires or rotates a DPoP nonce.

```mermaid
sequenceDiagram
    participant App as Mobile App
    participant SDK as Keylix Client
    participant NonceStore as NonceStore
    participant Server as AS or RS
    participant KS as Secure Hardware

    App->>Server: request + DPoP proof (no stale nonce)

    Server-->>App: 401 / 400<br/>error: "use_dpop_nonce"<br/>DPoP-Nonce: "server-nonce"

    App->>SDK: handleNonceChallenge(<br/>  nonce: "server-nonce",<br/>  error: "use_dpop_nonce",<br/>  originalRequest: original )

    SDK->>NonceStore: setNonce("server-nonce", scope: server)
    NonceStore-->>SDK: stored

    SDK->>SDK: generate NEW jti (CSPRNG)
    SDK->>SDK: build JWS input with NEW jti + nonce

    SDK->>KS: sign(jws_input, keyRef)
    KS-->>SDK: raw_signature

    SDK->>SDK: assemble JWS (fresh proof, new jti, with nonce)
    SDK-->>App: ProofResult.Success(newProofJwt)

    App->>Server: request + Authorization: DPoP token<br/>DPoP: newProofJwt

    alt success + new nonce provided
        Server-->>App: 200 OK<br/>DPoP-Nonce: "rotated-nonce"
        App->>NonceStore: setNonce("rotated-nonce", scope: server)
    else success, no new nonce
        Server-->>App: 200 OK
        Note over NonceStore: nonce retained for next request
    end
```

## 6. Token Refresh Flow

When the access token expires, the mobile app refreshes it while maintaining DPoP binding.

```mermaid
sequenceDiagram
    participant App as Mobile App
    participant SDK as Keylix Client
    participant AS as Authorization Server
    participant KS as Secure Hardware

    Note over App: access token expired

    App->>SDK: createProof(ProofRequest(<br/>  method: "POST",<br/>  url: "https://as.example.com/token",<br/>  nonce: NonceStore.asNonce ))

    SDK->>KS: sign(jws_input, keyRef)
    KS-->>SDK: raw_signature
    SDK-->>App: ProofResult.Success(proofJwt)

    App->>AS: POST /token<br/>grant_type=refresh_token<br/>&refresh_token=...<br/>&client_id=...<br/><br/>DPoP: proofJwt

    Note over AS: validate refresh token<br/>validate DPoP proof<br/>validate proof key == bound key

    alt refresh success
        AS-->>App: 200 OK<br/>{ token_type: "DPoP",<br/>  access_token: "eyJ..." (new),<br/>  refresh_token: "eyJ..." (rotated?),<br/>  expires_in: 3600 }

        App->>SDK: storeAccessToken(newToken, keyRef)

        Note over SDK: SAME proof key continued<br/>per ADR key lifecycle
    else proof key mismatch
        AS-->>App: 400 Bad Request<br/>{ error: "invalid_grant" }
        Note over App: key rotation detected<br/>may need re-authorization
    end
```

## 7. Bootstrap State Machine

```mermaid
stateDiagram-v2
    [*] --> UNINITIALIZED
    UNINITIALIZED : no key, no config

    UNINITIALIZED --> KEY_GENERATION : bootstrap(config)
    KEY_GENERATION : generate DPoP key in secure hardware

    KEY_GENERATION --> ATTESTING : if attestationRequired
    KEY_GENERATION --> TRUSTED_ACTIVE : if no attestation (hardware key)
    KEY_GENERATION --> HARDWARE_UNAVAILABLE : secure hardware absent
    HARDWARE_UNAVAILABLE --> DEGRADED_KEY : user consents (software)
    HARDWARE_UNAVAILABLE --> BOOT_FAILED : user declines

    ATTESTING : bind attestation to DPoP key<br/>(challenge = publicKey)

    ATTESTING --> VERIFYING : evidence submitted
    VERIFYING : Digitalis backend verification

    VERIFYING --> TRUSTED_ACTIVE : verdict = ALLOW
    VERIFYING --> DENIED : verdict = DENY
    DENIED : delete DPoP key from secure hardware
    DENIED --> [*]

    TRUSTED_ACTIVE : proof generation ready<br/>(key attested if attestation was required)
    DEGRADED_KEY : software key (degraded: true)

    TRUSTED_ACTIVE --> [*]
    DEGRADED_KEY --> [*]
    BOOT_FAILED --> [*]
```

## 8. Proof Generation State Machine

```mermaid
stateDiagram-v2
    [*] --> IDLE

    IDLE --> BUILDING : createProof(request)
    BUILDING : construct JWS input<br/>(htm, htu, iat, jti, ath?, nonce?)

    BUILDING --> SIGNING : JWS input ready
    SIGNING : call SecureSigner.sign(keyRef, data)

    SIGNING --> SERIALIZED : signature returned
    SERIALIZED : assemble compact JWS

    SERIALIZED --> IDLE : return ProofResult.Success(proofJwt)

    SIGNING --> FAILED : hardware error / user cancel
    FAILED --> IDLE : return ProofResult.Failure(error)

    BUILDING --> NONCE_ERROR : nonce required but not present
    NONCE_ERROR --> IDLE : return ProofResult.NonceRequired(nonce)
```

## Key Invariants Across All Flows

1. **Fresh `jti` per proof.** Every call to `createProof` generates a new `jti`. Retries after nonce challenges ALWAYS use a new `jti`.

2. **Same key per bound session.** The refresh-token/DPoP-key relationship is stable. The SDK does not rotate the proof key mid-session.

3. **Nonce scoping.** AS nonce and RS nonce are independent. Each is only included in proofs sent to its respective server.

4. **`ath` is always current.** The access-token hash is computed from the exact token the caller is presenting — never from a cached/stale token.

5. **Proof key in JWK header.** The DPoP header contains the full public JWK, enabling the server to verify the signature and extract the `cnf.jkt` confirmation.

6. **No silent bearer fallback.** If proof generation fails, the request is not sent as bearer. The caller receives a `Failure` result.
