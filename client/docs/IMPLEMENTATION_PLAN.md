# Implementation Plan

**Status:** design phase — initial baseline.

This document defines Keylix Client's phased implementation plan. Each phase has a concrete deliverable, entry criteria, exit criteria, and dependencies.

---

## Phase 0: Foundation (design hardening)

**Goal:** Make the design docs and conformance harness real enough that Phase 1 can start writing production code without ambiguity.

### Deliverables

| Item | Description | Owner |
|------|-------------|-------|
| Conformance vector corpus | JSON fixtures in `tests/consumed/`: 10+ valid proof cases, 10+ invalid cases, thumbprint vectors. Generated from `keylix-dpop` reference. | team |
| Shared test harness spec | Document defining the exact JSON schema for conformance vectors and the pass/fail contract each SDK must satisfy. | team |
| Proof vector generator | Script that pulls vectors from the `keylix` Rust workspace and normalizes them into `tests/consumed/proof-vectors.json`. | team |
| CI skeleton | GitHub Actions workflow (or equivalent) that: (1) lints markdown, (2) validates conformance vector schema, (3) placeholder for SDK test jobs. | team |
| API contract review | Cross-platform review of `docs/API_CONTRACT.md` — confirm every SDK owner agrees on type shapes, error semantics, and nonce behavior. | all |

### Exit Criteria

- [ ] `tests/consumed/proof-vectors.json` exists and passes schema validation.
- [ ] Every SDK owner has signed off on the API contract.
- [ ] CI runs on every PR (linting + vector validation, SDK tests are placeholders).

### Duration estimate

1–2 weeks.

---

## Phase 1: KMP Core + Android (first buildable target)

**Goal:** A working Android proof generator that passes the conformance corpus. This proves the security model, the API shape, and the signing-capability abstraction on the most complex platform.

### Milestones

#### M1.1: KMP core module (no platform deps)

```
sdks/kmp/
  src/commonMain/kotlin/com/micrantha/keylix/
    model/           — Jwk, ProofRequest, ProofResult, KeylixError, JwkThumbprint
    proof/           — ProofBuilder (RFC 9449, pure Kotlin, injectable deps)
    oauth/           — TokenBinding (ath computation), NonceStore
    internal/        — JwsCodec, JwkCodec, Thumbprint (RFC 7638)
  src/commonTest/kotlin/
    ProofBuilderTest.kt     — vector-based conformance
    JwkCodecTest.kt
    ThumbprintTest.kt
    NonceStoreTest.kt
```

**Entry:** Phase 0 complete.

**Exit:**
- `ProofBuilder` produces proofs that verify against `keylix-dpop` conformance vectors (using a test-only `SecureSigner` backed by a fixed key).
- `JwkCodec` roundtrips all JWK test vectors.
- `Thumbprint` matches RFC 7638 test vectors.
- All common tests pass.

#### M1.2: Android SecureSigner

```
sdks/android/
  src/main/kotlin/com/micrantha/keylix/storage/
    AndroidKeyStoreSigner.kt   — actual implementation
    SecureStorageManager.kt
  src/androidTest/kotlin/
    AndroidKeyStoreSignerTest.kt  — instrumentation: real key gen, signing
```

**Entry:** M1.1 complete.

**Exit:**
- Key generation in AndroidKeyStore succeeds (StrongBox on supported devices).
- Signature output is raw R||S (DER-to-raw conversion verified).
- Public key JWK export matches the proof's embedded JWK.
- `isHardwareBacked()` returns true on devices with secure hardware, false otherwise.

#### M1.3: Android KeylixClient + Bootstrap

```
sdks/android/
  src/main/kotlin/com/micrantha/keylix/
    KeylixClient.kt
    config/BootstrapConfig.kt
    attestation/DigitalisAttestation.kt  (stubbed; optional)
  src/androidTest/kotlin/
    KeylixClientTest.kt        — full bootstrap → proof → verify roundtrip
    AttestationStubTest.kt
```

**Entry:** M1.2 complete.

**Exit:**
- Full bootstrap → createProof → verify roundtrip passes on Android instrumented tests.
- Nonce challenge → retry flow works.
- Hardware unavailable → fallback consent flow works.
- All KXM-KEY, KXM-CORE, KXM-BIND, KXM-NONCE requirements covered.

#### M1.4: Conformance suite wired to CI

**Entry:** M1.3 complete.

**Exit:**
- CI runs instrumented Android tests on emulator.
- Conformance vectors from `tests/consumed/` are executed as part of the Android test suite.
- All vectors pass.

### Duration estimate

4–6 weeks (one engineer).

---

## Phase 2: iOS (Swift)

**Goal:** A working iOS proof generator that passes the same conformance corpus.

### Milestones

#### M2.1: iOS SDK skeleton + SecureSigner

```
sdks/ios/
  Sources/Keylix/
    Storage/SecureEnclaveSigner.swift
    Storage/SecureStorageManager.swift
    Model/ (Jwk, ProofResult, etc.)
    Internal/ (JwsCodec, JwkCodec, Thumbprint)
  Tests/
    SecureEnclaveSignerTests.swift
```

**Entry:** Phase 0 complete (independent of Phase 1, but benefits from lessons learned).

**Exit:**
- Secure Enclave key generation succeeds on device.
- Signature output is raw R||S (DER-to-raw conversion verified).
- Public key JWK export matches.

#### M2.2: iOS KeylixClient + ProofBuilder integration

**Entry:** M2.1 complete.

**Exit:**
- Full bootstrap → proof → verify roundtrip on iOS.
- ProofBuilder uses the same core algorithm as KMP (ported to Swift; verified via conformance vectors).
- Nonce handling works.
- Hardware unavailable (simulator) → fallback consent flow works.

#### M2.3: Conformance suite wired to iOS CI

**Exit:**
- CI runs iOS tests on macOS runner with simulator.
- Conformance vectors pass.

### Duration estimate

3–4 weeks (one engineer), running in parallel with Phase 1 if staffing allows.

---

## Phase 3: KMP iOS + KMP shared framework

**Goal:** Unify Android and iOS under a single KMP framework with `expect`/`actual` platform signers.

### Milestones

#### M3.1: KMP iOS actual implementation

```
sdks/kmp/src/iosMain/kotlin/
  SecureSignerIos.swift        — Swift implementation called via cinterop
  OR
  SecureSignerIos.kt           — Kotlin calling Security framework via cinterop
```

**Entry:** Phase 1 (Android) and Phase 2 (iOS) both complete.

**Exit:**
- KMP `expect SecureSigner` has `actual` implementations for both Android and iOS.
- Shared proof builder (KMP common) produces platform-native proofs.
- Same conformance vectors pass on both targets.

#### M3.2: KMP framework distribution

**Exit:**
- `sdks/kmp` produces an XCFramework for iOS and AAR for Android.
- Consumer apps can depend on the KMP module from both Kotlin (Android) and Swift (iOS).

### Duration estimate

2–3 weeks.

---

## Phase 4: React Native bridge

**Goal:** A React Native package that delegates to the native SDKs.

### Milestones

#### M4.1: RN module (Android bridge + iOS bridge)

```
sdks/react-native/
  src/index.ts, KeylixClient.ts, types.ts
  android/KeylixModule.kt      — wraps Android KeylixClient
  ios/KeylixModule.swift       — wraps iOS KeylixClient
  __tests__/KeylixClient.test.ts — mocked native tests
```

**Entry:** Phase 1 (Android) and Phase 2 (iOS) complete.

**Exit:**
- RN app can bootstrap, createProof, handleNonceChallenge.
- E2E test: RN app on device generates a verifiable proof.

#### M4.2: RN npm package + example app

**Exit:**
- Package published to npm (or local registry).
- Example RN app demonstrates full OAuth + DPoP flow.

### Duration estimate

2–3 weeks.

---

## Phase 5: Web + CLI adapters

**Goal:** Browser and desktop proof generation.

### Milestones

#### M5.1: Web adapter (TypeScript + WebCrypto)

```
adapters/web/
  src/KeylixClient.ts
  src/CryptoKeySigner.ts
  src/ProofBuilder.ts
  __tests__/*.test.ts
```

**Entry:** Phase 0 complete.

**Exit:**
- WebCrypto key generation (non-extractable).
- Proof generation passes conformance vectors.
- No hardware → no attestation; documented limitation.

#### M5.2: CLI adapter (Rust preferred; TS fallback)

```
adapters/cli-rust/
  src/main.rs                   — wraps keylix-core
  Cargo.toml
OR
adapters/cli-ts/
  src/KeylixClient.ts           — wraps keytar + crypto
```

**Entry:** Phase 0 complete (or Phase 1 for Rust path).

**Exit:**
- CLI can generate a DPoP proof from OS keychain-stored key.
- Useful for development/testing.

### Duration estimate

1–2 weeks each.

---

## Phase 6: Attestation integration (optional, policy-driven)

**Goal:** Digitalis attestation as an optional bootstrap layer.

### Milestones

#### M6.1: Android attestation bridge

```
sdks/android/src/main/kotlin/com/micrantha/keylix/attestation/
  DigitalisAttestation.kt       — real implementation calling Play Integrity
```

**Entry:** Phase 1 (Android working), Digitalis backend operational.

**Exit:**
- Attestation token obtained, sent to Digitalis, verdict received.
- Key generation happens FIRST (per ADR KXC-0004); the attestation challenge is bound to the generated key. Verdict = DENY → key is deleted; bootstrap fails.
- Verdict = DENY → bootstrap fails.

#### M6.2: iOS attestation bridge

```
sdks/ios/Sources/Keylix/Attestation/
  DigitalisAttestation.swift    — DCAppAttestService integration
```

**Entry:** Phase 2 (iOS working), Digitalis backend operational.

**Exit:**
- Same as M6.1 for iOS.

### Duration estimate

2–3 weeks per platform (attestation is tricky; budget time for platform quirks).

---

## Phase 7: Rust core FFI (deferred, see ADR KXC-0006)

**Goal:** Single Rust implementation shared across platforms via FFI.

**Entry criteria:**
1. Native implementations prove the API shape.
2. Conformance corpus is stable.
3. A clear need emerges (e.g., a platform that cannot implement the core natively).

### Duration estimate

Deferred. Re-evaluate after Phase 4.

---

## Dependency Graph

```text
Phase 0 (Foundation)
  ├──→ Phase 1 (KMP + Android)
  │      ├──→ Phase 3 (KMP iOS unification)
  │      ├──→ Phase 4 (React Native)  ←── Phase 2 (iOS)
  │      └──→ Phase 6 (Attestation)
  ├──→ Phase 2 (iOS) ──────────────────→ Phase 3, 4, 6
  ├──→ Phase 5 (Web + CLI)
  └──→ Phase 7 (Rust FFI, deferred)
```

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| DER-to-raw R||S conversion bugs on a platform | Medium | High | Conformance vectors catch this early; test on real devices |
| StrongBox fragmentation on Android | High | Medium | Graceful TEE fallback; document assurance levels |
| Secure Enclave key loss on iOS restore | Low | High | Document backup/restore behavior; key is device-bound |
| Attestation backend unavailable | Medium | Low | Attestation is optional; document fallback |
| KMP/Native iOS interop complexity | Medium | Medium | Start with cinterop; evaluate Kotlin/Native direct calls |
| Conformance drift between platforms | Medium | High | Shared vector corpus; CI gates on all platforms |
| NIST/OAuth spec evolution | Low | Medium | Profile-based design; algorithm agility for future |
| Attestation bypass techniques | Medium | High | Digitalis backend verifies; nonce binding; key attestation cert chain |

## Definition of Done (per platform)

A platform is "done" when:

1. [ ] All KXM-* requirements for that platform are implemented and covered by tests.
2. [ ] Conformance vectors pass (proof generation).
3. [ ] Roundtrip test passes (key gen → JWK → proof → verify).
4. [ ] Negative tests pass (every error variant).
5. [ ] Nonce flow test passes (challenge → retry).
6. [ ] Attestation integration works (if enabled).
7. [ ] Hardware fallback works (if applicable).
8. [ ] No sensitive data in logs (verified by log inspection test).
9. [ ] Public API documented with usage examples.
10. [ ] CI runs tests on every PR.
