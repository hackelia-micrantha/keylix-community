# Replay and Nonce State Stores

Keylix exposes replay and nonce state as explicit security capabilities. The bundled in-memory implementations are reference stores for tests and single-instance deployments; they are not cluster-safe.

## Security guarantees

`InMemoryReplayStore` implements one atomic process-local operation:

```text
check_and_record(replay_key, expires_at) -> Fresh | Replay | StoreFailure
```

The reference implementation serializes this operation with one process-local mutex. A duplicate proof submitted concurrently to the same process can therefore produce at most one `Fresh` result.

Replay state is fail-closed. Active markers are never evicted to admit another marker. When the configured capacity is exhausted after expired records have been removed, insertion fails rather than reopening the replay window.

Replay expiry is inclusive of the proof acceptance boundary. If a proof can still be accepted at `iat + max_proof_age`, its marker remains active through that second and may be removed only afterward. With the v0.1 default `max_proof_age = 300s` and `allowed_future_skew = 300s`, a newly accepted future-dated proof can require up to 600 seconds of remaining retention from the verifier's current clock.

## Topology and high availability

The reference stores advertise:

- topology: `SingleProcess`
- consistency: `ProcessLocalAtomic`

These guarantees do not extend across processes, hosts, replicas, or regions. A horizontally scaled protected resource must inject a shared `ReplayStore` whose atomicity and consistency cover every instance that may accept the same proof. Suitable implementations normally require a backend primitive equivalent to atomic insert-if-absent with expiry; a `contains` followed by `insert` sequence is not sufficient.

Distributed adapters must preserve the same fail-closed semantics. Store unavailability, loss of the required consistency guarantee, or capacity failure must not be reported as `Fresh` when strict replay protection is enabled.

## Capacity and memory behavior

Configured capacity is a logical upper bound, not an eager allocation request. The reference stores grow on demand up to that bound.

Choose capacities from the expected maximum number of simultaneously active proof identifiers or nonce contexts, including burst traffic and the full replay-retention window. Reaching the bound is intentionally visible as a dependency failure; Keylix does not silently evict active security state.

## Clock assumptions

Replay expiry uses the injected `Clock`. Deployments are responsible for maintaining a sufficiently synchronized and monotonic-enough wall clock for their configured proof-age/skew policy. Large backward jumps can retain markers longer; large forward jumps can expire them early and therefore undermine replay protection. Production deployments should monitor clock synchronization and use a shared time basis consistent with the verifier policy.

## Client nonce state

Client nonce state is keyed by `NonceContext`, which combines:

- `AuthorizationServer` or `ResourceServer` namespace; and
- an application-supplied stable server identifier.

The two namespaces are deliberately distinct even when the server identifier string is the same. A nonce learned from an authorization server is never implicitly reused for a resource server, and state from one server identifier is never reused for another.

A challenge establishes nonce state for that exact context. A successful response containing a new nonce rotates the stored value for the next request. A successful response without a nonce does not clear existing state; clearing is an explicit lifecycle action via `forget`. This prevents an established nonce requirement from silently downgrading back to nonce-less behavior.

Every retry is expected to build a fresh DPoP proof and therefore a fresh `jti`, even when only the nonce changed.

## Server nonce state

Server nonce enforcement is opt-in. Before a context has been issued a nonce, `expected_nonce` returns no requirement. Calling `issue_nonce` generates a fresh unpredictable nonce, stores it for that context, and establishes enforcement. A subsequent `issue_nonce` rotates the expected value; an older proof nonce is then stale.

The bundled `RandomNonceGenerator` uses 128 random bits encoded with unpadded base64url. Applications may inject another generator, but generated values must remain unpredictable and bounded.

Server nonce state and replay state are independent controls. Reusing a currently acceptable nonce does not permit reuse of an already-recorded proof identifier.

## Explicit credential handling

Nonce values are redacted from ordinary `Debug` output. `DpopNonce::as_header_value()` is the explicit credential-bearing accessor intended for `DPoP-Nonce` header emission. Callers should avoid logging or tracing that return value.
