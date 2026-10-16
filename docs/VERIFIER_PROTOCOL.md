# Keylix verifier protocol v1

The packaged verifier is a sender-binding service. It does not validate Dubnium
credentials, construct application principals, authorize capabilities, or infer
trusted request targets from forwarding headers.

## Trust boundary

The reference host listens on a local Unix-domain socket. By default the socket
is created with mode 0600 in an owner-only service runtime directory. On Linux,
an explicit `--socket-group-gid GID` profile permits one separately isolated
local consumer group. The configured GID is trusted deployment input: the verifier process must
also have that GID as its filesystem GID or a supplementary group, and the
socket directory must already carry that exact group through setgid and be
traversal-only (02710); setuid/sticky bits and POSIX access/default ACLs are
rejected. The verifier process must start with umask 0117, so `bind(2)` creates
the socket as 0660 atomically. Startup acquires an owner-only exclusive lock in
the socket directory before stale-socket recovery and bind, then validates the
new socket's exact owner/GID/type/mode without mutating the directory's SGID or
publication mode. The group profile therefore remains compatible with service
sandboxes such as systemd `DynamicUser=yes` / `RestrictSUIDSGID=yes`, provided
the supervisor pre-provisions the 02710 runtime directory and process umask. A
second live verifier cannot mutate the socket path. In every profile each request is still HMAC-authenticated before the
inner host-validation assertion is decoded.

The peer credential file is owner-only JSON:

~~~json
{
  "schema_version": 1,
  "peers": [
    {
      "id": "dubnium-operator",
      "secret_base64url": "<32 random bytes, base64url without padding>"
    }
  ]
}
~~~

The peer secret is a service-to-service credential. It must be delivered through
a runtime credential mechanism such as systemd credentials or an equivalently
protected owner-only file. It must not be stored in Nix source, Git, logs,
command-line arguments, public fixtures, or browser/mobile storage.

The socket parent, peer-credential path, and replay-state path are absolute
paths traversed one component at a time through directory descriptors. Symlinked
components, group/other-writable ancestors, and ancestors owned by identities
other than root or the verifier's effective file-creation UID are rejected. The
default socket parent and replay directory are owner-only and service-owned. In
the explicit Linux group transport profile only the socket parent may expose
group traversal, and only through a setgid directory whose group exactly matches
the configured trusted GID; group write/read, `other` access, setuid/sticky bits,
POSIX access ACLs, and POSIX default ACLs are rejected. Replay
state and the peer credential file remain owner-only. Credential reads, replay
mutations, and socket-directory ACL inspection stay descriptor-relative after
admission, so later pathname substitution cannot redirect trusted state.
Filesystem group admission is transport reachability only: authenticated peer
envelopes remain mandatory and never become application identity or
authorization.

## Framing and authenticated envelope

Each Unix-stream connection carries one newline-terminated JSON envelope and one
newline-terminated response.

The outer request fields are:

- version: integer 1;
- peer_id: allowlisted service identity;
- correlation_base64url: a fresh 32-byte random correlation value, base64url-no-pad encoded;
- payload_base64url: base64url-no-pad encoding of the inner JSON bytes;
- mac_base64url: HMAC-SHA-256 over the domain-separated request input.

A client generates a new correlation value for every verification attempt and
retains it until the matching response has been authenticated. Reusing a
correlation value for another verification attempt is not permitted.

Request MAC input is the byte concatenation:

~~~text
"keylix-verifier-request-v1\0" || peer_id || "\0" || correlation || decoded_payload
~~~

Authenticated responses copy the exact request correlation value and use:

~~~text
"keylix-verifier-response-v1\0" || peer_id || "\0" || correlation || decoded_payload
~~~

A client accepts a response only when its authenticated peer identity and
correlation match the exact request it sent. This prevents an old valid
`verified` response from being substituted for a different verification
attempt. Response authentication also prevents a consuming host from trusting
an arbitrary local process that can merely mimic verifier JSON.

## Inner request

After peer authentication, the verifier decodes exactly:

~~~json
{
  "version": 1,
  "method": "GET",
  "target": "https://operator.example/v1/health",
  "access_token": "<exact validated credential bytes>",
  "dpop_proof": "<exact DPoP compact JWS>",
  "confirmation_jkt": "<trusted cnf.jkt from validation of that exact credential>"
}
~~~

Unknown fields are rejected. Actor, principal, role, workspace, session, scope,
capability, authorization decisions, forwarding headers, and nonce-policy
selectors are not part of the contract.

The target is already trusted effective-target input. The verifier never derives
it from Forwarded or X-Forwarded-*.

## Result

Success returns only sender-binding evidence:

~~~json
{
  "status": "verified",
  "version": 1,
  "binding": {
    "key_thumbprint": "<verified RFC 7638 jkt>",
    "proof_issued_at_unix": 1700000000,
    "nonce_enforced": false,
    "replay_checked": true
  }
}
~~~

Failure returns a stable class and no reflected request content. If server-owned
nonce policy is enabled, nonce_required or nonce_mismatch may include the nonce
needed for a fresh-proof retry inside the authenticated response.

## Resource bounds

The reference host is intentionally single-flight and one-request-per-connection.
Decoded verifier payloads are capped at 32 KiB and peer credential documents at
16 KiB. Each request frame and response frame has an absolute two-second
lifetime; drip-feeding bytes cannot extend that deadline. Replay and nonce stores
are bounded and fail closed on capacity/backend indeterminacy. The replay
directory must already exist as a private service-owned directory.

The packaged host requires an owner-only persistent replay directory. The
directory is opened once as a filesystem capability and all entry enumeration,
reads, atomic creation, and removal remain relative to that descriptor. One live
replay-store instance holds an exclusive advisory lock for that directory, and
operations inside the instance are serialized before capacity checks and replay
publication. Crash-left pending publication files are scavenged only while that
exclusive instance lock is held during store initialization; a live writer's
pending file is never removed by another replay check. Each accepted replay key
therefore remains effective across verifier restarts without re-resolving a
replaceable pathname. Unreadable, malformed, concurrently owned, or unexpected
replay state fails closed.

The listener is bound only after credentials and verifier state initialize
successfully. A pathname left by an earlier terminated instance is removed only
when it is an owner-matching Unix socket and no live listener accepts a
connection; a live socket or any differently typed entry fails closed.

This profile is suitable for one verifier instance on one local filesystem.
Multi-instance deployment still requires a shared atomic replay backend or an
explicit single-writer/routing design and is not silently treated as safe.

## Browser boundary

Browser/WebAssembly clients never connect to this verifier directly. Browser DPoP
key custody needs a separately reviewed client adapter and threat model; plaintext
private keys in localStorage are not an acceptable substitute for Android
Keystore or iOS Secure Enclave custody.
