# Security Policy

Keylix implements authentication-adjacent security protocol primitives. Treat defects involving proof verification, key handling, replay protection, token binding, URI normalization, algorithm selection, or nonce processing as potentially security-sensitive.

## Supported versions

Keylix is pre-release. No version is currently designated production-supported.

## Reporting a vulnerability

Please do **not** disclose suspected vulnerabilities in a public issue.

Use GitHub's private vulnerability reporting for this repository when available. If private reporting is unavailable, contact the repository owner privately before publishing technical details.

A useful report includes:

- affected revision/version;
- threat scenario and attacker capabilities;
- minimal reproduction or test vector;
- expected versus observed behavior;
- whether secrets, keys, tokens, or proof material may have been exposed;
- suggested remediation, if known.

## Security posture

Until a release explicitly states otherwise:

- APIs are unstable;
- cryptographic and protocol behavior has not received an independent audit;
- the project must not be relied on as the sole protection for production credentials;
- TLS and normal OAuth authorization validation remain mandatory around DPoP.
