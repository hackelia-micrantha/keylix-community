# Keylix Publication Boundary

`hackelia-micrantha/keylix` is the private canonical repository. `hackelia-micrantha/keylix-community` is the public development, review, and distribution surface.

## Invariants

- Publication flows one way from the private canonical repository to this public repository.
- Security semantics are public by default: protocol behavior, cryptographic design, threat models, public APIs, conformance tests, fuzz targets, and security-relevant ADRs belong here.
- Private deployment topology, credentials, operational evidence, embargoed vulnerabilities, unreleased experiments, and environment-specific configuration must not be published.
- Public and private implementations must not diverge into separate security semantics.
- External contributions are accepted against the public repository and must be reconciled into the private canonical repository before the next publication.

## Publication gate

Future publication automation must perform secret scanning and an explicit path/content allow-or-deny review before updating this repository. The initial repository baseline was copied only while the canonical repository was itself public.
