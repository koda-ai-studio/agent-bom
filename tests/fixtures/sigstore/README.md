# Sigstore verification fixture

This public signature bundle was read from the official Sigstore Cosign image
`ghcr.io/sigstore/cosign/cosign:v3.1.4`. It contains public verification material,
not signing keys. Tests verify its certificate, log proof, timestamp, identity,
and signed image digest offline; altered copies must be rejected.

- image: `ghcr.io/sigstore/cosign/cosign:v3.1.4`
- manifest: `sha256:f4e9b14a20e7e4d5b8c61015deb8873d20461a7bb0ef2bd219f9466e198c2b34`
- blob: `sha256:d13d6ff9b56fb05f68da451a1089650de57e47ae6290b6db78eb684aea09cd6f`
