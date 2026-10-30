# Executive brief

Open **Executive brief** from the dashboard Overview, or from Reports. The page
reads `GET /v1/brief` with the current authenticated session and tenant. The
endpoint requires a brief read grant; access to an individual posture endpoint
does not automatically authorize this aggregate. An unavailable read shows an
error and removes the previous preview and download controls.

## Preview → artifact → investigation

1. Review the generated timestamp, tenant, posture and canonical remediation
   priorities. Owner and SLA provenance belong to the individual finding
   occurrence. Follow a finding to its evidence or open Remediation.
2. Inspect the ranked paths' snapshot, reachability, collection coverage and
   returned/total counts. An unavailable path read is not a clean result.
3. Download Markdown for a review or JSON for the complete structured response.
   Both preserve the current preview. These files are unsigned and may contain
   sensitive tenant evidence; share them through your approved channels.
4. Inspect scope-specific scan history and **Source scope and read consistency**.
   Independent source reads are not a transactionally consistent snapshot, and
   history comparisons are not deltas against tenant-wide posture.

The read-only demo uses the same synthetic estate as the other demo pages.
Its brief and downloads say **Sample data**. Sample mode disables signed-pack
and verification-key actions; use your own authenticated control plane for them.

## Verify the separate signed pack

Use **Download signed pack** to retrieve the compliance bundle through the
current authenticated transport. **Check signing configuration** reports the
server's algorithm, key ID and verifiability status; it does not verify a bundle.
An ephemeral HMAC signer remains explicitly unverifiable.

For Ed25519, download the public key, independently confirm it with the operator
through a trusted channel, and save the trusted key as `pinned.pem`:

```bash
agent-bom attest compliance-verify compliance-pack.json --public-key pinned.pem --json
```

A valid signature does not establish complete collection, exploitation or
framework attestation. Inspect the pack's own scope; it is a separate read from
the brief. See [audit and compliance verification](audit-and-compliance-verification.md)
for signing configuration, HMAC deployments and key rotation.

The CLI remains available without the dashboard:

```bash
agent-bom report brief --format markdown
agent-bom report brief --format json
```

Configure the control-plane URL and credentials using the CLI's existing API
options or environment settings. Do not place credentials in shared links.
