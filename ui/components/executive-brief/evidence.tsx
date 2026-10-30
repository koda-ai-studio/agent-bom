"use client";
import { useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";
import { type BriefVerificationKey, saveBriefArtifact } from "@/lib/executive-brief";
import { Card } from "@/components/card";
import { PanelButton } from "@/components/integrations/panel-kit";

export function BriefEvidence({ sample }: { sample: boolean }) {
  const [key, setKey] = useState<BriefVerificationKey | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  async function retrieve(pack: boolean) {
    setBusy(true); setError(false);
    try {
      if (pack) {
        const blob = await api.downloadCompliancePack();
        if (mounted.current) saveBriefArtifact(blob, "compliance-pack.json");
      } else {
        const result = await api.getComplianceVerificationKey();
        if (mounted.current) setKey(result);
      }
    } catch { if (mounted.current) setError(true); }
    finally { if (mounted.current) setBusy(false); }
  }
  return <Card className="space-y-3">
    <h2 className="text-lg font-semibold">Signed evidence and verification</h2>
    <p className="text-sm leading-6 text-ink-secondary">The brief is unsigned. The compliance pack is a separate artifact with its own scope. Checking signing configuration does not verify a bundle or establish compliance attestation.</p>
    {sample ? <p className="text-sm text-ink-secondary">Sample environment: use your own control plane for a trusted signed pack. Sample downloads are not production evidence.</p> : null}
    <div className="flex flex-wrap gap-2">
      <PanelButton disabled={busy || sample} onClick={() => void retrieve(true)}>Download signed pack</PanelButton>
      <PanelButton disabled={busy || sample} onClick={() => void retrieve(false)}>Check signing configuration</PanelButton>
      {key?.signature_verifiable && key.algorithm === "Ed25519" && key.public_key_pem ? <PanelButton onClick={() => saveBriefArtifact(new Blob([key.public_key_pem!], { type: "application/x-pem-file" }), "verification-key.pem")}>Download verification key</PanelButton> : null}
    </div>
    {key ? <p role="status" className="break-words text-sm">Signing: {key.algorithm} · {key.verification_status} · Key: {key.key_id ?? "Not recorded"}{key.remediation ? ` · ${key.remediation}` : ""}</p> : null}
    {error ? <p role="alert" className="text-sm">Evidence download unavailable. Check your authenticated access and signing configuration, then retry.</p> : null}
    <p className="text-sm leading-6 text-ink-secondary">For Ed25519, confirm the downloaded key with the control-plane operator through a trusted channel before accepting it. Save that trusted key as pinned.pem, then run:</p>
    <pre className="overflow-x-auto whitespace-pre-wrap break-words rounded-lg bg-surface-muted p-3 text-xs leading-6">agent-bom attest compliance-verify compliance-pack.json --public-key pinned.pem --json</pre>
    <a className="text-sm underline" href="https://koda-ai-studio.github.io/agent-bom/deployment/audit-and-compliance-verification/" target="_blank" rel="noreferrer">Signing, HMAC and verification guide</a>
  </Card>;
}
