---
type: fixed
---

{
 "skill_name": "deploy-helper",
 "source_file": "/home/dev/proj/.claude/skills/deploy-helper/SKILL.md",
 "verdict": "malicious",
 "review_verdict": "blocked",
 "overall_recommendation": "blocked",
 "confidence": "high",
 "provenance_verdict": "unverified",
 "content_verdict": "malicious",
 "categories": [
  {
   "name": "Purpose & Capability",
   "key": "purpose_capability",
   "level": "info",
   "summary": "Name and description present but no required binaries declared",
   "details": [
    "Name declared: deploy-helper",
    "Description provided"
   ],
   "evidence": []
  },
  {
   "name": "Instruction Scope",
   "key": "instruction_scope",
   "level": "fail",
   "summary": "Prompt coercion, credential access, or data exfiltration pattern detected",
   "details": [
    "Behavioral finding: Prompt coercion or guardrail override"
   ],
   "evidence": [
    "prompt_coercion: Detected in /home/dev/proj"
   ]
  },
  {
   "name": "Install Mechanism",
   "key": "install_mechanism",
   "level": "fail",
   "summary": "No install methods and no source URL \u2014 cannot verify provenance",
   "details": [],
   "evidence": []
  },
  {
   "name": "Credentials",
   "key": "credentials",
   "level": "pass",
   "summary": "No required credentials",
   "details": [
    "No credential env vars referenced"
   ],
   "evidence": []
  },
  {
   "name": "Persistence & Privilege",
   "key": "persistence_privilege",
   "level": "info",
   "summary": "Missing field(s): persistence, telemetry, privilege_escalation \u2014 cannot fully verify",
   "details": [],
   "evidence": []
  }
 ],
 "recommendations": [
  "Declare required binaries in requires.bins",
  "Remove credential file access patterns or isolate the tool",
  "Provide at least one install method and a source URL",
  "Set persistence: false, telemetry: false, and privilege_escalation: false"
 ],
 "review_reasons": [
  "Instruction Scope: Prompt coercion, credential access, or data exfiltration pattern detected",
  "Install Mechanism: No install methods and no source URL \u2014 cannot verify provenance",
  "Natural-language credential exfiltration (credential_exfiltration)"
 ],
 "reviewer_guidance": [
  "Review credential exposure and private-data access paths before exposing this skill to real data."
 ],
 "publisher_guidance": [
  "Declare required binaries in requires.bins",
  "Remove credential file access patterns or isolate the tool",
  "Provide at least one install method and a source URL",
  "Set persistence: false, telemetry: false, and privilege_escalation: false"
 ],
 "provenance": {
  "status": "unsigned",
  "reason": "no_sigstore_bundle",
  "sha256": "5ac2b83149d3a372e4e9e47995e08656a1202f744ca84477c590804dc5a1dd08",
  "signer": "",
  "rekor_log_index": -1,
  "has_sigstore_bundle": false
 },
 "audit": {
  "passed": false,
  "findings": 6
 }
}
