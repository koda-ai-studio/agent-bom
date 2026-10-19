// ── Scan Pipeline Step Types ────────────────────────────────────────────────

export const PIPELINE_STEPS = [
  { id: "discovery", label: "Discovery", icon: "Search" },
  { id: "extraction", label: "Extraction", icon: "Package" },
  { id: "scanning", label: "Scanning", icon: "Bug" },
  { id: "enrichment", label: "Enrichment", icon: "Zap" },
  { id: "analysis", label: "Analysis", icon: "Shield" },
  { id: "output", label: "Report", icon: "FileText" },
] as const;

// ─── Threat Framework Catalogs ────────────────────────────────────────────────

/** OWASP LLM Top 10 (2025) — code → human-readable name */
export const OWASP_LLM_TOP10: Record<string, string> = {
  LLM01: "Prompt Injection",
  LLM02: "Sensitive Information Disclosure",
  LLM03: "Supply Chain",
  LLM04: "Data and Model Poisoning",
  LLM05: "Improper Output Handling",
  LLM06: "Excessive Agency",
  LLM07: "System Prompt Leakage",
  LLM08: "Vector and Embedding Weaknesses",
  LLM09: "Misinformation",
  LLM10: "Unbounded Consumption",
};

/** OWASP MCP Top 10 — code → human-readable name */
export const OWASP_MCP_TOP10: Record<string, string> = {
  MCP01: "Token Mismanagement & Secret Exposure",
  MCP02: "Privilege Escalation via Scope Creep",
  MCP03: "Tool Poisoning",
  MCP04: "Software Supply Chain Attacks",
  MCP05: "Command Injection & Execution",
  MCP06: "Intent Flow Subversion",
  MCP07: "Insufficient Auth & Authorization",
  MCP08: "Lack of Audit & Telemetry",
  MCP09: "Shadow MCP Servers",
  MCP10: "Context Injection & Over-Sharing",
};

/** OWASP Agentic Top 10 (2026) — code → human-readable name */
export const OWASP_AGENTIC_TOP10: Record<string, string> = {
  ASI01: "Agent Goal Hijack",
  ASI02: "Tool Misuse & Exploitation",
  ASI03: "Identity & Privilege Abuse",
  ASI04: "Agentic Supply Chain Vulnerabilities",
  ASI05: "Unexpected Code Execution",
  ASI06: "Memory & Context Poisoning",
  ASI07: "Insecure Inter-Agent Communication",
  ASI08: "Cascading Failures",
  ASI09: "Human-Agent Trust Exploitation",
  ASI10: "Rogue Agents",
};

/** EU AI Act — article code → article title (technical evidence relevant to the article, not a legal classification) */
export const EU_AI_ACT: Record<string, string> = {
  "ART-9": "Risk Management System",
  "ART-10": "Data and Data Governance",
  "ART-12": "Record-Keeping",
  "ART-14": "Human Oversight",
  "ART-15": "Accuracy, Robustness and Cybersecurity",
  "ART-17": "Quality Management System",
};

/** NIST AI RMF 1.0 — subcategory ID → human-readable name */
export const NIST_AI_RMF: Record<string, string> = {
  "GOVERN-1.5": "Ongoing monitoring and periodic review of AI risk management",
  "GOVERN-6.1": "Policies address AI risks from third-party entities",
  "GOVERN-6.2": "Contingency processes for third-party data or AI system failures",
  "MAP-3.5": "Human oversight processes defined and documented",
  "MAP-4.1": "Technology and legal risks of AI components, including third-party software, mapped",
  "MAP-5.1": "Likelihood and magnitude of identified impacts documented",
  "MEASURE-2.6": "AI system evaluated regularly for safety risks",
  "MEASURE-2.7": "AI system security and resilience evaluated and documented",
  "MANAGE-1.3": "Responses to high-priority AI risks developed, planned, and documented",
  "MANAGE-4.1": "Post-deployment monitoring plans implemented",
};

/** NIST CSF 2.0 — category ID → human-readable name */
export const NIST_CSF: Record<string, string> = {
  "GV.SC-05": "Cyber supply chain risk management requirements established",
  "GV.SC-07": "Supplier risks identified, recorded, and mitigated",
  "ID.AM-05": "Assets prioritized based on classification and criticality",
  "ID.RA-01": "Vulnerabilities in assets are identified",
  "ID.RA-02": "Cyber threat intelligence received from information sharing forums",
  "ID.RA-05": "Threats, vulnerabilities, likelihoods, and impacts used to determine risk",
  "PR.AA-01": "Identities and credentials managed for authorized users and services",
  "PR.AA-03": "Users, services, and hardware are authenticated",
  "PR.DS-01": "Data-at-rest is protected",
  "PR.DS-02": "Data-in-transit is protected",
  "PR.PS-06": "Secure software development practices integrated and monitored throughout the lifecycle",
  "DE.CM-01": "Networks and network services are monitored",
  "DE.CM-09": "Computing hardware, software, runtime environments, and their data are monitored to find potentially adverse events",
  "RS.AN-03": "Analysis is performed to determine what has taken place",
  "RS.MI-01": "Incidents are contained",
};

/** ISO/IEC 27001:2022 Annex A — control ID → human-readable name */
export const ISO_27001: Record<string, string> = {
  "A.5.19": "Information security in supplier relationships",
  "A.5.20": "Addressing information security within supplier agreements",
  "A.5.21": "Managing information security in the ICT supply chain",
  "A.5.23": "Information security for use of cloud services",
  "A.5.28": "Collection of evidence",
  "A.8.8": "Management of technical vulnerabilities",
  "A.8.9": "Configuration management",
  "A.8.24": "Use of cryptography",
  "A.8.28": "Secure coding",
};

/** SOC 2 Trust Services Criteria — code → human-readable name */
export const SOC2_TSC: Record<string, string> = {
  "CC6.1": "Logical/physical access restriction",
  "CC6.6": "External access-boundary protection",
  "CC6.8": "Unauthorized/malicious software prevention and detection",
  "CC7.1": "Vulnerability and configuration-change detection",
  "CC7.2": "System-component anomaly monitoring",
  "CC7.4": "Security-incident response",
  "CC8.1": "Change authorization and control",
  "CC9.1": "Risk-mitigation activities",
  "CC9.2": "Vendor/third-party risk management",
};

/** CIS Controls v8 — safeguard ID → human-readable name */
export const CIS_CONTROLS: Record<string, string> = {
  "CIS-02.1": "Establish and maintain a software inventory",
  "CIS-02.3": "Address unauthorized software",
  "CIS-02.6": "Allowlist authorized libraries",
  "CIS-07.1": "Establish and maintain a vulnerability management process",
  "CIS-07.4": "Perform automated patch management",
  "CIS-07.5": "Perform automated vulnerability scans of internal assets",
  "CIS-07.6": "Perform automated vulnerability scans of public-facing assets",
  "CIS-16.1": "Establish and maintain a secure application development process",
  "CIS-16.7": "Use standard hardening configuration templates for application infrastructure",
  "CIS-16.12": "Implement code-level security checks",
};

/** CMMC 2.0 Level 2 — practice ID → human-readable name */
export const CMMC_PRACTICES: Record<string, string> = {
  "RA.L2-3.11.2": "Vulnerability scanning",
  "RA.L2-3.11.3": "Remediate vulnerabilities",
  "SI.L2-3.14.1": "Flaw remediation",
  "SI.L2-3.14.2": "Malicious code protection",
  "SI.L2-3.14.3": "Security alerts, advisories, and directives",
  "SI.L2-3.14.6": "Monitor communications for attacks",
  "SI.L2-3.14.7": "Identify unauthorized use",
  "SC.L2-3.13.1": "Monitor communications at boundaries",
  "SC.L2-3.13.2": "Employ architectural designs and techniques for security",
  "SC.L2-3.13.5": "Implement subnetworks for publicly accessible components",
  "CM.L2-3.4.1": "Establish and maintain baseline configurations",
  "CM.L2-3.4.2": "Establish and enforce security configuration settings",
  "CM.L2-3.4.3": "Track, review, and control changes",
  "AC.L2-3.1.1": "Limit system access to authorized users",
  "AC.L2-3.1.2": "Limit system access to authorized transactions and functions",
  "AC.L2-3.1.7": "Prevent non-privileged users from executing privileged functions",
  "IA.L2-3.5.3": "Use multi-factor authentication for local and network access",
};
