# Cyber Defense Playbook — Threat Intelligence & Defense-in-Depth Framework

**Last reviewed:** 2026-07-01

A practical cybersecurity playbook for financial services and other
high-value-target environments facing **brand-abuse, phishing, and
threat-disruption (TD)** campaigns. The framework combines
**sector threat-intelligence sharing**, **human-factors hardening**,
**SIEM-driven phishing response**, and **XDR with agentic SOC
automation** into a single operational reference.

**Primary scenario:** A G-SIB or large regional bank detects a coordinated
phishing wave impersonating its brand — lookalike domains, credential-harvest
pages, and BEC lures targeting customers and employees. The disruption team
must correlate intel, contain exposure, escalate takedowns, and feed
indicators back to sector peers.

**Secondary scenario:** A mid-sized manufacturing organization deploying
Bluetooth-connected smart headsets that maintain continuous communication
with a central server. The same controls generalize to IoT or BYOD
operational environments where endpoint telemetry and network encryption
remain relevant.

---

## Contents

- [1. Threat Intelligence & Indicator Sharing](#1-threat-intelligence--indicator-sharing)
- [2. Human Factor — Security Awareness Training](#2-human-factor--security-awareness-training)
- [3. Data Protection — VPN & Cryptography](#3-data-protection--vpn--cryptography)
- [4. System Defense — XDR & Agentic SOC](#4-system-defense--xdr--agentic-soc)
- [5. Splunk / SIEM Phishing Disruption Workflow](#5-splunk--siem-phishing-disruption-workflow)
- [6. MITRE ATT&CK Mapping (v19.1)](#6-mitre-attck-mapping-v191)
- [Interview Talking Points (Wells Fargo Threat Disruptions)](#interview-talking-points-wells-fargo-threat-disruptions)
- [References](#references)

---

## 1. Threat Intelligence & Indicator Sharing

Real-time monitoring of sector and federal threat intelligence feeds is
the foundation of a proactive cyber-defense posture — especially for
financial institutions where phishing and brand abuse move faster than
signature refresh cycles.

### 1.1 Indicator taxonomy

| Class | Examples | Operational Use |
|---|---|---|
| **Atomic indicators** | IP addresses, domain names, hashes, URLs, certificate fingerprints | Firewall blocklists, DNS sinkholes, email gateway blocks, SIEM correlation rules |
| **Computed indicators** | YARA rules, regex patterns, behavioral signatures, Sigma rules | Endpoint scanning, log-pattern detection, malware family attribution, brand-impersonation page detection |
| **TTPs** (Tactics, Techniques, Procedures) | MITRE ATT&CK technique IDs, kill-chain phase mappings | Threat-hunting hypotheses, detection-engineering coverage analysis, TD campaign attribution |

**Financial-sector indicator classes** (common in FS-ISAC and member sharing):

| Class | Examples | TD relevance |
|---|---|---|
| **Brand-abuse domains** | Typosquats, homoglyphs, punycode lookalikes (`wellsfarg0.com`) | Customer phishing, credential harvest, SEO poisoning |
| **Phishing infrastructure** | Bulletproof hosting IPs, fast-flux DNS, newly registered domains (NRDs) | Campaign pivot tracking, takedown prioritization |
| **Credential-harvest artifacts** | HTML form signatures, OAuth redirect chains, MFA-bypass kit hashes | BEC and account-takeover prevention |
| **Email-borne indicators** | Sender domains, SPF/DKIM failures, attachment hashes, QR-code landing URLs | Gateway blocking, Splunk correlation |

### 1.2 FS-ISAC — primary sector sharing for G-SIBs

For globally systemically important banks (G-SIBs) and large financial
institutions, **FS-ISAC** is the primary threat-intelligence exchange —
not CISA AIS. Member sharing is bidirectional, time-sensitive, and
structured for sector-specific context that federal feeds cannot replicate.

**Operational pattern:**

1. **Subscribe** to FS-ISAC feeds via **STIX/TAXII 2.1** endpoints and
   portal-delivered intel (campaign briefs, sector alerts, member-contributed IOCs).
2. **Query FS-ISAC Intelligence Exchange (IntelX)** for sector alerts, member-contributed IOCs,
   and campaign context. For credential-exposure scoping, use a separate breach/leak monitoring
   capability (paste sites, dark-web chatter) — use results to scope impact, not as sole attribution.
3. **Ingest** STIX 2.1 bundles into SIEM, email security, and XDR platforms;
   normalize to a common observable schema before rule deployment.
4. **Triage** sector hits against local telemetry within SLA (typically
   30–60 minutes for active phishing campaigns).
5. **Contribute back** sanitized indicators, TBD notes, and TTP mappings
   from local detections — the network effect is the product.

**Why FS-ISAC over AIS for G-SIBs:** Sector peers often see the same phishing
kits, BEC templates, and brand-abuse TTPs earlier than broader federal feeds,
with sector-specific enrichment (fraud loss context, regulatory notification
timelines) that AIS typically does not provide.

### 1.3 CISA Automated Indicator Sharing (AIS) — complementary layer

CISA AIS remains valuable as a **complementary, cross-sector** feed —
not the primary intel source for a G-SIB TD program.

**Current state (as of 2026-07-01):**

| Element | Detail |
|---|---|
| **Transport** | TAXII 2.1 servers; STIX 2.1 object bundles |
| **Legal authority** | CISA 2015 §105d information-sharing protections extended through **2026-09-30** (Consolidated Appropriations Act, 2026 §5008, signed 2026-02-03) |
| **Platform modernization** | CISA **TIES** (Threat Intelligence Enterprise Services) modernization underway — improved STIX 2.1 ingestion, member onboarding, and automated validation; AIS remains operational during transition and is planned for integration into TIES |

**Operational pattern:**

1. Subscribe to AIS TAXII 2.1 feeds alongside FS-ISAC — treat AIS as breadth, FS-ISAC as depth.
2. Auto-ingest STIX 2.1 indicators into SIEM and XDR; deduplicate against sector feeds to avoid rule sprawl.
3. Triage AIS-only hits within 4 hours (lower priority than active sector alerts).
4. Submit sanitized indicators from local detections back to AIS when they have cross-sector relevance (e.g., commodity phishing kit, widely reused C2).

### 1.4 YARA rule authoring — financial threat focus

YARA rules are the standard format for computed-indicator authoring.
A defensible rule library for TD work covers:

- **BEC and invoice-fraud lures** — subject-line patterns, HTML body markers,
  wire-transfer urgency language, executive-impersonation templates.
- **Credential-phishing pages** — form-action URLs, hidden iframe loaders,
  OAuth consent-screen clones targeting financial SSO portals.
- **Brand-abuse artifacts** — favicon/logo hash matches, CSS class names
  copied from legitimate login pages, punycode domain patterns in HTML.
- **Commodity malware** still seen in financial campaigns (Emotet successors,
  IcedID loaders, Cobalt Strike beacons) — family signatures remain relevant.
- **Behavioral patterns** — LOLBin abuse, encoded PowerShell, living-off-the-land
  tradecraft in post-phish execution chains.

**Example rule skeleton (credential-phish landing page):**

```yara
rule FIN_Phish_BrandLogin_Clone {
    meta:
        description = "Detects cloned login page artifacts common in FS brand-abuse campaigns"
        author = "TD Detection Engineering"
        mitre_attack = "T1566.002"
        severity = "high"
    strings:
        $s1 = "verify your account" nocase
        $s2 = "unusual activity detected" nocase
        $s3 = /action=["']https?:\/\/[^"']{5,60}\/(login|secure|verify)/ nocase
        $html_form = "<form" nocase
    condition:
        uint16(0) == 0x3c3f or uint16(0) == 0x6874  // HTML/PHP
        and 2 of ($s*) and $html_form
}
```

**Example rule skeleton (BEC attachment marker):**

```yara
rule FIN_BEC_WireTransfer_Urgency {
    meta:
        description = "Flags BEC-style wire transfer urgency in email attachments"
        mitre_attack = "T1566.001"
        severity = "medium"
    strings:
        $urgency1 = "urgent wire transfer" nocase
        $urgency2 = "payment must be sent today" nocase
        $urgency3 = "update our banking details" nocase
        $exec = "CEO" nocase
    condition:
        filesize < 500KB
        and 1 of ($urgency*) and $exec
}
```

Rules are versioned in a git-backed repository, tested in a staging
environment before production deployment, and reviewed quarterly against
active FS-ISAC campaign briefs.

---

## 2. Human Factor — Security Awareness Training

Human error remains the dominant initial-access vector in financial
phishing and BEC campaigns. Reducing that surface is non-optional.

### 2.1 Program objectives

- Teach employees and customers-facing staff to recognize **phishing**,
  **BEC**, **vishing**, and **brand-impersonation** attacks.
- Build muscle memory for **incident reporting** — a clear, low-friction
  path to the TD / SOC queue (not just IT helpdesk).
- Maintain awareness of **device-specific risks** (Bluetooth pairing for
  IoT endpoints; mobile banking app sideloading for consumer-facing roles).

### 2.2 Delivery patterns that work

| Pattern | Why it works |
|---|---|
| **Gamified phishing simulations** | Repeated low-stakes exposure builds recognition reflexes; use realistic bank-branded lures, not generic "free pizza" templates |
| **Recognition rewards** | Positive reinforcement outperforms compliance-by-fear; sustains engagement across high-turnover call-center and branch staff |
| **Role-specific modules** | Fraud analysts, executives, tellers, and developers face different attack surfaces; one-size training underperforms |
| **Quarterly refresh** | Phishing kit churn is measured in days; quarterly keeps BEC and brand-abuse content current |

### 2.3 Limits to acknowledge

- Outdated training material is worse than no training — it instills false confidence.
- Engagement is the binding constraint; without it, content quality is moot.
- Training reduces but does not eliminate human-vector risk. It must be layered with email security, XDR, and TD takedown workflows.

---

## 3. Data Protection — VPN & Cryptography

Encryption in transit and at rest is the second control layer — relevant
for remote workforce access to core banking systems and, secondarily, for
IoT endpoints communicating with central servers.

### 3.1 VPN role

For workforces operating across public and private networks, a VPN
encrypts data in transit between endpoints and internal services.
This blocks **man-in-the-middle (MitM)** attacks at the network layer.

### 3.2 Cryptographic protocols

- **IPSec** for site-to-site and remote-access VPN tunnels.
- **TLS 1.3 / SSL** for application-layer encryption (HTTPS, secure messaging, API gateways).
- **AES-256** for symmetric encryption of data at rest and within tunnels.
- **RSA / ECDSA** for asymmetric key exchange and certificate-based authentication.

### 3.3 Operational considerations

| Strength | Limitation |
|---|---|
| Defeats passive interception and most MitM attacks | Misconfiguration is the dominant failure mode; weekly config audit recommended |
| Compliance-aligned (NIST, ISO 27001, PCI-DSS, GLBA) | Latency overhead can affect real-time IoT communication (secondary scenario) |
| Mature tooling and broad protocol support | Quantum-computing threat horizon may obsolete current asymmetric primitives — track NIST PQC standards (ML-KEM, ML-DSA) |

---

## 4. System Defense — XDR & Agentic SOC

Modern TD programs extend beyond endpoint EDR to **Extended Detection and
Response (XDR)** — unified telemetry across endpoint, identity, email, cloud
SaaS, and network surfaces — augmented by **agentic SOC** automation for
high-volume phishing triage.

### 4.1 XDR capabilities

- **Unified telemetry:** Process, file, network, registry (endpoint); sign-in
  anomalies, conditional-access events (identity); OAuth grants, file shares
  (cloud SaaS); proxy/DNS logs (network).
- **Cross-domain correlation:** Link a phishing email click → browser download
  → credential use on SaaS → lateral movement attempt in a single incident timeline.
- **Automated containment:** Isolate endpoint, revoke session tokens, disable
  compromised accounts, block domains at proxy — orchestrated playbooks, not
  manual ticket hops.
- **Forensic timeline reconstruction** for regulatory and law-enforcement
  evidence packages.

### 4.2 Why XDR fits financial TD work

Brand-abuse campaigns rarely stop at the inbox. A customer phished on a
lookalike domain may reuse credentials on the real portal; an employee
clicking a BEC attachment may trigger endpoint execution and cloud
exfiltration. XDR connects those dots faster than siloed EDR + email gateway.

For the **secondary IoT scenario**, Bluetooth headsets and laptops
connected to a central server remain high-risk endpoints — XDR agents on
those hosts are still non-negotiable.

### 4.3 Agentic SOC — triage automation with governance

Agentic SOC tooling (LLM-assisted playbooks, auto-enrichment bots, case
summarization) is the emerging baseline for TD teams drowning in phishing
volume. Deploy with explicit governance:

| Capability | Governance guardrail |
|---|---|
| **Auto-enrichment** (WHOIS, passive DNS, VT, FS-ISAC lookup) | Read-only; no autonomous blocking without human approval for Tier-1 assets |
| **Case summarization and TTP mapping** | Analyst review before external sharing or regulatory notification |
| **Playbook execution** (domain block, user lockout) | Tiered autonomy: auto-execute on confirmed sector IOCs; human gate for novel indicators |
| **False-positive feedback loop** | Analyst dismissals retrain models; weekly FP review with detection engineering |

The trade-off is operational speed vs. trust. Agentic automation that
blocks legitimate customer-facing domains without human review is worse
than manual triage.

### 4.4 Known limitations

- False positives degrade analyst trust; tuning is continuous, not one-time.
- Agentic tools can hallucinate attribution — never treat LLM output as evidence.
- XDR alone does not solve initial-access vectors — it complements email
  security, FS-ISAC intel, and TD takedown workflows.

---

## 5. Splunk / SIEM Phishing Disruption Workflow

This section operationalizes the TD team's daily rhythm: ingest intel,
correlate email telemetry, open cases, escalate takedowns.

### 5.1 Data sources and correlation

| Source | Key fields | Correlation purpose |
|---|---|---|
| **Email gateway logs** (Proofpoint, Mimecast, etc.) | `sender`, `recipient`, `subject`, `url`, `attachment_hash`, `action` | Identify campaign scope, patient zero, click-through |
| **Proxy / DNS logs** | `dest_domain`, `src_ip`, `user`, `category` | Track post-click landing pages and C2 |
| **Identity logs** (Entra ID / Okta) | `signin`, `risk_level`, `conditional_access`, `app` | Detect credential use after phish |
| **FS-ISAC / AIS STIX feeds** | `indicator`, `confidence`, `campaign` | Match local hits to sector campaigns |
| **Breach/leak monitoring** (separate from FS-ISAC IntelX) | Exposed creds, paste mentions | Scope customer impact |

**Splunk correlation example (conceptual SPL):**

```spl
index=email action=allowed OR action=clicked
| lookup fs_isac_iocs domain AS url_domain OUTPUT campaign confidence
| where isnotnull(campaign) OR match(subject, "(?i)(verify|urgent|wire transfer|account suspended)")
| stats count values(recipient) AS victims values(url) AS urls by sender campaign
| where count > 5
| eval severity=case(confidence=="high", "P1", count>50, "P1", 1=1, "P2")
```

### 5.2 Case lifecycle

| Stage | Owner | Actions | SLA |
|---|---|---|---|
| **Detect** | SIEM / email gateway | Alert fires on IOC match or anomaly threshold | Real-time |
| **Triage** | L1 SOC / TD analyst | Enrich (WHOIS, VT, FS-ISAC), confirm true positive, assign severity | 30 min (active campaign) |
| **Contain** | TD analyst + detection eng | Block sender/domain at gateway, proxy sinkhole, revoke sessions if creds entered | 1 hour |
| **Escalate / takedown** | TD lead + legal | Registrar abuse report, hosting provider ticket, social-media impersonation report | 4–24 hours |
| **Recover & communicate** | Fraud + comms | Customer notification, password reset campaign, status page if needed | Per incident severity |
| **Close & share** | TD analyst | Document TTPs, submit STIX bundle to FS-ISAC (and AIS if cross-sector), update YARA/Sigma | 48 hours post-close |

### 5.3 Escalation and takedown checklist

1. **Preserve evidence** — full email headers, PCAP if available, landing-page snapshot (Forensic Snapshot tools).
2. **Identify infrastructure** — registrar, hosting AS, CDN depeer path.
3. **File abuse reports** — registrar (ICANN WHOIS abuse), hosting (Abuse@), Google Safe Browsing, Microsoft SmartScreen.
4. **Coordinate with FS-ISAC** — check if peer institutions are seeing the same kit; avoid duplicate takedown requests.
5. **Monitor reconstitution** — fast-flux and DGA variants often reappear within 24–72 hours; keep detection rules hot.

---

## 6. MITRE ATT&CK Mapping (v19.1)

This playbook's controls map to **MITRE ATT&CK v19.1** adversary tactics.
Notable v19.1 change: the retired **Defense Evasion** tactic split into
**Stealth (TA0005)** and **Defense Impairment (TA0112)**. Stealth covers
blending in to avoid detection; Defense Impairment covers actively disabling
or degrading security controls.

| ATT&CK Tactic | This Playbook's Coverage |
|---|---|
| **TA0001 — Initial Access** | Phishing (T1566), drive-by compromise; awareness training (§2); email gateway + XDR pre-execution |
| **TA0002 — Execution** | XDR behavioral monitoring; YARA-based execution gating |
| **TA0003 — Persistence** | XDR forensic timeline; registry/file monitoring; OAuth app persistence in cloud |
| **TA0005 — Stealth** | Masquerading (T1036), hidden window (T1564.003), obfuscated files (T1027) — common in phishing kit delivery |
| **TA0112 — Defense Impairment** | Disabling or modifying security tools (T1685; formerly T1562); LOLBin abuse when used to bypass monitoring |
| **TA0006 — Credential Access** | Credential-phish landing pages (T1056); MFA fatigue (T1621); VPN-enforced transmission |
| **TA0008 — Lateral Movement** | XDR network/identity telemetry; segmentation |
| **TA0010 — Exfiltration** | TLS encryption; DLP integration; cloud SaaS monitoring |
| **TA0011 — Command & Control** | FS-ISAC + AIS indicator subscriptions; SIEM correlation; DNS sinkholing |

**Threat Disruption — email / phishing / social-engineering techniques:**

| Technique ID | Name | TD operational response |
|---|---|---|
| **T1566.001** | Phishing: Spearphishing Attachment | Gateway block + attachment YARA; Splunk case if >N recipients |
| **T1566.002** | Phishing: Spearphishing Link | URL rewrite/block; landing-page takedown; FS-ISAC IOC share |
| **T1566.003** | Phishing: Spearphishing via Service | Monitor OAuth consent, shared-doc links (OneDrive, Google Drive lures) |
| **T1566.004** | Phishing: Voice (Vishing) | Call-center fraud playbook; cross-reference with SMS smishing (T1660) |
| **T1534** | Internal Spearphishing | XDR email telemetry; lateral phish detection post-account compromise |
| **T1656** | Impersonation | Brand-abuse domain takedown; customer comms; BEC wire-fraud hold procedures |
| **T1660** | Phishing for Information | Breach/leak monitoring for credential exposure; forced password reset scope |

Technique-level mapping for individual YARA rules lives in rule metadata
(`meta.mitre_attack` field).

---

## Interview Talking Points (Wells Fargo Threat Disruptions)

- **Sector intel first:** For a G-SIB, FS-ISAC STIX/TAXII 2.1 feeds and member sharing are the operational center of gravity; CISA AIS is complementary breadth — I would not treat federal feeds as the primary TD source.
- **End-to-end phishing workflow:** I think in Splunk correlation (email gateway → proxy → identity) with a defined case lifecycle — triage, contain, takedown, share back — not just "block the domain."
- **ATT&CK v19.1 awareness:** Defense Evasion split into Stealth (TA0005) and Defense Impairment (TA0112) — phishing kits often use stealth tradecraft (hidden iframes, obfuscated HTML) separately from impairing EDR or logging.
- **XDR + governed automation:** Agentic SOC tooling accelerates enrichment and case summarization, but takedown and customer-facing blocks need tiered human approval — speed without governance creates false-positive incidents.
- **Measurable outcomes:** I frame TD success as time-to-containment, takedown success rate, IOC reciprocity to FS-ISAC, and reduction in repeat campaign infrastructure — not just ticket volume closed.

---

## References

- CISA. *Automated Indicator Sharing (AIS) Program — TAXII 2.1 / STIX 2.1 Implementation Guide.* Updated 2025-11. https://www.cisa.gov/ais
- CISA. *Threat Intelligence Enterprise Services (TIES) — evolving cyber threat information sharing.* 2024–2026.
- FS-ISAC. *Member Threat Intelligence Sharing Framework.* Financial Services Information Sharing and Analysis Center, 2025.
- MITRE Corporation. *MITRE ATT&CK Framework v19.1.* Released 2025-10. https://attack.mitre.org
- MITRE Corporation. *ATT&CK v19.1 Release Notes — Defense Evasion split into Stealth (TA0005) and Defense Impairment (TA0112).* 2025-10.
- NIST. *SP 800-53 Rev. 5 — Security and Privacy Controls.* National Institute of Standards and Technology, 2020 (ongoing updates).
- NIST. *Cybersecurity Framework (CSF) 2.0.* February 2024.
- NIST. *Post-Quantum Cryptography Standards (FIPS 203, 204, 205).* August 2024.
- OASIS. *STIX 2.1 & TAXII 2.1 Specifications.* 2021 (current transport standard for AIS and FS-ISAC).
- U.S. Congress. *Consolidated Appropriations Act, 2026 §5008 — CISA 2015 extension through 2026-09-30.* Public Law, signed 2026-02-03.
- IBM. *Cost of a Data Breach Report 2025.* July 2025.
- ISO/IEC. *27001:2022 — Information Security Management Systems.* International Organization for Standardization.

---

**License:** MIT — see [LICENSE](LICENSE).

**Author:** Mahmoud ("Michael") Al Kurdi · [LinkedIn](https://www.linkedin.com/in/mahmoud-michael-al-kurdi) · [Portfolio](https://km-it-ops.github.io) · [GitHub](https://github.com/KM-it-ops)
