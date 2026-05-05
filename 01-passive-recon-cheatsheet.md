# Passive Reconnaissance — Nation-State Operator Field Manual

> **Classification:** Comprehensive passive intelligence collection reference for APT operations. Every technique gathers information with **zero or low-touch contact** with target infrastructure. Mapped to MITRE ATT&CK TA0043 (Reconnaissance). The goal is to build a complete target profile before sending a single probe.
>
> **Environment baseline:** Modern enterprise — Windows 10/11 + Server 2019/2022, MDE-class EDR with AMSI/ETW/ASR/Tamper Protection/LSA Protection/Credential Guard, hybrid Entra ID with Conditional Access + PIM + MFA + Identity Protection, on-prem AD with tiering/LAPS/gMSA/Protected Users, SIEM correlation, 24/7 SOC with automated containment, egress filtering, DNS logging, segmentation. Passive recon by definition produces no on-target signal — the baseline matters for **interpreting** the intel against current defenses, not for evading detection during collection.
>
> **OPSEC taxonomy used throughout:**
> - **PURE PASSIVE** — Third-party data sources only. Target sees zero packets. Third-party services log your queries.
> - **LOW-TOUCH ACTIVE** — Indirect contact with cloud-provider endpoints adjacent to target (e.g., `getuserrealm.srf` for tenant discovery). Target sees nothing; provider sees a query.
> - **TARGET-TOUCH ACTIVE** — Direct request to target-controlled infrastructure (favicon fetch, document download, mail bounce probe). Reveals operator IP unless proxied.

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

- [0 — Methodology & OPSEC](#0--methodology--opsec)
- [1 — Domain & DNS Intelligence](#1--domain--dns-intelligence)
- [2 — IP, Network & ASN Intelligence](#2--ip-network--asn-intelligence)
- [3 — Certificate & TLS Intelligence](#3--certificate--tls-intelligence)
- [4 — Email & Personnel Intelligence](#4--email--personnel-intelligence)
- [5 — Code Repository & Technical Leak Intelligence](#5--code-repository--technical-leak-intelligence)
- [6 — Credential & Breach Intelligence](#6--credential--breach-intelligence)
- [7 — Cloud & Identity-Plane Passive Recon](#7--cloud--identity-plane-passive-recon)
- [8 — Technology & Supply Chain Profiling](#8--technology--supply-chain-profiling)
- [9 — Financial, Legal & Organizational Intelligence](#9--financial-legal--organizational-intelligence)
- [10 — Threat Intelligence](#10--threat-intelligence)
- [11 — Physical & Wireless Pre-Attack Intelligence](#11--physical--wireless-pre-attack-intelligence)
- [12 — Target Profile Compilation](#12--target-profile-compilation)
- [13 — Tool Quick Reference (Maintenance Status)](#13--tool-quick-reference-maintenance-status)
- [14 — MITRE ATT&CK Mapping Matrix](#14--mitre-attck-mapping-matrix)

---

## 0 — METHODOLOGY & OPSEC

```
═══════════════════════════════════════════════════════════
SYSTEMATIC PASSIVE RECONNAISSANCE WORKFLOW
═══════════════════════════════════════════════════════════
GOAL: Complete target profile before sending a single probe to target infra.
Most techniques below are PURE PASSIVE. A subset is LOW-TOUCH ACTIVE or
TARGET-TOUCH ACTIVE — tagged ⚠ throughout with explicit OPSEC RATING.

PHASE 1: ORGANIZATIONAL INTELLIGENCE
├── Corporate structure (subsidiaries, acquisitions, partners)
├── Employee enumeration (names, roles, emails, social media footprint)
├── Technology stack (job postings, GitHub, registries, DNS)
├── Financial/legal records (SEC 8-K Item 1.05 disclosures, contracts, M&A)
└── Physical locations (offices, data centers, remote sites, satellite imagery)

PHASE 2: DIGITAL INFRASTRUCTURE MAPPING
├── Domain & subdomain enumeration (CT logs, passive DNS, Chaos dataset)
├── IP range & ASN identification (BGP, Team Cymru, PeeringDB)
├── Certificate analysis (SANs, issuers, JARM fingerprints)
├── Cloud asset discovery (S3, Blob, GCS via passive search)
├── Identity-plane fingerprinting (Entra, Okta, Auth0, federation metadata)
├── Email infrastructure (MX, SPF, DKIM, DMARC, MTA-STS, BIMI)
└── CDN / WAF / hosting / SaaS provider identification

PHASE 3: VULNERABILITY & EXPOSURE INTELLIGENCE
├── Credential exposure (breach DBs, stealer logs, IAB markets, paste sites)
├── Code repository leaks (GitHub, GitLab, Postman, package registries)
├── Public CI/CD log mining (GH Actions, CircleCI, preview deploys)
├── Document metadata (usernames, internal hostnames, software versions)
├── Previous incidents (8-K disclosures, HHS OCR, ransomware leak sites)
└── Bug bounty / disclosed-scope intelligence (HackerOne/Bugcrowd public scope)

PHASE 4: ATTACK SURFACE COMPILATION
├── Merge sources → unified target profile (see §12 template)
├── High-value targets (IT admins, execs, developers, identity admins)
├── External attack surface (services, apps, cloud, identity)
├── Initial access vector prioritization (weighted by OPSEC cost)
└── Active recon plan + engagement infrastructure plan
```

```
═══════════════════════════════════════════════════════════
OPSEC FOR PASSIVE RECON
═══════════════════════════════════════════════════════════
OPSEC RATING for this entire section: META — operator hygiene, not technique
DETECTION (target):  None
DETECTION (third-party): YOU are the entity being logged here
═══════════════════════════════════════════════════════════

OPERATOR INFRASTRUCTURE (separate from C2 / engagement infrastructure):
  - Dedicated research VM, never used for attributable activity
  - Browser per persona (Mullvad Browser or Brave with isolated profile per ID)
  - WebRTC disabled, canvas / font / WebGL fingerprinting countermeasures
  - Rotating commercial VPN exit nodes (Mullvad, IVPN — paid in cash/Monero)
  - Tor for high-sensitivity queries (CT logs, paste sites, dark web markets)
  - Time-zone, language, locale aligned with sock-puppet persona origin
  - Burner SIMs (MySudo, Hushed, Google Voice via Monero-purchased number)

SOCK-PUPPET HYGIENE:
  - Aged accounts: >6 months absolute minimum, >1 year preferred for LinkedIn
  - Complete profile (photo, bio, posts, connections) — empty profile = burned
  - "Connections-of-connections" strategy: connect to common loose contacts
    of target's employees BEFORE viewing target employees directly
  - LinkedIn anonymous viewing requires Premium (Career or Business);
    "private mode" alone does NOT suppress viewer notifications
  - Email aliases per persona: SimpleLogin, DuckDuckGo, AnonAddy
  - Photo: AI-generated face (thispersondoesnotexist.com) — but reverse-image-
    search every photo before use; AI faces have known artifact patterns
    that defenders increasingly detect

THIRD-PARTY EXPOSURE (every service below logs YOUR queries):
  - crt.sh / CertSpotter / Censys Certs — query log + IP retention
  - Shodan / Censys / FOFA / ZoomEye / Quake / Netlas — API key telemetry
  - urlscan.io — DEFAULTS submissions to PUBLIC; use `visibility=private` or
    enterprise key, otherwise the target sees your scan in their brand alerts
  - VirusTotal — uploads are PUBLIC unless on enterprise tier
  - HIBP / DeHashed / IntelX / LeakCheck — query telemetry tied to API key
  - Hunter.io / Snov.io / RocketReach — query history visible in account
  - Use unique API keys per engagement; rotate / discard after engagement end
  - NEVER use a personal account for any operational query

LEGAL FRAMING (verify with engagement counsel — varies by jurisdiction):
  - Search engines, CT logs, WHOIS, internet-scan databases query publicly
    indexed data — generally lawful in most jurisdictions
  - Breach data acquisition / use varies wildly; engagement Rules of
    Engagement must explicitly authorize credential reuse for testing
  - Stealer-log marketplace contact may itself be regulated — purchase of
    stolen access can violate CFAA / EU NIS2 / UK Computer Misuse Act
  - Document everything with timestamps for operational reporting and any
    post-engagement legal review

WHAT NEVER TO DO:
  - Connect TCP to any target IP address (DNS resolution via 8.8.8.8 is OK;
    connecting to the resolved IP is active recon)
  - Send any email to target addresses (probes target's mail security stack
    AND triggers brand-monitoring alerts on out-of-pattern senders)
  - Submit target URLs to PUBLIC scanners (urlscan.io public, VirusTotal
    public) — observable by anyone watching the target's third-party-mention
    surface; tips off the engagement before initial access
  - Use personal accounts or attributed infrastructure for any query
  - Browse target's website with attributed identity / cookies
```

---

## 1 — DOMAIN & DNS INTELLIGENCE

> **Typical chains through this section:** CT log mining → subdomain inventory → passive DNS lookup of each → IP/ASN ownership map → infrastructure-provider identification → target-touch-active confirmation in §3 (cert/TLS) and §7 (cloud).

### 1.1 — Passive Subdomain Enumeration

```bash
# ═══════════════════════════════════════════════════════════
# MULTI-SOURCE PASSIVE SUBDOMAIN AGGREGATION
# MITRE ATT&CK: T1590.005 (IP Addresses), T1596.001 (DNS/Passive DNS),
#               T1596.003 (Digital Certificates)
# OPSEC RATING:  PURE PASSIVE — third-party data sources only
# DETECTION (target):     None — target sees zero
# DETECTION (third-party): API keys / IP visible to each data provider
# ═══════════════════════════════════════════════════════════
# Each tool below queries a different overlapping set of public sources.
# Run all four; deduplicate; this is the modern minimum.

subfinder -d target.com -all -silent -o subfinder.txt   # 50+ sources, very fast
amass enum -passive -d target.com -o amass.txt           # OWASP, more thorough
assetfinder --subs-only target.com > assetfinder.txt
findomain -t target.com -q > findomain.txt

# Combine and deduplicate
cat subfinder.txt amass.txt assetfinder.txt findomain.txt | sort -u > all_subdomains.txt
wc -l all_subdomains.txt

# ═══════════════════════════════════════════════════════════
# PROJECTDISCOVERY CHAOS DATASET (curated, weekly-updated)
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# Chaos publishes deduplicated subdomain dumps from CT + ProjectDiscovery's
# scanners. Best single-source baseline before running multi-tool aggregation.
# Requires free API key from chaos.projectdiscovery.io
chaos -d target.com -silent -o chaos.txt
# Or download the bulk index for a major target if listed:
# https://chaos-data.projectdiscovery.io/index.json

# ═══════════════════════════════════════════════════════════
# DATA SOURCES QUERIED (informational — these are the upstream feeds)
# ═══════════════════════════════════════════════════════════
# Active providers (2026):
#   crt.sh, CertSpotter, Censys (Certs API), VirusTotal, SecurityTrails,
#   Shodan, AlienVault/LevelBlue OTX, DNSDumpster, HackerTarget, RapidDNS,
#   Wayback Machine, Common Crawl, Anubis, BinaryEdge, IntelX, Chaos,
#   Threatcrowd successor (Constella), DigitalCloud, BeVigil, BuiltWith
#
# DEAD / EFFECTIVELY OFFLINE — do NOT rely on these (subfinder/amass may
# still attempt them silently and return nothing):
#   bufferover.run     (RapidAPI migration failed, free tier dead since 2024)
#   riddler.io         (domain expired Feb 2025, permanently offline)
#   threatcrowd.org    (folded into AT&T Cybersecurity / LevelBlue OTX)
#   sublist3r built-in sources (project alive; many sources stale)
```

### 1.2 — Certificate Transparency (CT) Log Mining

```bash
# ═══════════════════════════════════════════════════════════
# crt.sh (PRIMARY — Sectigo-operated, free, no API key required)
# MITRE ATT&CK: T1596.003 (Digital Certificates), T1590.005
# OPSEC RATING:  PURE PASSIVE
# DETECTION (target): None
# DETECTION (third-party): crt.sh logs source IP per query
# ═══════════════════════════════════════════════════════════
# Every TLS cert ever issued for the target — reveals subdomains, internal
# names, dev/staging environments, acquisition domains, partner integrations
curl -s "https://crt.sh/?q=%25.target.com&output=json" \
  | jq -r '.[].name_value' | sort -u

# Wildcard search at deeper levels (finds *.dev.target.com etc.)
curl -s "https://crt.sh/?q=%25.%25.target.com&output=json" \
  | jq -r '.[].name_value' | sort -u

# Keyword-targeted search for high-value names
for kw in internal vpn dc admin dev stage qa test corp prod sso auth; do
  curl -s "https://crt.sh/?q=%25${kw}%25.target.com&output=json" \
    | jq -r '.[].name_value' | sort -u >> ct_keywords.txt
done
sort -u ct_keywords.txt -o ct_keywords.txt

# crt.sh PostgreSQL direct (when web frontend is overloaded — common in 2024+)
psql -h crt.sh -p 5432 -U guest certwatch -c \
  "SELECT DISTINCT name_value FROM certificate_and_identities \
   WHERE plainto_tsquery('certwatch', 'target.com') @@ identities.name_tsvector;"

# ═══════════════════════════════════════════════════════════
# CERTSPOTTER (SSLMate — alternative when crt.sh is degraded)
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
curl -s "https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names&expand=issuer" \
  | jq -r '.[].dns_names[]' | sort -u

# ═══════════════════════════════════════════════════════════
# CENSYS CERTS API (deeper search; free tier limited Nov 2024+)
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# Free unauthenticated web search remains; API requires paid tier.
# https://search.censys.io/certificates?q=names%3A%22target.com%22

# ═══════════════════════════════════════════════════════════
# CT LOG DIRECT (when aggregators fail — query Merkle-tree logs directly)
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# Active CT logs (Google Argon, Cloudflare Nimbus, Sectigo, DigiCert):
# https://ct.googleapis.com/logs/<year>/argon<N>/ct/v1/get-entries
# https://ct.cloudflare.com/logs/nimbus<year>/ct/v1/get-entries
# Use sslmate's certspotter CLI for log mirroring:
certspotter -watchlist target.com -no_save  # streams new certs as issued

# ═══════════════════════════════════════════════════════════
# WHAT CT LOGS REVEAL
# ═══════════════════════════════════════════════════════════
# - Internal hostnames        (dc01.corp.target.com, mail-internal.target.com)
# - Dev/staging environments  (dev.target.com, staging-api.target.com)
# - Cloud-provisioned hosts   (target-prod.eastus.cloudapp.azure.com)
# - Acquired companies        (acquired-co.target.com on shared cert)
# - Partner integrations      (partner-api.target.com)
# - Geographic distribution   (eu.target.com, ap.target.com, jp.target.com)
# - Pre-launch products       (cert issued weeks before product announcement)
```

### 1.3 — DNS Record Analysis

```bash
# ═══════════════════════════════════════════════════════════
# AUTHORITATIVE-RECORD ENUMERATION VIA PUBLIC RESOLVERS
# MITRE ATT&CK: T1590.002 (DNS), T1590.001 (Domain Properties)
# OPSEC RATING:  LOW-TOUCH ACTIVE — public resolver may forward uncached
#                queries to target's authoritative NS; target sees a query
#                from Google/Cloudflare resolver IP, not yours
# DETECTION (target): If the target operates / monitors authoritative DNS,
#                     they may see resolver-source queries. Volume / timing
#                     correlation is theoretically possible but rare in prac-
#                     tice. Spread queries across resolvers and time.
# ═══════════════════════════════════════════════════════════
# RFC 8482: dig ANY is unreliable — servers may refuse or minimize. Use
# explicit record types every time.
dig @8.8.8.8 target.com A     +short    # IPv4 address(es)
dig @1.1.1.1 target.com AAAA  +short    # IPv6 address(es)
dig @8.8.8.8 target.com MX    +short    # Mail servers → email provider
dig @8.8.8.8 target.com TXT   +short    # SPF/DKIM/DMARC/verification tokens
dig @8.8.8.8 target.com NS    +short    # Nameservers → DNS hosting
dig @8.8.8.8 target.com SOA   +short    # SOA record (admin email, serial)
dig @8.8.8.8 target.com CNAME +short    # Aliases → CDN/cloud hosting
dig @8.8.8.8 target.com CAA   +short    # Authorized CA list (cert issuance)

# Email-policy records (see §7.8 for interpretation)
dig @8.8.8.8 _dmarc.target.com   TXT   +short
dig @8.8.8.8 _mta-sts.target.com TXT   +short  # MTA-STS policy ID
dig @8.8.8.8 _smtp._tls.target.com TXT +short  # TLS-RPT reporting endpoint
dig @8.8.8.8 default._bimi.target.com TXT +short  # BIMI brand-mark URI

# DKIM selector probing (selector names are not enumerable but common ones leak)
for sel in google selector1 selector2 s1 s2 mail dkim k1 k2 default \
           sendgrid mandrill smtp pm-bounces zoho sparkpost mailgun amazonses; do
  result=$(dig @8.8.8.8 ${sel}._domainkey.target.com TXT +short)
  [ -n "$result" ] && echo "DKIM selector found: $sel"
done

# Reverse DNS on discovered IPs
dig @8.8.8.8 -x <IP> +short

# ═══════════════════════════════════════════════════════════
# WHAT TXT RECORDS REVEAL (verification-token enumeration)
# ═══════════════════════════════════════════════════════════
# google-site-verification=...     → uses Google Workspace / Search Console
# MS=ms########                    → uses Microsoft 365 (tenant ID embedded)
# atlassian-domain-verification=   → uses Atlassian Cloud
# docusign=                        → DocuSign integration
# adobe-idp-site-verification=     → Adobe Sign / Federated Adobe ID
# facebook-domain-verification=    → Meta Business Manager
# apple-domain-verification=       → Apple Business / Apple Pay
# notion-domain-verification=      → Notion workspace
# stripe-verification=             → Stripe account
# zoom_verify_=                    → Zoom-managed domain
# segment-site-verification=       → Segment (analytics integration)
# Each token confirms an account at a SaaS provider — pivot to §8 supply chain
# analysis and §7.6 third-party IdP fingerprinting.
```

### 1.4 — Passive DNS Databases

```bash
# ═══════════════════════════════════════════════════════════
# HISTORICAL DNS RESOLUTION (what IPs / what hostnames over time)
# MITRE ATT&CK: T1596.001 (DNS/Passive DNS)
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# Reveals: infrastructure changes, hosting migrations, previously-used IPs
# (often still reachable and forgotten), shared-hosting relationships,
# historical CDN-fronting reveals (origin IP discovery — see §3.4)

# SecurityTrails (SaaS, free tier limited)
# https://securitytrails.com/domain/target.com/dns
curl -s "https://api.securitytrails.com/v1/domain/target.com" \
  -H "APIKEY: $SECURITYTRAILS_KEY"

# Microsoft Defender External Attack Surface Management (Defender EASM)
# Successor to RiskIQ / PassiveTotal (Microsoft acquired RiskIQ July 2021).
# Community / free tier deprecated; commercial product only as of 2024.
# https://learn.microsoft.com/en-us/azure/external-attack-surface-management/

# DNSDB (Farsight, owned by DomainTools — gold standard for passive DNS)
# Commercial; the largest historical pDNS dataset available
curl -s "https://api.dnsdb.info/dnsdb/v2/lookup/rrset/name/target.com/A" \
  -H "X-API-Key: $DNSDB_KEY" -H "Accept: application/x-ndjson"

# VirusTotal (passive DNS + relations graph; free with API key)
curl -s "https://www.virustotal.com/api/v3/domains/target.com/relations" \
  -H "x-apikey: $VT_KEY"

# Free / no-key alternatives:
# https://dnshistory.org/
# https://viewdns.info/iphistory/?domain=target.com
# https://www.threatminer.org/domain.php?q=target.com
# https://opendata.rapid7.com/  (Rapid7 Project Sonar FDNS — bulk download)
```

### 1.5 — DNS-Based Infrastructure & Provider Identification

```bash
# ═══════════════════════════════════════════════════════════
# CNAME / NS / MX → PROVIDER MAPPING (extended, 2026-current)
# MITRE ATT&CK: T1590.001 (Domain Properties), T1591.002 (Business
#               Relationships), T1596.004 (CDNs)
# OPSEC RATING:  PURE PASSIVE (lookups go to public resolvers)
# ═══════════════════════════════════════════════════════════
dig @8.8.8.8 target.com CNAME +short
dig @8.8.8.8 target.com NS    +short
dig @8.8.8.8 target.com MX    +short

# ─── HOSTING / PaaS / EDGE COMPUTE ──────────────────────────
# CNAME *.cloudfront.net           → AWS CloudFront
# CNAME *.elb.amazonaws.com        → AWS ELB/ALB/NLB
# CNAME *.amplifyapp.com           → AWS Amplify
# CNAME *.elasticbeanstalk.com     → AWS Elastic Beanstalk
# CNAME *.azurewebsites.net        → Azure App Service
# CNAME *.cloudapp.azure.com       → Azure VM (cloud service)
# CNAME *.azureedge.net            → Azure CDN (deprecating Q4 2026)
# CNAME *.appspot.com              → Google App Engine
# CNAME *.run.app                  → Google Cloud Run
# CNAME *.web.app / *.firebaseapp.com → Firebase Hosting
# CNAME *.workers.dev              → Cloudflare Workers
# CNAME *.pages.dev                → Cloudflare Pages
# CNAME *.r2.dev                   → Cloudflare R2 public bucket
# CNAME *.vercel.app               → Vercel (Next.js / static)
# CNAME *.netlify.app              → Netlify
# CNAME *.fly.dev                  → Fly.io
# CNAME *.herokuapp.com            → Heroku
# CNAME *.render.com               → Render
# CNAME *.railway.app              → Railway
# CNAME *.deno.dev                 → Deno Deploy
# CNAME *.ghost.io                 → Ghost (managed CMS)
# CNAME *.webflow.io               → Webflow
# CNAME *.shopify.com              → Shopify storefront
# CNAME *.myshopify.com            → Shopify (alternative)
# CNAME *.squarespace.com          → Squarespace
# CNAME *.wixsite.com              → Wix
#
# ─── DNS HOSTING ────────────────────────────────────────────
# NS *.awsdns                      → AWS Route 53
# NS *.azure-dns.com / .net / .org / .info → Azure DNS
# NS *.cloudflare.com              → Cloudflare DNS
# NS *.googledomains.com           → Google Cloud DNS
# NS *.dnsmadeeasy.com             → DNS Made Easy
# NS *.nsone.net                   → NS1 (managed DNS)
# NS *.ultradns.*                  → Vercara UltraDNS
# NS *.akam.net                    → Akamai DNS
#
# ─── EMAIL ──────────────────────────────────────────────────
# MX *.google.com                  → Google Workspace
# MX *.outlook.com                 → Microsoft 365 / Exchange Online
# MX *.protection.outlook.com      → Microsoft Exchange Online Protection
# MX *.pphosted.com                → Proofpoint Email Protection
# MX *.mimecast.com                → Mimecast
# MX *.barracudanetworks.com       → Barracuda Email Security
# MX *.iphmx.com                   → Cisco IronPort / Secure Email Cloud
# MX *.amazonses.com               → AWS SES
# MX *.mailcontrol.com             → Forcepoint (formerly Websense)
# MX *.messagelabs.com             → Symantec / Broadcom Email Security
# MX *.zix.com / *.zixport.com     → Zix (encrypted email)
# MX *.minecast.com                → typo-squat watchlist (Mimecast lookalike)
#
# ─── WAF / CDN / SECURITY EDGE (see also §7.7) ──────────────
# CNAME *.akamaiedge.net           → Akamai
# CNAME *.akamaihd.net             → Akamai (older config)
# CNAME *.fastly.net               → Fastly
# CNAME *.cdn77.org                → CDN77
# CNAME *.bunnycdn.com             → Bunny CDN
# CNAME *.incapdns.net             → Imperva (formerly Incapsula)
# CNAME *.edgesuite.net            → Akamai (legacy)
# CNAME *.b-cdn.net                → BunnyCDN alias

# Each indicator is a pivot:
#   Microsoft 365 MX → §7.3 Entra tenant outsider recon
#   Google Workspace MX → §7.4 Workspace recon
#   Proofpoint/Mimecast MX → §7.8 mail security posture
#   Cloudflare CNAME → §3.4 origin-IP discovery may be relevant
```

### 1.6 — Hostname Inference from Email Headers & Bounces

```bash
# ═══════════════════════════════════════════════════════════
# INTERNAL HOSTNAME LEAKAGE VIA EMAIL ARTIFACTS
# MITRE ATT&CK: T1590.004 (Network Topology), T1590.001 (Domain Properties)
# OPSEC RATING:  PURE PASSIVE — harvest from existing public artifacts
# DETECTION (target): None when reading existing public sources
# ═══════════════════════════════════════════════════════════
# Mail-relay hostnames frequently leak via Received: headers in any email
# originating from the target. Operators harvest from:
#
#   - Mailing-list public archives (LKML, Apache, IETF, OpenStack lists)
#     where target's employees have posted from work email
#   - GitHub / GitLab PR commit signatures and merge messages
#     git log --format='%ae %ce' | grep target.com
#   - Public bug-tracker comments (Bugzilla, Launchpad, Apache Jira)
#   - Conference CFP / mailing list submissions
#   - NANOG / network-operator public mailing list archives
#
# What you extract from a Received: chain:
#   Received: from MAIL1.CORP.TARGET.LOCAL (10.50.12.15) by
#       mx1-edge.target.com (Postfix) with ESMTP id 4XYZ;
#       Tue, 28 Apr 2026 09:14:22 -0500 (CDT)
#
# That single line reveals:
#   - Internal AD domain naming convention   (CORP.TARGET.LOCAL)
#   - Internal mail server hostname pattern  (MAIL1.CORP.TARGET.LOCAL)
#   - Internal RFC1918 range in use          (10.50.12.0/24)
#   - Edge MTA hostname pattern              (mx1-edge.target.com)
#   - Edge MTA software                      (Postfix)
#   - Time zone of mail origin               (CDT — US Central)
#
# Tooling:
# Search public mailing list archives:
#   site:lists.fedoraproject.org "@target.com"
#   site:mail-archive.com "@target.com"
#   site:groups.google.com "@target.com"
#
# Out-of-office auto-replies (CAREFUL — soliciting one is TARGET-TOUCH ACTIVE):
#   Out-of-office replies routinely include internal phone systems, names of
#   colleagues, alternate contact email addresses, and sometimes calendar info.
#   Harvest from any list reply chain where someone hit a target employee's
#   OOO during prior public discussion.
```

```
═══════════════════════════════════════════════════════════
SECTION 1 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §2 IP/ASN mapping (subdomains resolved to IPs feed ASN discovery)
Enables → §3 Certificate intelligence (subdomain list seeds JARM/cert mining)
Enables → §7 Cloud recon (cloud CNAMEs flag tenant existence)
Prereq for → §3.4 origin-IP discovery (need historical pDNS data)
Alternative → If subfinder/amass underperform, fall back to direct CT log
              mining (§1.2) and Chaos dataset bulk download.
```

---

## 2 — IP, NETWORK & ASN INTELLIGENCE

> **Typical chains through this section:** Subdomains from §1 → resolve to IPs → IPs to ASN → ASN to all announced prefixes → cross-reference Shodan/Censys for service inventory → PeeringDB for facility/peering intel → §3 cert mining over the discovered IP space.

### 2.1 — ASN & IP Range Discovery

```bash
# ═══════════════════════════════════════════════════════════
# ASN LOOKUP — TEAM CYMRU WHOIS (one-shot IP → ASN+Org+Country)
# MITRE ATT&CK: T1590.005 (IP Addresses), T1590.001 (Domain Properties)
# OPSEC RATING:  PURE PASSIVE
# DETECTION (target): None
# DETECTION (third-party): Team Cymru sees query
# ═══════════════════════════════════════════════════════════
# Standard tradecraft for batch IP→ASN resolution. Faster than BGPView for
# bulk work because it's a single whois query that returns everything.
whois -h whois.cymru.com " -v 8.8.8.8"

# Bulk mode (newline-separated IPs from stdin):
echo "begin
verbose
8.8.8.8
1.1.1.1
end" | whois -h whois.cymru.com

# DNS-based interface (avoids whois timeouts):
dig +short 8.8.8.8.origin.asn.cymru.com TXT
# Output: "15169 | 8.8.8.0/24 | US | arin | 2014-03-14"

# ═══════════════════════════════════════════════════════════
# bgp.tools (PRIMARY — community-run BGP intel, free for non-commercial)
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# Faster, more complete prefix and looking-glass data than BGPView for
# many queries. Standard since ~2023.
whois -h bgp.tools " -v AS15169"           # ASN summary
whois -h bgp.tools " -v 8.8.8.8"           # IP → AS path
# Web UI: https://bgp.tools/as/15169  https://bgp.tools/prefix/8.8.8.0/24

# ═══════════════════════════════════════════════════════════
# BGPView API (still useful for JSON output)
# ═══════════════════════════════════════════════════════════
curl -s "https://api.bgpview.io/search?query_term=Target+Corp" \
  | jq '.data.asns[] | "\(.asn) \(.name) \(.country_code)"'

curl -s "https://api.bgpview.io/asn/12345/prefixes" \
  | jq '.data.ipv4_prefixes[].prefix'

curl -s "https://api.bgpview.io/ip/8.8.8.8" \
  | jq '.data | {prefixes: .prefixes, rir: .rir_allocation}'

# ═══════════════════════════════════════════════════════════
# IRR (Internet Routing Registry) DIRECT QUERIES
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# IRR contains operator-declared routing intent. Often broader than what's
# actually announced on BGP — captures intent + reserved-but-not-yet-active.
whois -h whois.radb.net -- '-i origin AS12345' | grep ^route
whois -h rr.ntt.net    -- '-i origin AS12345' | grep ^route
whois -h whois.arin.net "n + AS12345"

# Hurricane Electric BGP toolkit (web UI, no key)
# https://bgp.he.net/AS12345
# Reveals: peers, upstreams, downstreams, prefix list, cone of customers

# ═══════════════════════════════════════════════════════════
# ENUMERATING ALL ASNs A LARGE ORG OWNS
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# Big enterprises and telcos commonly have multiple ASNs (acquisitions, regions)
curl -s "https://api.bgpview.io/search?query_term=Target" \
  | jq '.data.asns[] | "\(.asn) \(.name) \(.country_code)"'

# ARIN / RIPE / APNIC / AFRINIC / LACNIC web databases
# https://search.arin.net/rdap/?searchFilter=name&query=Target+Corp
# https://apps.db.ripe.net/db-web-ui/query?searchtext=target
```

### 2.2 — WHOIS & Reverse WHOIS

```bash
# ═══════════════════════════════════════════════════════════
# DOMAIN / IP REGISTRATION DATA
# MITRE ATT&CK: T1596.002 (WHOIS)
# OPSEC RATING:  PURE PASSIVE
# DETECTION (third-party): registrar/RIR sees query
# ═══════════════════════════════════════════════════════════
whois target.com
whois <IP_address>
# Extract: registrant org, admin/tech contacts, nameservers, registration
# dates, registrar, status flags (clientHold, clientTransferProhibited)

# Most modern registrations use WHOIS privacy (post-GDPR especially).
# HISTORICAL WHOIS retains pre-privacy records — primary value source.
# https://whois.domaintools.com/target.com    (paid tier for full history)
# https://www.whoisxmlapi.com/                (paid API)
# https://viewdns.info/whois/?domain=target.com  (free, limited)

# ═══════════════════════════════════════════════════════════
# REVERSE WHOIS — find other domains by same registrant
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# Reveals: shadow IT, forgotten assets, sister brands, parent-co domains
# https://reversewhois.domaintools.com/   (paid)
# https://www.whoxy.com/                  (cheap API)
curl -s "https://api.whoxy.com/?key=$WHOXY_KEY&reverse=whois&name=John+Smith"
curl -s "https://api.whoxy.com/?key=$WHOXY_KEY&reverse=whois&email=admin@target.com"

# Pivot inputs that work well: registrant name, org name, registrant email,
# registrant phone, registrant address — anything from a pre-privacy WHOIS
# record on one of the target's domains seeds discovery of all the rest.
```

### 2.3 — Internet-Wide Scan Databases

```bash
# ═══════════════════════════════════════════════════════════
# SHODAN — INTERNET-WIDE SERVICE DATABASE
# MITRE ATT&CK: T1596.005 (Search Open Technical Databases: Scan Databases),
#               T1592.002 (Software)
# OPSEC RATING:  PURE PASSIVE — Shodan pre-indexes; you query their data
# DETECTION (target): None for query; if Shodan re-scans the target after
#                     your query, target sees Shodan's scanner IPs (a normal
#                     baseline; not attributable to you)
# DETECTION (third-party): Shodan API key telemetry
# ═══════════════════════════════════════════════════════════
# Organization filter
shodan search 'org:"Target Corp"'
shodan search 'org:"Target Corp" port:443'

# Certificate-driven discovery (better than org: for orgs with mis-tagged ASNs)
shodan search 'ssl.cert.subject.cn:"target.com"'
shodan search 'ssl:"target.com"'
shodan search 'ssl.cert.issuer.cn:"Internal CA target.com"'

# Hostname / DNS-based
shodan search 'hostname:target.com'
shodan search 'http.html:"target.com"'

# Service-specific high-value queries
shodan search 'org:"Target Corp" port:3389'              # exposed RDP
shodan search 'org:"Target Corp" port:22'                # SSH
shodan search 'org:"Target Corp" port:445'               # exposed SMB (rare/bad)
shodan search 'org:"Target Corp" port:8443'              # mgmt interfaces
shodan search 'org:"Target Corp" port:5985,5986'         # WinRM
shodan search 'org:"Target Corp" port:8080,8888,9090'    # admin panels
shodan search 'org:"Target Corp" "Server: Apache"'
shodan search 'org:"Target Corp" product:"OpenSSH"'      # SSH version banner
shodan search 'org:"Target Corp" vuln:CVE-2024-3400'     # known-vuln search

# Per-host detail
shodan host <IP>

# Aggregate facets (count by port / product / version / org)
shodan stats --facets port 'org:"Target Corp"'
shodan stats --facets product 'org:"Target Corp"'
shodan stats --facets vuln 'org:"Target Corp"'
shodan stats --facets ssl.version 'org:"Target Corp"'

# JARM / JA3S TLS-fingerprint queries (see also §3.3)
shodan search 'ssl.jarm:"3fd3fd0003fd3fd00042d43d000000abcdef..."'

# ═══════════════════════════════════════════════════════════
# CENSYS — DIFFERENT SCAN VANTAGE FROM SHODAN
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# Free unauthenticated web search remains; API restricted to paid tiers
# since November 2024. Web UI: https://search.censys.io/
# Query: services.tls.certificates.leaf_data.subject.common_name: "target.com"

# ═══════════════════════════════════════════════════════════
# FOFA / ZoomEye / Quake / Hunter — non-Western scanners
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# Different vantage; broader Asia-Pacific coverage than Shodan/Censys.
# FOFA:    https://en.fofa.info/         (Beijing Huashun Xin'an / Qi An Xin)
# ZoomEye: https://www.zoomeye.org/      (Knownsec)
# Quake:   https://quake.360.net/        (360 / Qihoo — free public search)
# Hunter:  https://hunter.qianxin.com/   (Qi'anxin — free public search)
# Netlas:  https://netlas.io/            (newer Western alt; clean API)

# Quake query examples (web UI / API):
# domain:"target.com"
# cert:"target.com"
# org:"Target Corp"
# Hunter query examples:
# domain.suffix="target.com"
# ip="1.2.3.0/24"

# ═══════════════════════════════════════════════════════════
# GREYNOISE — IS THIS IP A KNOWN SCANNER OR LEGITIMATE?
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# Useful for understanding what background internet noise hits target IPs
# (and inverse: confirming that target IPs are NOT themselves scanners)
# https://viz.greynoise.io/
curl -s "https://api.greynoise.io/v3/community/<IP>" \
  -H "key: $GREYNOISE_KEY"
```

### 2.4 — PeeringDB & Network-Operator Intelligence

```bash
# ═══════════════════════════════════════════════════════════
# PEERINGDB — NETWORK OPERATOR FACILITY / IXP / PEERING INTEL
# MITRE ATT&CK: T1590.004 (Network Topology), T1591.002 (Business Relationships)
# OPSEC RATING:  PURE PASSIVE — public database, no auth required for reads
# ═══════════════════════════════════════════════════════════
# PeeringDB exposes data-center, IXP, peering-policy, and contact data tied
# to ASNs. Material for nation-state operations targeting infrastructure or
# physical-proximity attacks.
curl -s "https://www.peeringdb.com/api/net?asn=12345" | jq
curl -s "https://www.peeringdb.com/api/netfac?asn=12345" | jq    # facilities
curl -s "https://www.peeringdb.com/api/netixlan?asn=12345" | jq  # IXP membership

# Reveals:
#   - Physical data center locations (Equinix XX1, Coresite NYC1, etc.)
#   - IXP membership (network reachability map)
#   - NOC / abuse / policy contacts (org-published email + phone)
#   - Peering policy ("open", "selective", "restrictive")
#   - Expected port speeds per facility

# ═══════════════════════════════════════════════════════════
# RIR SOURCE-OF-TRUTH RECORDS
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# https://search.arin.net/rdap/         (North America)
# https://apps.db.ripe.net/             (Europe / Middle East)
# https://wq.apnic.net/static/search.html  (Asia-Pacific)
# https://lacnic.net/cgi-bin/lacnic/whois  (Latin America)
# https://www.afrinic.net/whois         (Africa)
# Each RIR exposes contact records, abuse handles, IP block delegation history

# ═══════════════════════════════════════════════════════════
# ROBTEX (still operational; legacy interface, useful for cross-reference)
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# https://www.robtex.com/dns-lookup/target.com
# https://www.robtex.com/ip-lookup/8.8.8.8
```

### 2.5 — Internet Archive & Historical URL Data

```bash
# ═══════════════════════════════════════════════════════════
# WAYBACK MACHINE — HISTORICAL WEB SNAPSHOTS
# MITRE ATT&CK: T1593.002 (Search Open Websites: Search Engines),
#               T1594 (Search Victim-Owned Websites)
# OPSEC RATING:  PURE PASSIVE — query against archive.org, not target
# ═══════════════════════════════════════════════════════════
waybackurls target.com | sort -u > wayback_urls.txt

# Filter for high-value file extensions
grep -iE '\.(php|asp|aspx|jsp|jspx|env|json|xml|conf|cfg|ini|yaml|yml|bak|backup|sql|sqlite|db|zip|tar|gz|7z|log|txt|csv|md|pem|key|p12|pfx)$' \
  wayback_urls.txt > wayback_interesting_files.txt

# Filter for high-value paths
grep -iE '(admin|api|config|upload|debug|test|staging|dev|internal|backup|secret|token|password|private|dashboard|portal|console|mgmt|swagger|openapi|graphql|actuator|.git|.svn|wp-admin|phpinfo)' \
  wayback_urls.txt > wayback_interesting_paths.txt

# Wayback CDX API (programmatic, more flexible than waybackurls)
curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=json&fl=original,timestamp,statuscode,mimetype&from=20200101&to=20261231" \
  | jq -r '.[1:][] | @csv' > wayback_cdx.csv

# Direct Wayback browse:
# https://web.archive.org/web/*/target.com/*

# ═══════════════════════════════════════════════════════════
# gau — combines Wayback, Common Crawl, OTX/LevelBlue, URLScan
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# Canonical repo: github.com/lc/gau
gau target.com --threads 5 --providers wayback,commoncrawl,otx,urlscan \
  | sort -u > gau_urls.txt

# Combine with waybackurls + dedupe
cat wayback_urls.txt gau_urls.txt | sort -u > all_historical_urls.txt

# ═══════════════════════════════════════════════════════════
# urlscan.io — PUBLIC SUBMISSION ARCHIVE (do NOT submit; query existing)
# MITRE ATT&CK: T1593.002, T1596 (Search Open Technical Databases)
# OPSEC RATING:  PURE PASSIVE for QUERY; LOW-TOUCH ACTIVE for SUBMISSION
# ═══════════════════════════════════════════════════════════
# urlscan.io's public archive is one of the richest passive sources for:
#   - target's external footprint (every domain anyone has scanned)
#   - JavaScript dependencies and third-party trackers
#   - Screenshot history (visual regression / brand monitoring)
#   - Related-IP discovery via re-renders of target sites
#   - Pre-launch / staging URLs that someone scanned before public launch
#
# Search by domain (returns all historical scans):
curl -s "https://urlscan.io/api/v1/search/?q=domain:target.com&size=100" \
  -H "API-Key: $URLSCAN_KEY" | jq

# Search by IP (find all hostnames pointed at this IP)
curl -s "https://urlscan.io/api/v1/search/?q=ip:8.8.8.8&size=100" \
  -H "API-Key: $URLSCAN_KEY" | jq

# Search by JARM, certificate hash, page hash — extreme pivot power:
curl -s "https://urlscan.io/api/v1/search/?q=hash:%22<sha256>%22&size=100"
curl -s "https://urlscan.io/api/v1/search/?q=cert.subjectName:target.com"
curl -s "https://urlscan.io/api/v1/search/?q=jarm:%223fd3fd...%22"

# DO NOT SUBMIT TARGET URLs to urlscan.io public — visible in their feed
# and observable by anyone watching target's brand-mention surface.
# Use API submission with `visibility=private` if submission is required:
# curl -X POST https://urlscan.io/api/v1/scan/ \
#   -H "API-Key: $URLSCAN_KEY" \
#   -d '{"url":"https://target.com","visibility":"private"}'
```

```
═══════════════════════════════════════════════════════════
SECTION 2 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §3 cert/TLS analysis (run JARM scans against IP space discovered)
Enables → §7 cloud recon (Shodan facets surface cloud-tagged IPs in target ASN)
Prereq for → §11 physical recon (PeeringDB facility list seeds geo)
Alternative → If Shodan returns thin results for Asia-targeted enterprises,
              switch to Quake (§2.3) and Hunter for better regional coverage.
Cross-ref → §1.4 passive DNS (historical IP→subdomain resolution feeds 2.1)
```

---

## 3 — CERTIFICATE & TLS INTELLIGENCE

> **Typical chains through this section:** CT log mining (§1.2) seeds subdomain inventory → JARM-fingerprint Shodan/Censys against the IP space (§2.3) → identify app-stack categories → compare cert SANs across discovered IPs to find shared origins → use historical certs from passive DNS (§1.4) to find pre-CDN origin IP for §3.4.

### 3.1 — Certificate Transparency Deep Dive

```bash
# ═══════════════════════════════════════════════════════════
# CT-DRIVEN ASSET INVENTORY (most comprehensive single source)
# MITRE ATT&CK: T1596.003 (Digital Certificates)
# OPSEC RATING:  PURE PASSIVE
# DETECTION (target): None
# DETECTION (third-party): crt.sh / CertSpotter logs query source IP
# ═══════════════════════════════════════════════════════════
# Strip wildcards and dedupe to a clean subdomain list
curl -s "https://crt.sh/?q=%25.target.com&output=json" \
  | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > ct_subdomains.txt
wc -l ct_subdomains.txt

# Pull issuer + validity to identify cert provisioning patterns
curl -s "https://crt.sh/?q=%25.target.com&output=json" \
  | jq -r '.[] | [.name_value, .issuer_name, .not_before, .not_after] | @csv' \
  > ct_full.csv

# What you read from issuers:
#   "Let's Encrypt" / "ZeroSSL"     → automated DevOps issuance
#   "DigiCert" / "GlobalSign"       → enterprise PKI procurement
#   "Internal Certificate Authority"→ private PKI accidentally CT-logged
#   "Cloudflare Inc"                → cert managed by Cloudflare
#   "Amazon"                        → ACM-managed cert
#   "Microsoft IT TLS CA"           → Microsoft-issued cert

# Targeted keyword search inside cert SANs
for kw in admin internal corp dev stage qa test vpn dc sso auth ldap exch \
          mail mx smtp imap owa cas sql sap erp jenkins git artifact; do
  curl -s "https://crt.sh/?q=%25${kw}%25.target.com&output=json" \
    | jq -r '.[].name_value' 2>/dev/null
done | sort -u > ct_keywords.txt

# Internal-CA leakage: certs whose CN looks like internal hostnames
# (dc01.corp.target.local, exchange.internal.target.com) almost always
# escape into CT when public-CA-issued certs accidentally include the SAN
grep -iE '(\.local|\.internal|\.corp|\.lan|\.intra)' ct_subdomains.txt
```

### 3.2 — Favicon Hash Discovery

```bash
# ═══════════════════════════════════════════════════════════
# FAVICON-HASH PIVOT (fingerprint-based asset discovery)
# MITRE ATT&CK: T1592.002 (Software), T1596.005 (Scan Databases)
# OPSEC RATING:  TARGET-TOUCH ACTIVE if you fetch favicon directly;
#                PURE PASSIVE if Shodan already has the hash for target IPs
# DETECTION (target): If you fetch directly: one HTTP GET to /favicon.ico
#                     from operator IP. Trivially logged. Use proxy / Tor
#                     OR query Shodan for pre-computed hashes.
# ═══════════════════════════════════════════════════════════
# Calculate the mmh3 hash of the favicon → query Shodan/Censys for any
# server returning the same favicon = same web app fingerprint = related infra
python3 - <<'PY'
import requests, mmh3, codecs
r = requests.get('https://target.com/favicon.ico', timeout=10)
fav_b64 = codecs.encode(r.content, 'base64')
print(f"Favicon mmh3 hash: {mmh3.hash(fav_b64)}")
PY

# Then in Shodan / Censys / FOFA / Quake:
shodan search 'http.favicon.hash:-1234567890'
# Censys: services.http.response.favicons.shodan_hash: -1234567890
# FOFA:   icon_hash="-1234567890"
# Quake:  favicon:"-1234567890"

# Useful for finding:
#   - Forgotten/dev/staging instances of the same app
#   - Same vendor's app deployed across multiple customers
#   - Phishing infra that copied the target's favicon

# PURE-PASSIVE alternative — pull favicon hash from Shodan's existing scan
# of a known target IP, no HTTP fetch from operator:
shodan host <IP> | grep -i favicon
# Then pivot from that hash back into Shodan/Censys.
```

### 3.3 — JARM TLS Fingerprinting

```bash
# ═══════════════════════════════════════════════════════════
# JARM — ACTIVE TLS HANDSHAKE FINGERPRINT (Salesforce, 2020)
# MITRE ATT&CK: T1596.005 (Scan Databases), T1592.002 (Software)
# OPSEC RATING:  TARGET-TOUCH ACTIVE if you compute against target;
#                PURE PASSIVE if Shodan/Censys already has it
# DETECTION (target): If computed directly: 10 TLS handshakes from operator
#                     IP — distinctive fingerprint at the network level
# ═══════════════════════════════════════════════════════════
# JARM sends 10 specially-crafted TLS Client Hellos and hashes the responses.
# The result fingerprints the SERVER stack — useful for:
#   - Identifying C2 frameworks operated by other actors against target
#   - Finding all servers running the same application stack
#   - Distinguishing application/version variants with the same banner
#
# Compute (against operator-controlled or research-target host):
git clone https://github.com/salesforce/jarm
python3 jarm/jarm.py target.com

# Pivot via Shodan / Censys (PURE PASSIVE — query their existing scan data):
shodan search 'ssl.jarm:"<jarm-hash>"'
# Censys: services.tls.ja3s: <ja3s-hash>
#         services.jarm.fingerprint: "<jarm-hash>"
# urlscan: jarm:"<jarm-hash>"

# Known JARM fingerprints for offensive tooling (rotate; published lists go
# stale fast as developers tweak default TLS configs):
# - Cobalt Strike default profile, default Sliver, default Mythic, etc.
# - Useful both to AVOID burned fingerprints in your own infra AND to
#   identify where someone else is running similar tooling
# Reference list: https://github.com/cedowens/JARM-C2-Hashes (community)
```

### 3.4 — Origin-IP Discovery Behind CDN/WAF

```bash
# ═══════════════════════════════════════════════════════════
# WHEN TARGET FRONTS WITH CLOUDFLARE / AKAMAI / FASTLY: FIND ORIGIN
# MITRE ATT&CK: T1590.005 (IP Addresses), T1596.001/.003 (Passive DNS, Certs)
# OPSEC RATING:  PURE PASSIVE (techniques below all use third-party data)
# ═══════════════════════════════════════════════════════════
# Why bother: bypasses CDN-layer WAF, exposes origin's actual server stack,
# and frequently reveals less-hardened management interfaces.

# 1. Historical passive DNS — what IP did this hostname resolve to BEFORE
#    the CDN was adopted?
# (See §1.4 for SecurityTrails / DNSDB / VirusTotal queries)

# 2. CT logs — issuer or SAN may reveal cert installed on origin IP
#    Look for certs naming target.com hosted by non-CDN issuers / non-CDN ranges
#    https://crt.sh/?q=target.com  → cross-ref each cert's seen-on-IP via Censys

# 3. Email infrastructure — MX hosts often point to origin, not CDN
dig @8.8.8.8 target.com MX +short
# Resolve each MX → that IP often shares hosting with origin web infra

# 4. Sibling subdomains not behind CDN
# ftp.target.com, mail.target.com, vpn.target.com, autodiscover.target.com,
# webmail.target.com — these are commonly direct-attached to origin
for sub in ftp mail mx mx1 mx2 smtp pop imap webmail vpn autodiscover \
           remote rdp owa lyncdiscover sip cpanel ssh git build ci jenkins; do
  ip=$(dig @8.8.8.8 ${sub}.target.com A +short | head -1)
  [ -n "$ip" ] && echo "${sub}.target.com → ${ip}"
done

# 5. Censys cert-search for target's cert FOUND ON A NON-CDN IP
# search.censys.io: services.tls.certificates.leaf_data.subject.common_name:
#   "target.com" and not autonomous_system.name: "CLOUDFLARENET"

# 6. SSRF / misconfigured headers from cached snapshots
# Some origins return their origin IP in error pages, headers (X-Origin-IP),
# or in Cloudflare Workers logs accidentally exposed via Wayback

# 7. Server-status / phpinfo / debug endpoints leaked in Wayback
# Wayback indexes 200 OK responses from origin pre-CDN — rare but valuable

# 8. Real-IP services (commercial / community)
# https://crimeflare.org/  — defunct but archived data still useful
# Censys / Shodan certificate searches cross-referenced against Cloudflare AS
```

```
═══════════════════════════════════════════════════════════
SECTION 3 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §7 cloud asset discovery (cert SANs reveal cloud-hosted endpoints)
Enables → §10 threat intel (JARM matches against APT C2 fingerprint lists)
Prereq → §1.2 CT log mining must run first to seed cert inventory
Alternative → If favicon-hash pivot returns nothing, try favicon hashes for
              SUBSIDIARIES discovered in §9 — often share branding/template
Cross-ref → §3.4 origin-IP discovery uses §1.4 passive DNS as primary input
```

---

## 4 — EMAIL & PERSONNEL INTELLIGENCE

> **Typical chains through this section:** Multi-source email harvest → format-pattern inference → LinkedIn employee enumeration → cross-validate via Hunter.io/Phonebook.cz → enrich each individual via Epieos / Holehe / Maigret to map social presence → tier targets by phishing value → §6 breach-database lookup of every harvested email.

### 4.1 — Email Address Harvesting

```bash
# ═══════════════════════════════════════════════════════════
# theHarvester — MULTI-SOURCE AGGREGATOR (laramies)
# MITRE ATT&CK: T1589.002 (Email Addresses), T1589.003 (Employee Names)
# OPSEC RATING:  PURE PASSIVE — third-party data only
# DETECTION (target): None
# DETECTION (third-party): each upstream sees a query
# ═══════════════════════════════════════════════════════════
# v4.4.x current. `-b all` runs every source — many silently fail or hit
# CAPTCHAs (Bing, Google, sometimes LinkedIn). The "all" coverage is wider
# in name than in returned data; rerun specific high-yield sources solo.
theHarvester -d target.com -b all -l 500 -f harvester_all.html

# High-yield sources to run individually:
theHarvester -d target.com -b crtsh -l 500
theHarvester -d target.com -b certspotter
theHarvester -d target.com -b bing -l 500
theHarvester -d target.com -b duckduckgo
theHarvester -d target.com -b hunter -l 500     # requires Hunter API key
theHarvester -d target.com -b intelx -l 500     # requires IntelX key
theHarvester -d target.com -b github-code       # requires GitHub PAT
theHarvester -d target.com -b otx               # LevelBlue OTX (FKA AlienVault)
theHarvester -d target.com -b dnsdumpster
theHarvester -d target.com -b virustotal -l 500

# ═══════════════════════════════════════════════════════════
# HUNTER.IO — EMAIL DISCOVERY + FORMAT INFERENCE
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# Free tier: 25 searches/month. Paid: more + verification.
curl -s "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=$HUNTER_KEY&limit=100" \
  | jq '.data | {pattern: .pattern, organization: .organization, emails: [.emails[] | {value, first_name, last_name, position, department, seniority, sources: [.sources[].uri]}]}'

# Hunter returns the inferred format pattern (`{first}.{last}`, `{f}{last}`, etc.)
# This is the highest-leverage single field — enables targeted email generation
# from any LinkedIn employee list.

# Email Verifier (DOES touch target's MTA — use sparingly, single-target only)
# curl -s "https://api.hunter.io/v2/email-verifier?email=user@target.com&api_key=$HUNTER_KEY"
# ⚠ TARGET-TOUCH ACTIVE — Hunter's verifier connects to target's MX

# ═══════════════════════════════════════════════════════════
# PHONEBOOK.CZ (Intelligence X) — FREE EMAIL/SUBDOMAIN/URL SEARCH
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# https://phonebook.cz/ → search target.com → type: email
# Owned by Intelligence X (also operates intelx.io — see §6.1)
# 20B+ records; free with rate limits

# ═══════════════════════════════════════════════════════════
# OTHER COMMERCIAL EMAIL DISCOVERY
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# Snov.io        https://snov.io/email-finder       (paid, good UI)
# Apollo.io      https://app.apollo.io/             (paid, very thorough)
# RocketReach    https://rocketreach.co/            (paid, exec focus)
# SignalHire     https://www.signalhire.com/        (paid, social cross-ref)
# Lusha          https://www.lusha.com/             (paid, B2B focus)
# Clearbit Connect  Chrome extension for LinkedIn email enrichment
# Skrapp.io      https://skrapp.io/                 (paid, LinkedIn focus)
```

### 4.2 — Email Format Discovery

```bash
# ═══════════════════════════════════════════════════════════
# DERIVING THE EMAIL ADDRESS FORMAT
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# Common patterns (rank-ordered by enterprise frequency):
#   first.last@target.com        ← most common in EN-locale enterprises
#   firstlast@target.com
#   flast@target.com
#   first.l@target.com
#   firstl@target.com
#   first_last@target.com
#   first@target.com             ← startups, small orgs
#   lastfirst@target.com         ← rare
#   last.first@target.com        ← rare
#   first.middle.last@target.com ← legal / medical / academic
#   employeeid@target.com        ← rare; manufacturing / large legacy enterprises
#
# Discovery sources:
#   1. Hunter.io domain-search returns `pattern` field directly
#   2. Any single confirmed email reveals the format
#   3. press@, careers@, info@, security@ frequently use first.last
#   4. SEC EDGAR contact emails (§9.1) reveal exec format
#   5. CSR / customer-service public emails on the target's website
#
# Verify by triangulation across 3+ confirmed emails to reduce ambiguity
# (e.g., john.smith@ + jane.doe@ + bob.jones@ confirms first.last@)
```

### 4.3 — Employee Enumeration

```bash
# ═══════════════════════════════════════════════════════════
# LINKEDIN — PRIMARY SOURCE (use sock-puppet account; see §0.2)
# MITRE ATT&CK: T1589.003 (Employee Names), T1591.004 (Identify Roles)
# OPSEC RATING:  PURE PASSIVE if browsing logged-in; profile views are
#                visible to viewees by default
# DETECTION (target): LinkedIn shows profile viewers to the viewee unless
#                     viewer has Premium with Anonymous mode enabled.
#                     Sock-puppet account choice matters.
# ═══════════════════════════════════════════════════════════
# Manual: Company page → People tab → filter by role/location/keyword
# https://www.linkedin.com/company/target-corp/people/

# linkedin2username (initstring) — generates email lists from LinkedIn
# https://github.com/initstring/linkedin2username   (active; v1.x as of 2025)
# Requires authenticated cookie from sock-puppet LinkedIn session
python3 linkedin2username.py -c "Target Corp" -n target.com -d 100

# CrossLinked (m8sec) — no LinkedIn auth required (scrapes Google/Bing for
# LinkedIn-mention snippets, parses names from there)
# https://github.com/m8sec/CrossLinked            (active)
python3 crosslinked.py -f '{first}.{last}@target.com' "Target Corp"

# ═══════════════════════════════════════════════════════════
# TIER STRUCTURE FOR TARGET PRIORITIZATION
# ═══════════════════════════════════════════════════════════
# TIER 1 — IDENTITY & INFRASTRUCTURE ADMINS
#   - Domain admins, Entra ID Global / Privileged Role admins
#   - Identity Security engineers (Conditional Access ownership)
#   - Cloud platform admins (AWS root, GCP org admin, Azure subscription owners)
#   - Highest leverage; smallest count; most actively monitored
#
# TIER 2 — DEVELOPERS & DEVOPS
#   - GitHub/GitLab admins, CI/CD owners, build engineers
#   - Often hold cloud creds with broader scope than they realize
#   - Frequent push-to-public-repo accidents
#
# TIER 3 — EXECUTIVES & C-SUITE
#   - High-value data access; often bypass security controls
#   - Financial, M&A, legal, strategy
#   - Targeted by APT for espionage / pretexting (CEO fraud / BEC)
#
# TIER 4 — IT HELPDESK / SUPPORT
#   - Pretext value for callback / impersonation attacks
#   - Often have password-reset privileges on user accounts
#
# TIER 5 — NEW HIRES
#   - Less trained, eager to comply with requests pretexting "IT onboarding"
#   - Often onboarded mid-week via clearly-templated comms
#
# TIER 6 — HR / FINANCE / LEGAL
#   - Habituated to opening attachments (resumes, invoices, contracts)
#   - HR has org-chart authority — useful pivot for pretexting
```

### 4.4 — Social Media OSINT

```bash
# ═══════════════════════════════════════════════════════════
# CROSS-PLATFORM PERSONAL FOOTPRINT MAPPING
# MITRE ATT&CK: T1593.001 (Social Media), T1591.004 (Identify Roles)
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# X (Twitter):
#   - from:@target_corp / search "target.com" / "works at Target Corp"
#   - Employees post: tech stack frustrations, internal projects, layoff news,
#     conference attendance, work-from-home/office routines
#
# LinkedIn:
#   - Job postings → tech stack, security tools, compliance scope
#   - Employee profiles → certifications, prior employers, skills lists
#   - Company posts → recent product launches, internal events, new offices
#   - LinkedIn LIVE recordings → faces, voices, internal slide content
#
# GitHub (organizational + personal):
#   - https://github.com/target-org → public repos, members, recent activity
#   - github.com/{employee} → personal repos that may contain work code
#   - Commit-author email harvesting via `git log --format="%ae"`
#
# Reddit:
#   - r/sysadmin / r/cybersecurity / r/devops — employees ask questions
#     that reveal internal tooling (e.g., "anyone else dealing with X
#     in CrowdStrike?") under thinly-pseudonymous accounts
#   - Cross-reference posting times / writing style with social profiles
#
# Glassdoor / Blind / Fishbowl:
#   - Employee reviews → internal tools, culture, security-team capacity,
#     burnout indicators, recent layoffs/reorgs
#   - Salary / benefits posts → seniority distribution, role inflation
#   - Blind: pseudonymous but verified-corporate-email; rich gossip
#
# Instagram / Facebook:
#   - Badge photos (badge format, color, access levels visible)
#   - Office photos (network equipment in background, monitor content,
#     whiteboard contents from after-hours posts)
#   - Conference / event attendance (CFP submissions, slide content)
#
# YouTube / Vimeo:
#   - Internal training videos accidentally set to "Unlisted" but indexed
#   - Marketing webinars showing internal app screenshots
#   - Conference recordings of employee talks (rich tech-stack reveal)
#
# OPSEC: One sock-puppet identity per platform; rotate VPN exit per identity.
#   Never log into LinkedIn via the same browser profile that ever logs into
#   Twitter — LinkedIn's mobile-cookie correlation links accounts by device.
```

### 4.5 — Modern OSINT Enrichment Platforms

```bash
# ═══════════════════════════════════════════════════════════
# REVERSE-EMAIL-AGAINST-CONNECTED-SERVICES (2024+ tradecraft)
# MITRE ATT&CK: T1589.002, T1589.003, T1593.001
# OPSEC RATING:  PURE PASSIVE
# DETECTION (third-party): the enrichment platform logs your queries
# ═══════════════════════════════════════════════════════════
# These tools take an email and return every public service where that email
# is registered. The signal is the existence of an account, not its content.
# Heavily used by APT for personnel profiling and pretext development.

# EPIEOS — paid SaaS, very deep
# https://epieos.com/  → enter email → returns Google, Skype, LinkedIn,
#   GitHub, Twitter, Pinterest, Strava, Adobe, Spotify, etc. confirmations
#   plus partial Google profile data (display name, profile photo)

# OSINT.industries — commercial, broader API
# https://osint.industries/

# HOLEHE (open-source; checks ~120 services)
# https://github.com/megadose/holehe
holehe user@target.com

# MAIGRET (open-source; username → 3000+ sites cross-reference)
# https://github.com/soxoj/maigret
maigret jsmith --html

# SHERLOCK (similar to Maigret; username focus)
# https://github.com/sherlock-project/sherlock
sherlock jsmith

# WHATSMYNAME WEB (https://whatsmyname.app/) — username search across 600+ sites

# Defensive cross-check: search the executive's name + likely usernames
# (firstinitial+lastname, lastname+number, leetspeak variants, prior
# employer concatenations) on Have I Been Pwned (§6.1) — personal-email
# breaches frequently expose work-related credentials via password reuse.

# Pivot value: confirms a person is on a particular service → enables targeted
# pretexts (Strava workout patterns reveal physical office presence; Spotify
# listening revealed-via-shared-playlist enables conversation hooks; LinkedIn
# course history reveals security-training gaps).
```

```
═══════════════════════════════════════════════════════════
SECTION 4 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §6 breach lookup (every harvested email gets HIBP/DeHashed query)
Enables → §5 GitHub commit-author email harvesting (git log %ae filter)
Enables → §11 physical recon (badge photos, office locations from social)
Prereq → §1 domain inventory (need target.com confirmed before harvesting)
Cross-ref → §7.3 Entra tenant recon — confirm each email belongs to the
            tenant via getuserrealm / unauth Graph endpoints
```

---

## 5 — CODE REPOSITORY & TECHNICAL LEAK INTELLIGENCE

> **Typical chains through this section:** Org-name → GitHub org search → member enumeration → personal-repo cross-cull → secret scanning across all → expand to Postman / NPM / Docker Hub / public CI logs → metadata extraction from any documents found in repos → §6 cred reuse if secrets surface.

### 5.1 — GitHub / GitLab / Bitbucket Secret Scanning

```bash
# ═══════════════════════════════════════════════════════════
# MANUAL DORK STRINGS (paste into GitHub search UI)
# MITRE ATT&CK: T1593.003 (Code Repositories)
# OPSEC RATING:  PURE PASSIVE
# DETECTION (target): None
# DETECTION (third-party): GitHub logs searches against your token/account
# ═══════════════════════════════════════════════════════════
# Use sock-puppet GitHub account with API token (PAT). Searches without auth
# are heavily rate-limited; Personal Access Tokens raise limits substantially.
#
# Target-domain dorks:
#   "target.com" password
#   "target.com" api_key OR secret OR token
#   "target.com" AWS_ACCESS_KEY OR AKIA OR ASIA
#   "target.com" jdbc: OR connectionString
#   "target.com" BEGIN PRIVATE KEY
#   "target.com" "smtp.target.com"
#   "@target.com" extension:env
#
# Org-scoped dorks (when GitHub org name is known):
#   org:target-org filename:.env
#   org:target-org filename:id_rsa
#   org:target-org filename:credentials
#   org:target-org filename:wp-config.php
#   org:target-org filename:secrets.yml
#   org:target-org filename:.aws/config
#   org:target-org filename:.npmrc
#   org:target-org filename:.dockercfg
#   org:target-org extension:pem private
#   org:target-org extension:sql password
#   org:target-org extension:psd1 password
#   org:target-org "BEGIN OPENSSH PRIVATE KEY"
#   org:target-org "Bearer eyJ"   ← JWT tokens
#   org:target-org "xoxb-"        ← Slack bot tokens
#   org:target-org "ghp_"         ← GitHub Personal Access Tokens
#   org:target-org "sk_live_"     ← Stripe live keys
#   org:target-org "AKIA"         ← AWS access key prefix

# ═══════════════════════════════════════════════════════════
# trufflehog — verified-secret scanning across full git history
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# Modern syntax: `trufflehog git <url>`. Both --only-verified (canonical per
# Trufflehog docs) and --results=verified work; --only-verified is the
# documented form.
trufflehog git https://github.com/target-org --only-verified --json \
  | jq '. | {DetectorName, RawV2, SourceMetadata}'

# Scan a single repo across all branches and full history
trufflehog git https://github.com/target-org/internal-tool --only-verified

# Scan all repos in an org (uses GitHub API to enumerate)
trufflehog github --org=target-org --only-verified --token=$GH_PAT

# Filesystem mode (after `git clone --mirror` for depth)
trufflehog filesystem ./target-org-mirror --only-verified

# ═══════════════════════════════════════════════════════════
# gitleaks — fast regex-based scanning
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# v8.19+ deprecated `gitleaks detect` in favor of `gitleaks git/directory/stdin`
# Old commands still work but documentation hides them.
gitleaks git https://github.com/target-org/repo -v --report-path=gitleaks.json

# Scan a directory after cloning
gitleaks directory ./local-repo -v

# ═══════════════════════════════════════════════════════════
# GitDorker — automated dork rotation
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# https://github.com/obheda12/GitDorker (active)
python3 GitDorker.py -tf $GH_PAT -org target-org -d Dorks/alldorksv3

# ═══════════════════════════════════════════════════════════
# WHAT TO HUNT FOR (priority order)
# ═══════════════════════════════════════════════════════════
# - Hardcoded credentials   (DB passwords, cloud API keys, OAuth client secrets)
# - Internal infrastructure (RFC1918 IPs, internal hostnames, AD domain names)
# - CI/CD configs           (.github/workflows, Jenkinsfile, .gitlab-ci.yml,
#                            CircleCI .config.yml — secrets via env vars)
# - Infrastructure-as-code  (Terraform .tf, CloudFormation, Pulumi, Ansible
#                            vault files, Helm values.yaml)
# - Container configs       (Dockerfile, docker-compose.yml, k8s manifests)
# - Private keys            (SSH, TLS, code-signing certs, GPG)
# - SaaS API tokens         (Slack xoxb-, GitHub ghp_, Stripe sk_live_,
#                            Twilio SK*, SendGrid SG.*, Datadog, etc.)
# - Internal documentation  (architecture diagrams, onboarding guides
#                            accidentally pushed to public repos)
# - Old commits             (trufflehog scans full history; secrets removed
#                            from HEAD often remain in older commits)
```

### 5.2 — GitHub Code Search (Post-2023 Operators)

```bash
# ═══════════════════════════════════════════════════════════
# GITHUB CODE SEARCH (the indexed search at github.com/search?type=code)
# MITRE ATT&CK: T1593.003 (Code Repositories)
# OPSEC RATING:  PURE PASSIVE — your queries are logged to your account
# ═══════════════════════════════════════════════════════════
# GitHub launched the new code search in 2023 with substantially different
# operators. Legacy search (the dorks in §5.1) still partially works but
# the new operators are stronger and index more.

# Operator reference (UI at github.com/search?type=code):
#   path:filename                  → match path / filename
#   path:**/.env                   → glob path matching
#   language:python                → language filter
#   content:"password"             → exact-phrase content match
#   org:target-org                 → org scope
#   repo:owner/repo                → single-repo scope
#   user:jsmith                    → user scope
#   /regex/                        → regex (limited; case-sensitive)
#   symbol:functionName            → symbol search (def/decl)
#   NOT term                       → exclusion
#
# Example queries (paste in the github.com search bar):
#   org:target-org path:**/.env
#   org:target-org path:**/secrets.yml content:"password:"
#   org:target-org content:"AKIA" language:Terraform
#   org:target-org /(?i)password\s*=\s*"[A-Za-z0-9]{12,}"/
#   user:jsmith content:"target.com" content:"BEGIN PRIVATE KEY"
#
# ═══════════════════════════════════════════════════════════
# CROSS-PLATFORM CODE SEARCH (when GitHub returns thin)
# ═══════════════════════════════════════════════════════════
# Sourcegraph public:   https://sourcegraph.com/search   (extensive, free tier)
# Searchcode:           https://searchcode.com/          (smaller but unique index)
# grep.app:             https://grep.app/                (regex over GitHub mirror)
# publicwww.com:        https://publicwww.com/           (HTML-snippet code search)
# Google + site:gitlab.com / site:bitbucket.org / site:gitea.io
```

### 5.3 — GitHub Actions Public Workflow Logs

```bash
# ═══════════════════════════════════════════════════════════
# PUBLIC CI LOG MINING — SECRET INTERPOLATION LEAKS
# MITRE ATT&CK: T1593.003 (Code Repositories)
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# GitHub Actions masks secrets via simple substring replacement before
# writing to logs. The masking fails when:
#   - Secret is encoded (base64, URL-encoding) before logging
#   - Secret is partially logged (one segment of a multi-part credential)
#   - Secret appears inside a stack trace or environment dump
#   - A non-masked variable is constructed from secret + literal
#   - Build script echoes env-vars during debug builds
#
# Browse public workflow runs:
gh run list --repo target-org/repo --limit 50 --json databaseId,name,status,conclusion
gh run view <RUN_ID> --repo target-org/repo --log

# Find every public workflow file in an org:
gh search code --owner target-org --filename .github/workflows/*.yml

# Common leak patterns to search for in logs:
#   "***" appearing immediately before suspicious-looking text
#   echo $SECRET / echo "${SECRET}" / printenv
#   docker login output (registry passwords leaked in handshake)
#   curl -v with Authorization headers
#   terraform plan output (variable interpolation in resource args)
#   helm install --debug (Kubernetes secrets in chart values)
#
# Tools:
# https://github.com/SecurityDigress/keyfinder   (workflow-log scanner)
# https://github.com/AdnaneKhan/Gato              (GitHub Actions abuse audit)

# ═══════════════════════════════════════════════════════════
# CROSS-PLATFORM PUBLIC CI MINING
# ═══════════════════════════════════════════════════════════
# CircleCI public jobs (OSS projects):
#   https://app.circleci.com/pipelines/github/target-org/repo
# Travis CI legacy public logs:
#   https://app.travis-ci.com/github/target-org/repo
# Buildkite public pipelines:
#   https://buildkite.com/target-org/  (if org runs public pipelines)
# Drone CI public dashboards (self-hosted, often reachable):
#   https://drone.target.com/  (Shodan: http.title:"Drone")
# Public Jenkins on the open internet:
#   shodan search 'http.title:"Dashboard [Jenkins]"'  → cross-ref against
#   target's IP space from §2
```

### 5.4 — Postman Public Workspace Leaks

```bash
# ═══════════════════════════════════════════════════════════
# POSTMAN PUBLIC WORKSPACE INTELLIGENCE
# MITRE ATT&CK: T1593.003 (Code Repositories), T1589.002 (Email Addresses)
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# Postman public workspaces are now a top-tier corporate credential exposure
# surface. Dec 2024 CloudSEK research: 30,000+ workspaces leaked tokens,
# API keys, internal endpoints across healthcare, fintech, and retail.
# https://www.cloudsek.com/blog/postman-data-leaks
#
# Why this happens: developers iteratively test APIs against production with
# real credentials in their workspace's "environment variables", then mark
# the workspace public to share with teammates without realizing env vars
# get exported with the workspace.
#
# Search for org footprint:
# https://www.postman.com/explore/apis  → search "target.com" / "Target Corp"
# https://www.postman.com/search?q=target.com&type=public-workspace
# https://www.postman.com/search?q=target.com&type=public-collection

# Postman API (requires free Postman account):
curl -s "https://www.postman.com/_api/ws/proxy" \
  -H "Content-Type: application/json" \
  -d '{"service":"search","method":"POST","path":"/search-all",
       "body":{"queryText":"target.com","domain":"public",
               "queryIndices":["collaboration.workspace",
                               "collaboration.collection",
                               "runtime.request","apinetwork.team"]}}'

# What to extract from a discovered workspace:
#   - Environment variables (often hold prod API keys)
#   - Pre-request scripts (auth flow logic + occasionally hardcoded secrets)
#   - Saved request URLs (internal endpoints not in any public docs)
#   - Example response bodies (sample data leaks PII / internal IDs)
#   - Collaborator list (employee names + emails)
#
# Tools:
# https://github.com/CloudSEK/PostmanScanner   (CloudSEK reference scanner)
# https://github.com/assetnote/postman-bulk    (Asset Note's bulk extractor)

# ═══════════════════════════════════════════════════════════
# SWAGGER / OPENAPI / GraphQL SCHEMA DISCOVERY
# OPSEC RATING:  PURE PASSIVE if querying CT/wayback; LOW-TOUCH if querying target
# ═══════════════════════════════════════════════════════════
# Many APIs publish their own schema. Discovery via Wayback / Google:
#   site:target.com swagger
#   site:target.com /openapi.json
#   site:target.com /v2/api-docs
#   site:target.com /graphql
#   site:target.com /__schema
# CT logs sometimes show api.target.com / docs.target.com / dev-api.target.com
```

### 5.5 — Public Package Registry Leaks

```bash
# ═══════════════════════════════════════════════════════════
# PACKAGE REGISTRY OSINT (NPM, PyPI, Docker Hub, HuggingFace)
# MITRE ATT&CK: T1593.003 (Code Repositories), T1591.002 (Business Relationships)
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# Internal hostnames, API endpoints, and occasionally tokens leak via
# packages published from corporate emails. Layer-history mining of Docker
# images is a reliable leak channel.

# ─── NPM ────────────────────────────────────────────────────
# Find packages by maintainer email
curl -s "https://registry.npmjs.org/-/v1/search?text=maintainer:user-target&size=250" | jq

# Find packages by org/scope
curl -s "https://registry.npmjs.org/-/v1/search?text=@target/&size=250" | jq

# Pull all metadata for a package (includes README, dependencies, scripts)
curl -s "https://registry.npmjs.org/<package-name>" | jq

# Tarball download for static analysis (TARGET-TOUCH for github-hosted repos)
npm pack <package-name>
tar -xzf <package-name>-*.tgz

# ─── PyPI ──────────────────────────────────────────────────
curl -s "https://pypi.org/simple/<package>/" | grep -o 'href="[^"]*'
curl -s "https://pypi.org/pypi/<package>/json" | jq '.info | {author_email, project_urls, requires_dist}'

# Search by author email (manual via web UI; API doesn't expose author search)
# https://pypi.org/search/?q=email%3Auser%40target.com

# ─── Docker Hub ────────────────────────────────────────────
# List public repos for an organization
curl -s "https://hub.docker.com/v2/repositories/target-org/?page_size=100" | jq

# Pull manifest WITHOUT downloading layers — reveals layer SHAs and history
curl -s "https://hub.docker.com/v2/repositories/target-org/image-name/" | jq
curl -s "https://registry-1.docker.io/v2/target-org/image-name/manifests/latest" \
  -H "Accept: application/vnd.docker.distribution.manifest.v2+json"

# Pull layer history (sometimes contains internal hostnames in env / labels):
docker pull target-org/image-name:tag
docker history --no-trunc target-org/image-name:tag

# Tools:
# https://github.com/genuinetools/reg          (registry inspector)
# https://github.com/wagoodman/dive            (interactive layer diff)
# https://github.com/cycodehq/raven            (CI/CD security scanner)

# ─── HuggingFace ───────────────────────────────────────────
# Org/user discovery
curl -s "https://huggingface.co/api/models?author=target-org&limit=100" | jq
curl -s "https://huggingface.co/api/datasets?author=target-org" | jq

# Model card content (often references internal data sources / training infra)
curl -s "https://huggingface.co/api/models/target-org/model-name"

# ─── Other registries to check ─────────────────────────────
# Maven Central:    https://search.maven.org/search?q=g:com.target
# CocoaPods:        https://cocoapods.org/search?q=on%3Aios+target
# Crates.io:        https://crates.io/users/target
# RubyGems:         https://rubygems.org/profiles/target
# Go modules:       https://pkg.go.dev/search?q=target.com
# NuGet:            https://www.nuget.org/profiles/Target
```

### 5.6 — Vercel / Netlify / Cloudflare Pages Preview-URL Leaks

```bash
# ═══════════════════════════════════════════════════════════
# PREVIEW-DEPLOYMENT URL DISCOVERY
# MITRE ATT&CK: T1594 (Search Victim-Owned Websites), T1593.003
# OPSEC RATING:  PURE PASSIVE for query (Wayback / urlscan / CT logs);
#                TARGET-TOUCH ACTIVE if you fetch the preview directly
# ═══════════════════════════════════════════════════════════
# Modern frontend platforms create preview URLs per branch / per PR / per
# commit. These are publicly resolvable, frequently expose pre-production
# code, debug endpoints, and unredacted secrets baked at build time.

# URL patterns to enumerate (via CT logs, Wayback, urlscan, GitHub PR links):
#   Vercel:           {project}-{hash}-{org}.vercel.app
#                     {project}-git-{branch}-{org}.vercel.app
#                     {project}.vercel.app  (production)
#   Netlify:          {site}--{branch}.netlify.app
#                     deploy-preview-{N}--{site}.netlify.app
#                     {commitsha}--{site}.netlify.app
#   Cloudflare Pages: {hash}.{project}.pages.dev
#                     {branch}.{project}.pages.dev
#   AWS Amplify:      {branch}.{appid}.amplifyapp.com
#   Render:           {service}-pr-{N}.onrender.com
#   Fly.io:           {app}.fly.dev
#   Firebase Hosting: {site}--pr{N}-{hash}.web.app

# Discovery flow:
# 1. CT log search for *.vercel.app + *.netlify.app + *.pages.dev that
#    contain target's name or branding strings
curl -s "https://crt.sh/?q=%25.vercel.app&output=json" \
  | jq -r '.[].name_value' | grep -i target

# 2. urlscan.io search by domain across these platforms
curl -s "https://urlscan.io/api/v1/search/?q=domain:vercel.app+AND+page.title:target&size=100"

# 3. GitHub PR comments/checks — Vercel and Netlify post preview URLs as
#    PR check comments. Search public PRs in target's GitHub org:
gh search prs --owner target-org --json url,body,comments \
  | jq '.[] | select(.body | test("(vercel|netlify|pages\\.dev)"))'

# 4. Search engines:
#    site:vercel.app "Target Corp"
#    site:netlify.app target.com
#    site:pages.dev "powered by Target"

# 5. Common-name brute (only against discovered platform-domains, NOT target):
for branch in main master develop staging dev qa preview; do
  for project in target target-app target-portal target-admin; do
    nslookup ${project}-git-${branch}-target-org.vercel.app 2>&1 | grep -A1 Name
  done
done
```

### 5.7 — Document Metadata Extraction

```bash
# ═══════════════════════════════════════════════════════════
# DOCUMENT METADATA → INTERNAL USERNAMES / VERSIONS / PATHS
# MITRE ATT&CK: T1592.002 (Software), T1589.003 (Employee Names)
# OPSEC RATING:  PURE PASSIVE if pulling from Wayback / Google cache
#                (Google removed cache: operator Sept 2024 — Wayback only now);
#                TARGET-TOUCH ACTIVE if downloading from target.com directly
# ═══════════════════════════════════════════════════════════
# PASSIVE acquisition path (preferred):
waybackurls target.com | grep -iE '\.(pdf|docx?|xlsx?|pptx?)$' | head -50 \
  | xargs -I {} curl -sL "https://web.archive.org/web/2026/{}" -o "./docs/$(basename {})"

# Alternative passive sources:
#   1. CommonCrawl (cc-index queries) — bulk-archive of public web
#   2. urlscan.io — saves rendered pages but not always document files
#   3. Russian-state archive (rusarchives.ru) — broader retention than Wayback

# TARGET-TOUCH alternative (use only if engagement RoE permits):
wget -r -l 1 -A pdf,doc,docx,xls,xlsx,ppt,pptx -nd -P ./docs/ https://target.com/

# ═══════════════════════════════════════════════════════════
# METADATA EXTRACTION (exiftool — local, no network)
# OPSEC RATING:  PURE PASSIVE (operator-local processing)
# ═══════════════════════════════════════════════════════════
exiftool -r -csv ./docs/ > metadata.csv

# High-value fields
exiftool -Author -Creator -Producer -LastModifiedBy -Company -Software \
         -Title -Subject -Keywords -CreatorTool ./docs/*.pdf

# Office-specific (XMP / DocSecurity)
exiftool -CompObjUserType -DocSecurity -Template -RevisionNumber \
         -TotalEditTime -CompanyName ./docs/*.docx

# Image metadata in embedded photos
exiftool -GPSLatitude -GPSLongitude -Make -Model -DateTimeOriginal ./docs/

# ═══════════════════════════════════════════════════════════
# WHAT METADATA REVEALS
# ═══════════════════════════════════════════════════════════
# - Active Directory usernames (Author, LastModifiedBy fields)
# - Software versions (Creator: "Microsoft Word 16.0.17328" → patch level)
# - Internal file paths (HyperlinkBase, Template paths like
#   "C:\Users\jsmith\OneDrive - Target Corp\Templates\Confidential.dotx")
# - Printer names (CreatorTool sometimes references "PDF Printer @ NYC-PRT01")
# - GPS coordinates (mobile-camera photos embedded in PDF/Office)
# - Save history (RevisionNumber + TotalEditTime → workflow patterns)
# - Embedded fonts (corporate-branded fonts → fingerprint other docs)

# ═══════════════════════════════════════════════════════════
# AUTOMATED METADATA TOOLING
# ═══════════════════════════════════════════════════════════
# FOCA (ElevenPaths — Windows GUI; v3.4.7.1 latest as of Aug 2025)
# https://github.com/ElevenPaths/FOCA
# Extracts metadata + infers internal network structure from document
# properties + cross-references discovered users against collected docs

# metagoofil (opsdisk fork — canonical, on Kali; original laramies fork dead)
# https://github.com/opsdisk/metagoofil
# ⚠ TARGET-TOUCH ACTIVE — downloads documents directly via Google search
metagoofil -d target.com -t pdf,doc,docx,xls,xlsx,ppt,pptx -l 100 -n 50 \
           -o ./docs/ -f metagoofil_results.html
```

```
═══════════════════════════════════════════════════════════
SECTION 5 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §6 cred reuse (every harvested credential gets HIBP/DeHashed lookup)
Enables → §4 employee enum (commit authors, doc Authors expand the roster)
Enables → §8 supply chain (NPM/Docker reveal which third parties target uses)
Prereq → §1 GitHub org name discovery (need org slug first; see §4 LinkedIn)
Cross-ref → §10 ransomware leak sites often publish dumped repos AFTER breach
Alternative → If GitHub is sparse, pivot to GitLab.com, Bitbucket, Gitea
              public instances (Shodan: http.title:"Sign in · GitLab")
```

---

## 6 — CREDENTIAL & BREACH INTELLIGENCE

> **Typical chains through this section:** Email list from §4 → batch HIBP/DeHashed/IntelX queries → identify breaches each email appears in → pull corresponding plaintext / hash dumps (where lawful) → §6.2 stealer-log enrichment for FRESH credentials (the dominant 2024-2026 source) → IAB market check → password-pattern analysis → spray candidate list compiled for §03 Initial Access cheatsheet.

### 6.1 — Breach Database Searches

```bash
# ═══════════════════════════════════════════════════════════
# HAVE I BEEN PWNED (HIBP) — CANONICAL BREACH INDEX
# MITRE ATT&CK: T1589.001 (Credentials), T1597.001 (Threat Intel Vendors)
# OPSEC RATING:  PURE PASSIVE
# DETECTION (target): None
# DETECTION (third-party): Troy Hunt's HIBP logs API key + IP per query
# ═══════════════════════════════════════════════════════════
# v3 API requires paid subscription for breached-account lookup.
# Pwned Passwords API (k-anonymity hash check) is free without auth.

# Per-email lookup (paid; subscription required)
curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/user@target.com" \
  -H "hibp-api-key: $HIBP_KEY" \
  -H "User-Agent: research-purposes" \
  | jq

# Domain-wide search (requires Domain Search subscription + DNS verification)
# https://haveibeenpwned.com/DomainSearch  → enter domain → verify ownership

# All breaches metadata (no auth required — useful for context)
curl -s "https://haveibeenpwned.com/api/v3/breaches" | jq

# Pwned Passwords (k-anonymity; FREE, no auth)
HASH=$(echo -n "Password123!" | sha1sum | awk '{print toupper($1)}')
PREFIX=${HASH:0:5}
SUFFIX=${HASH:5}
curl -s "https://api.pwnedpasswords.com/range/$PREFIX" | grep -i "$SUFFIX"

# ═══════════════════════════════════════════════════════════
# DEHASHED — SEARCH BY DOMAIN / EMAIL / USERNAME / IP / NAME
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# Independent (no Atlas Privacy acquisition confirmed as of April 2026).
# Returns: email, username, password (hashed/plain), name, source DB.
# https://dehashed.com/search?query=target.com
curl -s "https://api.dehashed.com/search?query=domain:target.com" \
  -u "$DEHASHED_EMAIL:$DEHASHED_KEY" -H 'Accept: application/json' \
  | jq '.entries[] | {email, username, password, name, database_name}'

# ═══════════════════════════════════════════════════════════
# INTELLIGENCE X (IntelX) — DEEP & DARK WEB INDEX
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# Indexes paste sites, leak forums, dark web marketplaces, public GitLeaks.
# https://intelx.io/?s=target.com
curl -s "https://2.intelx.io/intelligent/search" \
  -H "x-key: $INTELX_KEY" -H "Content-Type: application/json" \
  -d '{"term":"target.com","maxresults":100,"media":0,"sort":4}'

# ═══════════════════════════════════════════════════════════
# OTHER BREACH AGGREGATORS (vary in availability / price / coverage)
# ═══════════════════════════════════════════════════════════
# LeakCheck       https://leakcheck.io/             (paid)
# Snusbase        https://snusbase.com/             (paid; intermittent availability)
# LeakPeek        https://leakpeek.com/             (paid)
# BreachDirectory https://breachdirectory.org/      (free, limited)
# CIT0DAY mirrors (private; the original CIT0DAY combo collection circulates
#                  in operator circles; quality varies)
# Combolists from RaidForums successor sites (BreachForums, CrackedTo, Sinisrly)
#   — intermittent; require sock-puppet forum accounts

# ═══════════════════════════════════════════════════════════
# WHAT BREACH DATA YIELDS
# ═══════════════════════════════════════════════════════════
# - Plaintext or hashed passwords → crack offline → spray against target
# - Password PATTERNS (users reuse: Company2023!, Season+Year, child names,
#   sports teams) → enables tailored guessing not dictionary spray
# - Personal emails → corporate-email correlation (find work email from
#   personal-email breach)
# - Phone numbers → vishing / smishing campaigns
# - Physical addresses → physical access ops, mail-based phishing
# - Security question answers → password reset flows
```

### 6.2 — Stealer-Log Marketplaces & Aggregators

```bash
# ═══════════════════════════════════════════════════════════
# STEALER LOGS — DOMINANT 2024-2026 FRESH-CREDENTIAL SOURCE
# MITRE ATT&CK: T1589.001 (Credentials), T1597.001 (Threat Intel Vendors)
# OPSEC RATING:  PURE PASSIVE for query against intel platforms;
#                LOW-TOUCH ACTIVE for marketplace contact;
#                LEGAL EXPOSURE — purchase of stolen access can violate
#                CFAA / NIS2 / Computer Misuse Act regardless of authorization
#                from the engagement target. Verify with counsel.
# ═══════════════════════════════════════════════════════════
# Stealer logs are infostealer output — the credentials, cookies, autofill
# data, and crypto wallets harvested from victim machines. Major families:
#   RedLine (decline 2023+ after takedowns; LATEST forks still active)
#   Raccoon Stealer v1/v2 (active despite 2022 disruption)
#   Lumma Stealer (dominant 2024-2026)
#   StealC (active, MaaS model)
#   Vidar (active)
#   RisePro (active)
#   ACR Stealer (newer, 2024)
#   Atomic Stealer / AMOS (macOS-focused)
#
# Stealer logs are categorically different from breach dumps:
#   - FRESH (hours-to-days old, not 2-year-old breach)
#   - SESSION COOKIES included (bypass MFA via session replay)
#   - AUTOFILL data (every site the victim has saved password for)
#   - CRYPTO WALLET seed phrases
#   - Targeted enrichment by infrastructure (which victims work where)
#
# ═══════════════════════════════════════════════════════════
# COMMERCIAL STEALER-LOG INTEL FEEDS (legitimate, paid)
# ═══════════════════════════════════════════════════════════
# HudsonRock          https://www.hudsonrock.com/   (specialist; free public
#                                                    site for domain summaries)
# Flare               https://flare.io/             (full SaaS platform)
# Constella           https://constella.ai/         (identity-focused)
# Recorded Future     https://www.recordedfuture.com/  (broader threat intel,
#                                                       includes stealer feeds)
# IntSights / Rapid7   https://www.rapid7.com/      (Rapid7 acquired)
# SOCRadar            https://socradar.io/          (broad coverage)
# DarkOwl             https://www.darkowl.com/      (deep dark-web crawl)
# KELA                https://www.kelacyber.com/    (criminal-underground intel)
# Cybersixgill        https://cybersixgill.com/     (broad coverage)
#
# HudsonRock free public lookup (no auth):
# https://www.hudsonrock.com/free-tools/ → enter domain → returns
#   approximate count of corporate-credential infections + sample data

# ═══════════════════════════════════════════════════════════
# UNDERGROUND MARKETPLACES (operational caution required)
# ═══════════════════════════════════════════════════════════
# Russian-language clearnet/Tor markets that historically sold stealer logs:
#   - Russian Market (Genesis-style — bot/cookie-based access)
#   - 2easy.shop                  (logs by ZIP file per infection)
#   - Industrial Spy              (broader leak-for-sale)
#   - Telegram channels: @logscloud, @amigos_logs, similar (rotates frequently)
#
# Genesis Market was disrupted in April 2023 (Operation Cookie Monster — FBI
# led, multi-country); successors emerged within weeks. Russian Market remains
# active despite continued disruption attempts.
#
# Operator caution:
#   - Use isolated Tor-routed VM with no operational tooling
#   - Use throwaway crypto purchased with no PII trail
#   - Engagement RoE must explicitly authorize stealer-log enrichment
#   - Many marketplaces are honeypots / law-enforcement run / scam-only

# Output of stealer-log purchase ("logs"):
#   - Browser cookie databases per profile (Chrome, Edge, Firefox, Brave)
#     including session cookies for active corporate SSO
#   - Saved password databases (frequently includes corporate VPN, RDP,
#     admin panels — secrets the user wouldn't acknowledge having)
#   - System info (OS, AV, AD domain, hostname, install date)
#   - Crypto wallets, FTP creds, Discord tokens, Telegram session
#   - Screenshot at time of infection (often shows internal apps)
#
# Filter logs by hostname (find any log from a target's domain-joined machine):
#   grep -lr "target.com" ./purchased-logs/
#   grep -lr "@target.com" ./purchased-logs/
#   grep -lr "target.local" ./purchased-logs/
#   for d in ./logs/*/; do grep -l "DomainName.*target" "$d"/Information.txt; done
```

### 6.3 — Initial Access Broker (IAB) Forums & Channels

```
═══════════════════════════════════════════════════════════
INITIAL ACCESS BROKER INTELLIGENCE
MITRE ATT&CK: T1597.001 (Threat Intel Vendors), T1589.001 (Credentials)
OPSEC RATING:  PURE PASSIVE for monitoring; HIGH-RISK for marketplace contact
═══════════════════════════════════════════════════════════
IABs sell pre-validated network access (VPN, RDP, web shell, admin
credentials) to ransomware and APT operators. Their listings are the
single highest-fidelity public indicator of which orgs are about to be
ransomwared.

Active IAB forums / channels (rotate frequently; current as of Q1 2026):
  - exploit.in                  (Russian; primary, post-RaidForums shutdown)
  - xss.is                      (Russian; second-tier)
  - BreachForums                (English; periodically seized + relaunched)
  - LeakBase                    (English; BreachForums splinter)
  - CrackedTo                   (English; lower-tier)
  - Telegram channels:          (constantly rotate; @darkforums*, @ramp*)
  - Russian Market              (atomized access — single-host RDP creds)

Listing format you'll see (sanitized example):
  "Selling access — US — Manufacturing — $2.8B revenue — VPN +
   Domain User — 2,400 hosts — Citrix entry point — $25k starting"

Intelligence-only consumption:
  - Confirms target's likely upcoming compromise (use to update threat
    posture for defenders, NOT to pivot to attack)
  - Reveals attack-vector pattern (Citrix CVE wave, exposed RDP,
    initial-access malware family)
  - Identifies ransomware groups likely to follow

Aggregation services that monitor IAB postings (legal, paid):
  KELA, Flare, SOCRadar, Cybersixgill, Group-IB Threat Intelligence,
  Recorded Future, IntelBroker monitoring, Hudson Rock IAB module

Tooling for monitoring (operator-side, no purchase):
  https://github.com/Apr3y/iab-monitor       (Telegram channel scraper)
  https://github.com/HackToolKit/dread-monitor (forum monitoring)
```

### 6.4 — Dark Web & Paste-Site Monitoring

```bash
# ═══════════════════════════════════════════════════════════
# RANSOMWARE LEAK SITES (Tor — operator infrastructure required)
# MITRE ATT&CK: T1597.002 (Purchase Technical Data)
# OPSEC RATING:  PURE PASSIVE for monitoring, requires Tor; never download
#                stolen data over operational infrastructure
# ═══════════════════════════════════════════════════════════
# Active leak sites (rotate frequently — list current as of Q1 2026):
#   - LockBit (recurring takedown + relaunch)
#   - ALPHV / BlackCat (FBI takedown 2024; some splinter activity)
#   - Akira
#   - Play
#   - 8base
#   - Medusa
#   - Hunters International
#   - INC Ransom
#   - RansomHub
#   - Cl0p (data extortion focus)
#   - BianLian
#   - Qilin (Agenda)
#
# Aggregator sites (clearnet, view leak indices without per-group Tor):
#   https://ransomware.live/                  (real-time aggregation)
#   https://www.ransomlook.io/                (leak-site monitoring)
#   https://thedfirreport.com/                (post-attack analyses)
#   https://github.com/joshhighet/ransomwatch  (open-source watch list)
#   https://twitter.com/ecrime_ch              (eCrime channel monitoring)
#   https://github.com/cybermonitor/APT_CyberCriminal_Campagin_Collections

# ═══════════════════════════════════════════════════════════
# PASTE-SITE MONITORING
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# Pastebin has heavily restricted public scraping; many leaks now appear on:
#   - Doxbin            https://doxbin.com/
#   - JustPaste.it      https://justpaste.it/
#   - PrivateBin instances (self-hosted; not searchable)
#   - ControlC          https://controlc.com/
#   - GhostBin          https://ghostbin.site/
#   - Telegram channels (@*_paste, @leakedinfo, etc.)
#   - GitHub Gists      gist.github.com (search via §5.2 GitHub Code Search)
#   - Pastes-as-Service: textbin.com, pastefs.com, hastebin.com

# Search aggregators
# https://psbdmp.ws/                           (Pastebin dump archive)
# https://intelx.io/                           (IntelX indexes pastes)

# ═══════════════════════════════════════════════════════════
# TELEGRAM CHANNEL MONITORING (rising channel for stolen data trade)
# OPSEC RATING:  LOW-TOUCH ACTIVE — joining channels logs your account ID
# ═══════════════════════════════════════════════════════════
# Telegram has eclipsed many paste sites for stolen-data trade in 2023-2026.
# Channels rotate frequently as Telegram bans accounts.
# Indexing tools (imperfect but rising):
#   https://tgstat.com/                       (channel ranking + search)
#   https://lyzem.com/                        (channel search engine)
#   https://t.me/s/<channel>                  (web view, no Telegram account)
# Open-source channel scrapers:
#   https://github.com/expectocode/telegram-export
#   https://github.com/snoopgod/tgscan
```

### 6.5 — Google Dorking for Leaks

```
═══════════════════════════════════════════════════════════
GOOGLE / BING / DUCKDUCKGO DORKS — TARGET-DOMAIN
MITRE ATT&CK: T1593.002 (Search Engines)
OPSEC RATING:  PURE PASSIVE — search engines see only your queries
═══════════════════════════════════════════════════════════

# ─── HIGH-VALUE FILE EXTENSIONS ─────────────────────────────
site:target.com filetype:env                     # .env files with secrets
site:target.com filetype:sql                     # SQL dumps
site:target.com filetype:log                     # log files
site:target.com filetype:bak OR filetype:backup  # backups
site:target.com filetype:conf OR filetype:cfg    # config files
site:target.com filetype:xml password            # XML configs with passwords
site:target.com filetype:json (api OR token OR secret)
site:target.com filetype:yml password            # YAML configs
site:target.com filetype:properties              # Java properties files
site:target.com filetype:psd1 password           # PowerShell config

# ─── PATH / TITLE / URL DORKS ───────────────────────────────
site:target.com intitle:"index of"               # directory listings
site:target.com inurl:admin                      # admin panels
site:target.com inurl:login                      # login pages
site:target.com inurl:api                        # API endpoints
site:target.com inurl:swagger                    # API documentation
site:target.com inurl:v2/api-docs                # OpenAPI / Swagger 2
site:target.com inurl:graphql                    # GraphQL endpoints
site:target.com inurl:actuator                   # Spring Boot Actuator
site:target.com inurl:phpinfo                    # PHP info dumps
site:target.com inurl:.git                       # exposed .git directories
site:target.com inurl:wp-admin                   # WordPress admin
site:target.com inurl:console                    # admin consoles

# ─── CONFIDENTIAL DOCUMENTS ─────────────────────────────────
site:target.com filetype:pdf "confidential"
site:target.com filetype:pdf "internal use only"
site:target.com filetype:docx "do not distribute"
inurl:target.com filetype:pdf confidential

# ─── EXTERNAL LEAK SITES MENTIONING TARGET ──────────────────
site:pastebin.com "target.com"                   # Pastebin (limited)
site:github.com "target.com" password            # GitHub
site:gitlab.com "target.com" "BEGIN PRIVATE KEY"
site:trello.com "target.com"                     # Trello (often public)
site:*.atlassian.net "target.com"                # Confluence/Jira public
site:notion.site "target.com"                    # Notion public pages
site:notion.so "target.com"                      # Notion alt domain
site:*.s3.amazonaws.com "target"                 # exposed S3 buckets
site:*.blob.core.windows.net "target"            # exposed Azure blobs
site:*.storage.googleapis.com "target"           # exposed GCS buckets
site:*.linear.app "target.com"                   # Linear public projects
site:postman.com "target.com"                    # Postman public workspaces
site:reddit.com "target.com" inurl:r/sysadmin    # admin chatter

# ─── REFERENCES / CHEAT SHEET DBs ───────────────────────────
# Google Hacking Database: https://www.exploit-db.com/google-hacking-database
# DorkSearch:              https://dorksearch.com/
# Pagodo (auto-dorker):    https://github.com/opsdisk/pagodo

# ─── BING / DUCKDUCKGO PARITY ───────────────────────────────
# Bing supports `site:`, `filetype:`, `inurl:` similarly + has different
# index coverage (often retains links Google has dropped).
# DuckDuckGo lite (no JS) sometimes returns results filtered out of Google.
```

```
═══════════════════════════════════════════════════════════
SECTION 6 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §03 Initial Access (password spray candidate compilation)
Enables → §10 threat intel (ransomware leak sites confirm sector targeting)
Prereq → §4 email harvesting (need email list before HIBP/DeHashed lookup)
Cross-ref → §6.2 stealer logs feed §03 token-replay attacks
            (cookies + passwords from infected employee devices)
Alternative → If HIBP returns nothing, try DeHashed by username (NOT email)
              and IntelX by domain — different indices catch different breaches
```

---

## 7 — CLOUD & IDENTITY-PLANE PASSIVE RECON

> **Typical chains through this section:** DNS / cert / header indicators → cloud-provider identification → tenant-existence confirmation (Entra GetUserRealm, AWS account-ID disclosure, Okta tenant probe) → IdP federation discovery → tenant-branding fingerprint for phishing pretext → cloud-asset enumeration → §03 Initial Access targeting (device-code, OAuth consent, federated SSO).

### 7.1 — Cloud Provider Identification

```bash
# ═══════════════════════════════════════════════════════════
# DNS / CERT / HEADER INDICATORS OF CLOUD PROVIDER
# MITRE ATT&CK: T1590.001 (Domain Properties), T1591.002 (Business Relationships)
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# (See §1.5 for complete CNAME/NS/MX → provider mapping)
dig @8.8.8.8 target.com CNAME +short
dig @8.8.8.8 target.com NS    +short
dig @8.8.8.8 target.com MX    +short

# Quick cloud fingerprint summary:
# AWS:         CNAME *.amazonaws.com / *.cloudfront.net / *.elb.amazonaws.com
# Azure:       CNAME *.azurewebsites.net / *.cloudapp.azure.com / MX *.outlook.com
# GCP:         CNAME *.googleapis.com / *.appspot.com / *.run.app
# Cloudflare:  NS *.ns.cloudflare.com
# Workspace:   MX *.google.com / TXT google-site-verification=
# Microsoft365: MX *.protection.outlook.com / TXT MS=ms########

# Combined cert + DNS fingerprint via Censys:
# search.censys.io: services.tls.certificates.leaf_data.subject.common_name:
#   "target.com" and autonomous_system.organization: "AMAZON-02"
```

### 7.2 — Cloud Asset Discovery (S3 / Blob / GCS)

```bash
# ═══════════════════════════════════════════════════════════
# CLOUD STORAGE BUCKET DISCOVERY
# MITRE ATT&CK: T1593.003 (Code Repositories), T1596.005 (Scan Databases)
# OPSEC RATING:  LOW-TOUCH ACTIVE — DNS lookups + HTTP HEAD against
#                provider-controlled endpoints (NOT target's infra). Most
#                bucket probes hit AWS/Azure/GCP IPs, not target.
# ═══════════════════════════════════════════════════════════
# cloud_enum (initstring) — multi-cloud enumeration
# https://github.com/initstring/cloud_enum
python3 cloud_enum.py -k target -k "target corp" -k "targetcorp" \
                      -k "target-prod" -k "target-dev" \
                      -l cloud_results.txt --disable-azure-files

# ─── AWS S3 ─────────────────────────────────────────────────
# Bucket name patterns to test:
#   {target}, {target}-{env}, {target}-backup, {target}-logs,
#   {target}-prod, {target}-dev, {target}-staging, {target}-data,
#   {target}-internal, {target}-private, {target}-public, {target}-cdn,
#   {target}-uploads, {target}-images, {target}-archive
#
# DNS-based probe (PURE PASSIVE — no HTTP):
nslookup target.s3.amazonaws.com
# NXDOMAIN = bucket doesn't exist
# Resolves = bucket exists (regardless of public/private)
#
# HTTP HEAD probe (LOW-TOUCH ACTIVE — touches AWS, not target):
curl -sI "https://target.s3.amazonaws.com/" | head -1
# 200 OK / 403 Forbidden = exists; 404 = doesn't exist; check region in headers
#
# Region-specific:
curl -sI "https://target.s3.us-east-1.amazonaws.com/"
curl -sI "https://target.s3.eu-west-1.amazonaws.com/"
#
# Tools:
# https://github.com/sa7mon/S3Scanner   (active; bulk bucket testing)
# https://github.com/hueristiq/xs3      (alternate)

# ─── AZURE BLOB STORAGE ─────────────────────────────────────
# Pattern: {storage-account}.blob.core.windows.net
# Account names: 3-24 chars, lowercase + digits only, globally unique
nslookup target.blob.core.windows.net
curl -sI "https://target.blob.core.windows.net/"
# 400 InvalidQueryParameterValue = exists (account live, no container specified)
# Subdomains for Azure storage variants:
#   *.blob.core.windows.net    (Blob Storage)
#   *.file.core.windows.net    (Azure Files)
#   *.queue.core.windows.net   (Queue Storage)
#   *.table.core.windows.net   (Table Storage)
#   *.dfs.core.windows.net     (Data Lake Gen2)

# ─── GCP CLOUD STORAGE ──────────────────────────────────────
# Pattern: storage.googleapis.com/{bucket-name} OR {bucket}.storage.googleapis.com
curl -sI "https://storage.googleapis.com/target/"

# ═══════════════════════════════════════════════════════════
# SHODAN/CENSYS FOR EXPOSED CLOUD STORAGE
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
shodan search 'http.title:"target" "ListBucketResult"'   # public S3 listings
shodan search 'http.title:"BlobNotFound"'                 # Azure blob 404s
shodan search 'http.html:"NoSuchKey" host:storage.googleapis.com'

# ═══════════════════════════════════════════════════════════
# PUBLIC CLOUD-CONTAINER REGISTRIES
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# AWS ECR Public Gallery:   https://gallery.ecr.aws/  (search target name)
# Google Artifact Registry: gcr.io/, us-docker.pkg.dev/ (often public)
# Azure Container Registry: target.azurecr.io (test for existence)
nslookup target.azurecr.io
```

### 7.3 — Entra ID / Azure Tenant Outsider Recon

```bash
# ═══════════════════════════════════════════════════════════
# ENTRA ID TENANT EXISTENCE & FEDERATION DISCOVERY
# MITRE ATT&CK: T1590.001 (Domain Properties), T1591.002 (Business Relationships),
#               T1597.001 (Threat Intel Vendors)
# OPSEC RATING:  LOW-TOUCH ACTIVE — queries hit login.microsoftonline.com,
#                NOT target. Microsoft sees the query; target sees nothing.
# DETECTION (target):     None
# DETECTION (Microsoft):  Standard tenant-discovery traffic; not anomalous
# ═══════════════════════════════════════════════════════════
# These endpoints are public-by-design — they're the public side of
# federated SSO bootstrapping. Standard outsider recon for any Entra-tenant
# enterprise in 2026.

# ─── 1. OPENID CONFIGURATION (tenant existence + tenant ID) ─
curl -s "https://login.microsoftonline.com/target.com/.well-known/openid-configuration" \
  | jq '{issuer, token_endpoint, authorization_endpoint, tenant_region_scope}'
# If response contains tenant ID GUID → tenant exists. Issuer URL embeds it:
#   https://login.microsoftonline.com/<TENANT_GUID>/v2.0
# tenant_region_scope reveals NA / EU / AS / WW data residency

# ─── 2. GETUSERREALM (federation status; not "GECOS") ───────
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=user@target.com&xml=1"
# OR JSON form:
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=user@target.com&json=1" | jq
# NameSpaceType: "Managed"   → cloud-only Entra (or pass-through auth)
# NameSpaceType: "Federated" → on-prem ADFS / third-party IdP federation
# NameSpaceType: "Unknown"   → no tenant, or username invalid
# FederationBrandName: shows the IdP brand string ("My Company SSO")
# AuthURL: URL of the federated IdP — pivot to §7.6 Okta/Auth0/PingFed recon

# ─── 3. AADInternals — STRUCTURED OUTSIDER RECON ────────────
# https://aadinternals.com/aadinternals/  (Dr. Nestori Syynimaa; active)
# PowerShell module — outsider recon requires NO authentication
Install-Module AADInternals
Import-Module AADInternals
Invoke-AADIntReconAsOutsider -DomainName target.com
# Returns:
#   - Tenant ID (GUID)
#   - Tenant brand name
#   - Tenant region
#   - All registered domains in the tenant (via federation metadata aggregation)
#   - Per-domain: federation status, MX target, SPF, MTA-STS, DNSSEC
#   - DesktopSSO status (sso.target.com / autologon.microsoftazuread-sso.com)
Get-AADIntTenantInformation -Domain target.com
Get-AADIntLoginInformation -Domain target.com

# ─── 4. TENANT BRANDING (visual fingerprint for pretexts) ───
# Tenant logos / sign-in customization are publicly cached:
curl -sI "https://aadcdn.msftauth.net/shared/1.0/content/images/microsoft_logo_*.svg"
curl -sI "https://aadcdn.msftauth.net/dbd5a2dd-xxxxxxxxxx/logintenantbranding/0/bannerlogo"
# Get tenant branding by issuing browser-style request:
curl -s "https://login.microsoftonline.com/<TENANT_GUID>/v2.0/.well-known/openid-configuration"
# Tenant logos confirm tenant ownership for phishing-pretext infrastructure.

# ─── 5. AUTODISCOVER (federation chain discovery) ───────────
curl -s "https://outlook.office.com/autodiscover/autodiscover.json/v1.0/user@target.com?Protocol=Autodiscoverv1"
# Returns tenant URL pattern + protocol info → confirms tenant active

# ─── 6. FEDERATIONMETADATA.XML (federated IdP technical detail) ─
# For ADFS / federated tenants, the federation metadata is public-by-design:
curl -s "https://sts.target.com/FederationMetadata/2007-06/FederationMetadata.xml" | xmllint --format -
# Reveals:
#   - Signing certificate (public key + issuer details)
#   - Token-issuance endpoint URLs
#   - Supported claim issuers / claim types
#   - WS-Trust + SAML protocol bindings
#   - ADFS server hostname pattern

# ─── 7. ROADtools / ROADrecon (post-cred enumeration; mention) ─
# https://github.com/dirkjanm/ROADtools
# ROADrecon requires AT LEAST a valid token to enumerate tenant — it's
# powerful but NOT pure-outsider. AADInternals is the unauth outsider tool.

# ─── 8. TENANT-DOMAIN ENUMERATION (alt domains in same tenant) ─
# A single tenant frequently hosts multiple domains. Enumerate via:
curl -s "https://login.microsoftonline.com/<TENANT_GUID>/v2.0/.well-known/openid-configuration"
# OR via AADInternals which aggregates federated domains
Get-AADIntTenantDomains -Domain target.com
# Reveals: target.com, target.onmicrosoft.com, acquisitions.target.com,
#          target-staging.com, etc.

# ═══════════════════════════════════════════════════════════
# MICROSOFT GRAPH UNAUTHENTICATED ENDPOINTS
# OPSEC RATING:  LOW-TOUCH ACTIVE
# ═══════════════════════════════════════════════════════════
# Most Graph endpoints require auth. The following do NOT and reveal
# tenant-level info to outsiders:
curl -s "https://login.microsoftonline.com/<TENANT_GUID>/v2.0/.well-known/openid-configuration"
curl -s "https://aadcdn.msftauthimages.net/dbd5a2dd-.../logintenantbranding/0/customcss"
curl -s "https://login.microsoftonline.com/common/userrealm/user@target.com?api-version=2.1"
```

### 7.4 — Google Workspace Outsider Recon

```bash
# ═══════════════════════════════════════════════════════════
# GOOGLE WORKSPACE TENANT CONFIRMATION
# MITRE ATT&CK: T1590.001 (Domain Properties)
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# Google Workspace doesn't expose an OpenID configuration as cleanly as
# Entra; tenant existence is inferred from MX + SPF + verification TXT.

# 1. MX records → Google
dig @8.8.8.8 target.com MX +short | grep -i google
# Expected: aspmx.l.google.com, alt1.aspmx.l.google.com, etc.

# 2. SPF record → Google sender authorization
dig @8.8.8.8 target.com TXT +short | grep -i 'include:_spf.google.com'

# 3. Verification token confirms tenant exists
dig @8.8.8.8 target.com TXT +short | grep -i 'google-site-verification='

# 4. Calendar / Drive "available for sharing" probe (LOW-TOUCH ACTIVE):
#    Querying https://calendar.google.com/calendar/u/0/embed?src=user%40target.com
#    returns 404 vs 200 indicating account existence in some flows.
#    Use sparingly — automated probing trips Google rate limits + abuse alerts.

# 5. DKIM selector probe:
dig @8.8.8.8 google._domainkey.target.com TXT +short

# Google Cloud Customer ID (Workspace tenant ID) is NOT publicly enumerable
# without authenticated access. Workspace recon is shallower than Entra recon.
```

### 7.5 — AWS Account-ID Enumeration

```bash
# ═══════════════════════════════════════════════════════════
# AWS ACCOUNT ID DISCOVERY (passive pivots)
# MITRE ATT&CK: T1591.002 (Business Relationships), T1590.005 (IP Addresses)
# OPSEC RATING:  PURE PASSIVE → LOW-TOUCH ACTIVE depending on technique
# ═══════════════════════════════════════════════════════════
# Why it matters: 12-digit AWS account ID is the persistent identifier that
# pivots to S3 bucket name guessing, IAM-role guessing, cross-account trust
# mapping, and is the seed for Pacu / CloudFox post-exploitation.
# Aaron Frichette ("Frichetten") and Daniel Grzelak documented the techniques.

# ─── 1. CONFUSED-DEPUTY S3 BUCKET POLICY PROBE ──────────────
# (LOW-TOUCH — touches AWS endpoints, not target)
# https://github.com/Frichetten/aws-account-detective
aws-account-detective bucket --bucket-name target-prod-data
# Mechanism: send a crafted GetBucketPolicy / GetObjectAcl request and parse
# the AccessDenied error message — the bucket-owner account ID is leaked
# in the error in some configurations.

# ─── 2. CLOUDFRONT ORIGIN HEADERS ───────────────────────────
# Some CloudFront distributions return X-Amz-Cf-Id and X-Amz-Cf-Pop headers
# that, combined with the distribution ID, can be cross-referenced to
# account ID via timing or via leaked resource ARNs in 5xx error pages.

# ─── 3. PUBLIC LAMBDA FUNCTION URLs ─────────────────────────
# Lambda Function URLs follow pattern:
#   https://<url-id>.lambda-url.<region>.on.aws/
# Account ID is NOT in the URL but error responses sometimes include
# the function ARN: arn:aws:lambda:us-east-1:123456789012:function:name

# ─── 4. PUBLIC ECR REGISTRY ─────────────────────────────────
# Pattern: <account-id>.dkr.ecr.<region>.amazonaws.com
# If target publishes a container image to public ECR:
#   gallery.ecr.aws/<alias>/<image>
# the account ID is sometimes resolvable via the public-gallery alias.

# ─── 5. SAML / SSO METADATA URLs ────────────────────────────
# AWS SSO metadata URLs sometimes contain account IDs:
#   https://signin.aws.amazon.com/saml?Action=ECPMetadata
#   https://<custom>.awsapps.com/start

# ─── 6. SERVICE CONTROL POLICY SIDE-CHANNEL ─────────────────
# Quiet Riot tool: enumerate principal existence (UserName / RoleName) in
# a given account when account ID is known — completes the chicken-and-egg.
# https://github.com/righteousgambit/quiet-riot

# ─── 7. ACCOUNT.AWS.AMAZON.COM PROBE ────────────────────────
# Submitting an account email to https://signin.aws.amazon.com/ returns
# different responses based on whether the account exists. (Use LOW-TOUCH;
# AWS rate-limits aggressively and logs to abuse@aws.amazon.com)

# Tooling consolidation:
#   https://github.com/initstring/cloud_enum   (some AWS account-enum)
#   https://github.com/Frichetten/aws-account-detective
#   https://github.com/righteousgambit/quiet-riot
#   https://github.com/ServerlessOpsIO/cloud_enum_aws

# Once account ID known, pivot to:
#   - CloudFox / Pacu account-level recon (requires creds, but seed is now set)
#   - S3 bucket guessing across known patterns + account ID
#   - IAM role assumption attempts (requires victim's role-trust policy laxness)
#   - Cross-account resource sharing detection via Resource Access Manager
```

### 7.6 — Okta / Auth0 / PingFederate / OneLogin Tenant Fingerprinting

```bash
# ═══════════════════════════════════════════════════════════
# THIRD-PARTY IdP TENANT DISCOVERY
# MITRE ATT&CK: T1590.001 (Domain Properties), T1591.002 (Business Relationships)
# OPSEC RATING:  LOW-TOUCH ACTIVE — touches IdP endpoints (Okta/Auth0/Ping),
#                NOT target. IdP sees the query.
# ═══════════════════════════════════════════════════════════
# Many enterprises front identity with Okta / Auth0 / OneLogin / PingOne
# even when Entra is the authoritative directory. Tenant fingerprinting:
#   - Confirms which IdP brand the user's MFA prompt will look like
#     (informs phishing-pretext fidelity)
#   - Reveals SSO endpoint URLs (target for §03 Initial Access SAML/OIDC abuse)
#   - Identifies pre-provisioned SSO apps (pivot inventory for OAuth consent)

# ─── OKTA ───────────────────────────────────────────────────
# Tenant pattern: {tenant}.okta.com  (or .oktapreview.com, .okta-emea.com)
# Probe existence:
curl -sI "https://target.okta.com/" | head -1
# 200 = tenant exists; 404 = doesn't; 302 to a login = exists with custom branding
curl -s "https://target.okta.com/.well-known/okta-organization" | jq
curl -s "https://target.okta.com/api/v1/org" | jq   # org info if not blocked

# Common naming patterns to guess: target, target-corp, target-prod,
# targetcorporate, targetinc, target-sso, target-okta

# ─── AUTH0 ──────────────────────────────────────────────────
# Tenant pattern: {tenant}.auth0.com  OR custom domain
curl -sI "https://target.auth0.com/" | head -1
curl -s "https://target.auth0.com/.well-known/openid-configuration" | jq

# ─── PINGFEDERATE / PINGONE ─────────────────────────────────
# PingFederate (on-prem):    {pf-host}/idp/startSSO.ping
# PingOne (cloud):           https://auth.pingone.com/{env-id}/as/
# PingID (MFA):              https://desktop.pingone.com/
curl -s "https://auth.pingone.com/.well-known/openid-configuration"
curl -s "https://sso.target.com/idp/startSSO.ping?PartnerSpId=app"

# ─── ONELOGIN ───────────────────────────────────────────────
curl -sI "https://target.onelogin.com/" | head -1
curl -s "https://target.onelogin.com/openid/.well-known/openid-configuration"

# ─── DUO SECURITY (MFA) ─────────────────────────────────────
# Duo customers expose admin URL pattern: admin-{custid}.duosecurity.com
# Probe customer ID via SAML metadata if target publishes it.

# ═══════════════════════════════════════════════════════════
# DETECTION OF FEDERATION CHAIN
# ═══════════════════════════════════════════════════════════
# Chain Entra GetUserRealm output (§7.3) → AuthURL field → resolve to
# discover the federated IdP. Common output:
#   AuthURL: https://login.microsoftonline.com/...   = native Entra
#   AuthURL: https://target.okta.com/...             = Okta-fronted
#   AuthURL: https://sts.target.com/adfs/...         = on-prem ADFS
#   AuthURL: https://login.target.com/...            = custom OIDC/SAML
#   AuthURL: https://target.auth0.com/...            = Auth0-fronted

# Tooling:
# https://github.com/SpecterOps/Mythic              (post-creds, references)
# Manual probes are reliable; no widely-maintained "okta-spoofing-tools" repo
# exists as of April 2026 — operators script these one-shot probes themselves.
```

### 7.7 — WAF / CDN / Security-Vendor Detection

```bash
# ═══════════════════════════════════════════════════════════
# WAF / CDN / SECURITY-EDGE FINGERPRINTING
# MITRE ATT&CK: T1590.006 (Network Security Appliances), T1596.004 (CDNs)
# OPSEC RATING:  PURE PASSIVE (via Shodan/Censys); LOW-TOUCH ACTIVE if
#                fetching headers directly
# ═══════════════════════════════════════════════════════════
# PURE PASSIVE — Shodan/Censys headers (their scan, not yours)
shodan search 'hostname:target.com' --fields http.headers,http.title

# LOW-TOUCH ACTIVE — direct curl (one HTTP request from operator IP)
curl -sI "https://target.com/" | grep -iE 'server|cf-ray|x-amz|x-akamai|x-cdn|x-cache|via|x-fastly'

# ═══════════════════════════════════════════════════════════
# COMMON WAF / CDN / SECURITY HEADER INDICATORS
# ═══════════════════════════════════════════════════════════
# CDN / EDGE:
#   Cloudflare       cf-ray, cf-cache-status, server: cloudflare
#   Fastly           x-served-by, x-cache, x-fastly-* headers
#   AWS CloudFront   x-amz-cf-id, x-amz-cf-pop, via: 1.1 ...cloudfront.net
#   Akamai           x-akamai-transformed, akamai-origin-hop, akamai-grn
#   Microsoft Azure  x-msedge-ref, x-cache, x-azure-ref
#   Google Cloud CDN via: 1.1 google
#   StackPath        x-sp-edge, server: StackPath
#   BunnyCDN         server: BunnyCDN, cdn-cache, cdn-uid
#   CDN77            x-77-cache
#   Imperva/Incapsula x-cdn: Incapsula, x-iinfo, visid_incap_* cookie
#
# WAF (often layered on CDN):
#   Cloudflare WAF   cf-ray, cf-mitigated header, "Attention Required"
#                    challenge page, hcaptcha challenge
#   AWS WAF          x-amzn-requestid, x-amzn-trace-id, AccessDenied JSON
#   Imperva (Incap)  visid_incap, incap_ses_, x-iinfo headers
#   Akamai Kona      AkamaiGHost, ak_bmsc cookie, "Reference #18..." page
#   F5 BIG-IP / ASM  server: BigIP, BIGipServer{pool} cookie, X-Cnection
#   Citrix NetScaler ns_af= cookie, citrix_ns_* cookie, server: NS
#   Fortinet FortiWeb server: FortiWeb, FORTIWAFSID cookie
#   Palo Alto        server: PanOS (rare for web), x-pan-* headers
#   Sucuri           x-sucuri-id, x-sucuri-cache, server: Sucuri/Cloudproxy
#   Wordfence        wzrk_uuid cookie (WordPress), wf_loginalerted
#   Barracuda WAF    server: Barracuda, X-BarraExt
#   Radware          x-rdwr-port-int, x-rdwr-srv
#   ModSecurity      Mod_Security Action, server: Apache/2... +mod_security
#   StackPath WAF    x-sp-* + WAF challenge page
#
# DDoS PROTECTION (separate from WAF):
#   Project Shield    server: Project Shield (Google for journalists / NGOs)
#   Cloudflare Magic  cf-magic-* (transit-layer)
#   AWS Shield Adv    transparent unless attacked
#   Akamai Prolexic   transparent; reveal via routed traffic patterns

# Tools:
# wafw00f         (TARGET-TOUCH ACTIVE — 2-3 probes from operator IP)
#                 https://github.com/EnableSecurity/wafw00f
wafw00f https://target.com -a -v
# whatwaf         alternative
# https://github.com/Ekultek/WhatWaf
```

### 7.8 — Email Security Posture Assessment

```bash
# ═══════════════════════════════════════════════════════════
# DMARC / SPF / DKIM / MTA-STS / TLS-RPT / BIMI ANALYSIS
# MITRE ATT&CK: T1590.001 (Domain Properties), T1591.002 (Business Relationships)
# OPSEC RATING:  PURE PASSIVE — public DNS records
# ═══════════════════════════════════════════════════════════
# Determines email-spoofing feasibility for §03 Initial Access phishing.

# ─── MX (gateway identification) ────────────────────────────
dig @8.8.8.8 target.com MX +short
# *.protection.outlook.com  → Microsoft EOP
# *.pphosted.com            → Proofpoint
# *.mimecast.com            → Mimecast
# *.barracudanetworks.com   → Barracuda
# *.iphmx.com               → Cisco Secure Email Cloud
# *.amazonses.com           → AWS SES (sender; rare as inbound MX)
# *.mailcontrol.com         → Forcepoint
# *.zix.com                 → Zix encrypted email

# ─── SPF (sender authorization) ─────────────────────────────
dig @8.8.8.8 target.com TXT +short | grep '^"v=spf1'
# Parse "include:" entries to identify ALL authorized senders:
dig @8.8.8.8 target.com TXT +short | grep -oE 'include:[^ "]+'
# Common includes:
#   include:_spf.google.com       → Google Workspace
#   include:spf.protection.outlook.com → Microsoft 365
#   include:_spf.salesforce.com   → Salesforce sends mail on behalf
#   include:sendgrid.net          → SendGrid (marketing / transactional)
#   include:amazonses.com         → AWS SES
#   include:mailgun.org           → Mailgun
#   include:_spf.mlsend.com       → MailerLite
#   include:servers.mcsv.net      → Mailchimp
#   include:_spf.pphosted.com     → Proofpoint outbound
#
# SPF terminator: -all (hard fail) / ~all (softfail) / ?all (neutral) / +all (FATAL)

# ─── DMARC (enforcement policy) ─────────────────────────────
dig @8.8.8.8 _dmarc.target.com TXT +short
# v=DMARC1; p=<policy>; rua=mailto:...; ruf=mailto:...; sp=<subdomain-policy>
# Policy values:
#   p=reject       → strict; spoofing typically blocked at receiver
#   p=quarantine   → suspicious mail goes to junk
#   p=none         → REPORT-ONLY; receivers do not act on failures
#                    BUT M365 / Workspace still apply heuristic anti-spoofing
# rua / ruf addresses sometimes belong to a 3rd-party DMARC provider:
#   *@dmarcian.com, *@valimail.com, *@agari.com, *@dmarcanalyzer.com
#   → reveals which DMARC vendor target uses (intel for §8 supply chain)

# Subdomain policy (sp=):
#   sp=reject      → subdomain spoofing also blocked
#   sp=none        → subdomain spoofing may succeed even if p=reject

# ─── MTA-STS (TLS-enforced delivery policy) ─────────────────
dig @8.8.8.8 _mta-sts.target.com TXT +short
# v=STSv1; id=20251015T120000Z   → policy ID, fetch policy file:
curl -s https://mta-sts.target.com/.well-known/mta-sts.txt
# mode: enforce / testing / none — enforce blocks downgrades

# ─── TLS-RPT (TLS reporting endpoint) ───────────────────────
dig @8.8.8.8 _smtp._tls.target.com TXT +short
# v=TLSRPTv1; rua=mailto:tls-rpt@target.com

# ─── DKIM (selector enumeration) ────────────────────────────
for sel in google selector1 selector2 s1 s2 mail dkim k1 k2 default \
           sendgrid mandrill smtp pm-bounces zoho sparkpost mailgun \
           amazonses pphosted mimecast salesforce hubspot; do
  result=$(dig @8.8.8.8 ${sel}._domainkey.target.com TXT +short)
  [ -n "$result" ] && echo "DKIM ${sel}: $result"
done

# ─── BIMI (brand indicator) ─────────────────────────────────
dig @8.8.8.8 default._bimi.target.com TXT +short
# v=BIMI1; l=https://target.com/bimi.svg; a=https://target.com/bimi-vmc.pem
# BIMI requires DMARC p=quarantine or stricter; absence implies p=none

# ═══════════════════════════════════════════════════════════
# WHAT EMAIL POSTURE TELLS YOU FOR INITIAL ACCESS PLANNING
# ═══════════════════════════════════════════════════════════
# p=reject + Proofpoint/Mimecast → spoofing blocked at receiver gateway;
#   use lookalike domain (typo, homoglyph, registered TLD) or legitimate-
#   account compromise (compromise a vendor's mail account, send via them)
# p=quarantine                   → spoofed mail lands in junk; user
#                                  retrieval depends on filter UX
# p=none + no gateway             → direct domain spoofing may work (verify
#                                  via test send to operator-controlled MX)
# Missing DMARC entirely         → spoofing-permissive; many M365 tenants
#                                  still flag via SmartScreen / heuristics
# include:_spf.google.com        → Google Workspace target
# include:spf.protection.outlook.com → Microsoft 365 target
# Many SPF includes              → vendor sprawl = potential pivot via
#                                  vendor-account compromise

# Tools:
# dmarcian.com, mxtoolbox.com    (web GUIs)
# checkdmarc                     (CLI; free)
# https://github.com/domainaware/checkdmarc
checkdmarc target.com
```

```
═══════════════════════════════════════════════════════════
SECTION 7 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §03 Initial Access (Entra device-code phishing, OAuth consent,
          AWS account-ID seeding for post-cred privesc)
Enables → §04 Persistence (federation-trust paths, app registrations)
Prereq → §1 DNS recon (cloud provider mapping seeds tenant discovery)
Cross-ref → §4 personnel intel (each email's tenant membership confirmed
            via §7.3 GetUserRealm)
Alternative → If Entra recon returns "Unknown" namespace, target may be
              cloud-only Workspace (§7.4) or a non-federated ADFS island
```

---

## 8 — TECHNOLOGY & SUPPLY CHAIN PROFILING

> **Typical chains through this section:** Multi-source tech-stack fingerprint → identify defensive stack from job postings (EDR / SIEM / firewall vendor) → enumerate third-party SaaS via SPF includes + CNAME chains → public job-board API mining for org-chart structure → vendor compromise as a pivot path.

### 8.1 — Technology Stack Identification

```bash
# ═══════════════════════════════════════════════════════════
# MULTI-SOURCE TECH STACK FUSION
# MITRE ATT&CK: T1592.002 (Software), T1591.002 (Business Relationships)
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# No single source is complete — fuse all of:
#   1. DNS records (mail/CDN/DNS hosting/cloud platform — see §1.5)
#   2. Job postings (required tech, security tools, compliance — §8.2/8.3)
#   3. GitHub repos (languages, frameworks, libs, CI/CD — §5)
#   4. Conference talks (employees presenting on tech they use — §4.4)
#   5. LinkedIn profiles (skills/experience tech listings)
#   6. Shodan / Censys (server headers, service versions, TLS configs — §2.3)
#   7. Wappalyzer / BuiltWith / Netcraft (web tech fingerprinting)
#   8. Package registries (NPM/PyPI maintainers reveal internal stack — §5.5)

# BuiltWith (web tech profiling)
# https://builtwith.com/target.com
# Free tier: domain summary; Paid: relationships (other sites by same org)

# Wappalyzer (free 50 lookups/month)
# https://www.wappalyzer.com/lookup/target.com
# Browser extension also available; reveal stack while logged-out browsing

# Netcraft (site report + tech detection)
# https://sitereport.netcraft.com/?url=target.com

# WhatRuns (Chrome extension)
# https://www.whatruns.com/

# Other passive tech detectors:
# Webspoo (https://w3techs.com/sites/info/target.com)
# Wapiti (CLI; https://github.com/wapiti-scanner/wapiti — but actively scans)

# CLI command-line equivalents (TARGET-TOUCH; one HTTP request):
curl -sI "https://target.com/" | grep -iE 'x-powered-by|x-aspnet|server|x-runtime'
curl -s "https://target.com/" | grep -oE '(WordPress|Drupal|Joomla|Shopify|Magento|Wix|Squarespace|Webflow|Ghost|Hugo|Jekyll|Gatsby|Next\.js|Nuxt|React|Vue|Angular)'
```

### 8.2 — Job Posting Analysis

```
═══════════════════════════════════════════════════════════
JOB POSTING NARRATIVE INTELLIGENCE
MITRE ATT&CK: T1591.004 (Identify Roles), T1592.002 (Software)
OPSEC RATING:  PURE PASSIVE
═══════════════════════════════════════════════════════════
Sources:
  - LinkedIn Jobs    (https://www.linkedin.com/jobs/search/?keywords=Target+Corp)
  - Indeed           (https://www.indeed.com/cmp/Target-Corp/jobs)
  - Glassdoor        (https://www.glassdoor.com/Jobs/Target-Corp-Jobs-...)
  - Built In         (https://builtin.com/company/target-corp)
  - Stack Overflow   (https://stackoverflow.com/jobs/companies/target-corp)
  - The Muse         (https://www.themuse.com/companies/targetcorp/jobs)
  - Otta / Welcome to the Jungle  (UK/EU focus)
  - Hired            (engineering-focused)

Tech-stack signals (literal job-posting text → defensive intel):
  "Experience with AWS, Terraform, Kubernetes"     → cloud-native + IaC
  "EKS / GKE / AKS expertise"                      → managed K8s in use
  "Datadog / New Relic / Honeycomb experience"     → observability vendor
  "Splunk Engineer" / "Splunk SOAR developer"      → SIEM + SOAR vendor
  "CrowdStrike / Falcon administration"            → EDR vendor confirmed
  "Microsoft Defender XDR / Sentinel KQL"          → Microsoft security stack
  "SentinelOne / Singularity"                      → S1 EDR confirmed
  "Carbon Black / VMware Carbon Black"             → CB (waning post-VMware)
  "Palo Alto firewall management"                  → perimeter = PAN
  "Fortinet / FortiGate engineer"                  → perimeter = Fortinet
  "Cisco ASA / Firepower expertise"                → perimeter = Cisco
  "Zscaler ZIA / ZPA"                              → SASE/ZTNA = Zscaler
  "Netskope / Cato Networks"                       → SASE alt vendors
  "Tenable.io / Qualys / Rapid7 InsightVM"         → vuln scanner vendor
  "Active Directory / Entra ID hybrid expertise"   → identity hybrid model
  "Okta / SailPoint / Saviynt"                     → IGA / IdP stack
  "ServiceNow developer (CMDB, ITSM)"              → ITSM platform
  "Workday / SAP SuccessFactors / Ceridian Dayforce" → HR platform

Compliance signals:
  "HIPAA compliance"                               → healthcare data (PHI)
  "PCI-DSS"                                        → payment card data
  "SOC 2 Type II"                                  → auditor-driven controls
  "FedRAMP Moderate / High"                        → US fed government data
  "ITAR / EAR"                                     → defense / military data
  "FERPA"                                          → education records
  "GDPR / CCPA / LGPD"                             → broad PII exposure

Org-structure signals:
  - "Reports to VP of Engineering" → flat structure
  - Number of distinct security roles open simultaneously → security team size
  - Locations of openings → footprint expansion / contraction signals
  - Re-postings of same role → high turnover OR unfillable due to RoE/budget

Defensive-stack-inferred targeting:
  - Identified EDR vendor → tailor on-host evasion (see ttp-cheatsheet
    series: §05 Privilege Escalation, §07 Defense Evasion)
  - Identified SIEM → understand correlation surface (KQL for Sentinel,
    SPL for Splunk, EQL/Lucene for Elastic)
  - Identified CASB / SASE → understand egress monitoring depth
  - Compliance scope → exfil priority (PHI / cardholder data / IP)
```

### 8.3 — Public Job-Board APIs

```bash
# ═══════════════════════════════════════════════════════════
# PROGRAMMATIC JOB-BOARD HARVEST (faster than LinkedIn scraping)
# MITRE ATT&CK: T1591.004 (Identify Roles), T1592.002 (Software)
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# Greenhouse, Lever, and Workday expose public job-board APIs that ANY
# org using them serves WITHOUT auth. These return structured JSON of
# every open req including team / location / requirements.

# ─── GREENHOUSE ─────────────────────────────────────────────
# Pattern: boards.greenhouse.io/{org-slug}
# JSON API:
curl -s "https://boards.greenhouse.io/v1/boards/target-corp/jobs?content=true" | jq

# Per-job detail:
curl -s "https://boards.greenhouse.io/v1/boards/target-corp/jobs/<job_id>" | jq

# Common org-slug patterns: lowercase company name, target, target-corp,
# targetinc, target-engineering, etc. Discover slug via:
# https://boards.greenhouse.io/{slug} → 200 = exists; 404 = doesn't

# ─── LEVER ──────────────────────────────────────────────────
# Pattern: jobs.lever.co/{org-slug}
# API:
curl -s "https://api.lever.co/v0/postings/target-corp?mode=json" | jq
curl -s "https://api.lever.co/v0/postings/target-corp/<post-id>?mode=json" | jq

# ─── WORKDAY ────────────────────────────────────────────────
# Pattern: {org}.wd1.myworkdayjobs.com OR {org}.wd5.myworkdayjobs.com (varies)
# Workday's public job listings are exposed via JSON APIs:
curl -s -X POST "https://target.wd1.myworkdayjobs.com/wday/cxs/target/External/jobs" \
  -H "Content-Type: application/json" \
  -d '{"appliedFacets":{},"limit":50,"offset":0,"searchText":""}' | jq

# Discover Workday tenant ID via the public site URL pattern.

# ─── ASHBY (modern HR vendor; growing share) ────────────────
# Pattern: jobs.ashbyhq.com/{org-slug}
curl -s "https://api.ashbyhq.com/posting-api/job-board/{org-slug}" | jq

# ─── BAMBOOHR ───────────────────────────────────────────────
# Pattern: {org}.bamboohr.com/jobs/
curl -s "https://{org}.bamboohr.com/jobs/embed2.php" | jq

# ─── SMARTRECRUITERS / ICIMS / JOBVITE ──────────────────────
# https://api.smartrecruiters.com/v1/companies/{slug}/postings
# https://careers-{org}.icims.com/jobs/intro
# https://app.jobvite.com/CompanyJobs/Careers.aspx?nl=1&c={id}

# Why these matter beyond LinkedIn:
#   - Job ID + req title structure reveals internal team naming
#   - "Hiring Manager" field sometimes present → executive name
#   - Posting age + repost frequency → team velocity / turnover
#   - Salary band (where required by law) → seniority / budget signals
#   - Specific tooling required in job text (raw, not LinkedIn-summarized)
```

### 8.4 — Supply Chain & Third-Party Mapping

```
═══════════════════════════════════════════════════════════
THIRD-PARTY VENDOR & PARTNER ENUMERATION
MITRE ATT&CK: T1591.002 (Business Relationships), T1597.001 (Threat Intel)
OPSEC RATING:  PURE PASSIVE
═══════════════════════════════════════════════════════════

VENDOR DISCOVERY SOURCES:
  - SPF includes (§7.8)               → email-sending third parties
  - DKIM selectors (§7.8)             → mail-as-a-service vendors
  - TXT verification tokens (§1.3)    → SaaS account confirmations
  - TLS cert SANs (§3.1)              → integrated partner domains
  - Privacy policy                     → list of "data processors" (GDPR Art 28)
  - Terms of service                   → identifies marketing/CRM/payment vendors
  - Press releases                     → vendor selection announcements
  - SEC 10-K / 10-Q "material contracts" → top-tier IT vendors named
  - Job postings (§8.2)                → "experience with [vendor X]"
  - DNS CNAME chains (§1.5)            → SaaS provider integrations
  - Acquisitions (§9)                  → legacy domains with weaker security
  - Public RFP / procurement docs      → past vendor evaluations
  - Bug bounty scope (§10.4)           → in-scope subdomains often = SaaS hosts
  - LinkedIn employee bios             → "previously at [target's vendor]"
                                          (former employees confirm vendor use)

WHY THIS MATTERS — TRUSTED THIRD PARTIES ARE PIVOT POINTS:
  - MSP / MSSP compromise        → direct privileged access to target
  - SaaS compromise              → data access without touching target infra
  - Vendor VPN / B2B tunnel      → network-level access via established trust
  - Supply chain code injection  → npm/pip/Maven dep replacement attacks
  - Federated identity B2B       → cross-tenant access policy abuse
  - Shared CI/CD infrastructure  → supply-chain-style code injection
  - Marketing platform abuse     → mass-mailing pretext via legitimate vendor

KEY VENDOR CATEGORIES TO ENUMERATE:
  - IT outsourcing / MSP partners
  - Cloud platform (primary: AWS/Azure/GCP) + secondary (DR / multi-cloud)
  - Email security gateway        (Proofpoint / Mimecast / Barracuda / Cisco)
  - EDR / endpoint security       (CrowdStrike / SentinelOne / Defender / etc)
  - SIEM                          (Splunk / Sentinel / Elastic / Sumo / etc)
  - SASE / ZTNA                   (Zscaler / Netskope / Cato / Palo Prisma)
  - Identity provider             (Entra / Okta / PingOne / OneLogin / Auth0)
  - Privileged Access Management  (CyberArk / BeyondTrust / Delinea / HashiCorp)
  - Vulnerability management      (Tenable / Qualys / Rapid7)
  - GRC / compliance              (ServiceNow / Vanta / Drata / OneTrust)
  - HRIS                          (Workday / SAP SuccessFactors / BambooHR)
  - Finance / ERP                 (NetSuite / SAP / Oracle / Workday Finance)
  - CRM                           (Salesforce / HubSpot / Microsoft Dynamics)
  - Code hosting + CI             (GitHub Enterprise / GitLab / Bitbucket)
  - Code-signing / cert mgmt      (DigiCert / GlobalSign / Sectigo / SSLMate)
  - Payment processor             (Stripe / Adyen / Worldpay / Braintree)
  - Authentication helpers (3rd-party MFA, e.g. Duo / Yubico services)

TOOLING:
  - Censys "shared certificates" pivot — find all hosts sharing target's cert
  - Spiderfoot (smicallef OSS or Intel 471 commercial HX) — vendor enumeration
    https://github.com/smicallef/spiderfoot
  - Maltego transforms (commercial; subscription needed) — relationship graph
  - Hunchly (paid; web-archiving for OSINT investigations)
```

### 8.5 — Container & Artifact Registry Discovery

```bash
# ═══════════════════════════════════════════════════════════
# PUBLIC CONTAINER & ARTIFACT REGISTRY ENUMERATION
# MITRE ATT&CK: T1593.003 (Code Repositories), T1592.002 (Software)
# OPSEC RATING:  PURE PASSIVE for query; LOW-TOUCH ACTIVE for image pull
# ═══════════════════════════════════════════════════════════
# (Cross-references §5.5 package registries; this subsection focuses on
# container-specific discovery not already covered.)

# ─── DOCKER HUB ─────────────────────────────────────────────
curl -s "https://hub.docker.com/v2/repositories/target-org/?page_size=100" | jq
curl -s "https://hub.docker.com/v2/users/target-org/" | jq

# ─── AWS ECR PUBLIC GALLERY ─────────────────────────────────
# https://gallery.ecr.aws/  → search "target"
# Public ECR namespace: gallery.ecr.aws/<alias>/<image>
curl -s "https://api.us-east-1.gallery.ecr.aws/describeRepositories" \
  -H "Content-Type: application/x-amz-json-1.1" \
  -d '{"registryAliasName":"target-alias"}'

# ─── GOOGLE ARTIFACT REGISTRY / GCR ─────────────────────────
# Pattern: gcr.io/{project-id}/<image>  OR  *.docker.pkg.dev/{project-id}/
# Tag listing (requires registry name guessing):
curl -s "https://gcr.io/v2/{project-id}/<image>/tags/list"

# ─── AZURE CONTAINER REGISTRY ───────────────────────────────
# Pattern: target.azurecr.io
nslookup target.azurecr.io
curl -sI "https://target.azurecr.io/v2/"   # 401 = exists (ACR auth required)

# ─── QUAY.IO (Red Hat) ──────────────────────────────────────
curl -s "https://quay.io/api/v1/repository?namespace=target-org&public=true" | jq

# ─── HARBOR (self-hosted; Shodan-discoverable) ──────────────
shodan search 'http.title:"Harbor"'
# Cross-reference against target IP space from §2

# ─── LAYER HISTORY MINING (after pull) ──────────────────────
docker pull target-org/image:latest
docker history --no-trunc target-org/image:latest
# Reveals: build args, Dockerfile content (sometimes secrets in env), build
# user, base image (lineage), labels (often include build hostname)

# Tools:
# https://github.com/wagoodman/dive       (interactive layer browser)
# https://github.com/genuinetools/reg     (registry CLI, multi-platform)
# https://github.com/cycodehq/raven       (CI/CD security scanner)
```

### 8.6 — Mobile App Store Passive Recon

```bash
# ═══════════════════════════════════════════════════════════
# iOS APP STORE / GOOGLE PLAY DISCOVERY
# MITRE ATT&CK: T1591.002 (Business Relationships), T1592.002 (Software)
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# Mobile apps are an under-attended attack surface. Public store listings
# expose: hardcoded API endpoints, third-party SDK declarations, privacy
# disclosures revealing data types collected.

# ─── iOS APP STORE ──────────────────────────────────────────
# Search:
curl -s "https://itunes.apple.com/search?term=Target+Corp&entity=software&country=us&limit=50" \
  | jq '.results[] | {trackName, sellerName, bundleId, version, releaseNotes, supportedDevices, contentAdvisoryRating}'

# Per-app detail:
curl -s "https://itunes.apple.com/lookup?id=<APP_ID>&country=us" | jq

# Privacy "nutrition label" (Apple Privacy disclosures since iOS 14.3):
# Visible on the app's App Store page:
# https://apps.apple.com/us/app/target/idXXXXXXX
# Reveals data types collected, linkage to identity, third-party tracking

# ─── GOOGLE PLAY ────────────────────────────────────────────
# Search:
# https://play.google.com/store/search?q=Target+Corp&c=apps
# Per-app detail and Data Safety section accessible via:
# https://play.google.com/store/apps/details?id=com.target.app

# Tools:
# https://github.com/JoMingyu/google-play-scraper (Node.js scraper)
# https://github.com/facundoolano/google-play-scraper-py (Python port)

# ─── APK ANALYSIS (passive store-page only) ─────────────────
# DO NOT download APK from APKMirror / APKPure for static analysis without
# noting that the download itself is TARGET-TOUCH for the source mirror
# (and may also be a copyright-policy issue depending on source). For pure
# passive: review the store listing's screenshot pack + permission list.

# What store listings reveal:
#   - Backend API base URLs (sometimes in screenshots / release notes)
#   - SDK list (Apple privacy nutrition labels enumerate every SDK)
#   - Permissions claimed (Android — reveals scope of access)
#   - Update cadence (slow updates = under-resourced mobile team)
#   - Crash signature in release notes (indicates platforms in active issue)
```

```
═══════════════════════════════════════════════════════════
SECTION 8 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §03 Initial Access (defensive stack identified → tailor evasion)
Enables → §10 threat intel (vendor compromise paths inform threat picture)
Prereq → §1 DNS recon (SPF includes feed vendor enum)
Cross-ref → §5 code repo (NPM/Docker maintainers reveal internal stack)
Alternative → If Greenhouse/Lever/Workday API returns nothing, target uses
              alternate ATS (Ashby, BambooHR, SmartRecruiters, iCIMS, Jobvite)
              — try each by org-slug guessing
```

---

## 9 — FINANCIAL, LEGAL & ORGANIZATIONAL INTELLIGENCE

> **Typical chains through this section:** Corporate-structure walk (parent → subsidiaries → recent acquisitions) → SEC 8-K Item 1.05 disclosures for ongoing-incident context → regulatory scope (HIPAA/PCI/SOX/etc.) determines exfil priority → court records reveal historical security failures and vendor disputes.

### 9.1 — Corporate Structure & Financial Data

```bash
# ═══════════════════════════════════════════════════════════
# US PUBLIC COMPANIES — SEC EDGAR
# MITRE ATT&CK: T1591 (Gather Victim Org Information), T1597 (Search Closed)
# OPSEC RATING:  PURE PASSIVE
# DETECTION (third-party): SEC enforces 10 req/sec rate limit + UA header
# ═══════════════════════════════════════════════════════════
# Full-text search (efts.sec.gov is the canonical search backend):
curl -s "https://efts.sec.gov/LATEST/search-index?q=%22Target+Corp%22&dateRange=custom&startdt=2024-01-01&enddt=2026-04-28&forms=10-K,10-Q,8-K,DEF+14A" \
  -H "User-Agent: research user@example.com" | jq

# Filing browser:
# https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK=&company=target&type=10-K
# https://www.sec.gov/edgar/search/

# Filing types and what they reveal:
#   10-K           Annual report — revenue, subsidiaries, risk factors,
#                  IT spend, security disclosures, named vendors
#   10-Q           Quarterly — recent changes, material acquisitions
#   8-K            Current report — material events including Item 1.05
#                  cybersecurity incidents (see §9.2)
#   DEF 14A        Proxy — exec compensation, board composition,
#                  related-party transactions
#   S-1 / S-3      Registration statements — pre-IPO disclosures
#   S-4            M&A registration — acquisition target intel (rich)
#   13D / 13G      Beneficial ownership — major shareholders
#   Schedule 14A   Proxy soliciting materials

# Per-filing JSON via EDGAR's REST API:
curl -s "https://data.sec.gov/submissions/CIK0000027419.json" \
  -H "User-Agent: research user@example.com" | jq '.recent.form[]'

# ═══════════════════════════════════════════════════════════
# OTHER CORPORATE REGISTRIES (international)
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# OpenCorporates  https://opencorporates.com/companies?q=target  (global, free)
# UK Companies House  https://find-and-update.company-information.service.gov.uk/
# EU EBR          https://e-justice.europa.eu/  (multi-country)
# Canada CBR      https://www.ic.gc.ca/app/scr/cc/CorporationsCanada/
# Australia ASIC  https://asic.gov.au/  (paid for full extracts)
# India MCA       https://www.mca.gov.in/  (free; broad)
# DE / FR / NL    Bundesanzeiger, infogreffe, KvK
# OFFSHORE LEAKS  https://offshoreleaks.icij.org/  (Panama/Paradise/Pandora Papers)
# OCCRP Aleph     https://aleph.occrp.org/  (investigative journalism dataset)

# ═══════════════════════════════════════════════════════════
# COMMERCIAL CORPORATE INTEL
# OPSEC RATING:  PURE PASSIVE (paid / subscription)
# ═══════════════════════════════════════════════════════════
# D&B (Dun & Bradstreet)  → corporate hierarchy, DUNS number tree
# Bureau van Dijk (Orbis) → global private + public company database
# Crunchbase              → funding, acquisitions, key people, investors
#                          https://www.crunchbase.com/
# PitchBook               → private market intel (deep)
# CB Insights             → tech funding + M&A
# ZoomInfo                → org-chart + contact intel (paid, very thorough)
```

### 9.2 — SEC Item 1.05 8-K Cybersecurity Disclosures

```bash
# ═══════════════════════════════════════════════════════════
# SEC CYBERSECURITY DISCLOSURE RULE (effective 18 Dec 2023)
# MITRE ATT&CK: T1597.002 (Purchase Technical Data — financial filings)
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# Material cybersecurity incidents must be disclosed via 8-K Item 1.05
# within 4 business days of materiality determination. Delay only with
# specific Attorney General authorization (national security / public safety).
# Smaller Reporting Companies got the rule effective June 2024.
#
# Primary source:
# https://www.sec.gov/newsroom/press-releases/2023-139
# https://www.sec.gov/files/rules/final/2023/33-11216.pdf

# ─── EDGAR FULL-TEXT SEARCH FOR ITEM 1.05 FILINGS ───────────
# All Item 1.05 filings across all registrants:
curl -s "https://efts.sec.gov/LATEST/search-index?q=%22Item+1.05%22&forms=8-K&dateRange=custom&startdt=2023-12-18&enddt=2026-04-28" \
  -H "User-Agent: research user@example.com" | jq

# Specific company:
curl -s "https://efts.sec.gov/LATEST/search-index?q=%22Item+1.05%22+%22Target+Corp%22&forms=8-K" \
  -H "User-Agent: research user@example.com"

# ─── WHAT 8-K ITEM 1.05 REVEALS ─────────────────────────────
# Required disclosure content (per the rule):
#   - Material aspects of the nature, scope, and timing of the incident
#   - Material impact on the registrant
#   - Whether incident is ongoing, contained, or fully remediated
#
# Operational intelligence value:
#   - Confirms an active incident (use for ATTRIBUTING ransomware claims
#     posted on leak sites — when target denies, 8-K confirms or doesn't)
#   - Reveals incident timeline (initial detection → public disclosure)
#   - Sometimes names attacker / TTP family (via vendor incident reports
#     filed as 8-K exhibits)
#   - Material-impact dollar figures (4 business days is "tip of iceberg";
#     amended 8-K filed weeks later contains expanded detail)
#
# Cross-reference with:
#   - Ransomware leak site postings (§6.4) — confirm victim attribution
#   - News coverage (Bloomberg, Reuters, WSJ — who broke the story first)
#   - DFIR Report (https://thedfirreport.com/) — sometimes does the deep dive
#   - Mandiant / CrowdStrike incident reports — sometimes named in 8-K

# ─── MONITORING AUTOMATION ──────────────────────────────────
# Set up RSS feed / polling against EDGAR Item 1.05 search:
# https://efts.sec.gov/LATEST/search-index?q=%22Item+1.05%22&forms=8-K&output=atom
# Slack-bot / email-alert scripts for ongoing monitoring of the sector.

# Tools:
# https://github.com/sec-edgar/sec-edgar           (Python EDGAR client)
# https://github.com/rsljr/edgarParser             (filing parser)
```

### 9.3 — Regulatory & Breach-Notification Filings

```
═══════════════════════════════════════════════════════════
PUBLIC BREACH-DISCLOSURE PORTALS BY JURISDICTION
MITRE ATT&CK: T1597.002 (Purchase Technical Data)
OPSEC RATING:  PURE PASSIVE
═══════════════════════════════════════════════════════════

US — FEDERAL
  - HHS OCR Breach Portal (HIPAA-covered entities, 500+ records affected)
    https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf
    Updated: now accepts Part 2 (substance use disorder) breaches
  - SEC 8-K Item 1.05 (see §9.2)
  - CISA Known Exploited Vulnerabilities (KEV) — not breach-disclosure but
    indicates which exploits CISA tracks against US infra
    https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  - FBI IC3 Annual Report (aggregate trend data)

US — STATE LEVEL
  Each state requires breach notification under varying thresholds:
  - California Civil Code §1798.82 (CCPA + AB-2273)
    https://oag.ca.gov/privacy/databreach/list
  - New York SHIELD Act
    https://ag.ny.gov/internet/data-breach
  - Texas BC §521.053
  - Massachusetts 201 CMR 17
    https://www.mass.gov/lists/data-breach-reports
  - Maine Att'y General data-breach portal
    https://www.maine.gov/ag/consumer/identity_theft/data_breach_notice.html
  - Washington State AG: https://www.atg.wa.gov/data-breach-notifications
  - Oregon AG, Vermont AG, Iowa AG — all maintain searchable databases

EU
  - GDPR Article 33/34 breach notifications
    Per-country DPA (Data Protection Authority) publishes some/none:
    UK ICO: https://ico.org.uk/action-weve-taken/data-security-incident-trends/
    Ireland DPC: annually-published statistics
    French CNIL: https://www.cnil.fr/fr/sanctions
    Italian Garante: https://www.garanteprivacy.it/
    German Bf-DI: https://www.bfdi.bund.de/

ASIA-PACIFIC
  - Australia OAIC NDB (Notifiable Data Breaches)
    https://www.oaic.gov.au/privacy/notifiable-data-breaches
  - Singapore PDPC enforcement decisions
    https://www.pdpc.gov.sg/Commissions-Decisions
  - Japan PPC published cases
  - South Korea KISA / PIPC

INDUSTRY-SPECIFIC (cross-border)
  - PCI Forensic Investigator (PFI) reports (private; not public usually)
  - HITRUST CSF certified breach disclosures
  - SWIFT customer security framework attestations (financial sector)
  - NERC CIP critical infrastructure incident reports (US energy)
  - FERC Form 715 (US energy regulatory)

THREAT BUREAU / NATIONAL CSIRT ADVISORIES
  - CISA Cybersecurity Advisories
    https://www.cisa.gov/news-events/cybersecurity-advisories
  - UK NCSC threat reports
    https://www.ncsc.gov.uk/section/keep-up-to-date/threat-reports
  - Canadian Centre for Cyber Security
    https://www.cyber.gc.ca/en/alerts-advisories
  - ENISA (EU) Threat Landscape annual report
    https://www.enisa.europa.eu/topics/cyber-threats/threats-and-trends
  - Japan JPCERT/CC
  - Australia ACSC threat reports

WHAT REGULATORY SCOPE TELLS YOU:
  HIPAA              → PHI present (high-value to PHI brokers + HIPAA
                       enforcement risk for victim org)
  PCI-DSS            → Cardholder data (CHD); BIN ranges + magnitude
                       inferable from filings
  SOX                → Financial reporting data; pre-earnings exfil
                       window of value to insider trading
  FERPA              → Education records
  ITAR / EAR         → Defense / military technical data; nation-state
                       targeting probable
  FedRAMP M / High   → US federal government data
  GLBA               → Financial-services consumer data
  HITRUST            → Health-sector security framework adoption
  CMMC               → US DoD contractor compliance level (2.0 effective 2025)
```

### 9.4 — Legal & Court Records

```bash
# ═══════════════════════════════════════════════════════════
# COURT RECORDS — LITIGATION INTELLIGENCE
# MITRE ATT&CK: T1591.002 (Business Relationships), T1597.001 (Threat Intel)
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# Litigation reveals: security failures, vendor disputes, employee
# misconduct, regulatory violations, ongoing investigations.

# ─── US FEDERAL ─────────────────────────────────────────────
# PACER (Public Access to Court Electronic Records) — paid per-page
# https://pacer.uscourts.gov/
# CourtListener / Free Law Project (free PACER mirror):
# https://www.courtlistener.com/?q=Target+Corp&type=r
# RECAP Project: free PACER docs as users contribute
# https://www.courtlistener.com/recap/

# Bankruptcy filings reveal vendor lists, IT contract details:
# https://www.uscourts.gov/court-records/find-case-pacer

# ─── US STATE ───────────────────────────────────────────────
# Vary by state; many maintain public dockets:
# - CA: https://appellatecases.courtinfo.ca.gov/
# - NY: https://iapps.courts.state.ny.us/iscroll/
# - DE: https://courts.delaware.gov/  (corporate litigation hub)
# - TX: https://search.txcourts.gov/

# ─── INTERNATIONAL ──────────────────────────────────────────
# UK: https://www.find-court-cases.service.gov.uk/
# EU CURIA: https://curia.europa.eu/  (CJEU case-law)
# UK Supreme Court: https://www.supremecourt.uk/decided-cases/

# ─── REGULATORY ENFORCEMENT ─────────────────────────────────
# SEC enforcement: https://www.sec.gov/litigation/litreleases
# DOJ press releases (cyber-related): https://www.justice.gov/news
# FTC cybersecurity orders: https://www.ftc.gov/legal-library
# CFPB enforcement: https://www.consumerfinance.gov/enforcement/

# ─── INTELLIGENCE FROM LITIGATION ───────────────────────────
# What to look for:
#   - Breach class-action complaints (specific TTPs alleged + remediation)
#   - Vendor disputes (reveals which vendor failed and how)
#   - Wage / discrimination suits (reveals org chart, salary bands, culture)
#   - IP / trade-secret cases (reveals what's worth protecting; discovery
#     filings can describe internal systems in detail)
#   - DOJ / FTC consent orders (impose specific security requirements;
#     reveals the regulatory baseline target must maintain)
#   - PII / privacy class actions (often quote internal emails verbatim)

# Tooling:
# https://www.docketalarm.com/  (paid; alerts on new filings)
# https://courtlistener.com/alerts/  (free RSS alerts)
```

```
═══════════════════════════════════════════════════════════
SECTION 9 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §10 threat intel (8-K Item 1.05 confirms ransomware/breach claims)
Enables → §03 Initial Access (regulatory scope informs exfil priority)
Prereq → §1 corporate-name confirmation
Cross-ref → §6.4 leak-site monitoring (cross-reference 8-K + leak site claims)
Alternative → If target is private (no SEC filings), shift weight to:
              OpenCorporates, D&B, Crunchbase, PitchBook + state-level
              business filings + court records
```

---

## 10 — THREAT INTELLIGENCE

> **Typical chains through this section:** Industry → likely APT groups → known TTPs → cross-reference target's defensive stack from §8 → evaluate which of those TTPs survive against target's controls → bug bounty disclosed scope → ransomware leak site monitoring → previous-incident research for already-known compromise patterns.

### 10.1 — Industry-Specific Threat Landscape

```
═══════════════════════════════════════════════════════════
WHO TARGETS THIS INDUSTRY — APT GROUP MAPPING
MITRE ATT&CK: T1597.001 (Threat Intel Vendors)
OPSEC RATING:  PURE PASSIVE
═══════════════════════════════════════════════════════════

PRIMARY APT GROUP TRACKERS:
  - MITRE ATT&CK Groups
    https://attack.mitre.org/groups/
  - Mandiant (Google Cloud) APT tracker
    https://cloud.google.com/security/mandiant
  - CrowdStrike Adversary Universe (280+ named adversaries as of 2026)
    https://www.crowdstrike.com/en-us/adversaries/
  - Microsoft Threat Intelligence + naming taxonomy (storm/typhoon/sleet)
    https://learn.microsoft.com/en-us/security/intelligence/microsoft-threat-actor-naming
  - Palo Alto Unit 42
    https://unit42.paloaltonetworks.com/
  - Cisco Talos
    https://blog.talosintelligence.com/
  - ESET WeLiveSecurity
    https://www.welivesecurity.com/
  - Kaspersky Securelist
    https://securelist.com/
  - Volexity
    https://www.volexity.com/blog/
  - Recorded Future Insikt Group
    https://www.recordedfuture.com/research
  - Group-IB Threat Intelligence
    https://www.group-ib.com/blog/
  - Sekoia.io blog
    https://blog.sekoia.io/
  - Trellix Advanced Research Center
    https://www.trellix.com/about/newsroom/stories/research/
  - NCC Group RIFT (Research Intelligence Fusion Team)
    https://research.nccgroup.com/
  - Sophos X-Ops
    https://news.sophos.com/en-us/category/threat-research/
  - Proofpoint Threat Insight
    https://www.proofpoint.com/us/blog/threat-insight
  - Trend Micro Research
    https://www.trendmicro.com/en_us/research.html
  - Symantec / Broadcom Threat Hunter Team
    https://symantec-enterprise-blogs.security.com/
  - Microsoft Threat Analytics (security.microsoft.com/threatanalytics)
    Customer-only; correlates DefenderXDR alerts with current campaigns

NAMING CONVENTIONS (cross-referencing the same actor across vendors):
  Common cross-refs (subject to dispute / change):
    APT29 = Cozy Bear = NOBELIUM = Midnight Blizzard = TA421 = UNC2452
    APT28 = Fancy Bear = STRONTIUM = Forest Blizzard = TA422
    Lazarus Group = Hidden Cobra = APT38 = Diamond Sleet = TA404
    APT41 = Wicked Panda = BARIUM = Brass Typhoon = TA415
    Volt Typhoon = VANGUARD PANDA = BRONZE SILHOUETTE
    Salt Typhoon = GhostEmperor = Earth Estries
    Scattered Spider = UNC3944 = Octo Tempest = Roasted 0ktapus
    Sandworm = VOODOO BEAR = APT44 = Seashell Blizzard = IRON VIKING

SECTOR → COMMON THREAT MAP (high-level; use as a starting frame):
  Healthcare         Ransomware (LockBit successors, BianLian, Akira),
                     APT41-style espionage for biotech IP
  Finance            Lazarus + APT38 (banking), Cl0p (mass exploit data),
                     Scattered Spider (social-engineering), Carbanak heritage
  Defense / Aerospace APT29, APT28, APT40, MuddyWater, Volt Typhoon
  Energy / Oil&Gas   Volt Typhoon, ENERGETIC BEAR/Berserk Bear,
                     Sandworm, Hexane / Lyceum
  Telecom            Salt Typhoon, APT41, MuddyWater, Earth Lusca,
                     LightBasin
  Government / NGO   Almost all top-tier APT (Russian, Chinese, North Korean,
                     Iranian) with regional / mission-specific weighting
  Manufacturing      Ransomware-prevalent; APT41, Lazarus for IP theft
  Retail             Ransomware, FIN7-heritage (POS / payment), Magecart
  Education / Research APT41, APT29, MuddyWater, Mustang Panda
  Tech / SaaS        Scattered Spider, APT29 (supply-chain), APT41
                     LAPSUS$ heritage, ShinyHunters (data extortion)
  Critical Infra     Volt Typhoon (US/PI), Sandworm (Ukraine focus),
                     Industroyer / CRASHOVERRIDE family
  Cryptocurrency     Lazarus / APT38, ScarCruft, Star Blizzard
  Legal / Consulting Espionage-heavy; APT29 (M&A interest), MuddyWater
```

### 10.2 — Previous Incident Research

```bash
# ═══════════════════════════════════════════════════════════
# HISTORICAL INCIDENT RESEARCH FOR SPECIFIC TARGET
# MITRE ATT&CK: T1597.001 (Threat Intel Vendors), T1597.002 (Purchase Tech Data)
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════

# Search engines:
#   "target.com" "data breach"
#   "Target Corp" "ransomware"
#   "target.com" "security incident"
#   site:bleepingcomputer.com "Target Corp"
#   site:thehackernews.com target.com
#   site:therecord.media target.com
#   site:databreaches.net target.com
#   site:cyberscoop.com target.com

# X (Twitter) search (operator account; sock puppet recommended):
#   "target.com" breach OR hack OR compromise OR ransomware
#   from:malwrhunterteam target.com
#   from:vxunderground target.com
#   from:campuscodi target.com   (Catalin Cimpanu — broad coverage)
#   from:BushidoToken target.com (TI analyst)

# Specific outlets that break breach news:
#   Bleeping Computer        https://www.bleepingcomputer.com/
#   The Record               https://therecord.media/
#   The Register             https://www.theregister.com/
#   Cyberscoop               https://cyberscoop.com/
#   Databreaches.net         https://www.databreaches.net/
#   Krebs on Security        https://krebsonsecurity.com/
#   The Hacker News          https://thehackernews.com/
#   Risky Business newsletter  https://risky.biz/

# DFIR-quality post-mortems:
#   The DFIR Report          https://thedfirreport.com/
#   Mandiant case studies    https://cloud.google.com/security/resources/insights
#   CrowdStrike GTR          https://www.crowdstrike.com/global-threat-report/
#   M-Trends (Mandiant)      annual report
#   Microsoft DDR            https://www.microsoft.com/security/business/microsoft-digital-defense-report
#   Sophos State of Ransomware annual

# AlienVault / LevelBlue OTX (rebranded 2024):
# https://otx.alienvault.com/ → search target domain/IP
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/target.com/general" | jq

# VirusTotal — target domain history of malware associations:
curl -s "https://www.virustotal.com/api/v3/domains/target.com" \
  -H "x-apikey: $VT_KEY" | jq '.data.attributes | {last_analysis_stats, categories, reputation}'

# ═══════════════════════════════════════════════════════════
# WHY THIS MATTERS
# ═══════════════════════════════════════════════════════════
# Previous incident → likely added specific defenses (e.g., post-2020 SUNBURST
#   victims hardened build pipelines; post-2024 LastPass ripples drove PAM
#   adoption). Specific defenses != broad uplift; gaps elsewhere persist.
# Known compromised by specific APT → their tools/implants may still be
#   present (sophisticated actors leave dormant footholds across reboots,
#   rebuilds, even cloud-native re-deployments).
# Ransomware victim → may have paid (enabling repeat targeting) or rebuilt
#   (entire posture may have changed dramatically — old recon stale).
# Public breach disclosure → security team budget likely increased AFTER but
#   institutional muscle memory of the TTP that worked persists for years.
```

### 10.3 — Ransomware Leak-Site Monitoring

```bash
# ═══════════════════════════════════════════════════════════
# RANSOMWARE LEAK-SITE INDEX MONITORING
# MITRE ATT&CK: T1597.002 (Purchase Technical Data)
# OPSEC RATING:  PURE PASSIVE for monitoring; HIGH-LEGAL-RISK for downloading
# ═══════════════════════════════════════════════════════════
# (See §6.4 for active group list; this subsection is monitoring tooling.)

# Aggregators (clearnet, view leak indices without per-group Tor):
#   https://ransomware.live/                    (real-time leak aggregation)
#   https://www.ransomlook.io/                  (broader monitoring)
#   https://github.com/joshhighet/ransomwatch   (open-source watch list)
#   https://twitter.com/ecrime_ch               (eCrime channel monitoring)
#   https://github.com/Tex0L/RansomWiki         (historical group catalog)

# Threat-intel platforms with leak-site modules:
#   KELA, Flare, SOCRadar, Cybersixgill, Group-IB, DarkOwl

# Per-group leak-site monitoring tools (rotate frequently as sites move):
#   ransomwatch maintains active onion lists; consult before assuming dead
#   The DFIR Report curates per-incident analyses with leak-site context

# Output you care about:
#   - Target organization name + sector + estimated revenue
#   - "% of files exfiltrated" claim (partial vs full encryption)
#   - "Negotiation status" indicators (wall posted = negotiations failed)
#   - Sample data leaked (validates claim authenticity)
#   - Time-to-leak-after-encryption (operational tempo of the group)

# Cross-reference with §9.2 SEC 8-K filings:
#   - Group claims compromise; target files no 8-K → either claim is false,
#     not yet material, or target is delaying disclosure
#   - Group claims compromise; target files 8-K → confirmed
#   - Target files 8-K; no group claim yet → APT espionage suspected
#     (state-aligned actors typically don't ransomware)
```

### 10.4 — Bug Bounty & Disclosed-Scope Intelligence

```bash
# ═══════════════════════════════════════════════════════════
# TARGET'S OWN BUG BOUNTY PROGRAM AS A RECON SOURCE
# MITRE ATT&CK: T1591.002 (Business Relationships), T1594 (Search Victim-Owned)
# OPSEC RATING:  PURE PASSIVE
# ═══════════════════════════════════════════════════════════
# A target's own bug bounty program is the highest-fidelity declaration of
# in-scope assets, exclusions, and known weaknesses. Disclosed reports
# (resolved, public) reveal historical attack patterns and current detection
# blind spots.

# ─── PRIMARY PLATFORMS ──────────────────────────────────────
# HackerOne     https://hackerone.com/target-corp
# Bugcrowd      https://bugcrowd.com/target-corp
# Intigriti     https://app.intigriti.com/programs/target-corp/
# YesWeHack     https://yeswehack.com/programs/target-corp
# Synack Red    private; less recon value (closed program)
# Cobalt        private SaaS; less recon value

# Self-hosted / direct submission:
# https://target.com/security
# https://target.com/.well-known/security.txt   (RFC 9116)
curl -s https://target.com/.well-known/security.txt
# security.txt reveals: PGP key, contact email, hiring URL, policy URL,
# canonical disclosure platform

# ─── HACKERONE PROGRAM PAGE (PUBLIC SCOPE) ──────────────────
# Public scope is exposed via API:
curl -s "https://hackerone.com/target-corp.json" | jq
# (Returns program metadata + scope definitions; many programs publish
# their scope publicly even if they are private-bounty)

# Per-program endpoints (some require auth):
curl -s "https://api.hackerone.com/v1/hackers/programs/target-corp" \
  -u "$H1_USER:$H1_KEY" | jq

# ─── DISCLOSED REPORTS (after researcher disclosure timeline) ─
# https://hackerone.com/target-corp/hacktivity
# Filter: state=Resolved + visibility=Public
# Each disclosed report reveals:
#   - The vulnerability class found (XSS, IDOR, SSRF, RCE, auth-bypass)
#   - The endpoint/asset where it was found (extends asset inventory)
#   - The remediation language (reveals what defense was added)
#   - Timeline (response cadence — slow vendor = current detection gaps)
#   - Researcher handle (sometimes pivot to their other work)

# Tooling:
# https://github.com/sw33tLie/bbscope              (HackerOne/Bugcrowd scope API)
bbscope h1 -t $H1_TOKEN -u $H1_USER -b -o > all_h1_scopes.txt
bbscope bc -t $BC_TOKEN -u $BC_USER -b -o > all_bc_scopes.txt

# https://github.com/arkadiyt/bounty-targets-data  (community-maintained
#                                                    daily-updated scope lists
#                                                    from H1 + BC + Intigriti)

# ═══════════════════════════════════════════════════════════
# WHAT BUG BOUNTY INTEL TELLS YOU
# ═══════════════════════════════════════════════════════════
# - In-scope domains/apps may NOT appear in subdomain enum (e.g., partner
#   domains explicitly added to scope by target)
# - Out-of-scope assets are sometimes the soft underbelly (target
#   acknowledges "this is legacy, please don't")
# - Reward bands hint at security maturity (low-tier bounty = under-resourced
#   security team; six-figure crit = mature program with active defense)
# - Hall of fame / credits page lists researchers who have found bugs —
#   their public writeups (with target's permission) reveal historical TTPs
# - Disclosed-but-unresolved reports → currently-known issues
# - Frequent re-tested in-scope assets → high attention; harder targets
# - "Self-XSS, missing security headers, BREACH/CRIME, etc. out of scope" →
#   reveals specific defender knowledge gaps to AVOID burning
```

```
═══════════════════════════════════════════════════════════
SECTION 10 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §03 Initial Access (defensive posture informs choice of vector)
Enables → §07 Defense Evasion (industry threat baseline informs EDR config)
Prereq → §1 organization confirmation; §8 defensive stack identification
Cross-ref → §9.2 SEC 8-K + §10.3 leak sites = high-confidence current victim
            attribution
Alternative → If no APT-attribution data exists for target's sector, look
              to neighbor verticals + supply chain (vendors of target may
              have been independently attributed)
```

---

## 11 — PHYSICAL & WIRELESS PRE-ATTACK INTELLIGENCE

> **Typical chains through this section:** Geo-locate offices → satellite imagery → street view for ingress points → WiGLE for nearby SSIDs → SSID-pattern recognition for guest/IoT/employee networks → Bluetooth dataset for IoT/asset enumeration → physical-proximity attack viability assessment.

### 11.1 — Physical Location Intelligence

```
═══════════════════════════════════════════════════════════
GEOLOCATION → INGRESS / EGRESS / ENVIRONMENTAL RECON
MITRE ATT&CK: T1591.001 (Determine Physical Locations)
OPSEC RATING:  PURE PASSIVE
═══════════════════════════════════════════════════════════

LOCATION DISCOVERY SOURCES:
  - SEC 10-K "Properties" section (physical facility list, square footage)
  - LinkedIn company profile (locations + employee count per location)
  - Glassdoor office reviews (often contain office address)
  - Google Maps "Target Corporate Headquarters" + "Target Office"
  - Press releases announcing new offices / data centers
  - PeeringDB facility data (data center locations from §2.4)
  - Job postings (location field — even "remote" reveals HR-tax base)
  - FCC license database (radio licenses tied to physical sites)
  - FAA RemoteID / Aircraft registration (corporate jets → exec travel)
  - Trademark filings (sometimes filed by region — reveals regional ops)

GOOGLE MAPS / STREET VIEW INTEL:
  - Office entrances (revolving door, mantrap, badge readers)
  - Loading docks (vehicle ingress, less-monitored entrances)
  - Parking areas (license plates of execs, vendor vans, security patrol)
  - Badge reader locations + types (visible card-reader brands → tech stack)
  - Camera positions (Pelco, Axis, Hikvision visible enclosures)
  - Nearby businesses (coffee shops within WiFi range = WiFi proximity ops)
  - Building security profile (guard booth, turnstiles, K-rated bollards)
  - Dumpster locations + collection schedule (dumpster diving feasibility)
  - Smoking areas + benches (tailgating + social engineering opportunity)
  - HVAC roof equipment (AC vents = physical intrusion paths)
  - Antenna / satellite dishes (private microwave / satellite uplink presence)

SATELLITE IMAGERY:
  - Google Earth Pro (free; high-res for major cities)
  - Maxar Technologies (commercial; very high-res; subscription)
  - Planet Labs (daily revisit; subscription)
  - Sentinel Hub (free; lower-res; ESA Copernicus)
  - Bing Maps aerial (sometimes more recent than Google)

  Use cases:
  - Roof access analysis (hatches, fire-escape routes, antenna mounts)
  - Construction / renovation activity (temporary security gaps; visible
    on imagery weeks before completion)
  - HVAC inspection routes (chiller locations, water source for sabotage)
  - Vehicle traffic patterns (shift-change times)
  - Telecom infrastructure (microwave dishes pointing to specific peers)

DATA CENTER LOCATIONS:
  - PeeringDB facility records (§2.4)
  - LinkedIn jobs filtering by data-center adjacent skill sets
  - Power utility public records (large meters → industrial customer)
  - Local building-permit records (often online; reveal facility renovations)
  - News coverage of data-center construction announcements
  - Hosting-provider customer lists (Equinix Marketplace, Digital Realty,
    CoreSite tenant directories)
```

### 11.2 — Wireless & BLE Pre-Attack Intelligence

```bash
# ═══════════════════════════════════════════════════════════
# WIGLE — GLOBAL WIRELESS DATABASE (WiFi + BLUETOOTH/BLE)
# MITRE ATT&CK: T1592.001 (Hardware), T1591.001 (Physical Locations)
# OPSEC RATING:  PURE PASSIVE
# DETECTION (third-party): WiGLE logs API queries
# ═══════════════════════════════════════════════════════════
# WiGLE has expanded from WiFi-only to also index Bluetooth/BLE devices
# (IoT inventory, asset trackers, devices visible from public sidewalk).

# Web search (browser):
# https://wigle.net/  → Search by SSID / address / coordinates

# API search by SSID:
curl -s "https://api.wigle.net/api/v2/network/search?ssid=Target&onlymine=false" \
  -H "Authorization: Basic $(echo -n $WIGLE_USER:$WIGLE_KEY | base64)"

# API search by geographic bounding box (around target's HQ):
curl -s "https://api.wigle.net/api/v2/network/search?onlymine=false&latrange1=40.7128&latrange2=40.7228&longrange1=-74.0060&longrange2=-73.9960" \
  -H "Authorization: Basic $(echo -n $WIGLE_USER:$WIGLE_KEY | base64)"

# Bluetooth/BLE search (newer endpoint):
curl -s "https://api.wigle.net/api/v2/bluetooth/search?ssid=Target" \
  -H "Authorization: Basic $(echo -n $WIGLE_USER:$WIGLE_KEY | base64)"

# ═══════════════════════════════════════════════════════════
# SSID PATTERN INTERPRETATION
# ═══════════════════════════════════════════════════════════
# Corporate SSID patterns reveal network segmentation:
#   Target-Corp        → primary employee WPA2/3-Enterprise (802.1X)
#   Target-Guest       → guest network (often open or PSK)
#   Target-IoT         → segmented IoT VLAN
#   Target-OT          → operational technology (industrial; often weak)
#   Target-BYOD        → personal-device segment
#   Target-Voice       → VoIP phone segment (Cisco/Polycom/Mitel signaling)
#   Target-Visitor     → contractor / vendor network
#   Target-Production  → actual workload SSID (very rare; usually wired only)
#
# BSSID OUI lookup (first 3 octets of MAC) → wireless vendor:
#   00:1B:0D     Cisco
#   00:24:97     Aruba (HPE)
#   00:13:E8     Aruba (legacy)
#   00:0C:E5     Meraki (Cisco)
#   F8:1A:67     Ruckus
#   80:2A:A8     Ubiquiti
#   00:E0:4C     Realtek
#   34:BD:FA     Aerohive (Extreme)
# Tool: https://standards-oui.ieee.org/ for full registry

# ═══════════════════════════════════════════════════════════
# WHAT WIRELESS INTEL ENABLES (cross-ref Wireless Cheatsheet)
# ═══════════════════════════════════════════════════════════
# - Known SSIDs → evil-twin setup (Karma, Mana, eaphammer)
# - Encryption type → attack vector:
#     WPA2-PSK         offline crack via PMKID or 4-way handshake capture
#     WPA2-Enterprise  EAP-relay (eaphammer), evil-twin + cred capture
#     WPA3-SAE         SAE downgrade attacks (Dragonblood family)
#     WPS-enabled      Pixie Dust attack (rare in modern enterprise)
# - Guest network → potential pivot if shared infra with corp
# - BSSID + signal-strength patterns → physical layout inference
# - BLE devices → IoT inventory (printers, cameras, badge readers, asset tags)

# ═══════════════════════════════════════════════════════════
# CELLULAR INFRASTRUCTURE (NICHE)
# ═══════════════════════════════════════════════════════════
# OpenCelliD     https://opencellid.org/    cell tower ID database
# CellMapper     https://www.cellmapper.net/ crowdsourced tower data
# Useful for: identifying private LTE / CBRS deployments, microcells in
# corporate facilities, IMSI-catcher detection during physical-recon
# preparation
```

```
═══════════════════════════════════════════════════════════
SECTION 11 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → Wireless cheatsheet (SSID + encryption type drives attack choice)
Enables → Physical penetration (ingress mapping, badge format, camera coverage)
Prereq → §9.1 corporate locations confirmed (SEC Properties section)
Cross-ref → §2.4 PeeringDB for data-center facility addresses
Alternative → If no SSIDs visible from public space, target may be in a
              SCIF or shielded environment — physical-proximity attacks
              become impractical; pivot to supply-chain / identity-plane
```

---

## 12 — TARGET PROFILE COMPILATION

```
═══════════════════════════════════════════════════════════
DELIVERABLE: PASSIVE RECON REPORT TEMPLATE
═══════════════════════════════════════════════════════════

SECTION 1 — ORGANIZATIONAL OVERVIEW
  □ Company name, industry (NAICS/SIC), revenue, employee count
  □ Subsidiaries, recent acquisitions (last 24 months), strategic partners
  □ Key personnel (IT admins, executives, developers, identity admins)
  □ Physical locations (HQ, branches, data centers — addresses + sizes)
  □ Regulatory environment (HIPAA, PCI, SOX, GDPR, ITAR, FedRAMP, CMMC)
  □ Recent SEC 8-K Item 1.05 filings (active or recent incidents)

SECTION 2 — DIGITAL INFRASTRUCTURE
  □ All discovered domains and subdomains (with current IP resolution)
  □ Historical IP/DNS changes (passive DNS — last 12 months)
  □ ASN(s) + IP prefixes + PeeringDB facility list
  □ Cloud providers + identified cloud assets (S3, Blob, GCS buckets)
  □ Email platform (M365 / Workspace / on-prem) + email-security vendor
  □ CDN / WAF vendor + origin-IP discovery results (if behind CDN)
  □ DNS hosting provider
  □ Web technology stack (CMS, frameworks, server software, libraries)
  □ Identified security tools (EDR, SIEM, email gateway, SASE, IGA, PAM)
  □ Identity stack (Entra/Workspace/Okta/Auth0/PingOne + federation map)
  □ Tenant IDs + Account IDs (Entra GUID, AWS account ID, GCP project IDs)

SECTION 3 — ATTACK SURFACE
  □ External services identified (Shodan/Censys/Quake/Hunter inventory)
  □ VPN / remote-access endpoints (vendor + version where determinable)
  □ Exposed management interfaces (cPanel, phpMyAdmin, Jenkins, GitLab)
  □ Development / staging environments
  □ API endpoints (Swagger / OpenAPI / GraphQL discovered)
  □ Mobile apps + their disclosed endpoints
  □ Bug bounty in-scope assets
  □ Legacy / acquired systems with potentially weaker security
  □ Public Postman workspaces
  □ Public CI/CD logs / preview-deployment URLs

SECTION 4 — CREDENTIAL INTELLIGENCE
  □ Email format pattern (first.last / flast / etc.) + confidence
  □ Email addresses (count + sample of high-tier targets)
  □ Breach exposure (per-employee: which DBs, dates, data classes)
  □ Stealer-log presence (HudsonRock summary; sample if RoE permits)
  □ Password patterns observed (rebuild candidate spray list)
  □ Code-repository secrets discovered (sanitized inventory)
  □ Document-metadata discovered usernames (exiftool extraction)

SECTION 5 — IDENTITY-PLANE INTEL
  □ Entra tenant ID (GUID), tenant region, registered domains
  □ Federation status per domain (Managed / Federated)
  □ Federated IdP brand (Okta / Auth0 / ADFS / PingOne / OneLogin)
  □ DesktopSSO status (sso.target.com endpoint)
  □ Tenant branding samples (logos, theme strings — pretext fidelity)
  □ AWS account ID (where determinable)
  □ Service-principal hints (from public Azure / AWS docs / press)

SECTION 6 — THREAT CONTEXT
  □ Previous public security incidents (timeline + attribution)
  □ Industry-specific APT groups likely to target sector
  □ Known CVEs affecting identified technology stack
  □ Ransomware group activity in sector (last 12 months)
  □ Bug bounty disclosed-report patterns (vulnerability class trends)
  □ Defender stack identified → known evasion landscape against it

SECTION 7 — RECOMMENDED INITIAL ACCESS APPROACH (analyst recommendation)
  □ Priority vector selection (weighted by OPSEC cost vs. expected return)
  □ Target selection (which 5-10 employees to phish first; sock puppets to use)
  □ Infrastructure requirements (domains needed, certs, C2 profile)
  □ Active recon priorities (what to scan first; cost/benefit)
  □ Pretext bank (for each priority target — leveraged from §4.5 enrichment
    + §11 physical context + §8 vendor stack)
```

---

## 13 — TOOL QUICK REFERENCE (MAINTENANCE STATUS)

```
═══════════════════════════════════════════════════════════
LEGEND: ✅ Active   ⚠ Stalled / Limited   ❌ Dead   $ Paid-only
═══════════════════════════════════════════════════════════

SUBDOMAIN / DNS:
  ✅ subfinder            ProjectDiscovery; multi-source aggregator
  ✅ amass                OWASP; passive + active modes; latest active 2026
  ✅ assetfinder          tomnomnom; v0.1.1 (Jan 2026); subdomain finder
  ✅ findomain            Edu4rdSHL; cross-platform; CT log driven
  ✅ chaos                ProjectDiscovery; bulk-curated subdomain dataset
  ✅ crt.sh               Sectigo-operated; free CT log search
  ✅ CertSpotter          SSLMate; CT log monitoring; free + paid tiers
  ✅ dnsx                 ProjectDiscovery; fast DNS resolution
  $  SecurityTrails       Historical DNS + WHOIS; paid API
  $  Defender EASM        Microsoft (formerly RiskIQ/PassiveTotal); paid
  $  DNSDB (DomainTools)  Largest pDNS dataset; paid
  ⚠ Sublist3r            aboul3la; some sources stale; superseded by subfinder
  ❌ bufferover.run       Effectively offline since 2024 (RapidAPI failed)
  ❌ riddler.io           Domain expired Feb 2025

IP / NETWORK:
  ✅ Shodan               $ for full features; free tier limited; CLI active
  ✅ Censys               Free web search; paid API since Nov 2024
  ✅ FOFA                 Chinese scanner; web search free; API paid
  ✅ ZoomEye              Knownsec; web search free; API paid
  ✅ Quake                360/Qihoo; free public search
  ✅ Hunter (Qianxin)     Free public search; Asia-Pacific coverage
  ✅ Netlas               Newer Western alt; clean API
  ✅ GreyNoise            Internet noise / scanner identification
  ✅ bgp.tools            Community-run; free for non-commercial; primary
  ✅ BGPView              JSON API; still useful for programmatic queries
  ✅ Team Cymru WHOIS     whois.cymru.com; bulk IP→ASN; standard tradecraft
  ✅ PeeringDB            Network operator / IXP / facility intel
  ✅ Hurricane Electric BGP bgp.he.net; web UI, no key
  ✅ whois (RIRs)         ARIN / RIPE / APNIC / LACNIC / AFRINIC
  ✅ Robtex               Legacy interface; useful cross-reference

WEB ARCHIVE / URL:
  ✅ waybackurls          tomnomnom; Wayback URL extraction
  ✅ gau                  github.com/lc/gau; Wayback+CommonCrawl+OTX+URLScan
                          (NOT hakluke/getallurls — that's the older/forked repo)
  ✅ Wayback Machine CDX  archive.org; programmatic snapshot retrieval
  ✅ urlscan.io           Public-submission archive; free tier + paid API
  ❌ Google cache:        operator removed Sept 2024; use Wayback
  ✅ Common Crawl         Bulk web archive; cc-index queries

CT LOGS:
  ✅ crt.sh               Primary; intermittent under load
  ✅ CertSpotter          SSLMate; CLI for log mirroring
  ✅ Censys Certs         Search interface; API paid
  ✅ Google CT logs       ct.googleapis.com (Argon, Xenon)
  ✅ Cloudflare CT logs   ct.cloudflare.com (Nimbus)

EMAIL / PERSONNEL:
  ✅ theHarvester         laramies; v4.4+ active; -b all per-source quality varies
  $  Hunter.io            Email discovery + format inference; paid
  ✅ linkedin2username    initstring; v1.x active 2025
  ✅ CrossLinked          m8sec; LinkedIn scrape via search engines
  ✅ Phonebook.cz         Intelligence X owned; free; 20B records
  $  Snov.io / Apollo / RocketReach / SignalHire / Lusha   B2B contact intel
  ✅ Holehe               megadose; email→service enumeration
  ✅ Maigret              soxoj; username→3000+ sites
  ✅ Sherlock             username search across 600+ sites
  $  Epieos               Premium OSINT enrichment
  $  OSINT.industries     Premium OSINT enrichment

CREDENTIAL / BREACH:
  $  HaveIBeenPwned       Subscription required for breach lookup
  $  DeHashed             Independent (no Atlas Privacy acquisition); paid
  $  IntelX               Deep+dark web index; paid tiers
  $  LeakCheck            Paid breach search
  $  Snusbase             Paid; intermittent availability
  $  HudsonRock           Free domain lookup; paid for full access
  $  Flare / Constella / Recorded Future / SOCRadar / KELA   Stealer-log feeds

CODE REPOSITORY:
  ✅ trufflehog           TruffleSec; --only-verified canonical flag
  ✅ gitleaks             v8.19+; `gitleaks git/directory/stdin` (detect deprecated)
  ✅ GitDorker            obheda12; GitHub dork automation
  ✅ GitHub Code Search   Post-2023; new operators (path:, content:, /regex/)
  ✅ Sourcegraph          Public code search across many forges
  ✅ grep.app             Regex over GitHub mirror
  ✅ PostmanScanner       CloudSEK; Postman public-workspace scanner
  ✅ keyfinder            Workflow-log secret scanner
  ✅ Gato                 GitHub Actions abuse audit

DOCUMENT / METADATA:
  ✅ exiftool             Metadata extraction (PDF, Office, images)
  ✅ FOCA                 ElevenPaths; v3.4.7.1 active (Aug 2025)
  ✅ metagoofil           opsdisk fork (canonical); Kali default
  ⚠ metagoofil (laramies) Original fork stalled; opsdisk supersedes

CLOUD / IDENTITY:
  ✅ cloud_enum           initstring; multi-cloud bucket enumeration
  ✅ S3Scanner            sa7mon; AWS S3 bulk testing
  ✅ AADInternals         Nestori Syynimaa; Entra outsider recon (PRIMARY)
  ✅ ROADtools            dirkjanm; Entra post-cred (NOT outsider)
  ✅ aws-account-detective  Frichetten; AWS account ID disclosure
  ✅ Quiet Riot           righteousgambit; AWS principal enumeration
  ✅ checkdmarc           DMARC/SPF/MTA-STS analyzer

INFRASTRUCTURE / TECH:
  ✅ BuiltWith            Free tier; paid relationships
  ✅ Wappalyzer           Free 50/month; paid plans
  ✅ Netcraft             Free site reports
  ✅ WhatRuns             Browser extension
  ✅ wafw00f              EnableSecurity; WAF detection (TARGET-TOUCH)
  ✅ checkdmarc           DMARC parsing CLI

FRAMEWORKS / META-TOOLS:
  ⚠ Recon-ng              lanmaster53; maintainer disengaged; legacy framework
  ⚠ SpiderFoot OSS        smicallef; Intel 471 acquired Nov 2022; HX is paid
  ✅ SpiderFoot HX        Commercial; Intel 471
  $  Maltego              Commercial; transforms-driven graph
  $  Hunchly              Commercial; web-archiving for OSINT investigations

WIRELESS / PHYSICAL:
  ✅ WiGLE                Wireless + BLE + cellular geographic database
  ✅ OpenCelliD           Cell tower ID database
  ✅ CellMapper           Crowdsourced tower data
  ✅ Google Maps / Earth  Free satellite + street view
  $  Maxar / Planet Labs  Commercial high-res satellite imagery

THREAT INTELLIGENCE:
  ✅ MITRE ATT&CK         attack.mitre.org
  ✅ ATT&CK Navigator     mitre-attack.github.io/attack-navigator
  ✅ ransomware.live      Real-time ransomware leak-site aggregation
  ✅ ransomwatch          joshhighet; open-source watch list
  ✅ The DFIR Report      thedfirreport.com; intrusion analyses
  ✅ AlienVault/LevelBlue OTX  otx.alienvault.com (rebranded 2024)
  ✅ VirusTotal           Free + paid tiers
  ✅ urlscan.io           Free + paid tiers
  $  Mandiant / CrowdStrike / Recorded Future / Microsoft Defender for Threat
                          Intelligence (formerly RiskIQ); paid

BUG BOUNTY INTEL:
  ✅ HackerOne / Bugcrowd / Intigriti / YesWeHack
  ✅ bbscope              sw33tLie; cross-platform scope API tool
  ✅ bounty-targets-data  arkadiyt; daily-updated scope dumps

METHODOLOGY REFERENCES:
  MITRE ATT&CK TA0043           https://attack.mitre.org/tactics/TA0043/
  OSINT Framework               https://osintframework.com/
  IntelTechniques (book + tools) https://inteltechniques.com/
  OSINT-Curious                 https://osintcurio.us/
  Bellingcat OSINT toolkit      https://www.bellingcat.com/category/resources/
  Trace Labs                    https://www.tracelabs.org/  (CTF tradecraft)
```

---

## 14 — MITRE ATT&CK MAPPING MATRIX

```
═══════════════════════════════════════════════════════════
TA0043 RECONNAISSANCE — COMPLETE SUB-TECHNIQUE COVERAGE
═══════════════════════════════════════════════════════════

T1589 — Gather Victim Identity Information
  ├── T1589.001 Credentials                  → §6 (breach DBs, stealer logs)
  ├── T1589.002 Email Addresses              → §4.1 (theHarvester, Hunter, Phonebook)
  └── T1589.003 Employee Names               → §4.3 (LinkedIn, CrossLinked)

T1590 — Gather Victim Network Information
  ├── T1590.001 Domain Properties            → §1, §1.5, §7 (DNS, providers)
  ├── T1590.002 DNS                          → §1.3, §1.4 (DNS records, pDNS)
  ├── T1590.003 Network Trust Dependencies   → §7.3, §8.4 (federation, vendors)
  ├── T1590.004 Network Topology             → §1.6, §2 (header inference, ASN)
  ├── T1590.005 IP Addresses                 → §2.1 (ASN/BGP), §3 (cert pivots)
  └── T1590.006 Network Security Appliances  → §7.7 (WAF/CDN detection)

T1591 — Gather Victim Org Information
  ├── T1591.001 Determine Physical Locations → §11.1 (geo, satellite, PeeringDB)
  ├── T1591.002 Business Relationships       → §8.4 (supply chain), §9 (M&A)
  ├── T1591.003 Identify Business Tempo      → §9 (filings cadence), §8.2 (jobs)
  └── T1591.004 Identify Roles               → §4.3 (LinkedIn), §8.2/8.3 (jobs)

T1592 — Gather Victim Host Information
  ├── T1592.001 Hardware                     → §11.2 (WiGLE BSSID OUI)
  ├── T1592.002 Software                     → §3.2 (favicon), §8 (tech stack)
  ├── T1592.003 Firmware                     → §11.2 (BLE/IoT inventory)
  └── T1592.004 Client Configurations        → §5.7 (document metadata)

T1593 — Search Open Websites/Domains
  ├── T1593.001 Social Media                 → §4.4 (X, LinkedIn, Reddit, etc.)
  ├── T1593.002 Search Engines               → §6.5 (Google dorks), §2.5 (Wayback)
  └── T1593.003 Code Repositories            → §5 (GitHub, Postman, registries)

T1594 — Search Victim-Owned Websites          → §5.6 (preview URLs), §6.5

T1595 — Active Scanning [NOT PASSIVE — see active recon cheatsheet]
  ├── T1595.001 Scanning IP Blocks
  ├── T1595.002 Vulnerability Scanning
  └── T1595.003 Wordlist Scanning

T1596 — Search Open Technical Databases
  ├── T1596.001 DNS/Passive DNS              → §1.4 (SecurityTrails, DNSDB)
  ├── T1596.002 WHOIS                        → §2.2 (whois, DomainTools)
  ├── T1596.003 Digital Certificates         → §1.2, §3 (CT logs, JARM)
  ├── T1596.004 CDNs                         → §1.5, §7.7 (CDN identification)
  └── T1596.005 Scan Databases               → §2.3 (Shodan, Censys, FOFA, etc.)

T1597 — Search Closed Sources
  ├── T1597.001 Threat Intel Vendors         → §6, §10 (HudsonRock, Mandiant, etc.)
  └── T1597.002 Purchase Technical Data      → §6.4, §9, §10.3 (leak sites,
                                                stealer-log purchase, court records)
```

---

## CHANGE SUMMARY (vs. prior revision dated 02 April 2026)

**Critical fixes:**
- **§7.3** — Removed "GECOS" mislabeling; correctly named GetUserRealm tenant federation discovery. GECOS is a Unix `/etc/passwd` field unrelated to Microsoft identity. Source: [MS-OAPXBC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-oapxbc/).

**Major additions:**
- **§1.1, §13** — Removed dead sources (`bufferover.run`, `riddler.io`); added ProjectDiscovery Chaos dataset as primary curated subdomain feed. Source: [PD subfinder discussion #1739](https://github.com/projectdiscovery/subfinder/discussions/1739) · [chaos.projectdiscovery.io](https://chaos.projectdiscovery.io/).
- **§1.2** — Added direct CT log queries (Google Argon/Xenon, Cloudflare Nimbus) and `certspotter` CLI mirroring as backup when crt.sh is degraded. Added crt.sh PostgreSQL direct connection.
- **§1.5** — Extended CNAME → provider mapping to cover modern hosting (Vercel, Netlify, Cloudflare Pages/Workers, Fly.io, Render, Railway, AWS Amplify, Firebase Hosting).
- **§1.6** — NEW: Hostname Inference from Email Headers & Bounces (G5).
- **§2.1** — Added Team Cymru `whois.cymru.com` and bgp.tools as primary BGP/ASN sources, supplementing BGPView (G7, M17).
- **§2.4** — NEW: PeeringDB & network-operator intelligence subsection (M16).
- **§2.5** — NEW: urlscan.io API mining subsection (G1).
- **§2.3** — Added Quake (Qi'anxin/360) and Hunter (Qianxin) Chinese internet scanners; corrected Censys free-tier policy (API access removed Nov 2024). Source: [docs.censys.com data-access-tiers-entitlements](https://docs.censys.com/docs/data-access-tiers-entitlements).
- **§3.3** — NEW: JARM TLS fingerprinting subsection (M8).
- **§3.4** — NEW: Origin-IP discovery behind CDN/WAF subsection.
- **§4.5** — NEW: Modern OSINT Enrichment subsection (Epieos, OSINT.industries, Holehe, Maigret, Sherlock) (M14).
- **§5.2** — NEW: GitHub Code Search post-2023 operators subsection (M11). Source: [GitHub Code Search docs](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax).
- **§5.3** — NEW: GitHub Actions public workflow logs subsection (M10).
- **§5.4** — NEW: Postman public workspace leaks subsection (M4). Source: [CloudSEK Dec 2024 disclosure](https://www.cloudsek.com/blog/postman-data-leaks-the-hidden-risks-lurking-in-your-workspaces).
- **§5.5** — NEW: Public package registry leaks (NPM, PyPI, Docker Hub, HuggingFace, Maven, Crates, RubyGems, Go modules, NuGet) (M9).
- **§5.6** — NEW: Vercel/Netlify/Cloudflare Pages preview-URL leak subsection (G6).
- **§5 (multiple)** — Updated `trufflehog` and `gitleaks` syntax guidance: `--only-verified` is the canonical Trufflehog flag (not `--results=verified` as previously stated), and `gitleaks git/directory/stdin` replaced deprecated `gitleaks detect` in v8.19+. Sources: [trufflesecurity.com docs](https://docs.trufflesecurity.com/git) · [gitleaks releases](https://github.com/gitleaks/gitleaks).
- **§6.2** — NEW: Stealer-log marketplaces & aggregators subsection (RedLine, Lumma, StealC, Vidar, ACR, AMOS) with HudsonRock/Flare/Constella/RecordedFuture/SOCRadar/KELA enrichment platforms (M6).
- **§6.3** — NEW: Initial Access Broker forums & channels subsection.
- **§6.4** — Updated dark web / paste-site monitoring (Pastebin restrictions, Doxbin, JustPaste, Telegram channel monitoring G20).
- **§7.1-7.8** — RESTRUCTURED: Cloud section reorganized into 8 subsections covering provider ID, asset discovery, Entra outsider recon (M5), Workspace recon, AWS account-ID enumeration (G2), Okta/Auth0/PingFed fingerprinting (G3), WAF/CDN detection (R2), and email-security posture (R2).
- **§7.3** — Expanded Entra ID outsider recon to a full subsection covering OpenID config, GetUserRealm, AADInternals (`Invoke-AADIntReconAsOutsider`, `Get-AADIntTenantInformation`), tenant branding fingerprint, AutoDiscover federation discovery, FederationMetadata.xml scraping, and Microsoft Graph unauthenticated endpoints (G10, G11). Source: [aadinternals.com/aadinternals/](https://aadinternals.com/aadinternals/).
- **§7.5** — NEW: AWS account-ID enumeration subsection covering S3 bucket-policy probes, CloudFront origin headers, public Lambda/ECR ARN leaks, Quiet Riot, aws-account-detective.
- **§7.6** — NEW: Okta / Auth0 / PingFederate / OneLogin tenant fingerprinting.
- **§7.8** — Expanded email security to include MTA-STS (RFC 8461), TLS-RPT (RFC 8460), and BIMI (RFC 9376).
- **§8.3** — NEW: Public job-board APIs (Greenhouse `boards.greenhouse.io/v1`, Lever `api.lever.co/v0`, Workday `wd1.myworkdayjobs.com/wday/cxs`, Ashby, BambooHR, SmartRecruiters, iCIMS, Jobvite) (M15).
- **§8.5** — NEW: Container & artifact registry discovery subsection (Docker Hub, ECR Public, GCR, ACR, Quay, Harbor).
- **§8.6** — NEW: Mobile app store passive recon (iOS App Store, Google Play, privacy nutrition labels).
- **§9.2** — NEW: SEC Item 1.05 8-K cybersecurity disclosures subsection covering the 18 Dec 2023 effective rule and 4-business-day disclosure window (M7). Source: [SEC press release 2023-139](https://www.sec.gov/newsroom/press-releases/2023-139).
- **§9.3** — Expanded regulatory & breach-notification coverage to include state AG portals (CA, NY, MA, ME, WA, OR, VT, IA), EU DPA portals (UK ICO, Irish DPC, French CNIL, Italian Garante, German BfDI), APAC (OAIC, PDPC, PPC, KISA), and CMMC 2.0 / FedRAMP scope.
- **§10.1** — Expanded APT-tracker source list to include Volexity, Talos, Unit 42, ESET, Securelist, Group-IB, Sekoia, NCC RIFT, Trellix, Sophos X-Ops, Proofpoint, Trend Micro, Symantec/Broadcom, MS Threat Analytics (G19); updated APT cross-naming taxonomy with current Microsoft sleet/typhoon/blizzard tracker.
- **§10.4** — NEW: Bug bounty & disclosed-scope intelligence (HackerOne, Bugcrowd, Intigriti, YesWeHack, security.txt, bbscope, bounty-targets-data) (G4).
- **§11.2** — Extended WiGLE coverage to include Bluetooth/BLE indexing and BSSID OUI lookup table for vendor identification (m8).
- **§13** — Restructured tool reference with maintenance status legend (✅/⚠/❌/$); flagged Recon-ng as stalled (M12), AlienVault→LevelBlue rebrand, RiskIQ→Defender EASM, gau canonical repo (lc/gau), Sublist3r as superseded, Google cache: removed, all dead URL/tool entries (G18).
- **§14** — NEW: Standalone ATT&CK mapping matrix; added previously-missing T1590.003 (Network Trust Dependencies), T1591.003 (Identify Business Tempo), T1596.004 (CDNs), T1592.003 (Firmware), T1592.004 (Client Configurations) (M13, R3).

**URL corrections:**
- Mandiant URL → `cloud.google.com/security/mandiant` (post-Google acquisition).
- CrowdStrike adversary list → `crowdstrike.com/en-us/adversaries/` (canonical).
- AlienVault OTX rebrand to LevelBlue OTX noted; URL still resolves but ownership/branding changed (May 2024 spinoff).

**Reframing:**
- Document preamble explicitly states OPSEC taxonomy (PURE PASSIVE / LOW-TOUCH ACTIVE / TARGET-TOUCH ACTIVE) used throughout each technique's banner header.
- Per-technique banner headers now include explicit MITRE ATT&CK ID, OPSEC RATING, DETECTION (target), and DETECTION (third-party) fields (matches user's Phase 4 style requirement).
- §0.2 OPSEC bullets expanded to include browser-fingerprint countermeasures, sock-puppet hygiene depth, third-party telemetry exposure (urlscan.io public-default warning, VT public-by-default), and legal-framing caveats for stealer-log marketplace contact.

**Removed:**
- Dead source URLs: `bufferover.run`, `riddler.io`, `community.riskiq.com` (replaced by Defender EASM).
- "GECOS" mislabeling in §7.
- Implied currency of `Recon-ng` as actively maintained framework.

---

## OUTSTANDING ITEMS — UNVERIFIED / EMERGING / CONTESTED

| Item | Status | Evidence Required to Resolve |
|---|---|---|
| DeHashed acquisition by Atlas Privacy (rumor circulated late 2025) | **Unverified** — no public press release found. DeHashed reads as independent as of April 2026. | A press release from DeHashed or Atlas Privacy, or a verified statement from DeHashed leadership. |
| Stealer-log marketplace operational status | **Volatile** — Russian Market remains active despite ongoing disruption attempts; Genesis Market disrupted April 2023; new entrants emerge monthly via Telegram. List in §6.2 / §6.3 reflects Q1 2026 snapshot. | Continuous monitoring via threat-intel feeds (KELA, Flare, Recorded Future) — list will drift within months. |
| AWS account-ID disclosure techniques (Frichetten / Grzelak research) | **Contested viability** — AWS has hardened error responses on several historical leak vectors; some 2022-era techniques no longer disclose account IDs reliably as of 2026. | Test against an operator-controlled AWS account; verify which specific error vectors still leak. |
| Microsoft Defender EASM (formerly RiskIQ) free-tier availability | **Contested** — Community-tier access to PassiveTotal data was deprecated in 2024 transition; some referenced features now require paid Defender EASM SKU. | Microsoft Learn documentation update; vendor confirmation of free-tier scope. |
| Wappalyzer 50-lookup/month free tier | **Confirmed but volatile** — Wappalyzer pricing changes have been frequent since acquisition; verify current rate at lookup. | wappalyzer.com pricing page check at time of use. |
| Censys API tier specifics | **Confirmed Nov 2024 change** — free unauthenticated web search remains; programmatic API requires paid tier. Specific rate limits subject to change. | docs.censys.com at time of use. |
| ROADtools 2026 issues (HTTP 403 on gather operations) | **Emerging** — Microsoft has tightened some Graph endpoints used by `roadrecon gather`; works against most tenants but failure mode increasing. | dirkjanm/ROADtools issue tracker; community-reported workarounds. |
| Postman public workspace leak landscape | **Confirmed historical (Dec 2024 CloudSEK)** — but Postman has issued security guidance and added warnings since; current incidence rate may be lower than peak. | Recent CloudSEK / Watchtowr / Snyk research on current corpus. |
| Google cache: operator removal | **Confirmed (Sept 2024)** — Google removed the operator and its documentation. Wayback Machine is the recommended successor. | searchenginejournal.com coverage; Google Search Help docs. |
| MITRE ATT&CK technique-ID renumbering | **Stable as of v15** — confirmed all listed technique IDs match attack.mitre.org as of April 2026. ATT&CK v16 expected later in 2026 may renumber. | attack.mitre.org direct verification at time of use. |
| Recon-ng maintenance status | **Confirmed stalled** — maintainer Tim Tomes (lanmaster53) has stated he stopped active maintenance. Project still functions; modules drift. | github.com/lanmaster53/recon-ng commit history; Tim Tomes public statements. |
| Russian-state archive (rusarchives.ru) availability for cross-archive recon | **Contested for non-Russian researchers** — service availability for Western-IP queries inconsistent post-2022. | Direct test with VPN routing; verify accessibility. |
| AT&T spinoff branding for OTX (LevelBlue Open Threat Exchange) | **Confirmed rebrand 2024** — `otx.alienvault.com` URL still resolves but branding/ownership has changed. May see further URL transition. | LevelBlue corporate communications. |
| AADInternals continued maintenance | **Confirmed active** — Dr. Nestori Syynimaa continues development as of Q1 2026; podcast appearances and blog posts continue. | aadinternals.com blog; module changelog. |
| Cybersixgill / KELA / Flare stealer-log SKU positioning | **Stable but moving** — vendor offerings evolve; specific feature parity changes quarterly. | Vendor sites at time of procurement. |

---

***Valid as of 28 April 2026***

*Mapped to: MITRE ATT&CK TA0043 (Reconnaissance) — full sub-technique coverage in §14. Companion documents: §02 Active Reconnaissance · §03 Initial Access · §04 Persistence · §05 Privilege Escalation · §06 Lateral Movement · §07 Exfiltration · §08 Active Directory · §09-12 Web/App/Mobile/Wireless · §13 Wireless.*
