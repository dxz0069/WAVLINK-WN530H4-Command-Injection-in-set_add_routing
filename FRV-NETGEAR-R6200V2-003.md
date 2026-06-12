# Netgear R6200v2 httpd sub_6e4bc OS Command Injection (Language config FTP download)

## Basic Information

| Field | Value |
|-------|-------|
| **VulnDB ID** | (Pending Assignment) |
| **CVE ID** | (Pending Assignment) |
| **CWE** | CWE-78 |
| **CVSS 3.1** | 8.8 (High) |
| **CVSS Vector** | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| **Type** | OS Command Injection |
| **Internal ID** | FRV-NETGEAR-R6200V2-003 |

## Affected Product

| Field | Value |
|-------|-------|
| **Vendor** | Netgear |
| **Product** | R6200v2 AC1200 Dual Band Gigabit Wi-Fi Router |
| **Version** | Firmware V1.0.3.12_10.1.11 |
| **Binary** | /usr/sbin/httpd (stripped) |
| **Architecture** | ARM (ARMEL) |
| **Function** | sub_6e4bc @ 0x6e4bc |

## Description

OS command injection in sub_6e4bc (0x6e4bc, 260B) of /usr/sbin/httpd in Netgear R6200v2 V1.0.3.12. Function purpose: Language config FTP download. Reads configuration via acosNvramConfig_get() (PLT 0xd2f8) and passes unsanitized to system() (PLT 0xc83c) through sprintf(). Command: `rm -f ...;ftpc -u <TAINTED>`

## Proof of Concept

```http
Attack vector: set NVRAM config values containing shell metacharacters via web management, then trigger Language config FTP download function.
Example: set FTP username to '; id' → triggers injection when ftpc invoked.
```

## Technical Evidence

- **Source**: acosNvramConfig_get() @ PLT 0xd2f8
- **Sink**: system() @ PLT 0xc83c
- **Call chain**: acosNvramConfig_get → sprintf → system
- **Verification**: angr CFGFast + direct taint tracking — CONFIRMED in 24 steps
- **0-day basis**: Not covered by CVE-2017-6862 (buffer overflow) or CVE-2020-11770 (auth bypass)

## Impact

Authenticated attacker can inject commands via NVRAM config values. Language config FTP download function executes as root.

## Fix Recommendation

Validate NVRAM values before use in commands. Use execve() with argument arrays. Filter shell metacharacters at write time.

## Discovery

| Field | Value |
|-------|-------|
| **Method** | FirmRec Cross-Firmware Genetic Vulnerability Mining |
| **Date** | 2026-04-22 |
| **Discoverer** | ST4R |
| **Verification** | angr CFG-guided taint analysis CONFIRMED (24 steps) |
| **Status** | CONFIRMED |

## Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-04-22 | Vulnerability discovered via FirmRec automated pipeline |
| TBD | Vendor notification |
| TBD | CVE ID assigned |
| TBD | Public disclosure (+90 days) |

---
*Discovered via FirmRec — IoT Firmware Genetic Vulnerability Mining Framework*
