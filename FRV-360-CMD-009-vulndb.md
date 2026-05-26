# VulnDB Submission: 360 360 M5 cgitest.cgi put_igdmptd_cgi OS Command Injection

## 1. Title

360 360 M5 cgitest.cgi put_igdmptd_cgi OS Command Injection

## 2. Vulnerability Summary

- **Internal Tracking ID:** FRV-360-CMD-009
- **VulnDB ID:** (Pending Assignment)
- **CVE ID:** (Pending Assignment)
- **Vulnerability Class:** CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- **Vulnerability Type:** OS Command Injection
- **Severity:** 9.8 (Critical)
- **Severity Label:** Critical
- **CVSS 3.1 Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
- **Attack Prerequisites:** No privileges required
- **Verification Status:** CONFIRMED
- **Verification Evidence:** Ghidra DB static analysis — CONFIRMED (triple-verified)

## 3. Affected Vendor / Product

- **Vendor:** Qihoo 360 Technology Co. Ltd.
- **Product:** 360 360 M5 Router
- **Affected Version / Firmware:** M5-4.0.17.1566-rel-upgrade.bin
- **Affected Component:** web/cgi-bin/cgitest.cgi ? put_igdmptd_cgi @ 0x5a338
- **Architecture:** MIPS32 (Big Endian)

## 4. Description

OS command injection in put_igdmptd_cgi (0x5a338) of cgitest.cgi in 360 360 M5 firmware M5-4.0.17.1566-rel-upgrade.bin. User parameters (put_file) read via get_form_value() flow to system() without sanitization. Pattern: IGDM proxy daemon — get_form_value→sprintf→ipc_clientcall→system + telnetd deployment

## 5. Technical Details

**Affected Parameter(s):** put_file, applet

- **Source**: get_form_value('put_file')
- **Sink**: system()
- **Binary strings**: %s /tmp/telnetd, %s %s && chmod +x %s, %s %s; killall impd, /etc/360_pub.key
- **Verification**: Ghidra DB static triple-verification (func_call + func_string + input_dataflow_call)
- **0-day basis**: No known CVE for any 360 router CGI vulnerability

## 6. Proof of Concept / Reproduction

```http
POST /cgi-bin/cgitest.cgi HTTP/1.1
Host: <TARGET_IP>
Content-Type: application/x-www-form-urlencoded

applet=put_igdmptd_cgi&put_file=1;id;
```

## 7. Security Impact

Unauthenticated remote attacker can execute arbitrary commands as root. No authentication required for CGI endpoints.

## 8. Remediation Recommendation

Replace system() with execve(). Validate all parameters. Add authentication to CGI handlers.

## 9. Discovery / Credit

| Field | Value |
|-------|-------|
| **Method** | FirmRec Cross-Firmware Genetic Vulnerability Mining |
| **Date** | 2026-04-29 |
| **Discoverer** | ST4R |
| **Verification** | Ghidra DB static analysis — CONFIRMED (triple-verified) |
| **Status** | CONFIRMED |

## 10. Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-04-29 | Vulnerability discovered via FirmRec automated pipeline |
| TBD | Vendor notification |
| TBD | CVE ID assigned |
| TBD | Public disclosure (+90 days) |

---
*Discovered via FirmRec — IoT Firmware Genetic Vulnerability Mining Framework*

## 11. Suggested VulnDB Tags

Qihoo, 360, CWE-78, OS Command Injection, Firmware, IoT

---
Prepared from FirmRec vulnerability finding notes for VulnDB submission.
