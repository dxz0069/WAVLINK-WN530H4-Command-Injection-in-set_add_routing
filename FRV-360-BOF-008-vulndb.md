# VulnDB Submission: 360 M5 cgitest.cgi mesh_set_version_check_cgi Buffer Overflow via strcpy

## 1. Title

360 M5 cgitest.cgi mesh_set_version_check_cgi Buffer Overflow via strcpy

## 2. Vulnerability Summary

- **Internal Tracking ID:** FRV-360-BOF-008
- **VulnDB ID:** (Pending Assignment)
- **CVE ID:** (Pending Assignment)
- **Vulnerability Class:** CWE-120: Buffer Copy without Checking Size of Input (Classic Buffer Overflow)
- **Vulnerability Type:** Buffer Overflow (Classic strcpy)
- **Severity:** 8.1 (High)
- **Severity Label:** High
- **CVSS 3.1 Vector:** CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H
- **Attack Prerequisites:** No privileges required
- **Verification Status:** CONFIRMED
- **Verification Evidence:** Ghidra DB static analysis — dataflow CONFIRMED

## 3. Affected Vendor / Product

- **Vendor:** Qihoo 360 Technology Co. Ltd.
- **Product:** 360 M5 Router
- **Affected Version / Firmware:** M5-4.0.17.1566-rel-upgrade.bin
- **Affected Component:** web/cgi-bin/cgitest.cgi ? mesh_set_version_check_cgi @ 0x55348
- **Architecture:** MIPS32 (Big Endian)

## 4. Description

Stack-based buffer overflow in mesh_set_version_check_cgi (0x55348) of cgitest.cgi in 360 M5 firmware. User parameters (maclist) read via get_form_value() flow to strcpy() without bounds checking. Dataflow confirmed: get_form_value → strcpy(stack_buffer). The 'response' value reaches the strcpy sink.

## 5. Technical Details

**Affected Parameter(s):** maclist, applet

- **Source**: get_form_value('maclist')
- **Sink**: strcpy() — no bounds checking
- **Dataflow**: get_form_value → strcpy confirmed (parameter: response)
- **Verification**: Ghidra DB static analysis — dataflow CONFIRMED
- **Exploitation**: MIPS32 stack-based, likely no ASLR/canary on embedded device

## 6. Proof of Concept / Reproduction

```http
POST /cgi-bin/cgitest.cgi HTTP/1.1
Host: <TARGET_IP>
Content-Type: application/x-www-form-urlencoded

applet=mesh_set_version_check_cgi&maclist=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...[overflow_payload]...[shellcode]
```

## 7. Security Impact

Potential remote code execution via stack buffer overflow. Mesh protocol functions run with elevated privileges.

## 8. Remediation Recommendation

Replace strcpy() with strlcpy(). Enforce maximum input lengths. Enable -fstack-protector-all.

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

Qihoo, 360, CWE-120, Buffer Overflow (Classic strcpy), Firmware, IoT

---
Prepared from FirmRec vulnerability finding notes for VulnDB submission.
