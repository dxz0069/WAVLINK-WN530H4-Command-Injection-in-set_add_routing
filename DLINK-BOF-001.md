# Vulnerability Submission Draft: D-Link DSM-G600 load_file.cgi Multipart Crash

## Basic Information

| Field | Value |
|-------|-------|
| VulnDB ID | Pending assignment |
| CVE ID | Pending assignment |
| CWE ID | CWE-120 / CWE-787 candidate |
| CVSS v3.1 Score | 6.5 |
| CVSS v3.1 Vector | AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H |
| Vulnerability Type | Authenticated HTTP memory corruption / denial of service |
| Internal ID | DLINK-BOF-001 |

## Affected Product

| Field | Value |
|-------|-------|
| Vendor | D-Link |
| Product | DSM-G600 Wireless Network Storage Enclosure |
| Confirmed Firmware Version | REVA 1.01 |
| Confirmed Firmware Image | `dlink-DSM__DSM-G600_REVA_FIRMWARE_1.01.ZIP` |
| Affected Binary | `e_storage/bin/http` |
| Web Endpoint | `/load_file.cgi` |
| Architecture | ARM big-endian |
| Confirmed Binary SHA1 | `b1294640f6899db7d6e2f5600a273224889d1a9e` |
| Authentication | Required; reproduced with HTTP Basic `admin:` |

## Description

The DSM-G600 embedded HTTP daemon crashes while handling an authenticated multipart POST to `load_file.cgi`, the configuration-restore endpoint used by the Tools/System page. In the restored firmware rootfs under `qemu-armeb-static`, multipart bodies of approximately 8192 bytes or larger reproducibly terminate the target process with SIGSEGV.

The crash is endpoint-specific in the current evidence. Comparable long multipart uploads to `update.cgi` did not crash the daemon, and unauthenticated or bad-auth `load_file.cgi` probes were rejected or reset without terminating the process. The affected request therefore appears to require access to the management interface. The tested credential was `admin:` because DSM-family devices commonly shipped with an empty default admin password; default-credential exposure should be handled separately from this memory-corruption finding.

## Impact

An authenticated network attacker can crash the DSM-G600 HTTP management daemon, causing denial of service for the administrative interface. Because the crash is a target SIGSEGV in the HTTP process during multipart parsing or restore handling, exploitability beyond denial of service needs additional reverse-engineering before claiming code execution.

## Proof of Concept

Minimal request shape:

```http
POST /load_file.cgi HTTP/1.0
Host: <TARGET>
Authorization: Basic YWRtaW46
Content-Type: multipart/form-data; boundary=firmrec
Content-Length: <calculated>

--firmrec
Content-Disposition: form-data; name="file"; filename="x.bin"
Content-Type: application/octet-stream

<8192 or more bytes>
--firmrec--
```

The focused local reproduction script builds this request automatically:

```bash
python3 scripts/oneoff/verify_dsmg600_loadfile_crash_20260526.py
```

A minimal network-only PoC is also available for a live target or lab instance:

```bash
python3 scripts/oneoff/poc_dsmg600_loadfile_crash_20260526.py <target-ip> --user admin --password '' --size 12000
```

## Runtime Evidence

Focused verification artifacts:

- `scripts/oneoff/verify_dsmg600_http_active_20260526.py`
- `scripts/oneoff/verify_dsmg600_loadfile_crash_20260526.py`
- `inout/reports/0day_verification_20260526/dsmg600_101_http_runtime_20260526.json`
- `inout/reports/0day_verification_20260526/dsmg600_101_http_active_runtime_20260526.json`
- `inout/reports/0day_verification_20260526/dsmg600_101_loadfile_crash_runtime_20260526.json`
- `inout/reports/0day_verification_20260526/dsmg600_101_loadfile_crash_verdict_20260526.md`
- `inout/reports/0day_verification_20260526/dsmg600_101_loadfile_duplicate_check_20260526.json`
- `inout/reports/0day_verification_20260526/public_duplicate_refresh_20260526_1044.json`
- `inout/reports/0day_verification_20260526/public_duplicate_refresh_20260526_1200.json`
- `inout/reports/0day_verification_20260526/public_duplicate_refresh_20260526_1200.md`
- `scripts/oneoff/poc_dsmg600_loadfile_crash_20260526.py`

Stable SIGSEGV cases from the focused matrix:

| Case | Auth | Payload Length | Result |
|------|------|----------------|--------|
| `post_load_file_admin_empty_8192` | `admin:` | 8192 bytes | target SIGSEGV |
| `post_load_file_admin_empty_12000` | `admin:` | 12000 bytes | target SIGSEGV |
| `post_load_file_admin_empty_20000` | `admin:` | 20000 bytes | target SIGSEGV |
| `post_load_file_admin_empty_field_x_12000` | `admin:` | 12000 bytes | target SIGSEGV |

Negative controls:

| Case Group | Result |
|------------|--------|
| `GET /` without auth | 401, process remains alive |
| `GET /load_file.cgi` without auth | 401, process remains alive |
| `POST /load_file.cgi` without auth | no SIGSEGV observed |
| `POST /load_file.cgi` with bad auth | no SIGSEGV observed |
| `POST /load_file.cgi` with `admin:` and 128/1024/4096 byte body | no SIGSEGV observed |
| `POST /update.cgi` with `admin:` and 12000 byte body | no SIGSEGV observed |

Boundary summary:

| Dimension | Observation |
|-----------|-------------|
| Authentication | SIGSEGV reproduced only after successful `admin:` authentication in this matrix |
| Endpoint | `load_file.cgi` crashes; `update.cgi` with comparable body does not |
| Body length | 4096 bytes and below did not crash; 8192 bytes and above crashed |
| Multipart field name | Both `file` and `x` triggered SIGSEGV at 12000 bytes after authentication |

Representative runtime signal:

```text
qemu: uncaught target signal 11 (Segmentation fault) - core dumped
```

## Public Duplicate Check

Public-record checks on 2026-05-26 did not find a directly matching public CVE or disclosure for `DSM-G600` plus `load_file.cgi`.

NVD API checks:

| Query | Result |
|-------|--------|
| `DSM-G600` | 0 CVE records |
| `D-Link DSM-G600` | 0 CVE records |
| `load_file.cgi DSM-G600` | 0 CVE records |

Search queries also checked included:

```text
"DSM-G600" "load_file.cgi"
"D-Link DSM-G600" "load_file.cgi"
"DSM-G600" "configuration" "vulnerability"
"D-Link" "DSM-G600" CVE vulnerability
site:exploit-db.com "DSM-G600"
site:packetstormsecurity.com "DSM-G600"
site:seclists.org "DSM-G600"
site:cxsecurity.com "DSM-G600"
```

Refresh note: follow-up public duplicate refreshes at 2026-05-26T10:44:03Z and 2026-05-26T11:59:23Z still did not find a direct `DSM-G600` / `load_file.cgi` public duplicate. The 11:59 refresh returned 0 NVD records for `D-Link DSM-G600`, `load_file.cgi DSM-G600`, and `D-Link DSM-G600 load_file.cgi`; the initially timed-out `DSM-G600` and `DSM-G600 vulnerability` keyword requests were retried at 2026-05-26T12:02Z and also returned 0 NVD records.

No search pass can prove global non-existence of private, vendor-only, or poorly indexed reports. Repeat the duplicate check immediately before external filing.

## Discovery

| Field | Value |
|-------|-------|
| Discovery Method | FirmRec cross-firmware vulnerability mining plus focused runtime verification |
| Date Verified | 2026-05-26 |
| Verification | Authenticated HTTP multipart probes in restored DSM-G600 rootfs under `qemu-armeb-static` |

## Suggested Fix

1. Add strict multipart upload size limits before buffering or parsing restore files.
2. Validate multipart boundaries, field names, and file lengths before copying into fixed-size buffers.
3. Reject malformed restore files before invoking restore/reboot logic.
4. Add regression tests for oversized configuration uploads.

## Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-05-26 | Runtime SIGSEGV reproduced in local verification harness |
| TBD | Duplicate/public-advisory review completed |
| TBD | Reported to D-Link PSIRT |
| TBD | CVE ID assigned |
| TBD | Public disclosure |
