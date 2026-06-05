# OpenClaw cron list跨群任务信息泄露漏洞

## 1. 漏洞标题

OpenClaw cron list跨群任务信息泄露漏洞

## 2. 漏洞厂商

OpenClaw

## 3. 影响产品

OpenClaw

项目地址：

```text
https://github.com/openclaw/openclaw
```

## 4. 影响对象类型

应用软件 / 服务端应用 / Agent 网关与 CLI 管理组件

## 5. 影响版本

经验证，以下版本或分支仍存在该问题：

```text
OpenClaw 2026.5.21
OpenClaw 2026.6.1
OpenClaw 2026.6.2-beta.1
OpenClaw 2026.6.4-alpha.1
```

可在 CNVD 中简写为：

```text
OpenClaw 2026.5.21 至 2026.6.4-alpha.1
```

说明：本地验证仓库当前 `HEAD` 的 `package.json` 版本为 `2026.5.21`；同时抽查 `v2026.6.1`、`v2026.6.2-beta.1`、`v2026.6.4-alpha.1` 标签，`cron list` 缺省不带上下文过滤的逻辑仍存在。

## 6. 漏洞类型

信息泄露 / 隐私泄露 / 访问控制缺陷

## 7. 漏洞等级建议

中危

## 8. CWE / CVSS

- CWE：`CWE-200 Exposure of Sensitive Information to an Unauthorized Actor`
- CVSS 3.1：`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N`
- CVSS 分数：4.3

## 9. 漏洞描述

OpenClaw 的 cron 任务列表功能存在跨群/跨上下文信息泄露问题。在群聊或多上下文使用场景中，普通用户执行 `openclaw cron list` 时，系统默认不会按当前 group/context 过滤 cron jobs，而是返回当前 OpenClaw 实例中的全量 cron 任务列表。

由于 cron 任务通常包含任务名称、执行计划、启用状态、执行状态以及可能反映业务流程的描述信息，该缺陷会导致当前群用户看到其他群或其他上下文中的任务信息，造成跨群隐私泄露和租户/上下文隔离失效。

## 10. 漏洞成因

`openclaw cron list` CLI 在未显式指定 `--agent` 时，只向服务端传递 `includeDisabled` 参数，不传递当前群、当前 session、当前上下文或默认 agent 过滤条件。

受影响代码：

```ts
// src/cli/cron-cli/register.cron-add.ts:53-60
const listParams: Record<string, unknown> = {
  includeDisabled: Boolean(opts.all),
};
const agentId = normalizeOptionalString(opts.agent);
if (agentId) {
  listParams.agentId = sanitizeAgentId(agentId);
}
const res = await callGatewayFromCli("cron.list", opts, listParams);
```

服务端 cron list 逻辑中，只有在 `requestedAgentId` 存在时才执行 agent 过滤；当 `requestedAgentId` 为空时，所有已加载 cron jobs 都会进入结果集。

```ts
// src/cron/service/ops.ts:324-340
const requestedAgentId = normalizeOptionalAgentId(opts?.agentId);
const source = state.store?.jobs ?? [];
const filtered = source.filter((job) => {
  if (enabledFilter === "enabled" && !isJobEnabled(job)) {
    return false;
  }
  if (enabledFilter === "disabled" && isJobEnabled(job)) {
    return false;
  }
  if (
    requestedAgentId &&
    resolveEffectiveJobAgentId(job, state.deps.defaultAgentId) !== requestedAgentId
  ) {
    return false;
  }
  if (!query) {
    return true;
  }
  ...
});
```

项目现有测试也固化了该行为：

```ts
// src/cron/service.list-page-sort-guards.test.ts:94-103
it("keeps listPage unfiltered when agent id is omitted", async () => {
  ...
  const page = await listPage(state);
  expect(page.jobs.map((job) => job.id)).toEqual(["job-main", "job-ops"]);
});
```

```ts
// src/cli/cron-cli.test.ts:562-566
it("leaves cron list unfiltered when --agent is omitted", async () => {
  await runCronCommand(["cron", "list"]);
  const listCall = callGatewayFromCli.mock.calls.find((call) => call[0] === "cron.list");
  expect(listCall?.[2]).toEqual({ includeDisabled: false });
});
```

## 11. 攻击条件

攻击者需要满足以下条件：

1. 能够在 OpenClaw 群聊、频道、上下文或 CLI 管理入口中触发 `openclaw cron list`；
2. 当前 OpenClaw 实例中存在多个群、多个 agent、多个 session 或多个业务上下文的 cron 任务；
3. 攻击者本不应查看其他群或其他上下文的 cron 任务信息。

该漏洞通常不需要管理员权限；只要普通用户能够触发 cron list，即可能看到其他上下文任务信息。具体权限取决于部署环境对 OpenClaw CLI/命令入口的开放方式。

## 12. PoC

以下 PoC 用于在授权测试环境中验证该问题。

### 方式一：CLI 触发

1. 创建两个不同上下文或 agent 的 cron 任务：

```bash
openclaw cron add --name "GroupA Daily Report" --cron "0 9 * * *" --message "run group A report" --agent group-a
openclaw cron add --name "GroupB Daily Report" --cron "0 15 * * *" --message "run group B report" --agent group-b
```

2. 在未指定 agent/context 的情况下执行列表命令：

```bash
openclaw cron list
```

3. 实际结果中会同时出现 `GroupA Daily Report` 与 `GroupB Daily Report`。

预期行为应为：在 Group-B 或对应上下文中仅显示 Group-B 相关任务；只有管理员显式使用全局查看参数时才允许看到全部任务。

### 方式二：服务端逻辑最小化验证

构造两个 cron jobs：

```text
job-main: agentId = main
job-ops:  agentId = ops
```

调用：

```text
cron.list / listPage，不传 agentId
```

实际返回：

```text
job-main, job-ops
```

项目当前测试 `src/cron/service.list-page-sort-guards.test.ts` 已明确断言上述行为。

## 13. 触发过程

1. OpenClaw 实例中存在多个群、多个 agent 或多个会话上下文的 cron 任务。
2. 某一群或某一低权限上下文中的用户触发 `openclaw cron list`。
3. CLI 端未携带当前 group/context/session 过滤参数，仅传递 `includeDisabled`。
4. 服务端 `listPage` 收到空 `agentId`，不会进入 agent 过滤分支。
5. 服务端返回全部 cron jobs。
6. 当前用户可看到其他群或其他上下文的任务名称、计划时间、启用状态、执行状态等信息。

## 14. 验证结果

2026-06-05 对 `openclaw/openclaw` 本地仓库进行代码级复核，确认以下证据：

- `package.json` 当前版本：`2026.5.21`；
- `src/cli/cron-cli/register.cron-add.ts:53-60`：不带 `--agent` 时未传递任何上下文过滤条件；
- `src/cron/service/ops.ts:324-340`：只有 `requestedAgentId` 非空时才执行过滤；
- `src/cron/service.list-page-sort-guards.test.ts:94-103`：测试明确断言不传 agent 时返回全部 jobs；
- `src/cli/cron-cli.test.ts:562-566`：测试明确断言 `openclaw cron list` 缺省只传 `{ includeDisabled: false }`；
- 抽查 `v2026.6.1`、`v2026.6.2-beta.1`、`v2026.6.4-alpha.1` 标签，相关逻辑仍存在。

相关公开 issue：

```text
https://github.com/openclaw/openclaw/issues/31464
```

Issue 正文描述：在某一群执行 `openclaw cron list` 会显示所有群的 cron jobs，包括其他群任务名称和 schedules，造成 privacy leak。

## 15. 漏洞影响

成功触发该漏洞可能造成：

- 当前群用户看到其他群的 cron 任务名称；
- 泄露其他群或其他业务上下文的计划任务时间；
- 泄露任务执行状态或失败状态；
- 暴露业务流程、自动化任务用途、内部系统名称或运营节奏；
- 在多租户、多群、多团队共用同一 OpenClaw 实例时造成上下文隔离失效。

该漏洞不直接泄露凭据或任务输出内容，但 cron job 名称和 schedule 可能包含业务敏感信息，因此属于信息泄露/隐私泄露风险。

## 16. 临时解决方案

在官方修复发布前，建议采取以下临时缓解措施：

1. 限制普通用户触发 `openclaw cron list` 的权限；
2. 在群聊或公开频道中暂时禁用 cron list 命令；
3. 要求管理员查看任务时显式使用受控入口，并避免在普通群上下文中返回全局列表；
4. 对 cron 任务名称进行脱敏，避免在任务名称中包含客户名、项目名、内部系统名、业务计划等敏感信息；
5. 如必须使用，可要求所有列表查询显式携带 `--agent <id>` 或等效上下文过滤参数。

## 17. 修复建议

建议厂商进行如下修复：

1. 将 `openclaw cron list` 的默认行为改为按当前 group/context/session/agent 过滤；
2. 仅允许 owner/admin 使用显式全局参数查看全部 cron jobs；
3. 区分 `--all` 的语义：避免将“包含 disabled jobs”和“显示全部上下文 jobs”混用；
4. 在服务端 `cron.list` / `listPage` 层强制执行权限校验，不仅依赖 CLI 端传参；
5. 为群 A / 群 B 增加回归测试，确保群 A 不能看到群 B 的任务；
6. 对 API/CLI JSON 输出同样应用过滤，避免非人类可读输出绕过限制；
7. 对历史 cron jobs 进行审计，检查任务名称或描述中是否包含敏感信息。

