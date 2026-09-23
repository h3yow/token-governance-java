# Token Governance（访问凭证签发 / 刷新旋转 / 权限判定）

一套**本地可运行**的访问凭证生命周期与授权判定实现。目标是让凭证状态与授权结论，
在**并发**与**运行时状态变更**下保持**确定、可解释**。

- 凭证：访问凭证（Access Token）+ 刷新凭证（Refresh Token），内存存储。
- 刷新旋转：同一刷新凭证并发使用**最多成功一次**；已消费 / 已过期 / 已吊销均被拒绝，且原因可区分。
- 授权判定：同时考虑**角色**与**属性**；显式拒绝优先、默认拒绝；规则缺失或冲突绝不静默放行，并返回逐条依据。
- 状态即时生效：吊销或权限调整后，**下一次访问**即按最新状态判定。
- 时钟偏差：在可配置容忍窗口内不把有效凭证误判为过期；吊销是硬状态，先于过期判定，杜绝吊销竞态越权。

---

## 1. 技术栈与运行

- Java 21+、Spring Boot 3.4.x、JUnit 5。
- 无需数据库 / 外部中间件，全部状态在内存。

```bash
# 构建并运行全部测试
mvn test

# 启动本地服务（默认 8080；如端口被占用可指定其它端口）
mvn spring-boot:run
mvn spring-boot:run -Dspring-boot.run.arguments=--server.port=8089
```

启动时会自动播种演示主体与规则（见 `config/DemoDataInitializer`）：

| 主体 | 角色 | 属性 |
| --- | --- | --- |
| alice | `editor` | `department=engineering`, `blacklisted=false` |
| bob | `viewer` | `department=sales`, `blacklisted=false` |

预置规则：

| 规则 | 条件（动作/资源/角色/属性） | 效力 |
| --- | --- | --- |
| `allow-editor-engineering` | edit / document / 角色 `editor` / `department=engineering` | ALLOW |
| `allow-anyone-view` | view / document / 无角色要求 / 无属性要求 | ALLOW |
| `deny-blacklisted-view` | view / document / `blacklisted=true` | DENY |

---

## 2. HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/tokens` | 为 `subject` 签发一对新凭证 |
| POST | `/api/tokens/refresh` | 用刷新凭证旋转出一对新凭证 |
| POST | `/api/tokens/revoke` | 吊销凭证（自动识别 access/refresh），整族失效 |
| POST | `/api/check` | 校验访问凭证并做授权判定，返回结论与逐条依据 |
| POST | `/api/admin/roles` | 运行时调整主体角色（即时生效） |
| POST | `/api/admin/attributes` | 运行时调整主体属性（即时生效） |

### 2.1 签发

```bash
curl -s -X POST localhost:8080/api/tokens \
  -H 'Content-Type: application/json' \
  -d '{"subject":"alice"}'
# => {"accessToken":"...","refreshToken":"...","accessExpiresAt":...,"refreshExpiresAt":...}
```

### 2.2 刷新旋转

```bash
curl -s -X POST localhost:8080/api/tokens/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refreshToken":"<上一步的 refreshToken>"}'
```

### 2.3 授权判定（返回可解释依据）

```bash
curl -s -X POST localhost:8080/api/check \
  -H 'Content-Type: application/json' \
  -d '{"accessToken":"<accessToken>","action":"edit","resource":"document"}'
```

响应中的 `trace` 逐条给出每条规则是否命中、效力与人类可读原因，例如：

```json
{
  "permitted": true,
  "code": "PERMIT",
  "reason": "命中允许规则: [allow-editor-engineering]",
  "trace": [
    {"ruleId":"allow-editor-engineering","matched":true,"effect":"ALLOW",
     "detail":"命中：动作=edit，资源=document，角色满足[editor]，属性满足[department=engineering] => ALLOW"}
  ]
}
```

### 2.4 运行时调整权限（即时生效）

```bash
# 降权：alice 立刻失去 edit 能力（无需更换凭证）
curl -s -X POST localhost:8080/api/admin/roles \
  -H 'Content-Type: application/json' \
  -d '{"subject":"alice","roles":["viewer"]}'

# 加黑名单：view 立即被显式拒绝
curl -s -X POST localhost:8080/api/admin/attributes \
  -H 'Content-Type: application/json' \
  -d '{"subject":"alice","attributes":{"department":"engineering","blacklisted":"true"}}'
```

### 2.5 吊销（整族即时失效）

```bash
curl -s -X POST localhost:8080/api/tokens/revoke \
  -H 'Content-Type: application/json' \
  -d '{"token":"<accessToken 或 refreshToken>"}'
# 之后该旋转家族内的所有 access / refresh 立即不可用，/api/check 返回 403 REVOKED
```

### 2.6 错误码（拒绝原因可区分）

凭证类错误通过 HTTP 状态码 + `error` 字段双重区分：

| error 码 | HTTP | 含义 |
| --- | --- | --- |
| `NOT_FOUND` | 404 | 凭证不存在 |
| `WRONG_TYPE` | 404 | 凭证类型用错（拿 access 当 refresh 等） |
| `EXPIRED` | 410 | 已过期（且已超出时钟偏差容忍窗口） |
| `REVOKED` | 403 | 已被吊销（含整族连带） |
| `ALREADY_CONSUMED` | 409 | 刷新凭证已被消费：并发抢占失败或重放 |

授权结论码：`PERMIT`、`DENY_EXPLICIT`、`DENY_NO_RULE`、`DENY_CONFLICT`、`DENY_SUBJECT_NOT_FOUND`。

---

## 3. 凭证生命周期

```
                 签发 issue()
                      │
                      ▼
                 ┌─────────┐   rotate() 成功(CAS 抢到)   ┌─────────┐
   refresh ─────►│ ACTIVE  │ ───────────────────────────►│ CONSUMED│
                 └────┬────┘                              └─────────┘
                      │ 过期(超出 skew 窗口)
                      ▼
                 ┌─────────┐
                 │ EXPIRED │（终态：不可再换取）
                 └─────────┘
        revoke*（任意时刻，整族）
                      ▼
                 ┌─────────┐
                 │ REVOKED │（终态：access/refresh 同族全部失效）
                 └─────────┘
```

- **家族（family）**：一次签发给每个主体分配一个 `familyId`；之后每次刷新旋转
  **延续同一家族**。吊销任意成员即把整族置为 `REVOKED`，实现“一次吊销，整条刷新链与
  同族访问凭证一起失效”。
- **旋转原子性**：刷新凭证状态用 `AtomicReference` 保存，旋转时执行
  `ACTIVE -> CONSUMED` 的 CAS。并发请求中只有一个线程能成功，其余得到
  `ALREADY_CONSUMED`，因此同一刷新凭证**最多成功一次**，重放也会被同一机制挡住。
- **拒绝判定顺序**：`不存在 -> 类型错误 -> 已吊销 -> 已过期`。
  吊销是“硬状态”，优先于过期，避免在临界时刻因过期判断掩盖吊销。
- **旋转 / 吊销互斥**：同一家族上加锁，旋转“登记新成员”与“整族吊销”互斥；
  旋转在返回新凭证前会复查新成员状态，保证吊销刚发生时不会返回一对仍有效的新凭证，
  消除吊销竞态下的短暂越权窗口。

### 3.1 时钟偏差容忍

过期判断使用：`当前时间 - clockSkew >= expiresAt` 才算过期（默认容忍 30 秒，
见 `GovernanceConfig.CLOCK_SKEW_MILLIS`）。

- 在容忍窗口内，即使本节点时钟略快、凭证看似“刚过期”，仍判有效，**不误杀**；
- 一旦越过容忍边界才判 `EXPIRED`；
- 吊销不受时钟影响：任何偏差下被吊销凭证都不会放行。

---

## 4. 授权判定规则

判定在**每次访问时即时读取**主体当前角色与属性（`SubjectDirectory`），凭证不携带
也不缓存授权信息，因此吊销 / 权限调整在下一次 `/api/check` 立即生效。

### 4.1 规则匹配（合取）

一条规则包含：`action`、`resourceName`、可选 `requiredRole`、可选属性条件
`attributeName/attributeValue`、以及效力 `ALLOW/DENY`。命中需要**全部**满足：

1. `action` 与请求动作相等；
2. `resourceName` 与资源名相等；
3. 若配置了角色条件，主体当前角色集合必须包含该角色；
4. 若配置了属性条件，主体当前属性必须等于期望值。

### 4.2 结论如何得出（确定性、可解释）

对所有规则求值并记录到 `trace`，然后：

1. 同时存在命中的 `DENY` 与 `ALLOW` → **`DENY_CONFLICT`（拒绝）**，拒绝优先，绝不静默放行；
2. 仅命中 `DENY` → `DENY_EXPLICIT`（显式拒绝）；
3. 仅命中 `ALLOW` → `PERMIT`；
4. 没有任何规则命中 → `DENY_NO_RULE`（默认拒绝）；
5. 主体不存在 / 已注销 → `DENY_SUBJECT_NOT_FOUND`。

即：**显式拒绝优先于允许，默认拒绝，冲突也拒绝**，且每种结论都带可区分的 `code` 与逐条依据。

---

## 5. 测试

测试位于 `src/test/java/.../tests`，均在日志中打印输入与判定依据：

| 测试类 | 覆盖场景 |
| --- | --- |
| `TokenServiceTest` | 并发刷新（16 线程仅 1 成功）、重放、不存在、过期、**时钟偏差边界**、整族吊销、**100 轮旋转/吊销竞态** |
| `AuthorizationServiceTest` | 角色+属性合取、显式拒绝优先、默认拒绝、冲突拒绝、主体缺失、权限调整即时生效 |
| `AccessGuardTest` | 凭证校验 + 实时授权端到端联动、吊销/降权/提权即时生效 |
| `HttpApiIntegrationTest` | HTTP 全流程：签发、刷新、重放 409、不存在 404、默认拒绝、吊销 403 |

```bash
mvn test
```

---

## 6. 代码结构

```
src/main/java/com/github/h3yow/tokengovernancejava
├── token/                 # 凭证生命周期
│   ├── Token.java          # 凭证实体（AtomicReference 状态 + CAS）
│   ├── TokenService.java   # 签发/旋转/校验/吊销（并发安全、家族锁）
│   ├── TokenState / TokenType / RejectionReason
│   └── TokenException / TokenPair / AccessValidation
├── authz/                 # 授权判定
│   ├── PolicyRule.java     # 规则 + 合取匹配
│   ├── AuthorizationService.java  # 求值 + 拒绝优先/默认拒绝/冲突拒绝 + trace
│   ├── SubjectDirectory / PolicyRepository  # 实时主体状态 / 规则仓库
│   ├── AccessGuard.java    # 凭证校验 + 授权判定 串联
│   └── AuthorizationDecision / DecisionTrace / DecisionCode / Effect
├── web/                    # REST 接口与统一异常映射
└── config/                 # Spring 装配（TTL、时钟偏差）与演示数据
```
