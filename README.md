# Token Governance（访问凭证签发 / 刷新旋转 / 会话管理 / 权限判定）

一套**本地可运行**的访问凭证生命周期、登录会话（设备）管理与授权判定实现。目标是让凭证状态与授权结论，
在**并发**与**运行时状态变更**下保持**确定、可解释**。

- 凭证：访问凭证（Access Token）+ 刷新凭证（Refresh Token），内存存储。
- 刷新旋转：同一刷新凭证并发使用**最多成功一次**；已消费 / 已过期 / 已吊销均被拒绝，且原因可区分。
- 会话管理：同一用户多会话（设备）并存，可查看清单、按会话或按用户整体下线，**立即生效**且互不影响；
  每用户有效会话数有**可配置上限**，到上限明确拒绝。
- 重放检测：已消费的刷新凭证在宽窗口之后再次出现，按**会话泄露**处理——整个会话立即作废，
  包括上一次旋转换出的新凭证，拒绝原因 `REPLAY_DETECTED` 可区分。
- 授权判定：同时考虑**角色**与**属性**；显式拒绝优先、默认拒绝；规则缺失或冲突绝不静默放行，并返回逐条依据。
- 状态即时生效：吊销、会话下线或权限调整后，**下一次访问**即按最新状态判定。
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
| POST | `/api/tokens` | 为 `subject` 签发一对新凭证（可选 `device` 来源标识） |
| POST | `/api/tokens/refresh` | 用刷新凭证旋转出一对新凭证 |
| POST | `/api/tokens/revoke` | 吊销凭证（自动识别 access/refresh），整族失效 |
| GET | `/api/sessions?subject=...` | 查看某用户当前有效会话清单（只含元信息，不含凭证） |
| POST | `/api/sessions/end` | 单独结束某个会话，立即生效 |
| POST | `/api/sessions/end-all` | 结束某用户的全部会话 |
| POST | `/api/check` | 校验访问凭证并做授权判定，返回结论与逐条依据 |
| POST | `/api/admin/roles` | 运行时调整主体角色（即时生效） |
| POST | `/api/admin/attributes` | 运行时调整主体属性（即时生效） |

### 2.1 签发

```bash
curl -s -X POST localhost:8080/api/tokens \
  -H 'Content-Type: application/json' \
  -d '{"subject":"alice"}'
# => {"accessToken":"...","refreshToken":"...","accessExpiresAt":...,"refreshExpiresAt":...,"sessionId":"..."}

# 可选：携带设备/来源标识，便于按设备管理会话
curl -s -X POST localhost:8080/api/tokens \
  -H 'Content-Type: application/json' \
  -d '{"subject":"alice","device":"phone"}'
```

老客户端不传 `device` 时行为不变：照常签发，归入来源标识为 `default` 的会话。

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

### 2.6 会话管理（按设备下线）

```bash
# 查看 alice 当前有效会话（只含会话标识与元信息，绝不返回凭证）
curl -s 'localhost:8080/api/sessions?subject=alice'
# => [{"sessionId":"...","subject":"alice","deviceLabel":"phone",
#      "createdAt":...,"lastRefreshedAt":...,"expiresAt":...,"expired":false}, ...]

# 单独下线某个会话（比如只踢掉手机）：该会话名下全部凭证立即失效，其它会话不受影响
curl -s -X POST localhost:8080/api/sessions/end \
  -H 'Content-Type: application/json' \
  -d '{"sessionId":"<要结束的 sessionId>"}'

# 一次下线 alice 的所有会话，返回结束的会话数
curl -s -X POST localhost:8080/api/sessions/end-all \
  -H 'Content-Type: application/json' \
  -d '{"subject":"alice"}'
# => {"ended":3,"subject":"alice"}
```

### 2.7 错误码（拒绝原因可区分）

凭证类错误通过 HTTP 状态码 + `error` 字段双重区分：

| error 码 | HTTP | 含义 |
| --- | --- | --- |
| `NOT_FOUND` | 404 | 凭证不存在 |
| `WRONG_TYPE` | 404 | 凭证类型用错（拿 access 当 refresh 等） |
| `EXPIRED` | 410 | 已过期（且已超出时钟偏差容忍窗口） |
| `REVOKED` | 403 | 已被吊销（含整族连带、会话下线连带） |
| `ALREADY_CONSUMED` | 409 | 刷新凭证已被消费：并发抢占失败（宽窗口内的再次使用） |
| `REPLAY_DETECTED` | 409 | 刷新凭证疑似被重放：所属会话已整体作废 |
| `SESSION_NOT_FOUND` | 404 | 会话不存在或已结束 |
| `SESSION_LIMIT_EXCEEDED` | 409 | 该用户有效会话数已达上限 |

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
  `ALREADY_CONSUMED`，因此同一刷新凭证**最多成功一次**。消费时刻被记录：
  宽窗口之后同一凭证再次出现判定为**事后重放**，整个会话作废并返回
  `REPLAY_DETECTED`（详见 4.2）。
- **拒绝判定顺序**：`不存在 -> 类型错误 -> 已吊销 -> 已过期`。
  吊销是“硬状态”，优先于过期，避免在临界时刻因过期判断掩盖吊销。
- **旋转 / 吊销互斥**：同一家族上加锁，旋转“登记新成员”与“整族吊销”互斥；
  旋转在返回新凭证前会复查新成员状态，保证吊销刚发生时不会返回一对仍有效的新凭证，
  消除吊销竞态下的短暂越权窗口。
- **签发 / 结束互斥**：签发时“登记会话 + 登记凭证”在同一家族锁临界区内完成，
  登记后复查会话状态；若会话在签发过程中被并发结束，立即补偿吊销并以 `REVOKED`
  拒绝本次签发，已结束会话名下绝不残留可用凭证（详见 4.2）。

### 3.1 时钟偏差容忍

过期判断使用：`当前时间 - clockSkew >= expiresAt` 才算过期（默认容忍 30 秒，
见 `GovernanceConfig.CLOCK_SKEW_MILLIS`）。

- 在容忍窗口内，即使本节点时钟略快、凭证看似“刚过期”，仍判有效，**不误杀**；
- 一旦越过容忍边界才判 `EXPIRED`；
- 吊销不受时钟影响：任何偏差下被吊销凭证都不会放行。

---

## 4. 登录会话（设备）管理

### 4.1 会话与凭证生命周期的关系

**一个登录会话 = 一个刷新家族（sessionId 即 familyId）**：

- 每次签发（`POST /api/tokens`）建立一个新会话，同时发出该会话的第一对凭证；
  同一用户可并存多个互不影响的会话（手机 / 平板 / 电脑各自一串凭证）。
- 会话存续期间的每次刷新旋转都在**同一家族内**换代，会话元信息
  （最近一次刷新时间、到期时间）随旋转更新；会话到期时间 = 当前刷新凭证的到期时间。
- **结束会话 = 整族吊销**：会话名下已发出的全部凭证（含最近一次旋转换出的新访问凭证）
  立即失效，下一次使用即被拒绝（`REVOKED`）；其它会话的凭证完全不受影响。
- 反向也成立：通过 `/api/tokens/revoke` 吊销某家族任意成员，对应会话同步结束，
  不再出现在会话清单中。

### 4.2 边界与并发语义

- **结束与签发并发**：签发方把“登记会话 + 登记凭证”放在同一家族锁临界区内，
  并在登记后复查会话状态。两种交错只有两种结果：要么签发先完成、随后的结束
  把刚签发的凭证一并吊销（下一次使用即 `REVOKED`）；要么结束先生效、签发以
  `REVOKED` 被拒绝。绝不会出现“清单里已看不到该会话、刚签发的凭证却还能用”，
  也不会出现“结束返回成功但实际未生效”。
- **结束与刷新并发**：结束操作与旋转在家族锁上串行化。要么旋转先完成、随后整族
  （含刚换出的新凭证）被吊销；要么结束先生效、旋转以 `REVOKED` 被拒绝。
  两种交错下都不会出现“会话已结束却仍返回一对可用新凭证”，也不会出现“结束未生效”。
  结束操作一旦返回，该会话名下所有凭证（含旧凭证）的下一次使用必被拒，
  不存在“结束刚返回、旧凭证短暂还能用”的窗口。
- **结束不存在的会话**：如实返回 `SESSION_NOT_FOUND`（404），不当作成功；
  重复结束同一会话同样报错。按用户整体下线是幂等语义，返回实际结束的会话数（可为 0）。
- **会话数上限**：每用户同时存在的有效会话数由
  `governance.session.max-active-per-subject` 配置（默认 5）。到上限时签发被
  `SESSION_LIMIT_EXCEEDED`（409）**明确拒绝**，不会悄悄挤掉旧会话，也不会无限增长；
  结束或自然到期的会话会释放名额。
- **重放检测**：刷新凭证被消费时记录消费时刻。同一凭证在**重放宽窗口**
  （`governance.token.replay-grace-millis`，默认 10 秒）**之后**再次出现，
  判定为事后重放（疑似泄露）：整个会话立即作废——包括上一次旋转换出的、看起来还很新的
  访问凭证——并返回 `REPLAY_DETECTED`（409），与 `NOT_FOUND` / `WRONG_TYPE` /
  `EXPIRED` / `ALREADY_CONSUMED` 明确区分。宽窗口**之内**的再次使用视为并发抢输，
  仍报 `ALREADY_CONSUMED`，不株连会话；并发下同一张刷新凭证仍然最多成功一次。

### 4.3 兼容范围

- 老调用方式完全可用：`POST /api/tokens` 只传 `subject` 时照常签发，
  自动归入来源标识为 `default` 的会话；`TokenService.issue(subject)` 等
  原有 Java 调用方式行为不变。
- 会话清单只暴露 `sessionId` 与元信息（来源、建立时间、最近刷新、到期情况），
  **绝不返回凭证本身**。

### 4.4 本地验证

```bash
mvn test          # 全部用例（含 SessionServiceTest 的 13 个会话场景）
mvn spring-boot:run
# 然后按 2.6 节的 curl 示例走一遍：签发（带 device）→ 查清单 → 单独下线 → 全部下线
```

并发与重放类行为由自动化测试稳定复现，日志会打印每个用例的输入与判定依据：

- `SessionServiceTest#end_all_racing_issue_never_leaves_usable_tokens` /
  `end_single_session_racing_issue_never_leaves_usable_tokens`：
  用插闩注册表把“会话已登记、凭证未登记”的窗口固定下来，确定性验证结束与签发竞态；
- `SessionServiceTest#issue_and_end_all_stress_invariant`：100 轮并发签发/全部下线压测；
- `SessionServiceTest#end_session_racing_rotate_never_leaves_usable_tokens`：
  100 轮结束/旋转竞态；
- `SessionServiceTest#replayed_refresh_kills_whole_session_including_rotated_tokens` /
  `consumed_within_grace_window_is_not_treated_as_replay`：事后重放株连会话、
  宽窗口内不误判；
- `TokenServiceTest`：16 线程并发刷新仅 1 次成功、100 轮旋转/吊销竞态。

---

## 5. 授权判定规则

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

## 6. 测试

测试位于 `src/test/java/.../tests`，均在日志中打印输入与判定依据：

| 测试类 | 覆盖场景 |
| --- | --- |
| `TokenServiceTest` | 并发刷新（16 线程仅 1 成功）、重放、不存在、过期、**时钟偏差边界**、整族吊销、**100 轮旋转/吊销竞态** |
| `SessionServiceTest` | 多会话并存与独立旋转、老调用方式默认会话、清单不暴露凭证、单独结束会话、按用户全部下线、结束不存在会话报错、**重放后新凭证连带失效**、宽窗口内不误判、**100 轮结束/旋转竞态**、**结束/签发竞态（插闩确定性复现 + 100 轮压测）**、会话数上限拒绝与释放 |
| `AuthorizationServiceTest` | 角色+属性合取、显式拒绝优先、默认拒绝、冲突拒绝、主体缺失、权限调整即时生效 |
| `AccessGuardTest` | 凭证校验 + 实时授权端到端联动、吊销/降权/提权即时生效 |
| `HttpApiIntegrationTest` | HTTP 全流程：签发、刷新、重放 409、不存在 404、默认拒绝、吊销 403、会话清单/单会话下线/全部下线、会话上限 409 |

```bash
mvn test
```

---

## 7. 代码结构

```
src/main/java/com/github/h3yow/tokengovernancejava
├── token/                 # 凭证生命周期
│   ├── Token.java          # 凭证实体（AtomicReference 状态 + CAS + 消费时刻）
│   ├── TokenService.java   # 签发/旋转/校验/吊销（并发安全、家族锁、重放检测）
│   ├── TokenState / TokenType / RejectionReason
│   └── TokenException / TokenPair / AccessValidation
├── session/               # 登录会话（设备）管理
│   ├── LoginSession.java   # 会话实体（id 即 familyId，一次性 ACTIVE->ENDED）
│   ├── SessionRegistry.java# 会话注册表（按用户索引、上限校验、原子结束）
│   ├── SessionService.java # 清单查看 / 单会话下线 / 按用户全部下线
│   └── SessionView / SessionState / SessionRejection / SessionException
├── authz/                 # 授权判定
│   ├── PolicyRule.java     # 规则 + 合取匹配
│   ├── AuthorizationService.java  # 求值 + 拒绝优先/默认拒绝/冲突拒绝 + trace
│   ├── SubjectDirectory / PolicyRepository  # 实时主体状态 / 规则仓库
│   ├── AccessGuard.java    # 凭证校验 + 授权判定 串联
│   └── AuthorizationDecision / DecisionTrace / DecisionCode / Effect
├── web/                    # REST 接口与统一异常映射
└── config/                 # Spring 装配（TTL、时钟偏差）与演示数据
```
