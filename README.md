# Token Governance（访问凭证签发 / 刷新旋转 / 权限判定）

一套**本地可运行**的访问凭证生命周期与授权判定实现。目标是让凭证状态与授权结论，
在**并发**与**运行时状态变更**下保持**确定、可解释**。

- 凭证：访问凭证（Access Token）+ 刷新凭证（Refresh Token），内存存储。
- 刷新旋转：同一刷新凭证并发使用**最多成功一次**；已消费 / 已过期 / 已吊销均被拒绝，且原因可区分。
- **登录会话（设备）管理**：同一用户可在手机、平板、电脑等多个会话上并存；可查会话清单、单独下线某台设备或一次下线全部设备；会话结束后名下所有凭证（含刚旋转换出的访问凭证）立即失效。
- **刷新重放按会话泄露处理**：一张已用过的刷新凭证在旋转收尾之后再次出现，判定为会话泄露，整个会话（含看似很新的访问凭证）立即作废，并返回与“不存在 / 类型错误 / 过期 / 并发抢输”都不同的原因码。
- 授权判定：同时考虑**角色**与**属性**；显式拒绝优先、默认拒绝；规则缺失或冲突绝不静默放行，并返回逐条依据。
- 状态即时生效：吊销、会话结束或权限调整后，**下一次访问**即按最新状态判定。
- 时钟偏差：在可配置容忍窗口内不把有效凭证误判为过期；吊销是硬状态，先于过期判定，杜绝吊销竞态越权。

---

## 1. 技术栈与运行

- Java 21+、Spring Boot 3.4.x、JUnit 5。
- 无需数据库 / 外部中间件，全部状态在内存。
- 可配置项（`src/main/resources/application.properties`，也可用命令行覆盖）：
  - `token-governance.max-sessions-per-subject`：每用户有效登录会话数上限，默认 `5`。

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
| POST | `/api/tokens` | 为 `subject` 签发一对新凭证（可带 `deviceLabel` 标识设备/来源） |
| POST | `/api/tokens/refresh` | 用刷新凭证旋转出一对新凭证；事后重放按会话泄露作废整个会话 |
| POST | `/api/tokens/revoke` | 吊销凭证（自动识别 access/refresh），整族失效 |
| GET | `/api/sessions?subject=` | 查询某用户当前有效会话清单（仅元信息，不含凭证） |
| POST | `/api/sessions/end` | 结束单个会话（`sessionId`），名下凭证立即失效 |
| POST | `/api/sessions/end-all` | 结束某用户全部会话（`subject`） |
| POST | `/api/check` | 校验访问凭证并做授权判定，返回结论与逐条依据 |
| POST | `/api/admin/roles` | 运行时调整主体角色（即时生效） |
| POST | `/api/admin/attributes` | 运行时调整主体属性（即时生效） |

### 2.1 签发

老客户端只传 `subject` 即可，行为与历史完全一致，按一个**默认设备会话**（`deviceLabel="default"`）处理：

```bash
curl -s -X POST localhost:8080/api/tokens \
  -H 'Content-Type: application/json' \
  -d '{"subject":"alice"}'
# => {"accessToken":"...","refreshToken":"...","accessExpiresAt":...,"refreshExpiresAt":...,"sessionId":"..."}
```

多设备登录时带上设备/来源标识，每台设备得到一个独立会话：

```bash
curl -s -X POST localhost:8080/api/tokens \
  -H 'Content-Type: application/json' \
  -d '{"subject":"alice","deviceLabel":"phone"}'
```

响应额外携带 `sessionId`（即该会话刷新家族 id），用于查看与下线；老客户端忽略该字段即可。

### 2.2 会话（设备）管理

```bash
# 查看 alice 当前还有哪些有效会话（只返回标识与元信息，不返回任何凭证）
curl -s 'localhost:8080/api/sessions?subject=alice'
# => {"subject":"alice","count":2,"sessions":[
#       {"sessionId":"...","subject":"alice","deviceLabel":"phone",
#        "createdAt":...,"lastRefreshedAt":...,"expiresAt":...}, ...]}

# 单独下线某一台设备：该会话名下所有凭证立即失效，其它设备不受影响
curl -s -X POST localhost:8080/api/sessions/end \
  -H 'Content-Type: application/json' -d '{"sessionId":"<phone 的 sessionId>"}'

# 一次下线某用户的全部会话
curl -s -X POST localhost:8080/api/sessions/end-all \
  -H 'Content-Type: application/json' -d '{"subject":"alice"}'
# => {"subject":"alice","ended":2}
```

边界行为：

- 结束**不存在或已结束**的会话返回 `404 SESSION_NOT_FOUND`，不会被当成成功。
- 每用户有效会话数有上限（默认 5，可用 `token-governance.max-sessions-per-subject` 配置）；
  到上限时签发返回 `409 SESSION_LIMIT_REACHED`，**明确拒绝**，既不悄悄挤掉旧会话，也不会无限增长。
  已结束 / 已自然到期的会话不再占用名额；结束一个会话或等其到期后即可在新设备登录。

### 2.3 刷新旋转

```bash
curl -s -X POST localhost:8080/api/tokens/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refreshToken":"<上一步的 refreshToken>"}'
```

- 多个请求**并发**抢同一张刷新凭证：只有一次成功，其余得到 `409 ALREADY_CONSUMED`（第一次并发抢输，不作废会话）。
- 旋转**收尾之后**（相隔一个很短的并发宽限窗口，见 §3.2）同一张已消费刷新凭证再次出现：
  判定为会话泄露，整个会话立即作废，返回 `401 REPLAY_DETECTED`。

### 2.4 授权判定（返回可解释依据）

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

### 2.5 运行时调整权限（即时生效）

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

### 2.6 吊销（整族即时失效）

```bash
curl -s -X POST localhost:8080/api/tokens/revoke \
  -H 'Content-Type: application/json' \
  -d '{"token":"<accessToken 或 refreshToken>"}'
# 之后该旋转家族内的所有 access / refresh 立即不可用，/api/check 返回 403 REVOKED
```

### 2.7 错误码（拒绝原因可区分）

凭证类错误通过 HTTP 状态码 + `error` 字段双重区分：

| error 码 | HTTP | 含义 |
| --- | --- | --- |
| `NOT_FOUND` | 404 | 凭证不存在 |
| `WRONG_TYPE` | 404 | 凭证类型用错（拿 access 当 refresh 等） |
| `EXPIRED` | 410 | 已过期（且已超出时钟偏差容忍窗口） |
| `REVOKED` | 403 | 已被吊销（含整族/会话连带） |
| `ALREADY_CONSUMED` | 409 | 刷新凭证已被消费：**第一次并发使用抢输**（不作废会话） |
| `REPLAY_DETECTED` | 401 | 旋转收尾后再次出现的刷新凭证：**会话泄露重放**，整个会话已作废 |
| `SESSION_NOT_FOUND` | 404 | 结束的会话不存在或已结束 |
| `SESSION_LIMIT_REACHED` | 409 | 该用户有效会话数已达上限，签发被拒绝 |

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

- **家族（family）= 会话（session）**：一次签发创建一个登录会话，并为其分配一个
  `familyId`（同时也是 `sessionId`）；之后每次刷新旋转**延续同一族**。吊销任意成员或结束
  该会话即把整族置为 `REVOKED`，实现“结束一次，整条刷新链与同族访问凭证一起失效”。
- **旋转原子性**：刷新凭证状态用 `AtomicReference` 保存，旋转时执行
  `ACTIVE -> CONSUMED` 的 CAS。并发请求中只有一个线程能成功，因此同一刷新凭证
  **最多成功一次**，不会出现两份都有效的凭证。
- **并发抢输 vs 重放（关键区分）**：CAS 抢输的重复提交按进入时机分两类——
  与赢家**真正并发**的首用竞争返回 `ALREADY_CONSUMED`（不惩罚会话）；旋转**收尾之后**
  才出现的重复凭证视为泄露重放，返回 `REPLAY_DETECTED` 并**作废整个会话**
  （含刚旋转换出、看似还很新的访问凭证）。判据见 §3.2。
- **拒绝判定顺序**：`不存在 -> 类型错误 -> 已吊销 -> 已过期`。
  吊销是“硬状态”，优先于过期，避免在临界时刻因过期判断掩盖吊销。
- **旋转 / 吊销 / 结束会话互斥**：同一家族上加锁，旋转“登记新成员”、整族吊销与结束会话互斥；
  旋转在返回新凭证前会复查会话与新成员状态，保证会话刚结束时不会返回一对仍有效的新凭证，
  消除结束/刷新并发下的短暂越权窗口。签发占用名额与“结束全部会话”另在主体级锁上互斥。

### 3.1 登录会话（设备）与凭证生命周期的关系

```
  issue(subject, deviceLabel)
            │  创建会话 Session(ACTIVE) + 首个刷新家族(familyId == sessionId)
            ▼
   ┌──────────────────────────────────────────────┐
   │  SESSION ACTIVE（一个设备）                    │
   │   access/refresh 反复 rotate，始终同族          │
   │   元信息 lastRefreshedAt / expiresAt 随之刷新    │
   └──────────────────────────────────────────────┘
      │ endSession / endAllSessions / 重放作废 / 整族吊销
      ▼
   SESSION ENDED：名下历史所有 access/refresh（含最新一张）立即 REVOKED
```

- 多会话：同一用户多次签发产生多个**互不影响**的会话（设备），各自独立旋转、独立下线。
- 清单：`GET /api/sessions` 只返回**会话标识 + 元信息**（来源、建立时间、最近刷新、到期），
  `SessionInfo` 结构中不包含任何凭证字段。只列出仍有效（ACTIVE 且未到期）的会话。
- 名额：每用户有效会话数有上限（默认 5，可配 `token-governance.max-sessions-per-subject`），
  达上限签发被明确拒绝；已结束/已到期会话不占名额。
- 兼容：不传 `deviceLabel`（或旧的只传 `subject` 的调用）一律归为 `deviceLabel="default"`
  的普通会话；旧的签发/刷新/吊销/判定接口路径与既有字段保持不变，新字段（`sessionId`、
  `deviceLabel`）都是增量。

### 3.2 并发宽限窗口（如何分辨“抢输”与“重放”）

纯软件层面无法分辨“被调度器暂停的并发请求”和“旋转完成后才发出的重放”，因此实现采用
两个判据（见 `TokenService`）：

1. 请求**进入旋转逻辑前**快照该刷新凭证“旋转是否已收尾”（`rotationClosed`）：未收尾 → 并发竞争者；
2. CAS 抢输后，再看距赢家完成消费的**真实时间**（`System.nanoTime()`，与可拨的业务时钟无关）
   是否在 500ms 并发宽限窗口（`CONCURRENT_GRACE_NANOS`）内：在窗口内 → 仍按并发抢输
   `ALREADY_CONSUMED`；超出窗口才确定为事后重放 `REPLAY_DETECTED`。

这保证了高并发/调度抖动下不会把合法的并发请求误判成泄露，而真实攻击者隔了网络与时间
再次提交旧刷新凭证时，整个会话会被可靠作废。

### 3.3 时钟偏差容忍

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
| `TokenServiceTest` | 并发刷新（16 线程仅 1 成功）、**事后重放 REPLAY_DETECTED 连新 access 一并失效**、不存在、过期、**时钟偏差边界**、整族吊销、**100 轮旋转/吊销竞态** |
| `SessionServiceTest` | **多会话并存与清单（仅元信息）、老调用默认会话、单独下线不影响他人、结束全部会话、重放作废整个会话（含刚换出的 access）、24 线程并发重放仍只一份有效、100 轮结束/刷新竞态、会话上限拒绝（不挤旧）、到期释放名额** |
| `AuthorizationServiceTest` | 角色+属性合取、显式拒绝优先、默认拒绝、冲突拒绝、主体缺失、权限调整即时生效 |
| `AccessGuardTest` | 凭证校验 + 实时授权端到端联动、吊销/降权/提权即时生效 |
| `HttpApiIntegrationTest` | HTTP 全流程：签发、刷新、重放 409、不存在 404、默认拒绝、吊销 403；**会话清单/下线、重放 401、SESSION_NOT_FOUND 404、SESSION_LIMIT_REACHED 409** |

运行（仅依赖本机与仓库已有依赖，无外部服务）：

```bash
mvn test
```

想在本地手动验证会话能力：

```bash
mvn spring-boot:run
# 两台设备签发
curl -s -X POST localhost:8080/api/tokens -H 'Content-Type: application/json' \
  -d '{"subject":"alice","deviceLabel":"phone"}'
curl -s -X POST localhost:8080/api/tokens -H 'Content-Type: application/json' \
  -d '{"subject":"alice","deviceLabel":"tablet"}'
# 看清单
curl -s 'localhost:8080/api/sessions?subject=alice'
# 调整上限后再连续签发，可观察 SESSION_LIMIT_REACHED
mvn spring-boot:run -Dspring-boot.run.arguments=--token-governance.max-sessions-per-subject=2
```

---

## 6. 代码结构

```
src/main/java/com/github/h3yow/tokengovernancejava
├── token/                 # 凭证生命周期 + 会话管理
│   ├── Token.java          # 凭证实体（AtomicReference 状态 + CAS + 旋转收尾/消费时刻）
│   ├── TokenService.java   # 签发/旋转/校验/吊销 + 会话清单/单独或全部下线（家族锁、主体锁）
│   ├── TokenState / TokenType / RejectionReason
│   └── TokenException / TokenPair / AccessValidation
├── session/               # 登录会话（设备）
│   ├── LoginSession.java   # 会话聚合：状态 + 来源/建立/最近刷新/到期元信息
│   ├── SessionInfo.java    # 对外清单视图（无凭证字段）
│   ├── SessionState / SessionException / SessionRejectionReason
├── authz/                 # 授权判定
│   ├── PolicyRule.java     # 规则 + 合取匹配
│   ├── AuthorizationService.java  # 求值 + 拒绝优先/默认拒绝/冲突拒绝 + trace
│   ├── SubjectDirectory / PolicyRepository  # 实时主体状态 / 规则仓库
│   ├── AccessGuard.java    # 凭证校验 + 授权判定 串联
│   └── AuthorizationDecision / DecisionTrace / DecisionCode / Effect
├── web/                    # REST 接口（含 /api/sessions*）与统一异常映射
└── config/                 # Spring 装配（TTL、时钟偏差、会话上限）与演示数据
```
