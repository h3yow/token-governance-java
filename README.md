# 本地访问凭证签发、刷新与权限判定

一套纯内存、本地可运行的访问凭证（Access Token）/刷新凭证（Refresh Token）
生命周期管理与授权判定实现。目标是让**凭证生命周期**与**授权结论**在并发与
状态变更下保持确定、可解释：

- 同一刷新凭证并发使用至多成功一次，其余请求被明确拒绝且原因可区分；
- 授权判定同时考虑角色与属性，显式拒绝优先、默认拒绝、冲突不放行；
- 吊销与权限调整对后续访问立即生效；容忍轻微时钟偏差，且吊销/刷新竞态下无越权窗口。

## 1. 模块结构

```
credential/   凭证签发、旋转、吊销、解析（HMAC-SHA256 签名，内存存储）
authz/        主体目录、策略仓库、判定引擎、授权网关（凭证→主体→判定）
web/          本地演示 REST 接口与统一错误映射
config/       时钟/凭证参数装配 + 演示种子数据
```

## 2. 凭证生命周期

### 2.1 签发 `POST /api/tokens/issue`

为主体签发一对凭证：

- **访问凭证**：默认 10 分钟有效，`HMAC-SHA256` 防篡改；
- **刷新凭证**：默认 8 小时有效，**一次性**；
- 凭证载荷包含 `subjectId / familyId / version / jti / exp`。

其中：

- `familyId`（凭证族/会话）：同一会话内的每次旋转共享吊销状态；
- `version`：签发时主体的**权限版本**。主体角色/属性每调整一次版本号 +1，
  旧版本凭证在授权时立即失效（刷新不会提升版本，防止"刷新即提权"）。

### 2.2 刷新旋转 `POST /api/tokens/refresh`

请求体 `{"refreshToken": "..."}`，成功则旧刷新凭证立即作废，返回全新凭证对。

服务端按以下**确定顺序**检查，拒绝原因通过错误类型明确区分：

| 顺序 | 情况 | 错误类型 `CredentialErrorType` |
|---|---|---|
| 1 | 凭证无法识别/签名错误/类型不对 | `REFRESH_TOKEN_NOT_FOUND` |
| 2 | 凭证族已吊销 | `SESSION_REVOKED` |
| 3 | 刷新凭证此前已成功消费（重放） | `REFRESH_TOKEN_CONSUMED` |
| 4 | 已过期（超出时钟偏差窗口） | `REFRESH_TOKEN_EXPIRED` |

**一次性保证（并发安全）**：每个刷新凭证对应一个 `AtomicBoolean`，
消费动作是 CAS（compare-and-set），因此 N 个并发请求恰好 1 个成功。

**重放检测**：CAS 落败说明旧凭证被再次出示（可能被盗），服务端立即吊销
整个凭证族。CAS 落败者得到 `REFRESH_TOKEN_CONSUMED`，随后到达的请求得到
`SESSION_REVOKED`——拒绝原因始终可区分。

### 2.3 吊销

- `POST /api/tokens/revoke-family`，请求体 `{"familyId": "..."}`：吊销单个会话；
- `POST /api/subjects/{id}/revoke`：吊销该主体全部会话。

吊销与刷新在**同一个凭证族对象锁上原子执行**，因此两种竞态顺序都安全：

- 刷新先提交：旋转出的新凭证仍属于同一会话，吊销立即覆盖它；
- 吊销先提交：刷新被拒绝。不存在"刚旋转出来就越权"的时间窗。

### 2.4 访问凭证校验与时钟偏差

判定访问凭证时依次检查：会话存在 → 会话未吊销 → 未过期。

过期判定为：

```
now > exp + clockSkewLeeway   （默认 leeway = 30s）
```

判本地时钟比签发端快 30 秒以内时，有效凭证不会被误判为过期；
超过容忍窗口才返回 `ACCESS_TOKEN_EXPIRED`。其他错误归类：

| 情况 | 错误类型 |
|---|---|
| 格式非法/签名错误 | `ACCESS_TOKEN_MALFORMED` |
| 过期（超出 leeway） | `ACCESS_TOKEN_EXPIRED` |
| 会话吊销/因重放被清除 | `ACCESS_TOKEN_REVOKED` |

## 3. 授权判定规则

入口：`POST /api/authorize`，访问凭证放在 `Authorization: Bearer <token>` 头，
请求体 `{"action": "document:read", "resource": "docs/a.txt"}`。
主体身份**只取自凭证**，请求方无法通过请求体伪造 subjectId。

### 3.1 判定依据（角色 + 属性）

每条规则包含：依据类别（`ROLE` / `ATTRIBUTE`）、效果（`ALLOW` / `DENY`）、
动作、资源、角色名或属性键值：

- 动作：精确匹配或 `*`；
- 资源：精确串、`*`、或 `docs/*` 形式前缀；
- 角色规则：主体具备该角色即适用；
- 属性规则：主体具备该属性（且值相等，或仅要求属性存在）即适用。

一条规则同时满足"动作/资源匹配"且"角色或属性条件满足"才算适用。

### 3.2 结论合成（确定、可解释）

1. 收集**全部**适用规则；
2. 存在任意显式拒绝规则 → 拒绝（**显式拒绝优先于允许**）；
3. 允许与拒绝规则同时命中 → 仍拒绝，并额外给出 `CONFLICT_DENY_WINS` 依据；
4. 只有允许规则 → 允许；
5. 没有任何适用规则 → 默认拒绝（`NO_APPLICABLE_RULE`），**绝不静默放行**。

每个 `Decision` 都带 `reasons` 依据链（规则 ID、类别、命中细节）。

### 3.3 状态变更即时生效

每次授权都实时执行：

1. 校验访问凭证（签名/过期/吊销）；
2. 从主体目录读取**当前**角色、属性与版本；主体被删除 → `SUBJECT_MISSING`；
   凭证版本落后于当前版本 → `CREDENTIAL_INVALID`（旧凭证失效）；
3. 用最新状态做策略判定。

主体目录的"读取-修改-版本 +1"由 `ConcurrentHashMap.compute` 原子完成，
因此吊销、角色/属性调整对下一次访问必然生效。

## 4. 本地验证

需要 JDK 21+ 与 Maven。

```bash
# 全部单测（并发刷新/重放、吊销竞态、时钟偏差、引擎、网关）
mvn test

# 启动演示服务
mvn spring-boot:run
```

启动时已种子化主体与规则：

- `alice`：角色 `editor`，属性 `department=engineering`；
- `bob`：角色 `viewer`，属性 `region=restricted`（命中允许角色规则，
  同时命中 restricted 显式拒绝属性规则 → 冲突时拒绝优先）。

端到端手工验证：

```bash
# 1) 为 alice 签发凭证
TOKEN=$(curl -s -X POST localhost:8080/api/tokens/issue \
  -H 'Content-Type: application/json' -d '{"subjectId":"alice"}')
AT=$(echo "$TOKEN" | python3 -c 'import sys,json;print(json.load(sys.stdin)["accessToken"])')
RT=$(echo "$TOKEN" | python3 -c 'import sys,json;print(json.load(sys.stdin)["refreshToken"])')
FAM=$(echo "$TOKEN" | python3 -c 'import sys,json;print(json.load(sys.stdin)["familyId"])')

# 2) 授权判定 -> allowed=true，reasons 给出命中的允许规则
curl -s -X POST localhost:8080/api/authorize \
  -H "Authorization: Bearer $AT" -H 'Content-Type: application/json' \
  -d '{"action":"document:read","resource":"docs/a.txt"}'

# 3) 并发刷新：只有一次成功，其余返回 CONSUMED / REVOKED
for i in $(seq 1 8); do
  curl -s -X POST localhost:8080/api/tokens/refresh \
    -H 'Content-Type: application/json' -d "{\"refreshToken\":\"$RT\"}" &
done; wait

# 4) 吊销后再访问 -> allowed=false，原因 CREDENTIAL_INVALID（会话已吊销）
curl -s -X POST localhost:8080/api/tokens/revoke-family \
  -H 'Content-Type: application/json' -d "{\"familyId\":\"$FAM\"}"
curl -s -X POST localhost:8080/api/authorize \
  -H "Authorization: Bearer $AT" -H 'Content-Type: application/json' \
  -d '{"action":"document:read","resource":"docs/a.txt"}'

# 5) 权限调整后旧凭证立即失效
curl -s -X POST localhost:8080/api/subjects/alice/permissions \
  -H 'Content-Type: application/json' \
  -d '{"roles":[],"attributes":{"department":"engineering"}}'
```

## 5. 测试覆盖

| 测试类 | 场景 |
|---|---|
| `CredentialServiceTest` | 签发/解析、刷新重放归类、未知/过期/吊销刷新、整主体吊销、时钟偏差内有效/超窗过期、伪造凭证 |
| `ConcurrentRefreshTest` | 32 线程并发同一刷新凭证恰好 1 次成功；刷新与吊销并发无越权 |
| `AuthorizationEngineTest` | 角色允许、属性允许、显式拒绝覆盖允许、冲突 `CONFLICT_DENY_WINS`、缺规则默认拒绝、资源前缀、属性分级 |
| `AuthorizationGatewayTest` | 端到端放行/拒绝、吊销即时生效、权限版本变更旧凭证失效、刷新不抬权、授权即时生效、主体删除、非法凭证 |

测试用 SLF4J 打印**输入参数（角色/属性/动作/资源/凭证族）与判定依据链**，
错误用例同时打印期望与实际的 `CredentialErrorType`。
