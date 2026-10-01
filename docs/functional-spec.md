# hush-hush 功能规格（基于 Go 版实现整理）

本文描述 Go 版**当前实际行为**，作为 Workers + D1 重写的唯一依据。与语言无关；每一条都能在 Go 源码中找到对应（括号内为文件）。如果重写与本文有出入，以本文为准，并在 [workers-migration.md](workers-migration.md) 的"已知差异"中登记。

## 1. 产品定位

自托管的个人 secret 存储：一个 HTTPS API + 管理 Web UI。一个 owner（持 admin token）加若干 agent（持受限 token）。服务端存储的是密文；每次访问都记入审计日志。

组成部分：

| 组件 | 位置 | 与重写的关系 |
|---|---|---|
| 服务端 API | `main.go` `auth.go` `tokens.go` `admin.go` `audit.go` | **重写** |
| 管理 UI（原生 JS，无构建） | `ui/` | **原样复用** |
| 服务端管理 CLI（`token` / `audit` / `backup` / `audit-prune` / `healthcheck`） | `cli.go` `audit_cli.go` `maint.go` `healthcheck.go` | 无本地 DB 文件，需用别的方式替代 |
| 客户端 CLI `hush`（get/put/list/delete/init/migrate） | `cmd/hush/` | **不改**，只依赖 HTTP 契约 |

## 2. 数据模型（SQLite，`store.go`）

最终 schema（5 个迁移合并后）：

```sql
secrets   (name TEXT PRIMARY KEY, ciphertext BLOB NOT NULL, nonce BLOB NOT NULL,
           created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)

tokens    (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, token_hash BLOB NOT NULL UNIQUE,
           role TEXT NOT NULL CHECK (role IN ('admin','agent')),
           prefixes TEXT NOT NULL DEFAULT '[]',        -- JSON 数组，读前缀
           write_prefixes TEXT NOT NULL DEFAULT '[]',  -- JSON 数组，只创建前缀
           revoked_at INTEGER, expires_at INTEGER, created_at INTEGER NOT NULL, last_used_at INTEGER)

audit_log (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, token_name TEXT NOT NULL DEFAULT '',
           action TEXT NOT NULL, secret_name TEXT NOT NULL DEFAULT '', result TEXT NOT NULL,
           request_id TEXT NOT NULL DEFAULT '', remote_addr TEXT NOT NULL DEFAULT '')
           -- 索引: (ts) (token_name, ts) (secret_name, ts)
```

所有时间为 Unix 秒。迁移 5 的含义：admin token 必须在 90 天内过期（存量数据回填，新库无需）。

## 3. 配置（环境变量，`config.go`）

| 变量 | 含义 | 默认 |
|---|---|---|
| `MASTER_KEY` / `MASTER_KEY_FILE` | base64（标准、带填充）编码的 32 字节主密钥；二选一，同时设置报错 | 必填 |
| `RATE_LIMIT_PER_MINUTE` | 已认证 token 的限流 | 60 |
| `UNAUTH_RATE_LIMIT_PER_MINUTE` | 认证失败请求的按 IP 限流 | 10 |
| `TRUSTED_PROXIES` | 信任 `X-Forwarded-For` 的上游网段（拒绝 `0.0.0.0/0`） | 空 |
| `ADMIN_API` | 关闭则整个 `/v1/admin/*` 与 Web UI 不存在 | true |
| `DB_PATH` `LISTEN_ADDR` | SQLite 路径 / 监听地址 | `./hush.db` `127.0.0.1:8080` |

启动时：主密钥非法 → 拒绝启动；没有活跃 token → 警告；7 天内到期的 admin token → 警告。

## 4. 加密（`main.go`）

- 算法 AES-256-GCM，随机 12 字节 nonce，每次写入重新生成。
- AAD = `0x01 || name(UTF-8)`：绑定 secret 名与版本，防止密文换行/降级。
- 存储：`ciphertext = 0x01 || Seal(plaintext)`（Seal 输出为 `密文||16字节tag`），`nonce` 单独存一列。
- 读取时：长度为 0 → 500 `decrypt failed`；版本字节不是 0x01 → 500；解密失败 → 500。
- 响应从不返回密文或 nonce。
- 客户端 v2 加密（`hush init`）对服务端透明：值是 `hh2:base64...` 的不透明字符串，服务端照常再加密一层。

## 5. Token 与授权（`auth.go` `tokens.go`）

**Token 格式**：`hush_` + 64 位小写十六进制（32 随机字节）。库里只存 SHA-256；用 hash 查询，然后再用常量时间比较一次。

**两种角色**

| | admin | agent |
|---|---|---|
| 读 | 全部 | 仅名称以 `prefixes` 之一开头；`["*"]` 表示全部 |
| 写（PUT） | 全部，可覆盖 | 仅名称以 `write_prefixes` 之一开头，**只能创建不能覆盖**，覆盖得 409 |
| 删除 | 允许 | 禁止（403） |
| 管理 API | 允许 | 禁止（403） |
| 过期 | **必须**设置，≤90 天 | 可选 |

**认证失败**一律同一结果（401）：无头、不是 `Bearer `、token 为空、未知、已吊销、已过期、role 非法、admin 无过期时间、前缀 JSON 损坏（失败即拒绝，不放宽权限）。

**成功认证后**异步性质的副作用：更新 `last_used_at`（失败只告警，不影响请求）。

**前缀语法**：`^[a-zA-Z0-9_.-]{1,127}[._]$`，必须以 `.` 或 `_` 结尾（防止 `llm.` 匹配 `llmx.key`）。每次使用时重新校验存储的前缀，防止手改库而放宽权限。

**授权校验（`validateGrants`）**：
- admin：不得带任何前缀。
- agent：读前缀与写前缀至少一个；`*` 只能单独出现在读前缀里，**写前缀禁止 `*`**；前缀不得重复；格式必须符合上面的正则。

**其他规则**
- token 名 `^[a-zA-Z0-9_.-]{1,64}$`，**永不复用**（吊销后也不能重名）。
- `*` 读授权必须显式确认（HTTP 里 `confirm_all: true`，CLI 里要重输 token 名）。
- 创建时若写前缀与其他活跃 agent 的写前缀存在包含关系，返回 warnings（不阻止）。
- 吊销永久且立即生效。吊销已吊销的 token 返回 `already_revoked: true`。
- 不能吊销当前请求所使用的 token（409）。

## 6. 请求管线（`audit.go: secretsRoute`）

`/v1/secrets*` 与 `/v1/admin*` 的每个请求都走同一条管线：

1. 构造审计条目：action、request_id、remote_addr；路径里的 `{name}` 仅当匹配 `^[a-zA-Z0-9_.-]{1,128}$` 才写入 `secret_name`（任意客户端字节不会进审计表）。
2. 认证：
   - 失败：消耗**该 IP 的失败认证额度**；额度内 → 401 `unauthorized`；超限 → 429。
   - 成功：消耗**该 token 名的额度**；超限 → 429；否则执行 handler。
3. 响应先缓冲，不直接发出。
4. 根据状态码映射 result 并写**恰好一行**审计（若 handler 已在事务中写过则跳过）。
5. 审计写入失败：对"返回数据的动作"（get / list / token_list / audit_read）→ 500 `audit failed`，数据不外发（fail closed）；其他动作照常返回。
6. 输出一条结构化日志（不含值、不含 token），然后发出缓冲的响应。

**状态码 → result 映射**：<400 `allowed`；401 `unauthenticated`；403 `denied`；404 `not_found`；409 `conflict`；429 `rate_limited`；其他 <500 `bad_request`；≥500 `error`。

**审计 action**：`get list put delete other token_list token_create token_update token_revoke audit_read whoami`。

**写操作与审计原子**：成功的 PUT / DELETE / 管理变更，其数据变更与 "allowed" 审计行在同一事务提交；没有审计上下文则拒绝提交。

## 7. 限流（`ratelimit.go`）

- 令牌桶：容量 = 每分钟额度，补充速率 = 额度/60 每秒；初始为满。
- 两个限流器：按 token 名（已认证），按客户端 IP（仅认证失败时消耗）。
- IPv6 按 /64 归并；IPv4 与 `unknown` 原样。
- 超限响应：429 `{"error":"rate_limited"}` + `Retry-After`（向上取整的秒，最小 1）。
- 内存存储，重启清空；桶数封顶 10000，满时对新 key 拒绝（fail closed）。

## 8. 客户端 IP（`audit.go: clientIP`）

只有直连对端属于 `TRUSTED_PROXIES` 时才相信 `X-Forwarded-For`，且只取**最右一项**；该项不是合法 IP 则回退到对端地址。无法得到 → `unknown`。

## 9. HTTP API 契约

通用：JSON 响应带 `Content-Type: application/json`、`Cache-Control: no-store`；错误体 `{"error":"msg"}`；每个响应带 `X-Request-ID`（合法的入站值原样回显，规则 `^[a-zA-Z0-9_-]{1,128}$`，否则随机 16 hex）。

### 9.1 `GET /healthz`
无认证、不审计、不限流。`200 {"status":"ok"}`。

### 9.2 `GET /v1/secrets`
- 权限：admin 全部；agent 按读前缀；无任何授权 → `{"secrets":[]}`。
- 前缀过滤在 SQL 里做（`LIMIT` 作用于可见集合），用 `substr(name,1,n)=prefix`，不用 `LIKE`（`_` 是通配符）。
- 按 name 升序，上限 1000。
- `200 {"secrets":[{"name","created_at","updated_at"}]}`（不含 value）。

### 9.3 `GET /v1/secrets/{name}`
校验顺序：name 非法 → 400 `invalid name`；无读权限 → **403**（无论该名是否存在，防探测）；不存在 → 404；解密失败 → 500。
`200 {"name","value","created_at","updated_at"}`。

### 9.4 `PUT /v1/secrets/{name}`
校验顺序（前面的先生效）：
1. 权限门：admin 通过；agent 仅当 `canCreate(name)`（含 name 格式合法 + 命中写前缀），否则 403。在解析 body 与访问 DB 之前。
2. name 非法 → 400 `invalid name`
3. Content-Type 不是 `application/json`（忽略大小写与参数）→ 415
4. body 超过 65536+1024 字节 → 413 `request body too large`
5. JSON 严格解析：未知字段、类型不符、body 尾部多余内容 → 400
6. `value` 为空 → 400 `value required`
7. `value` 超过 65536 **字节**（UTF-8）→ 413 `value too large`
8. 写入：admin 为 upsert（保留 `created_at`，更新 ciphertext/nonce/updated_at）；agent 为"仅插入"，已存在 → 409 `already exists`，单条 SQL 完成，无检查-插入竞态。

`200 {"name","created_at","updated_at"}`。

### 9.5 `DELETE /v1/secrets/{name}`
仅 admin（agent 403，先于一切解析）。name 非法 → 400。**幂等**，不区分"已删除"与"本来不存在"，`204`。

### 9.6 其余 `/v1/secrets*`
先认证、限流、审计，再回应：`/v1/secrets` 的非 GET 方法 → 405 + `Allow: GET`；`/v1/secrets/{单段非空}` 的其他方法 → 405 + `Allow: GET, PUT, DELETE`；多段或空 → 404。（所以未认证者无法借此探测路径。）

### 9.7 管理 API（仅 `ADMIN_API=true`，全部要求 admin）

| 端点 | action | 行为 |
|---|---|---|
| `GET /v1/admin/me` | whoami | `{name, role, expires_at}`，UI 用来提示 token 即将过期 |
| `GET /v1/admin/tokens` | token_list | `{tokens:[{name,role,prefixes,write_prefixes,status,expires_at,last_used_at,revoked_at,created_at}]}`，按名排序，**永不含 hash**；status = active / revoked / expired |
| `POST /v1/admin/tokens` | token_create | body `{name, role, prefixes, write_prefixes, expires, confirm_all}`；`expires` 形如 `90d`、`12h`，空 = 不过期（admin 必须有）。`201 {name, token, warnings}`，**明文只出现这一次** |
| `PATCH /v1/admin/tokens/{name}` | token_update | body `{prefixes?, write_prefixes?, confirm_all}`；字段缺失 = 保持，`[]` = 清空；两者都缺 → 400；仅 active 的 agent token；`200 {name, prefixes, write_prefixes, warnings}` |
| `DELETE /v1/admin/tokens/{name}` | token_revoke | `200 {name, revoked:true, already_revoked}`；自吊销 → 409；不存在 → 404 |
| `GET /v1/admin/audit` | audit_read | 过滤 `token secret action result since until limit`，`{records:[{ts,token_name,action,secret_name,result,remote_addr,request_id}]}`，新到旧，默认 100，最大 10000 |
| 其他 `/v1/admin/*` | other | 认证 + admin 后 404 |

错误映射：token 已存在 / 已吊销 / 非 agent → 409（带原因文案）；找不到 → 404；非法授权 → 400（带原因文案）；其余 500 `db error`（不回显细节）。

管理 body 约束同 PUT：JSON content-type、≤16 KiB、禁止未知字段、禁止尾随数据。

时间过滤 `since`/`until`：先尝试整数 Unix 秒，再 RFC3339，再"多久以前"（`24h`/`7d`）。`since` 含、`until` 不含，`since < until`。`expires` 与"多久以前"接受 Go duration（`90m`、`12h`）加整数 `d` 后缀，必须为正。

### 9.8 Web UI
- `GET /` → 302 `/ui/`；`GET /ui/*` 静态文件（仅 `ADMIN_API=true`）。
- 响应头：严格 CSP（`default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`）、`X-Frame-Options: DENY`、`nosniff`、`Referrer-Policy: no-referrer`、`COOP: same-origin`、`Cache-Control: no-store`。
- UI 用粘贴的 admin token 登录，token 存在 sessionStorage，用 Bearer 头调用上面的 API，因此没有 cookie、没有 CSRF 面。UI 只用到 `/v1/secrets*` 与 `/v1/admin/{me,tokens,audit}`，路径全是相对的。

## 10. 管理 CLI（Go 版直接操作 DB 文件）

`token create|list|revoke|update`、`audit`（同 9.7 过滤）、`backup`（`VACUUM INTO`，可流式到 stdout）、`audit-prune --older-than 180d`、`healthcheck`。业务规则与 HTTP 管理 API **共用同一份代码**，所以两个入口一致。CLI 的独有价值是：**服务端还没有任何 token 时用来引导第一个 admin token**，以及不依赖 HTTP 的备份与清理。

## 11. 安全属性清单（重写必须保持）

1. 值与 token 明文永不进日志、审计、错误信息。
2. 无权限一律 403，不泄露名称是否存在。
3. 认证失败原因不可区分。
4. 写操作与其审计行原子；读操作在审计写失败时不外发数据。
5. 存储的授权数据每次使用前重新校验，损坏即拒绝。
6. 管理 token 强制过期；`*` 授权需显式确认；写前缀禁用 `*`。
7. 限流：认证失败按 IP、成功按 token；IPv6 归 /64。
8. 响应一律 `no-store`；UI 严格 CSP。
9. 客户端 IP 只信任受信代理，并只取最右一项。
