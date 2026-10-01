# Workers + D1 版设计与迁移

目标：把 [functional-spec.md](functional-spec.md) 描述的服务整套跑在 Cloudflare 上（Workers + D1 + Durable Objects），代码在 `worker/`。Go 版保持不动，二者共存。

## 1. 机制映射

| Go 版 | Workers 版 | 说明 |
|---|---|---|
| 静态 Go 二进制 + `net/http` | Worker（TypeScript，无运行时依赖） | 手写路由，保证 404/405/`Allow` 行为与 Go 的 mux 一致；不引入框架，减少供应链面 |
| SQLite 文件 | **D1**（同样是 SQLite） | 表结构与 Go 最终 schema 完全一致，两边的库可互相导入 |
| `database/sql` 事务 | `db.batch([...])` | D1 的 batch 是单个事务，任一语句失败整体回滚 |
| AES-256-GCM（`crypto/cipher`） | Web Crypto `AES-GCM` | 输出同为 `密文‖16 字节 tag`，AAD 与存储格式不变，**与 Go 版密文互通** |
| `MASTER_KEY(_FILE)` | Worker Secret `MASTER_KEY` | 不再支持 `_FILE` |
| 进程内令牌桶 | **Durable Object**（每个 key 一个实例） | Workers 是多实例，进程内存做不了限流；DO 是单线程串行，天然适合令牌桶 |
| `TRUSTED_PROXIES` + `X-Forwarded-For` | `CF-Connecting-IP` | Worker 只能经 Cloudflare 边缘访问，该头由边缘设置，客户端无法伪造；因此不再需要受信代理配置 |
| `//go:embed ui` | Workers Static Assets（`ASSETS` 绑定） | `run_worker_first`，由 Worker 加安全头后再回给浏览器 |
| 管理 CLI（`token` / `audit`） | 管理 HTTP API + UI（已存在）+ 引导脚本 | 见 §3 |
| `backup`（`VACUUM INTO`） | `wrangler d1 export` / D1 Time Travel | 见 §5 |
| `audit-prune` | Cron Trigger（可选，`AUDIT_RETENTION_DAYS`）+ 手动 SQL | 见 §5 |
| `healthcheck` 子命令 | 不需要 | `GET /healthz` 仍在，Cloudflare 自己管进程 |
| 结构化 slog 日志 | `console.log` JSON，Workers Logs 采集 | 字段保持一致 |

## 2. 关键设计决定

### 2.1 原子写 + 审计（对应规格 §6）
Go 在同一事务里 upsert + 写审计。Workers 版用一次 `batch`：

1. `INSERT ... ON CONFLICT ... RETURNING created_at`
2. `INSERT INTO audit_log ... SELECT ... WHERE changes() > 0`

第 2 句用 `changes()` 做条件：agent 的"只创建"撞上已存在时第 1 句什么都没写，第 2 句也不写，这样 409 不会留下一条 "allowed" 记录，随后由管线写 `conflict`。已在测试里验证 D1 的 `changes()` 在 batch 内可用。

### 2.2 读操作 fail closed（规格 §6.5）
与 Go 相同：handler 返回 `Response` 后先写审计，写失败则丢弃该响应，改回 500 `audit failed`。

### 2.3 限流（规格 §7）
- 每个 key（`token:<name>` / `ip:<bucket>`）一个 DO 实例，状态是 `{tokens, last}`，存在 DO storage 里（实例被回收后不丢）。
- 每次请求后设置 alarm，在"桶完全补满"的时刻清空存储，对应 Go 的"丢弃已满的桶"。攻击者喷洒 IP 产生的实例会自行消亡。
- IPv6 按 /64 归并，同 Go。
- **失败策略（有意差异）**：DO 调用异常时**放行并记录错误日志**（fail open）。Go 的内存限流器不会失败；这里若 fail closed，一次 DO 故障就会把所有合法 agent 锁在外面。限流在这里是滥用控制，不是认证边界——token 是 256 位随机数，无法被暴力破解。

### 2.4 请求体读取
Workers 没有 `io.LimitReader`。用流式 reader 读取，累计超过 `maxBodyBytes+1` 立刻 `cancel()`，不会把大 body 读进内存。

### 2.5 D1 的限制与应对
- 单条语句最多 100 个绑定参数。`list` 对 agent 的前缀过滤每个前缀占 1 个参数（前缀长度作为整数字面量内联，值仍绑定），再加上 `LIMIT`。因此新增校验：**每个 token 的读前缀 ≤ 64 个**（Go 版无此限制）。
- BLOB 以 `ArrayBuffer` 读写。
- D1 没有跨请求的读后写事务，`token update` 是"先读再 batch 写"，两个管理员同时改同一个 token 的授权可能后者覆盖前者。单人场景可接受（Go 版靠 SQLite 写锁避免了这点）。

### 2.6 配置
- `MASTER_KEY`：必须是标准 base64、带填充、解码后 32 字节。非法时 API 路由返回 500 `server misconfigured` 并记录错误（Go 是拒绝启动；Worker 没有启动阶段）。`/healthz` 不受影响。
- `wrangler.jsonc` 的 `vars`：`RATE_LIMIT_PER_MINUTE`、`UNAUTH_RATE_LIMIT_PER_MINUTE`、`ADMIN_API`、`AUDIT_RETENTION_DAYS`（新增，可选）。

## 3. 引导（没有 CLI 之后怎么创建第一个 admin token）

Go 版靠 `docker exec ... token create` 直接写库。Workers 上没有"本地库文件"，所以：

- `scripts/bootstrap-admin.mjs`：在本机生成 token，计算 SHA-256，通过 `wrangler d1 execute` 把 **只含 hash 的一行** 插进 D1，明文只打印一次。必须带过期时间（≤90 天），与规则一致。
- 之后所有 token 管理都在 Web UI / 管理 API 里完成。

威胁说明：明文 token 只在你本机终端出现；hash 通过 Cloudflare API 传输，用的是你的 wrangler 登录凭证。

## 4. 与 Go 版的已知差异

| # | 差异 | 原因 / 影响 |
|---|---|---|
| 1 | JSON 体有多余内容或非法时，统一返回 400 `invalid json`（Go 对"尾随数据"返回 `trailing data after json`） | 状态码相同，仅文案不同；`JSON.parse` 不暴露前缀边界 |
| 2 | 读前缀数量上限 64 | D1 绑定参数上限 |
| 3 | 限流 DO 故障时放行 | 见 §2.3 |
| 4 | 不支持 `MASTER_KEY_FILE`、`TRUSTED_PROXIES`、`LISTEN_ADDR`、`DB_PATH` | 在 Cloudflare 上无意义 |
| 5 | `ADMIN_API=false` 时 `/v1/admin/*` 返回 JSON 404（Go 是 mux 的纯文本 404） | 无安全影响 |
| 6 | 启动期警告（无活跃 token、admin token 7 天内到期）改在每日 Cron 里记日志；UI 横幅仍可用 | Worker 没有启动阶段 |
| 7 | 管理 CLI 与 `backup` 子命令不复存在 | 见 §3、§5 |
| 8 | `Content-Type` 检查只比对媒体类型，不校验参数语法 | Go 的 `ParseMediaType` 会拒绝畸形参数；属于边角，不影响安全 |
| 9 | 响应时间戳用 `Date.now()`；`last_used_at` 用 `ctx.waitUntil` 异步更新 | 少一次同步写，更低延迟；语义同 Go（失败只告警） |

## 5. 运维

- **备份**：`wrangler d1 export hush --remote --output backup.sql`；D1 另有 Time Travel（可回到 30 天内任意时刻）。备份里只有密文和 token hash；**主密钥不在备份里，要另行保管**——没有主密钥，备份无法解密。
- **审计清理**：设置 `AUDIT_RETENTION_DAYS=180` 后，每日 Cron 会删除更早的审计行；不设则不删。也可手动：`wrangler d1 execute hush --remote --command "DELETE FROM audit_log WHERE ts < strftime('%s','now','-180 days')"`。
- **轮换主密钥**：规格里没有该功能（Go 版同样没有）。需要时：用旧钥读出全部、新钥写回。本版不实现。

## 6. 从 Go 版迁移已有数据

schema 与密文格式都没变，所以只需要把**数据行**搬过去（`CREATE TABLE` 由 D1 迁移负责，不能再导入一次）。**主密钥必须沿用 Go 版的那一个**，否则已有密文解不开。

```bash
# 1. 停掉 Go 服务，保证没有新写入
# 2. 只导出数据行。导出文件含 token hash 与密文，用完即删
sqlite3 hush.db .dump | grep -E '^INSERT INTO "?(secrets|tokens|audit_log)"? ' > import.sql

# 3. 在 worker/ 下建表、导入、设置同一把主密钥
npx wrangler d1 migrations apply DB --remote
npx wrangler d1 execute DB --remote --file ../import.sql
npx wrangler secret put MASTER_KEY        # 粘贴 Go 版 MASTER_KEY 的值
```

导入后：Go 版签发的 token 明文继续有效（hash 原样导入），到期时间、吊销状态、读/写前缀都保留；admin token 仍受 90 天上限约束。

## 7. 验证记录

| 项目 | 结果 |
|---|---|
| 自动化测试（`npm test`，workerd 内运行） | 107 项通过；`tsc --noEmit` 无错误 |
| 密文互通 | 用 Go 的 `crypto/cipher` 生成固定向量：Workers 版能解开，且 `seal` 输出与 Go **逐字节一致**；SHA-256 token hash 同样一致 |
| 测试有效性 | 做了变异检查：故意改坏 `canRead`、审计条件、AAD、agent 覆盖规则，对应测试均会失败 |
| 真实 Go 客户端 | 构建 `cmd/hush`，对 `wrangler dev` 跑通 `health / put / get / list / delete`，错误场景（404、401）正常；开启 v2 客户端加密（`init` + `put` + `get`）通过，服务端只见 `hh2:` 不透明密文 |
| 管理 UI | 用 Chromium 打开：登录、Secrets / Tokens / 审计三个页签都正常渲染，严格 CSP 下无脚本错误 |
| Go → Workers 迁移 | 用真实 Go 服务端生成库（2 个 secret、admin / agent / 已吊销三个 token），按 §6 导入本地 D1：Go 签发的 token 可直接认证，Go 加密的 secret 能解密，吊销与写前缀授权保持有效 |
| 部署配置 | `wrangler deploy --dry-run` 通过：打包 44.6 KiB、无运行时依赖，D1 / DO / Assets 绑定正确 |

**没有验证的部分**（需要你的 Cloudflare 账号）：
- 真实部署与真实 D1（验证都在本地 miniflare / `wrangler dev` 里完成，D1 与 DO 的语义由 workerd 提供，但没跑过线上延迟、配额）。
- Cron Trigger 的真实触发（逻辑由 `scheduled()` 的测试覆盖）。
- 导出步骤用的是 Python `sqlite3.iterdump()`（本机没有 `sqlite3` 命令行），它与命令行 `.dump` 的 `INSERT` 输出格式一致；改用命令行时请先在 `--local` 上演练一遍。

## 8. 目录

```
worker/
  wrangler.jsonc        绑定: D1, DO, Assets；vars；Cron
  migrations/0001_init.sql
  src/
    index.ts            入口: fetch / scheduled，路由与管线
    config.ts           环境变量解析与校验（Env 类型）
    maintenance.ts      每日 Cron: 令牌告警、审计清理
    env.d.ts            Cloudflare.Env 类型声明
    crypto.ts           AES-GCM、SHA-256、常量时间比较、随机
    auth.ts             principal、授权规则、前缀校验、authenticate
    tokens.ts           token 业务规则（创建/更新/吊销/列表）
    secrets.ts          /v1/secrets 处理
    admin.ts            /v1/admin 处理
    audit.ts            审计写入与查询
    ratelimit.ts        Durable Object + 客户端
    http.ts             JSON 响应、请求 ID、客户端 IP、body 读取
    duration.ts         expires / since 的解析
  public/ui/            与根目录 ui/ 相同的静态文件
  scripts/bootstrap-admin.mjs
  test/                 vitest（workerd 内运行）
```
