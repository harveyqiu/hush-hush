# 用 Docker 部署 hush-hush

本文面向运维者：如何把 hush-hush 作为单个容器跑起来、日常怎么管理、出事怎么恢复。调用 API 的 agent 请看 [`agent-guide.md`](agent-guide.md)。

## 1. 威胁模型

hush-hush 的权限控制（每个 agent 一个 token、按前缀授权、审计日志）**只对走 HTTP API 的调用方有效**。下面这些人能绕过全部控制，直接拿到所有 secret：

- 能访问 Docker daemon 的人。加入 `docker` 组等同于宿主机 root：可以 `docker exec` 进容器，也可以挂载数据卷。
- 能读取数据卷（`hush-data`）**并且**能读取主密钥文件（`master_key`）的人。
- 宿主机的 root。

所以：

1. **agent 不能运行在有 Docker 权限的账户下**，也不能以挂载了数据卷或密钥文件的容器身份运行。
2. **主密钥和数据库备份分开存放**。只拿到其中一个没有用，两个都拿到就等于拿到全部明文。
3. **主密钥离线保存一份**，例如放在密码管理器里或打印出来。丢了主密钥，所有 secret 永久无法恢复。

## 2. 首次部署

### 2.1 准备

需要 Docker 和 Compose v2，以及一个会处理 HTTPS 的反向代理（Caddy、nginx、Traefik 都行）。

```bash
git clone <this repo> hush-hush && cd hush-hush
```

### 2.2 生成主密钥

```bash
openssl rand -base64 32 > master_key
sudo chown 65532:65532 master_key    # 容器以 uid 65532 运行，需要能读这个文件
sudo chmod 400 master_key
```

现在就把 `master_key` 的内容离线备份一份。这个文件已在 `.gitignore` 里，不要提交。

### 2.3 启动

```bash
docker compose up -d
docker compose ps          # 状态应为 (healthy)
docker compose logs hush   # 应看到 "listening" 和 "key_source":"file"
```

首次启动会在数据卷里创建数据库。日志里有 `no active tokens` 警告是正常的，下一步就创建 token。

`compose.yaml` 已经做了这些加固：
- 端口只发布到宿主机的 `127.0.0.1:8080`；
- 根文件系统只读；
- 去掉全部 Linux capability，并设置 `no-new-privileges`；
- 容器内以非 root 用户运行；
- 数据目录权限为 0700，数据库文件为 0600。

### 2.4 创建第一个 admin token

```bash
docker compose exec hush hush-hush token create --name admin --role admin --expires 30d
```

token 只打印这一次。把它存进密码管理器。

**admin token 只给人用，必须设置有效期**，最长 90 天。快到期前（界面会在最后 7 天提醒，服务启动日志里也有警告）新建一个 admin token 换上，再吊销旧的。admin token 不能续期：一个泄露的 admin token 没法给自己延长寿命。

### 2.5 配置反向代理

两种接法，任选其一。

#### 方式 A：Traefik（同一台 VPS 上的容器，推荐）

Traefik 和 hush 跑在同一台 VPS、同一个 Docker 上。两者之间走一个**专用的私有网络 `hush-edge`**，这个网络上只有它们两个容器：

```
互联网 ──443──► Traefik ──hush-edge（internal）──► hush:8080
                  │
                  └─ 你其他的应用（在 Traefik 自己的网络上，连不到 hush）
```

为什么不直接接到 Traefik 现有的公共网络上：那个网络上通常还有你其他走 Traefik 的应用，它们能绕过 Traefik 直接访问 `hush:8080`，下面的管理界面 IP 白名单就被绕过了。单独建一个网络有三个好处：

- 除了 Traefik，没有别的容器能连到 hush；
- 网段里只有 Traefik 会发请求给 hush，所以 `TRUSTED_PROXIES` 可以直接信任整个网段，不用给 Traefik 固定 IP；
- 网络是 `internal` 的，hush 容器访问不了外网，被攻破也没法把数据往外发。

`compose.traefik.yaml` 是叠加在 `compose.yaml` 上的配置，作用如下：

- 去掉宿主机端口映射；
- 把 hush 只接入 `hush-edge` 网络；
- `/v1/secrets` 和 `/healthz` 对外开放，agent 从哪里都能访问，每次调用仍然要带 token；
- `/ui`、`/v1/admin` 和根路径 `/` 只允许 `HUSH_ADMIN_ALLOW` 里的地址访问，其他来源由 Traefik 直接返回 403。

**前提**：
- Traefik v3，启用 Docker provider，且 `exposedByDefault=false`；
- 有一个 `websecure` 入口和一个证书解析器，名字可在 `.env` 里改；
- **Traefik 版本 ≥ v3.6**。Docker 29 要求客户端的 Docker API 版本至少为 1.40，更早的 Traefik 连不上 Docker、读不到容器标签。日志里会出现 `client version 1.24 is too old`。

**步骤**：

1. 创建私有网络（只做一次）：

   ```bash
   docker network create --internal --subnet 172.29.54.0/24 hush-edge
   ```

2. 让 Traefik 也接入这个网络。在 Traefik 自己的 compose 里，保留它原来的网络，再加上 `hush-edge`：

   ```yaml
   services:
     traefik:
       networks:
         - web          # Traefik 原来的网络（名字以你的为准）
         - hush-edge
   networks:
     web:
       external: true   # 或者按你原来的写法
     hush-edge:
       external: true
   ```

   然后执行 `docker compose up -d` 重建 Traefik。也可以临时执行 `docker network connect hush-edge traefik`，但这样 Traefik 重建后会丢失这个网络。

3. 复制并编辑环境变量文件：

   ```bash
   cp .env.example .env
   # 修改 HUSH_HOST、HUSH_ADMIN_ALLOW；入口和证书解析器名称如与默认不同也要改
   ```

   `.env` 里的 `COMPOSE_FILE=compose.yaml:compose.traefik.yaml` 会让之后所有 `docker compose ...` 命令自动带上 Traefik 配置。

4. 启动：`docker compose up -d`。

**验证**：

```bash
curl https://secrets.example.com/healthz                                # {"status":"ok"}
curl -o /dev/null -w '%{http_code}\n' https://secrets.example.com/ui/  # 白名单外应为 403
docker compose exec hush hush-hush audit --limit 3                      # REMOTE 列应为真实客户端 IP，而不是 172.29.54.x
```

**关于来源 IP**：Traefik 默认会丢弃客户端自己带来的 `X-Forwarded-For`，再写入它看到的真实地址，所以客户端无法伪造来源 IP。如果 Traefik 前面还有 CDN 或负载均衡，需要在 Traefik 的入口上配置 `forwardedHeaders.trustedIPs`，否则审计里记录的和白名单判断用的都会是 CDN 的地址。

`172.29.54.0/24` 如果和 VPS 上已有的网络冲突，创建网络时换一个网段，同时修改 `.env` 里的 `HUSH_EDGE_SUBNET`。

Traefik v2 的中间件叫 `ipwhitelist`，不叫 `ipallowlist`。用 v2 的话，要改 `compose.traefik.yaml` 里对应的标签。

#### 方式 B：宿主机上的反向代理（Caddy、nginx 等）

使用默认的 `compose.yaml`，它会把服务发布在 `127.0.0.1:8080`，把 HTTPS 流量转发过去即可。以 Caddy 为例：

```
secrets.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

nginx 需要 `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`，Caddy 默认就会设置这个头。建议同样在代理上限制 `/ui` 和 `/v1/admin` 的来源 IP。

**来源 IP**：从宿主机进入容器的流量，源地址是 compose 网络的网关 `172.29.53.1`。`compose.yaml` 已经设置 `TRUSTED_PROXIES: "172.29.53.1"`，只信任这个地址发来的 `X-Forwarded-For`。如果 `172.29.53.0/24` 和你已有的网络冲突，要把 `compose.yaml` 里的子网和 `TRUSTED_PROXIES` 一起改掉。

### 2.6 登录管理界面

打开 `https://secrets.example.com/ui/`（用 Traefik 时，要从 `HUSH_ADMIN_ALLOW` 列出的地址访问），粘贴 admin token。

- token 只保存在当前浏览器标签页里，关闭标签页即失效；空闲 15 分钟会自动退出。
- agent token 登录不了管理界面。

在界面里可以：
- **Secrets**：新建、查看、修改、删除；
- **Tokens**：给每个 agent 创建 token（明文只显示一次）、调整前缀、吊销；
- **审计日志**：按 token、名称、动作、结果、时间筛选。

## 3. 给 agent 签发 token

原则：**一个 agent 一个 token，只给它需要的前缀。**

在界面的 Tokens 页操作，或者用命令行：

```bash
# 只读 llm. 和 github. 下的 secret，90 天后过期
docker compose exec hush hush-hush token create --name llm-agent --role agent \
  --prefix llm. --prefix github. --expires 90d

# 允许在自己的命名空间 crawler. 下新建 secret（不能覆盖、不能删除），并能读回
docker compose exec hush hush-hush token create --name crawler --role agent \
  --prefix crawler. --write-prefix crawler.
```

- 前缀必须以 `.` 或 `_` 结尾：`llm.` 能匹配 `llm.openai`，但匹配不到 `llmx.key`。
- 读前缀 `*` 表示可以读全部 secret，需要额外确认，一般不要用。写前缀不允许用 `*`。
- 写入前缀和另一个 agent 重叠时会给出警告。建议每个 agent 用独占的命名空间。

把 token 交给 agent 时附上 [`agent-guide.md`](agent-guide.md)。

### 轮换 token

1. 新建一个 token，例如 `llm-agent-2`，前缀和旧 token 相同；
2. 把新 token 配置到 agent 上；
3. 在审计日志里确认旧 token 已经不再出现：`hush-hush audit --token llm-agent --since 1d`；
4. 吊销旧 token。吊销立即生效且不可撤销。

admin token 的轮换方式相同：在界面里用当前 admin token 新建一个 admin token，换上新的重新登录，再吊销旧的。当前正在用的 token 不能在界面里吊销自己。

## 4. 备份与恢复

### 备份

`backup` 子命令用 SQLite 的 `VACUUM INTO` 生成一致的副本，**服务运行时也可以执行**。加上 `--out -` 会把副本直接输出到宿主机，不在数据卷里留下任何文件：

```bash
umask 077
docker compose exec -T hush hush-hush backup --out - > backup-$(date +%F).db
```

备份文件里是密文和 token 哈希，**要和主密钥分开存放**。

### 恢复

```bash
docker compose down
docker run --rm -v hush-hush_hush-data:/data -v "$PWD:/restore:ro" alpine \
  sh -c 'cp /restore/backup-YYYY-MM-DD.db /data/hush.db && rm -f /data/hush.db-wal /data/hush.db-shm && chown 65532:65532 /data/hush.db && chmod 600 /data/hush.db'
docker compose up -d
```

恢复必须用**同一个主密钥**。token 也会一起恢复到备份时的状态，所以备份之后吊销过的 token 会重新生效，恢复后要再吊销一次。

## 5. 审计日志

每个 `/v1/secrets` 和 `/v1/admin` 请求都会写一行审计记录，**不包含 secret 值和 token 明文**：

```bash
docker compose exec hush hush-hush audit --since 1d
docker compose exec hush hush-hush audit --token llm-agent --result denied --since 7d
```

一直出现 `denied` 或 `unauthenticated`，通常说明 agent 配错了，或者 token 已经泄露。

审计表不会自动清理，可以在宿主机上配一个定时任务：

```bash
# 每周清理 180 天前的记录
0 3 * * 0  cd /path/to/hush-hush && docker compose exec -T hush hush-hush audit-prune --older-than 180d
```

## 6. 升级

```bash
(umask 077; docker compose exec -T hush hush-hush backup --out - > pre-upgrade.db)
git pull
docker compose up -d --build
```

数据库结构迁移在启动时自动执行，并且是幂等的。升级到"admin token 必须过期"的版本时，永不过期或有效期超过 90 天的 admin token 会被改为从升级时起 30 天后到期，请在这期间换上新的 admin token。**先备份再升级**：新版本迁移过的数据库，旧版本会拒绝启动；要回退，只能用升级前的备份恢复。

从 v0.1.0 的数据库迁移过来：把旧的 `hush.db` 按第 4 节的恢复步骤放进数据卷，并使用原来的 `MASTER_KEY`。

## 7. 配置参考

| 环境变量 | 镜像默认值 | 说明 |
|---|---|---|
| `MASTER_KEY_FILE` | –（compose 里设为 `/run/secrets/master_key`） | 主密钥文件（base64，32 字节）。推荐用这个 |
| `MASTER_KEY` | – | 直接传主密钥，会出现在 `docker inspect` 里，不推荐。和上一项只能二选一 |
| `DB_PATH` | `/data/hush.db` | 数据库路径 |
| `LISTEN_ADDR` | `0.0.0.0:8080` | 容器内的监听地址 |
| `TRUSTED_PROXIES` | 无（compose 里设为网关） | 信任其 `X-Forwarded-For` 的 IP 或 CIDR。拒绝 `0.0.0.0/0` |
| `RATE_LIMIT_PER_MINUTE` | 60 | 每个 token 每分钟的请求上限 |
| `UNAUTH_RATE_LIMIT_PER_MINUTE` | 10 | 每个 IP 每分钟允许的鉴权失败次数 |
| `ADMIN_API` | `true` | 设为 `false` 会关闭 `/v1/admin/*` 和管理界面，只能用命令行管理 |

## 8. 常见问题

**`docker compose logs` 里有 `permission denied`，读不了 `/run/secrets/master_key`。**
`master_key` 文件的属主不是 65532。执行 `sudo chown 65532:65532 master_key`。

**`token create` 报 `database is owned by uid ...`。**
用了 `docker compose exec -u 0` 之类的方式换了用户。去掉 `-u`，用镜像默认的用户执行。

**管理界面报"这个 token 不是 admin"。**
管理界面只接受 admin token。agent token 请交给 agent 使用。

**不想开放 HTTP 管理接口。**
设置 `ADMIN_API=false`。之后只能用 `docker compose exec` 执行命令行来管理。
