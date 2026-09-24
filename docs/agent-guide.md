# Agent 接入指南

本文面向调用 hush-hush 的程序和 LLM agent：怎么拿到 secret、每个状态码代表什么、出错时怎么处理。部署和管理 token 见 [`deploy/README.md`](../deploy/README.md)。

## 1. 你需要的两样东西

管理员会给你：

| 项 | 示例 | 说明 |
|---|---|---|
| 服务地址 | `https://secrets.example.com` | 下文记作 `$HUSH_URL` |
| token | `hush_` 加 64 位十六进制 | 下文记作 `$HUSH_TOKEN`，只会给你一次 |

token 只能读取（以及可选地新建）管理员授权给你的名称前缀，例如 `llm.`。你的每一次请求，不论成功与否，都会写入审计日志。

## 2. 快速开始

```bash
# 读一个 secret
curl -sS "$HUSH_URL/v1/secrets/llm.openai" \
  -H "Authorization: Bearer $HUSH_TOKEN"
# → {"name":"llm.openai","value":"sk-...","created_at":1790000000,"updated_at":1790000000}

# 只取值（需要 jq）
curl -sS "$HUSH_URL/v1/secrets/llm.openai" -H "Authorization: Bearer $HUSH_TOKEN" | jq -r .value
```

## 3. 接口

所有 `/v1/secrets` 接口都必须带 `Authorization: Bearer <token>`。响应都是 JSON，都带 `Cache-Control: no-store` 和 `X-Request-ID`。

### 3.1 读取：`GET /v1/secrets/{name}`

```
200 {"name":"llm.openai","value":"...","created_at":<unix秒>,"updated_at":<unix秒>}
```

### 3.2 列出可见名称：`GET /v1/secrets`

```
200 {"secrets":[{"name":"llm.anthropic","created_at":...,"updated_at":...}, ...]}
```

- 只返回你有读权限的名称，不含值。
- 没有可见名称时返回 `{"secrets":[]}`，不是 `null`。
- 最多返回 1000 条。

### 3.3 新建（仅当管理员授予了写入前缀）：`PUT /v1/secrets/{name}`

```bash
curl -sS -X PUT "$HUSH_URL/v1/secrets/crawler.session" \
  -H "Authorization: Bearer $HUSH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"value":"..."}'
# → 200 {"name":"crawler.session","created_at":...,"updated_at":...}
```

- 只能**新建**。名称已存在时返回 `409`，原值不变。agent 不能覆盖已有的值。
- 写权限不包含读权限。要读回自己写的值，你的 token 还需要同一前缀的读权限。
- agent 不能删除：`DELETE` 一律返回 `403`。

### 3.4 健康检查：`GET /healthz`

不需要 token，返回 `{"status":"ok"}`。可用来区分"服务不可达"和"token 有问题"。

## 4. 名称和值的规则

- 名称：`^[a-zA-Z0-9_.-]{1,128}$`，不能含 `/` 或空格。用 `.` 或 `_` 分层，例如 `llm.openai`、`github.deploy_key`。
- 前缀匹配是纯字符串前缀：前缀 `llm.` 能读 `llm.openai`，但不能读 `llmx.key` 或 `llm`。
- 值：非空字符串，最大 64 KiB。
- `PUT` 必须带 `Content-Type: application/json`，请求体只能是 `{"value":"..."}`，多余字段或多余内容都会被拒绝。
- 以 `hh2:` 开头的值是经 `hush` CLI 客户端加密的密文，原样返回给你。没有对应的 vault 口令就解不开，这种情况请联系管理员。

## 5. 状态码和处理方式

| 状态码 | `error` | 含义 | 你该怎么做 |
|---|---|---|---|
| 200 | – | 成功 | – |
| 400 | `invalid name` / `invalid json` / `value required` / `trailing data after json` / `read body` | 请求本身有误 | 修正请求，**不要重试** |
| 401 | `unauthorized` | token 缺失、错误、已吊销或已过期（服务端不区分） | **不要重试**，停下并通知管理员 |
| 403 | `forbidden` | 名称不在你的授权范围内，或者你执行了不允许的操作（写入范围外的名称、删除） | **不要重试**。检查名称是否拼错；确实需要的话，请管理员调整授权 |
| 404 | `not found` | 在授权范围内，但这个 secret 不存在 | 不要重试。注意：授权范围**外**的名称永远返回 403，不是 404 |
| 405 | `method not allowed` | 用了不支持的 HTTP 方法 | 修正调用方式 |
| 409 | `already exists` | 新建时名称已存在 | 不要重试。换一个名称，或者请管理员更新这个值 |
| 413 | `value too large` / `request body too large` | 值超过 64 KiB | 缩小内容 |
| 415 | `content-type must be application/json` | PUT 缺少 JSON Content-Type | 加上 `Content-Type: application/json` |
| 429 | `rate_limited` | 超过限流（默认每个 token 每分钟 60 次） | 按 `Retry-After` 头给出的秒数等待后再试 |
| 500 | `db error` / `decrypt failed` / `audit failed` / `rng failed` | 服务端问题 | 指数退避重试，最多 3 次（例如间隔 1s、2s、4s），仍失败就报告，并附上 `X-Request-ID` |

重试原则：只有 429 和 5xx 值得重试。4xx 的其他状态码重试也不会有不同结果，只会在审计日志里多出一串失败记录。

## 6. 代码示例

### Python（只用标准库）

```python
import json, os, time, urllib.error, urllib.request

HUSH_URL = os.environ["HUSH_URL"].rstrip("/")
HUSH_TOKEN = os.environ["HUSH_TOKEN"]


class HushError(Exception):
    def __init__(self, status, error, request_id):
        super().__init__(f"hush {status}: {error} (request_id={request_id})")
        self.status, self.error, self.request_id = status, error, request_id


def _call(method, path, body=None, retries=3):
    data = None if body is None else json.dumps(body).encode()
    for attempt in range(retries + 1):
        req = urllib.request.Request(HUSH_URL + path, data=data, method=method)
        req.add_header("Authorization", "Bearer " + HUSH_TOKEN)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as e:
            rid = e.headers.get("X-Request-ID", "")
            try:
                err = json.load(e).get("error", "")
            except ValueError:
                err = ""
            if e.code == 429 and attempt < retries:
                time.sleep(int(e.headers.get("Retry-After", "1")))
                continue
            if e.code >= 500 and attempt < retries:
                time.sleep(2 ** attempt)
                continue
            raise HushError(e.code, err, rid) from None


def get_secret(name):
    return _call("GET", "/v1/secrets/" + name)["value"]


def list_secrets():
    return [s["name"] for s in _call("GET", "/v1/secrets")["secrets"]]


def create_secret(name, value):  # 需要写入前缀；名称已存在时抛出 409
    return _call("PUT", "/v1/secrets/" + name, {"value": value})


if __name__ == "__main__":
    api_key = get_secret("llm.openai")  # 不要打印或记录这个值
```

### Shell

```bash
hush_get() {
  curl -sS --fail-with-body "$HUSH_URL/v1/secrets/$1" \
    -H "Authorization: Bearer $HUSH_TOKEN" | jq -r .value
}
OPENAI_API_KEY="$(hush_get llm.openai)" || { echo "hush: get failed" >&2; exit 1; }
export OPENAI_API_KEY
```

### Node.js（18+，内置 fetch）

```js
async function getSecret(name) {
  const res = await fetch(`${process.env.HUSH_URL}/v1/secrets/${name}`, {
    headers: { Authorization: `Bearer ${process.env.HUSH_TOKEN}` },
  });
  const body = await res.json();
  if (!res.ok) {
    throw new Error(`hush ${res.status}: ${body.error} (request_id=${res.headers.get("x-request-id")})`);
  }
  return body.value;
}
```

## 7. 安全要求（必须遵守）

1. **token 的保管**
   - 从环境变量或权限为 0600 的文件读取 token。
   - 不要写进代码、配置仓库、日志、错误信息或 LLM 的上下文和输出。
2. **secret 值的处理**
   - 只在内存里使用，不写磁盘，不打印，不放进异常消息。
   - 不要回显给用户，也不要传给其他模型或工具，除非这正是它的用途，比如把 API key 放进对应服务的请求头。
3. **按需读取**
   - 只读取当前任务需要的名称。
   - 不要为了"看看有什么"去遍历列表或猜测名称：每次尝试都会被审计，大量 403 会让管理员以为 token 被盗。
4. **缓存要短**
   - 启动时读一次、在进程内存里缓存，可以。
   - 不要把值持久化。
   - 值可能被轮换：调用下游服务得到认证错误时，重新向 hush-hush 读取一次再试。
5. **排障**
   - 报告问题时附上 `X-Request-ID` 响应头的值，管理员可以据此在审计日志里找到对应记录。
   - 也可以自己在请求里带一个 `X-Request-ID`（1–128 位字母、数字、`_`、`-`），服务端会沿用这个值。
6. **遇到 401，立即停止**
   - token 可能已被吊销或过期，继续请求没有意义。

## 8. 给 LLM agent 的提示词片段

可以直接放进 agent 的系统提示词或工具说明：

```text
You can fetch secrets from hush-hush:
- GET {HUSH_URL}/v1/secrets/{name} with header "Authorization: Bearer $HUSH_TOKEN" returns {"value": "..."}.
- GET {HUSH_URL}/v1/secrets lists the names you are allowed to read.
- You may only read names under your granted prefixes: <填写，例如 llm.>
- (If granted) PUT {"value": "..."} with Content-Type: application/json creates a NEW secret under: <填写，例如 crawler.>. It never overwrites; 409 means the name exists.
Rules:
- Never print, log, summarize, or repeat a secret value or the token. Use values only where they are needed (e.g. an API request header).
- Only request names you need for the current task; do not enumerate or guess names.
- 401 or 403: stop and report to the operator; do not retry. 404: the secret does not exist. 429: wait Retry-After seconds. 5xx: retry at most 3 times with backoff.
- When reporting an error, include the X-Request-ID response header, never the token.
```

## 9. 常见问题

**我明明有 `llm.` 前缀，为什么 `llm` 返回 403？**
前缀带分隔符，`llm.` 只匹配以 `llm.` 开头的名称，不包括 `llm` 本身。

**授权范围外的名称为什么是 403 而不是 404？**
为了不让 agent 借状态码探测其他名称是否存在。只有授权范围内的名称才会返回 404。

**列表里没有某个 secret，能直接 GET 吗？**
能不能读只取决于授权前缀，和列表无关。列表里没有，通常说明它不在你的授权范围内，或者还不存在。

**token 过期或被吊销后怎么办？**
所有请求都会返回 401。请管理员签发新 token；旧 token 不会恢复。
