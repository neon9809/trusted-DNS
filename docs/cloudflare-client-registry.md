# Cloudflare 多 client Registry 配置

## 1. 文档目的

本文档说明 Trusted-DNS v2 在 Cloudflare Workers 上启用多 client 时的最小配置方式。

目标：

- 保持 Worker 热路径无状态
- 保持持久状态最小化
- 只通过 Worker 环境变量完成多 client 路由

## 2. 背景

v2 中 Worker 会先基于请求 header 的 `client_id_prefix` 进行 client 路由，然后再进入 Bootstrap / Query / Refresh 流程。

为了做到“一个 Worker 服务多个 Docker”，Worker 需要一个 client registry。

## 3. 环境变量

### 3.1 单 client（默认）

如果不设置 `CLIENT_REGISTRY`，Worker 仍然采用 v1 单 client 模式：

- `ROOT_SEED`：单一 client 的 seed
- `DOH_UPSTREAMS`：默认 DoH 上游列表
- `DOH_TIMEOUT_MS`：默认超时

此模式下 Worker 会忽略请求中的 `client_id_prefix` 路由差异，行为与 v1 一致。

### 3.2 多 client（v2）

设置 `CLIENT_REGISTRY` 后，Worker 进入多 client 路由模式：

- Worker 将 `CLIENT_REGISTRY` 解析为一个 client 列表
- 对每个 client 的 `root_seed` 派生 `client_id`，并用前 8 字节作为路由 key
- 依据请求 header 的 `client_id_prefix` 查找对应 client

## 4. CLIENT_REGISTRY 格式

`CLIENT_REGISTRY` 是一个 JSON 数组（字符串形式），数组内每一项描述一个 client。

支持字段（同一字段可用两种命名方式）：

- `root_seed` 或 `rootSeedHex`（必填，hex string）
- `doh_upstreams` 或 `dohUpstreams`（可选，缺省则使用 `DOH_UPSTREAMS`）
- `doh_timeout_ms` 或 `dohTimeoutMs`（可选，缺省则使用 `DOH_TIMEOUT_MS` 或默认 5000）
- `enabled`（可选，默认为 true；若为 false 则该项被忽略）

示例：

```json
[
  {
    "root_seed": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "enabled": true
  },
  {
    "root_seed": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    "doh_upstreams": "[\"https://cloudflare-dns.com/dns-query\"]",
    "doh_timeout_ms": 3000,
    "enabled": true
  }
]
```

## 5. 路由规则

- Worker 使用 `client_id_prefix`（8 bytes）作为路由 key
- key 的计算方式为：`deriveClientId(root_seed).slice(0, 8)`
- 若找不到匹配的 client，则 Bootstrap / Query / Refresh 会返回错误响应（当前实现返回 `ERR_BAD_TICKET`）

## 6. 注意事项

- `CLIENT_REGISTRY` 中的 `root_seed` 属于敏感信息，不应写入代码仓库
- registry 仅用于路由与密钥派生，不应扩展为控制平面或状态数据库
- generation 状态仍然由 Durable Object 按 `client_id` 维度保存，保持最小状态模型不变

## 6.1 配置错误语义（建议按此理解）

- `CLIENT_REGISTRY` 存在但 JSON 解析失败：不会产生任何有效 client，所有请求都会命中“未知 client”错误
- `CLIENT_REGISTRY` 不是 JSON 数组：同上
- 某条 entry 缺失/不合法（例如 `root_seed` 不是 64 位 hex）：该 entry 会被忽略
- 多条 entry 派生出相同 `client_id_prefix`：以列表中更靠前的 entry 为准，后续重复项被忽略

## 7. 本地冒烟验证

仓库提供一个本地冒烟脚本，用于验证 `CLIENT_REGISTRY` 的 prefix 派生与映射逻辑是否自洽：

- [verify-client-registry.js](file:///workspace/worker/scripts/verify-client-registry.js)

运行方式（示例）：

```bash
cd worker
export DOH_UPSTREAMS='["https://cloudflare-dns.com/dns-query"]'
export DOH_TIMEOUT_MS='5000'
export CLIENT_REGISTRY='[{"root_seed":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","enabled":true},{"root_seed":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789","enabled":true}]'
node scripts/verify-client-registry.js
```

预期输出：

- `ok: registry entries=..., activePrefixes=...`
