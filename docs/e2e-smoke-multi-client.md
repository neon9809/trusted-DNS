# 多 Docker → 单 Worker（多 client）端到端冒烟验证

## 1. 目标

验证 v2 多 client registry 在端到端链路上满足：

- 一个 Worker 部署服务多个 Docker client
- 路由按 `client_id_prefix` 正确命中对应 client 的 seed
- generation 状态按 client 隔离，不串扰

## 2. 前置条件

- Worker 已启用 `CLIENT_REGISTRY`（见 [cloudflare-client-registry.md](file:///workspace/docs/cloudflare-client-registry.md)）
- 你有两套不同的 `ROOT_SEED`（hex 32 bytes，即 64 字符）

## 3. 准备两套 seed

准备两个 seed（示例）：

- SEED_A = `0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`
- SEED_B = `abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789`

实际使用时请自行生成随机 seed，不要复用示例 seed。

## 4. 计算 client_id_prefix（用于排障）

仓库提供一个小工具用于计算 `client_id` 与 `client_id_prefix`：

- [print-client-prefix.js](file:///workspace/worker/scripts/print-client-prefix.js)

示例：

```bash
cd worker
node scripts/print-client-prefix.js "$SEED_A"
node scripts/print-client-prefix.js "$SEED_B"
```

输出中 `client_id_prefix` 应不同。

## 5. 配置 Worker 多 client registry

将两个 seed 写入 `CLIENT_REGISTRY`：

```json
[
  { "root_seed": "SEED_A", "enabled": true },
  { "root_seed": "SEED_B", "enabled": true }
]
```

并设置 `DOH_UPSTREAMS` / `DOH_TIMEOUT_MS`（可选）。

注意：

- `CLIENT_REGISTRY` 中可以为不同 client 指定不同 `doh_upstreams` 与 `doh_timeout_ms`
- 不设置 `CLIENT_REGISTRY` 时 Worker 会退化为单 client 模式

## 6. 启动 Worker（本地开发）

在 `worker/` 目录启动本地 Worker：

```bash
cd worker
export DOH_UPSTREAMS='["https://cloudflare-dns.com/dns-query"]'
export DOH_TIMEOUT_MS='5000'
export CLIENT_REGISTRY='[{"root_seed":"'"$SEED_A"'","enabled":true},{"root_seed":"'"$SEED_B"'","enabled":true}]'
pnpm dev
```

记录本地 Worker 的访问地址（通常为 `http://localhost:8787`）。

## 7. 启动两个 Docker client 指向同一 Worker

启动两个 Docker 容器（或两个宿主机节点），它们满足：

- client A 使用 `ROOT_SEED=SEED_A`
- client B 使用 `ROOT_SEED=SEED_B`
- 两者都使用同一个 `WORKER_URL`（同一个 Worker）

示例（仅表达思路，具体命令以你现有 v1 的启动方式为准）：

```bash
docker run --rm \
  -e ROOT_SEED="$SEED_A" \
  -e WORKER_URL="http://host.docker.internal:8787/dns-query" \
  trusted-dns:latest

docker run --rm \
  -e ROOT_SEED="$SEED_B" \
  -e WORKER_URL="http://host.docker.internal:8787/dns-query" \
  trusted-dns:latest
```

## 8. 验证点（最小集）

### 8.1 路由命中

在 Worker 侧观察：

- client A 的请求应使用 SEED_A 派生的 `client_id_prefix`
- client B 的请求应使用 SEED_B 派生的 `client_id_prefix`

如果出现 “找不到匹配 client”，说明：

- `CLIENT_REGISTRY` 配置不包含对应 seed
- 或请求头的 prefix 与 seed 派生 prefix 不一致

### 8.2 generation 隔离

验证 “A 的 refresh / bootstrap 不影响 B 的 generation”。

最简单的观测方式：

- 让 A 执行一轮 bootstrap/refresh（会推进 generation）
- 再让 B 执行 bootstrap/refresh
- 两者得到的 generation 应各自独立推进，而不是共享同一条序列

## 9. 常见故障排查

- `CLIENT_REGISTRY` JSON 解析失败：确认是 JSON 数组字符串，且引号转义正确
- 两个 client 派生出了相同 prefix：说明 seed 重复或极小概率碰撞（应更换 seed）
- 上游超时：为单个 client 单独设置更小/更大的 `doh_timeout_ms` 或更换 `doh_upstreams`

## 10. 结论

当你能用两个不同 seed 的 Docker client 同时指向同一个 Worker 且均可正常 bootstrap/query/refresh，同时 generation 互不影响时，即完成多 client registry 的端到端冒烟验证。

## 11. 纯脚本化冒烟（无需 Docker）

如果你只想验证“多 client 路由 + generation 隔离 + 端到端加密链路”而不启动 Docker，可以使用仓库内的脚本：

- Bootstrap：`worker/scripts/bootstrap-smoke.js`
- Query：`worker/scripts/query-smoke.js`
- Refresh：`worker/scripts/refresh-smoke.js`

说明：

- Query 需要 DoH 上游可用。若你的环境无法访问公网 DoH，可用本地 DoH mock：
  - `worker/scripts/doh-mock-server.js`
  - 并在 `DOH_UPSTREAMS` 中配置 `http://127.0.0.1:8053/dns-query`（仅用于本地开发验证）
