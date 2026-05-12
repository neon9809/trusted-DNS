# Trusted-DNS v2.1.0 Release Notes

## 亮点

- 新增 `Deno` 与 `Fastly` 两个边缘运行时的 v2.1 PoC 兼容层
- 公共协议、加密、票据、解析器与 service-core 统一收口到 `platform/src`
- Cloudflare 主实现目录调整为 `platform/cloudflare_worker`
- 三个平台均已完成本地 smoke 验证：`bootstrap / query / refresh` 全链路跑通

## 架构调整

- 共享核心已从原 Cloudflare 实现目录抽离到 `platform/src`
- Cloudflare 目录仅保留入口、平台适配与 Durable Object 状态实现
- Deno 与 Fastly 目录只保留平台入口、配置与最小状态适配，保持轻量化与无状态原则

## 平台支持

### Cloudflare Workers

- 继续作为当前基线主实现平台
- 主运行时根目录已切换到 `platform/cloudflare_worker`
- 本地 `wrangler dev` smoke 已验证通过

### Deno

- 新增 `platform/deno/main.ts` 运行时入口
- 新增 `platform/deno/kv-store.ts` 的 Deno KV 适配骨架
- 新增 `platform/deno/deno.json`
- 新增 Deno Deploy Button 与最小部署说明

### Fastly

- 新增 `platform/fastly/index.ts` 运行时入口
- 新增 `platform/fastly/store.ts` 状态适配骨架
- 新增 `platform/fastly/fastly.toml`
- 新增 `platform/fastly/package.json`
- 新增 Fastly Cloud Deploy 按钮与最小部署说明

## 修复

- 修复多 client replay 误判：replay key 增加 `client_id_prefix` 维度，避免不同 client 在同一 isolate 内被误判为重放
- 修复 Fastly 入口重复重建内存 generation backend 的问题，避免同一进程内状态在请求间丢失
- 同步修正文档、CI 路径与忽略规则，适配新的 `platform/cloudflare_worker` 目录结构

## 验证

- Cloudflare：通过本地 DoH mock + `wrangler dev` 跑通 bootstrap/query/refresh
- Deno：通过适配器级本地 HTTP 包装层复用同一套 smoke 脚本跑通 bootstrap/query/refresh
- Fastly：通过适配器级本地 HTTP 包装层复用同一套 smoke 脚本跑通 bootstrap/query/refresh

## 兼容性与限制

- v2.1.0 的正式基线运行时仍为 Cloudflare Workers
- Deno 与 Fastly 当前属于 PoC 兼容层，目标是验证共享核心的可移植性
- Fastly 当前已具备 Cloud Deploy 骨架，但尚未完成原生 Fastly JavaScript runtime 下的正式发布验证

## 升级提示

- 旧的 `platform/worker` 路径已调整为 `platform/cloudflare_worker`
- 如果你的脚本、CI 或部署文档仍引用旧路径，需要同步更新
- 若要继续保持单 client 模式，可继续仅配置 `ROOT_SEED`
- 若要验证多 client 模式，优先使用 `CLIENT_REGISTRY`

## 安全提示

- `ROOT_SEED` 与 `CLIENT_REGISTRY` 仍属于敏感配置，只应通过平台环境变量或 Secret 注入
- v2.1.0 未改变“最小状态模型”原则：不持久化 DNS 查询内容、ticket 使用明细或请求历史
