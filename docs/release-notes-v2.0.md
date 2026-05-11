# Trusted-DNS v2.0 Release Notes

## 亮点

- Cloudflare Worker 支持多 client：一个 Worker 可服务多个 Docker 节点（按 `client_id_prefix` 路由）
- Worker 端核心流程 service 化：Bootstrap / Query / Refresh 已拆分为独立 service，并与运行时解耦
- 端到端验证脚本完善：提供可复现的 smoke suite（无需 Docker 也可验证完整加密链路）

## 兼容性与升级

- 默认行为保持与 v1 一致：不配置 `CLIENT_REGISTRY` 时，仍为单 client 模式（使用 `ROOT_SEED`）
- 启用多 client：设置 `CLIENT_REGISTRY`（JSON 数组字符串），Worker 将按请求 header 的 `client_id_prefix` 选择对应 client 的 seed 与上游配置

## 新增配置项（Worker）

- `CLIENT_REGISTRY`：可选，多 client registry（静态环境变量 JSON）
- `DOH_TIMEOUT_MS`：可选，上游超时（毫秒），默认 5000
- `PROTOCOL_PATH`：可选，协议路径，默认 `/dns-query`

多 client registry 文档：

- [cloudflare-client-registry.md](file:///workspace/docs/cloudflare-client-registry.md)

## 冒烟测试

端到端冒烟验证文档：

- [e2e-smoke-multi-client.md](file:///workspace/docs/e2e-smoke-multi-client.md)

一键 smoke suite（启动本地 DoH mock + Worker，然后跑完 bootstrap/query/refresh）：

- `worker/scripts/run-smoke-suite.js`

## 已知限制

- v2.0 仅覆盖 Cloudflare Worker 运行时
- Deno / Fastly 适配计划放入 v2.1

## 安全提示

- `ROOT_SEED` / `CLIENT_REGISTRY` 属于敏感信息，只应配置在部署环境变量/Secret 中，不应提交到仓库

