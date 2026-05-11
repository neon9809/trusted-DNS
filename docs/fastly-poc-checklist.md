# Fastly Compute PoC Checklist

## 1. 文档目的

本文档用于跟踪 Fastly Compute PoC 的实施进度。

该 PoC 的目标不是立即形成生产支持，而是验证 Trusted-DNS v2 在更不同的边缘运行时中的可行性。

## 2. PoC 目标

本 PoC 需要回答以下问题：

- [ ] 协议型 Worker 是否可接入 Fastly Compute
- [ ] 二进制请求 / 响应是否可稳定处理
- [ ] DoH relay 是否可正常工作
- [ ] 最小状态模型是否可被合理映射

## 3. 前置条件

- [ ] Cloudflare 主线核心分层稳定
- [ ] Deno PoC 已完成或至少已明确主要适配接口
- [ ] protocol-core / service-core 已可被 adapter 复用
- [ ] `platform-matrix.md` 已确认 Fastly 为第二 PoC 平台

## 4. 入口适配

- [ ] 确定 Fastly Compute 请求入口模型
- [ ] 设计二进制 body 读取方式
- [ ] 设计协议响应返回方式
- [ ] 明确环境配置接入方式
- [ ] 明确本地测试路径

## 5. 状态适配

- [ ] 明确 Fastly 可用状态能力
- [ ] 实现 `GenerationStore` 的 Fastly 版本
- [ ] 实现 `ClientRegistry` 的 Fastly 版本
- [ ] 明确 replay 处理策略
- [ ] 明确 PoC 阶段一致性假设

## 6. 核心接入

- [ ] 将 protocol-core 接入 Fastly adapter
- [ ] 将 service-core 接入 Fastly adapter
- [ ] 适配 resolver
- [ ] 适配 logger
- [ ] 适配 clock

## 7. 网络与 DoH relay

- [ ] 验证 fetch 到 DoH upstream 的基本能力
- [ ] 明确平台特有 backend / network 约束
- [ ] 验证主备竞速与回退策略是否可实现
- [ ] 记录必要的平台差异处理

## 8. Bootstrap 验证

- [ ] 接收 BootstrapReq
- [ ] 解析 header 与 payload
- [ ] lookup client
- [ ] 推进 generation
- [ ] 返回 BootstrapResp

## 9. Query 验证

- [ ] 接收 QueryReq
- [ ] 解析 ticket / nonce / ciphertext
- [ ] 完成 client lookup
- [ ] 完成 generation 校验
- [ ] 完成 replay / seq 校验
- [ ] 解密 query
- [ ] 执行 DoH relay
- [ ] 加密 response
- [ ] 返回 QueryResp

## 10. Refresh 验证

- [ ] 接收 RefreshReq
- [ ] 校验 refresh ticket
- [ ] 校验 `spent_bundle_gen`
- [ ] 校验 `spent_query_count`
- [ ] 校验 `refresh_proof`
- [ ] 推进 generation
- [ ] 返回新的 KeyBundle

## 11. PoC 边界控制

- [ ] 不为了 Fastly 单独改造 Docker 协议
- [ ] 不引入与主线冲突的状态模型
- [ ] 不以 PoC 为理由扩大平台抽象范围
- [ ] 不提前追求生产级运维能力

## 12. 基础测试

- [ ] Bootstrap smoke test
- [ ] Query smoke test
- [ ] Refresh smoke test
- [ ] 错误 client 测试
- [ ] 坏 ticket 测试
- [ ] 旧 generation 测试

## 13. 文档输出

- [ ] 记录 Fastly 入口适配方式
- [ ] 记录状态后端映射方案
- [ ] 记录 fetch / backend 差异
- [ ] 记录已知限制

## 14. PoC 完成标准

- [ ] Bootstrap / Query / Refresh 全链路跑通
- [ ] 核心逻辑复用 service-core
- [ ] 平台差异被控制在 adapter 中
- [ ] 限制项已文档化

## 15. 备注

- Fastly PoC 的重点是验证“架构能否进入另一种边缘计算环境”，不是立即形成第二正式平台
