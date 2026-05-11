# Deno Deploy PoC Checklist

## 1. 文档目的

本文档用于跟踪 Deno Deploy PoC 的实施进度。

该 PoC 的目标不是生产发布，而是验证 Trusted-DNS v2 核心架构在 Deno 平台上的可移植性。

## 2. PoC 目标

本 PoC 只回答以下三个问题：

- [ ] Bootstrap 能否跑通
- [ ] Query 能否跑通
- [ ] Refresh 能否跑通

## 3. 前置条件

- [ ] Cloudflare 主线的核心分层方向已明确
- [ ] protocol-core 已具备基本稳定性
- [ ] service-core 已不再直接依赖 Cloudflare API
- [ ] `platform-matrix.md` 已确认 Deno 作为第一 PoC 平台

## 4. 入口适配

- [ ] 定义 Deno 平台入口文件
- [ ] 设计请求接收方式
- [ ] 设计二进制 body 读取方式
- [ ] 设计二进制响应返回方式
- [ ] 设计环境变量读取方式
- [ ] 明确本地开发运行方式

## 5. 状态适配

- [ ] 确定 Deno KV 为状态后端
- [ ] 实现 `GenerationStore` 的 Deno 版本
- [ ] 实现 `ClientRegistry` 的 Deno 版本
- [ ] 明确 replay 处理是否仍采用内存短窗口模型
- [ ] 明确 Deno PoC 的状态一致性假设

## 6. 核心接入

- [ ] 将 protocol-core 接入 Deno adapter
- [ ] 将 service-core 接入 Deno adapter
- [ ] 接入 resolver
- [ ] 接入 logger
- [ ] 接入 clock

## 7. Bootstrap 验证

- [ ] 接收 BootstrapReq
- [ ] 正确解析 header 与 payload
- [ ] 正确 lookup client
- [ ] 正确推进 generation
- [ ] 正确返回 BootstrapResp

## 8. Query 验证

- [ ] 接收 QueryReq
- [ ] 解析 ticket 与 nonce
- [ ] 完成 client lookup
- [ ] 校验 generation
- [ ] 校验 replay / seq
- [ ] 解密 DNS query
- [ ] 完成 DoH relay
- [ ] 加密 DNS response
- [ ] 返回 QueryResp

## 9. Refresh 验证

- [ ] 接收 RefreshReq
- [ ] 校验 refresh ticket
- [ ] 校验 `spent_bundle_gen`
- [ ] 校验 `spent_query_count`
- [ ] 校验 `refresh_proof`
- [ ] 推进 generation
- [ ] 返回新的 KeyBundle

## 10. PoC 边界控制

- [ ] 不为 Deno PoC 引入新的协议分支
- [ ] 不为了 Deno 平台改写 Docker 端协议
- [ ] 不追求与 Cloudflare 的全部运维能力对齐
- [ ] 不引入与“轻量化、无状态”相冲突的平台特性

## 11. 基础测试

- [ ] Bootstrap smoke test
- [ ] Query smoke test
- [ ] Refresh smoke test
- [ ] 错误 client 测试
- [ ] 坏 ticket 测试
- [ ] 旧 generation 测试

## 12. 文档输出

- [ ] 记录 Deno 平台接入方式
- [ ] 记录 Deno KV 状态模型映射
- [ ] 记录已知限制
- [ ] 记录与 Cloudflare 的差异点

## 13. PoC 完成标准

- [ ] 能跑通 Bootstrap / Query / Refresh 全链路
- [ ] 核心逻辑复用 service-core
- [ ] 未引入平台特化协议
- [ ] 已知限制已文档化

## 14. 备注

- Deno PoC 的重点是验证“核心是否平台无关”，不是抢先做第二主平台
