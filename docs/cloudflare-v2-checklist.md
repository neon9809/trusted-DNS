# Cloudflare Workers v2 多 client Checklist

## 1. 文档目的

本文档用于跟踪 Cloudflare Workers v2 多 client 主线的实施进度。

该 checklist 只关注 Cloudflare 主平台，不覆盖 Deno 与 Fastly PoC。

## 2. 目标

目标是实现：

- 一个 Cloudflare Worker 部署服务多个 Docker client
- 保持热路径无状态
- 保持最小持久状态模型
- 不破坏现有 Docker 端轻量部署方式

## 3. 前置条件

- [ ] `v2-development-plan.md` 已确认
- [ ] `v2-architecture.md` 已确认
- [ ] `migration-v1-to-v2.md` 已确认
- [ ] 多 client 方案已冻结

## 4. 架构重构准备

- [ ] 梳理当前 Worker 中的平台耦合点
- [ ] 明确 protocol-core 范围
- [ ] 明确 service-core 范围
- [ ] 明确 Cloudflare adapter 范围
- [ ] 定义 `ClientRegistry` 接口
- [ ] 定义 `GenerationStore` 接口
- [ ] 定义 `ReplayGuard` 接口
- [ ] 定义 `Resolver` 接口

## 5. protocol-core 拆分

- [ ] 抽离 header encode / decode
- [ ] 抽离 session ticket encode / decode
- [ ] 抽离 refresh ticket encode / decode
- [ ] 抽离 KeyBundle serialize / deserialize
- [ ] 抽离 HKDF / AEAD / HMAC 逻辑
- [ ] 抽离 bootstrap proof 校验
- [ ] 抽离 refresh proof 校验
- [ ] 为 protocol-core 增加基础测试

## 6. service-core 拆分

- [ ] 提炼 bootstrap service
- [ ] 提炼 query service
- [ ] 提炼 refresh service
- [ ] 提炼 client lookup 流程
- [ ] 提炼 generation transition 流程
- [ ] 提炼统一错误处理路径
- [ ] 确保 service-core 不直接依赖 Cloudflare API

## 7. client registry

- [ ] 定义 client registry 数据结构
- [ ] 明确 `client_id_prefix` lookup 规则
- [ ] 明确 prefix 冲突策略
- [ ] 明确未知 client 错误语义
- [ ] 明确启用 / 禁用逻辑
- [ ] 明确最小元数据范围
- [ ] 明确不存储 DNS 内容

## 8. generation 状态模型

- [ ] 确认每个 client 独立 generation 命名空间
- [ ] 保留 `latestBundleGen` 作为核心权威状态
- [ ] 明确 `mark-used` 语义是否继续保留
- [ ] 明确 generation 推进的冲突处理
- [ ] 确认状态规模与 client 数量线性相关

## 9. Bootstrap 改造

- [ ] 请求先按 `client_id_prefix` 定位 client
- [ ] 按 client 上下文派生密钥
- [ ] 在 client 维度推进 generation
- [ ] 按 client 维度签发 KeyBundle
- [ ] 验证多 client bootstrap 不串扰

## 10. Query 改造

- [ ] Query 路径先定位 client
- [ ] 按 client 校验 session ticket
- [ ] 按 client 校验 generation
- [ ] 按 client 执行 replay 检查
- [ ] 保持 Query 热路径无持久化写放大
- [ ] 保持二进制协议不变形
- [ ] 验证跨 client ticket 被拒绝

## 11. Refresh 改造

- [ ] 按 client 校验 refresh ticket
- [ ] 校验 `spent_bundle_gen`
- [ ] 校验 `spent_query_count`
- [ ] 校验 `refresh_proof`
- [ ] 明确 refresh 失败错误码
- [ ] 在 client 维度推进 generation
- [ ] 验证 refresh 不串 client

## 12. Cloudflare adapter

- [ ] 保持入口文件足够薄
- [ ] 将 Durable Objects 调用下沉到 adapter 层
- [ ] 将 `env` 解析下沉到 adapter 层
- [ ] 清理 handler 中的直接平台依赖
- [ ] 明确 Cloudflare 配置组织方式

## 13. 回归测试

- [ ] 单 client 模式回归
- [ ] 多 client bootstrap 测试
- [ ] 多 client query 测试
- [ ] 多 client refresh 测试
- [ ] 旧 generation 拒绝测试
- [ ] 坏 ticket 拒绝测试
- [ ] 错误 client 拒绝测试
- [ ] replay 异常路径测试

## 14. 验收标准

- [ ] 一个 Worker 至少可服务三个独立 Docker client
- [ ] 不引入 Worker 持久 session table
- [ ] 不持久化 DNS 历史
- [ ] Query 热路径保持无状态
- [ ] Docker 端使用方式基本不变
- [ ] 多 client 路径具备基础测试覆盖

## 15. 备注

- Cloudflare 是 v2 主线，应先保证正确性，再考虑工程美化
- 若 Deno / Fastly PoC 与主线冲突，应优先保证 Cloudflare 主线推进
