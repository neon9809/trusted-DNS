# Trusted-DNS v2 任务拆分

## 1. 文档目的

本文档将 `docs/v2-development-plan.md` 中的里程碑与工作流进一步拆解为可执行任务，用于后续实现阶段的跟踪、排期与评审。

本文档覆盖以下范围：

- Cloudflare Workers v2 多 client 主线
- Deno Deploy PoC
- Fastly Compute PoC

## 2. 使用原则

任务拆分遵循以下原则：

- 先主线，后 PoC
- 先正确性，后工程化
- 先抽核心，后写 adapter
- 先保持兼容，后收紧语义

## 3. 里程碑映射

| 里程碑 | 目标 | 结果 |
|---|---|---|
| M0 | 冻结范围与方案 | 文档评审通过 |
| M1 | 抽离核心层 | protocol-core / service-core 边界成立 |
| M2 | Cloudflare 多 client | 一个 Worker 服务多个 Docker client |
| M3 | refresh 语义补强 | refresh 保留字段进入正式校验 |
| M4 | Deno Deploy PoC | 跑通 Bootstrap / Query / Refresh |
| M5 | Fastly Compute PoC | 跑通 Bootstrap / Query / Refresh |
| M6 | 文档收口 | 架构、迁移、矩阵、checklist 完整 |

## 4. 总体任务树

```text
v2
├── A. 架构重构
├── B. 协议与安全收口
├── C. Cloudflare Workers v2 多 client
├── D. Deno Deploy PoC
├── E. Fastly Compute PoC
└── F. 文档与验收
```

## 5. A. 架构重构

### A1. 梳理现有 Worker 模块边界

目标：

- 标注哪些代码属于协议层、服务层、平台层

任务：

- 识别 `protocol.ts`、`crypto.ts`、`tickets.ts` 的核心能力边界
- 识别 `handlers.ts` 中混合了哪些平台耦合逻辑
- 识别 `generation-store.ts` 与 Cloudflare 运行时的耦合点

完成标准：

- 输出模块归属清单
- 输出待抽象接口清单

### A2. 设计平台无关接口

目标：

- 明确 service-core 对外部世界的最小依赖

任务：

- 定义 `ClientRegistry`
- 定义 `GenerationStore`
- 定义 `ReplayGuard`
- 定义 `Resolver`
- 定义 `Clock`
- 定义 `Logger`

完成标准：

- 接口边界稳定
- 不直接泄漏平台特有 API

### A3. 拆分 protocol-core

目标：

- 将协议、票据、密钥逻辑从入口逻辑中独立出来

任务：

- 抽离协议编解码
- 抽离 KeyBundle 序列化
- 抽离 crypto 工具
- 抽离 proof 计算和校验

完成标准：

- protocol-core 可独立测试
- 不依赖平台 API

### A4. 拆分 service-core

目标：

- 将 Bootstrap / Query / Refresh 处理改写为平台无关流程

任务：

- 提炼 bootstrap service
- 提炼 query service
- 提炼 refresh service
- 提炼 client lookup 流程

完成标准：

- 核心流程不直接访问 `env`
- 核心流程不直接调用 Durable Objects

## 6. B. 协议与安全收口

### B1. 固化多 client 请求语义

目标：

- 明确请求如何从 header 路由到正确 client

任务：

- 定义 `client_id_prefix` lookup 规则
- 定义 prefix 冲突处理策略
- 定义未知 client 的错误语义

完成标准：

- client 路由语义进入文档
- 错误码与行为可测试

### B2. 固化 refresh 校验语义

目标：

- 将 refresh 保留字段升级为正式安全边界

任务：

- 定义 `spent_bundle_gen` 验证规则
- 定义 `spent_query_count` 验证规则
- 定义 `refresh_proof` 验证规则
- 定义失败错误码与行为

完成标准：

- refresh 校验规则文档化
- Docker / Worker 行为一致

### B3. 回归协议兼容性

目标：

- 保证 v2 不破坏核心协议兼容面

任务：

- 验证 header 结构未被无必要变更
- 验证 Query 热路径仍为二进制
- 验证 Bootstrap / Query / Refresh 形态保持稳定

完成标准：

- Docker 端无需重写协议栈

## 7. C. Cloudflare Workers v2 多 client

### C1. 设计 client registry 结构

目标：

- 明确 Worker 如何持有多个 client 的最小注册信息

任务：

- 设计 registry 数据结构
- 确定存储方式
- 设计启用 / 禁用逻辑

完成标准：

- registry 可支持至少三个 client

### C2. 改造 Bootstrap 路径

目标：

- Bootstrap 从单 client 假设改为多 client 上下文处理

任务：

- 先 lookup client
- 在 client 上下文中派生密钥
- 在 client 维度推进 generation

完成标准：

- 多个 client bootstrap 不串扰

### C3. 改造 Query 路径

目标：

- Query 按 client 上下文处理

任务：

- 通过 `client_id_prefix` 定位 client
- 以 client 维度校验 session ticket
- 以 client 维度校验 generation
- 以 client 维度执行 replay 检查

完成标准：

- 跨 client ticket 必须拒绝

### C4. 改造 Refresh 路径

目标：

- Refresh 在多 client 模型下正确工作

任务：

- client 维度校验 refresh ticket
- client 维度推进 generation
- 接入正式 refresh proof 校验

完成标准：

- refresh 在多 client 下行为稳定

### C5. 增加 Cloudflare 主线测试

目标：

- 为多 client 主线建立回归保护

任务：

- 多 client bootstrap 测试
- 多 client query 测试
- 多 client refresh 测试
- 错误 client / 错误 ticket / 旧 generation 测试

完成标准：

- 主路径具备回归测试覆盖

## 8. D. Deno Deploy PoC

### D1. Deno 入口适配

目标：

- 将 service-core 接入 Deno HTTP 入口

任务：

- 定义请求入口
- 定义配置读取方式
- 定义响应输出方式

完成标准：

- 能接收并处理协议请求

### D2. Deno 状态适配

目标：

- 使用 Deno KV 承载最小状态模型

任务：

- 实现 generation store
- 实现 client registry backend
- 明确 PoC 阶段的存储假设

完成标准：

- generation 状态可读写
- client registry 可 lookup

### D3. Deno 全链路验证

目标：

- 在 Deno 平台上完成完整 PoC

任务：

- bootstrap 流程验证
- query 流程验证
- refresh 流程验证

完成标准：

- 完成端到端连通性验证

## 9. E. Fastly Compute PoC

### E1. Fastly 入口适配

目标：

- 将 service-core 接入 Fastly 请求入口

任务：

- 定义请求入口适配
- 处理二进制 body
- 处理平台级响应封装

完成标准：

- 能接收协议请求并返回协议响应

### E2. Fastly 状态适配

目标：

- 在 Fastly 侧实现最小状态后端

任务：

- 实现 generation store
- 实现 registry backend
- 明确存储能力边界

完成标准：

- 最小状态模型可被验证

### E3. Fastly 全链路验证

目标：

- 在 Fastly 平台上完成完整 PoC

任务：

- bootstrap 验证
- query 验证
- refresh 验证

完成标准：

- 完成端到端连通性验证

## 10. F. 文档与验收

### F1. 文档同步

任务：

- 更新开发计划
- 更新架构设计
- 更新平台矩阵
- 更新迁移说明

### F2. Checklist 收口

任务：

- Cloudflare checklist
- Deno checklist
- Fastly checklist

### F3. 验收记录

任务：

- 记录每个里程碑的通过标准
- 记录未完成项与延期项

## 11. 优先级排序

### P0

- A2 平台无关接口
- A3 protocol-core
- A4 service-core
- C1 client registry 结构
- C2 / C3 / C4 Cloudflare 多 client 主路径
- B2 refresh 校验规则

### P1

- Cloudflare 主线测试
- Deno PoC

### P2

- Fastly PoC
- 文档收口与实施复盘

## 12. 建议执行顺序

推荐按以下顺序推进：

1. A1
2. A2
3. A3
4. A4
5. B1
6. C1
7. C2
8. C3
9. C4
10. B2
11. C5
12. D1
13. D2
14. D3
15. E1
16. E2
17. E3
18. F1 / F2 / F3

## 13. 最终说明

本文档的目标，是把 v2 从“方向明确”推进到“任务可执行”。

后续如果进入真正实施阶段，建议再为以下三条主线分别维护独立 checklist：

- Cloudflare Workers v2 多 client
- Deno Deploy PoC
- Fastly Compute PoC
