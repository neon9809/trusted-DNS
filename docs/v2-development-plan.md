# Trusted-DNS v2 开发计划

## 1. 文档目的

本文档用于正式定义 Trusted-DNS v2 的开发范围、设计原则、里程碑、交付顺序与验收标准。

v2 的范围被明确限制为以下三条平台主线：

1. **Cloudflare Workers v2 多 client 支持**
2. **Deno Deploy PoC**
3. **Fastly Compute PoC**

本文档只作为规划与实施依据，不代表所有 v2 工作必须在同一个发布版本中一次完成。

## 2. v2 范围声明

### 2.1 v2 要解决的问题

v1 当前采用严格的 **单 Docker 节点 <-> 单 Worker 部署** 模型。该模型在最小化状态、控制复杂度、快速部署方面是成功的，但也带来一个明确限制：

- 一个 Worker 部署只能服务一个 `client_id`
- 多个 Docker 节点无法安全复用同一个 Worker 部署

v2 的核心目标，就是在不破坏 v1 轻量化与无状态原则的前提下，将当前的单 client Worker 升级为多 client Worker。

### 2.2 v2 目标

v2 的正式目标分为两个层级：

- **主目标**：实现一个 Cloudflare Worker 部署服务多个 Docker client
- **次目标**：抽离平台无关的 Worker 核心能力，并在 Deno Deploy 与 Fastly Compute 上完成可运行的 PoC

### 2.3 v2 非目标

以下内容明确不在 v2 范围内：

- 一次性交付所有边缘平台的生产级支持
- 引入 Worker 侧持久化 session table
- 引入 Docker 侧数据库、控制平面服务或额外容器
- 将热路径协议从二进制改为 JSON
- 存储 DNS 查询历史、QNAME、QTYPE 或解析结果
- 支持 AWS CloudFront Functions
- 支持 Vercel Edge Functions
- 支持 Netlify Edge Functions

## 3. v1 资产与约束

v2 必须建立在 v1 已验证成功的设计资产之上，而不是推倒重来。

### 3.1 v1 已验证的正确方向

v1 已证明以下设计是正确且值得保留的：

- Docker 侧保持极简部署模型
- Worker 热路径使用紧凑二进制协议
- Query 过程不依赖 Worker 持久会话表
- Worker 仅持久化最小 generation 状态
- Bootstrap / Query / Refresh 的三阶段模型清晰稳定
- 票据与 generation 轮转机制天然适合无状态服务端

### 3.2 v1 的关键约束

当前 v1 存在以下硬约束：

- Worker 从单一 `ROOT_SEED` 派生唯一 `client_id`
- Worker 的 generation 命名空间只有一条
- 当前 `refresh_proof` 相关字段虽已存在，但尚未作为强制校验边界生效

### 3.3 v1 的协议预留点

以下字段已在 v1 协议中预留，v2 必须优先复用：

- `spent_bundle_gen`
- `spent_query_count`
- `refresh_proof`

这意味着 v2 的演进重点应放在 **语义补全与实现升级**，而不是贸然扩张 wire format。

## 4. v2 核心原则

### 4.1 轻量化原则

v2 必须继续保持“普通用户可低门槛部署”的体验：

- Docker 端仍保持单容器部署
- 仍以环境变量为主配置方式
- 不要求 Docker 侧接入外部数据库
- 不引入复杂控制平面

### 4.2 无状态原则

v2 Worker 热路径仍必须满足以下要求：

- 不维护持久化 session table
- 不对每次 query 进行持久化写入
- query 验证仍以票据自验证为主
- 仅保留最小且必要的 client 级状态

### 4.3 最小持久状态原则

v2 的持久状态规模应与 **client 数量** 线性相关，而不能与 **query 数量**、**ticket 数量** 线性相关。

允许的持久状态示例：

- `client_id -> latest_bundle_gen`
- 最小 client registry 元数据
- 仅在必要时引入的极小 replay 辅助状态

禁止的持久状态示例：

- 每次查询的审计日志
- ticket 生命周期明细
- per-client DNS 请求历史

### 4.4 协议稳定原则

v2 应尽量保持现有协议结构稳定：

- 先复用现有预留字段
- 先补强语义，再扩充负载结构
- 平台差异不得污染协议核心

### 4.5 平台隔离原则

Cloudflare、Deno、Fastly 的运行时差异必须收敛在 adapter 层，不能直接渗入协议与服务流程主逻辑。

## 5. v2 目标架构

v2 建议将 Worker 拆分为三层结构。

### 5.1 协议核心层

职责：

- 头部编解码
- ticket 编解码
- bootstrap proof 校验
- refresh proof 校验
- HKDF / AEAD / HMAC
- KeyBundle 序列化与反序列化
- 错误响应构造

要求：

- 不依赖 Cloudflare API
- 不依赖 Durable Objects
- 可以被多个平台复用

### 5.2 服务核心层

职责：

- Bootstrap 流程
- Query 流程
- Refresh 流程
- client 路由与上下文构建
- generation 迁移逻辑
- resolver 调度

建议抽象的接口：

- `ClientRegistry`
- `GenerationStore`
- `ReplayGuard`
- `Resolver`
- `Clock`
- `Logger`

### 5.3 平台适配层

职责：

- HTTP 入口绑定
- 环境变量与配置读取
- 状态后端接入
- 平台特有 fetch / storage 行为封装
- 平台部署配置

v2 的目标适配器：

- `cloudflare`
- `deno`
- `fastly`

## 6. 多 client 设计决策

### 6.1 核心结论

v2 不应让多个 Docker 节点共享同一个 `ROOT_SEED`。

正确模型应为：

- 每个 Docker client 保持自己独立的 seed 材料
- Worker 侧维护一个轻量级 client registry
- 请求进入后通过 `client_id_prefix` 路由到对应 client 上下文

### 6.2 采用该模型的原因

这样可以完整保留 v1 的安全边界：

- 每个 Docker 节点拥有独立 `client_id`
- 每个 client 拥有独立 generation 命名空间
- ticket / refresh 校验天然按 client 隔离
- 从设计上杜绝 client 碰撞

### 6.3 client registry 约束

registry 必须保持极简。

建议包含：

- `client_id`
- `client_id_prefix`
- seed 材料或等价派生源
- `enabled/disabled` 状态

可选元数据：

- 显示名称
- 创建时间
- 运维备注

明确禁止存储：

- DNS 查询内容
- ticket 使用明细
- DNS 响应数据

### 6.4 generation 状态模型

v1 的 generation 状态模型应继续保留：

- 每个 client 一条最小 generation 状态
- 最新 generation 唯一权威
- 旧 generation 自动失效

这是 v1 最有价值的设计资产之一，v2 不应替换为更重的模型。

### 6.5 replay 处理策略

v2 应继续保持 replay 机制轻量，但必须清晰文档化平台语义：

- 默认可接受 isolate-local 的短窗口 replay 防护
- 若要增强 replay 保障，不能破坏最小状态模型
- 不同平台的一致性差异必须明确写入文档

## 7. 平台策略

### 7.1 Cloudflare Workers v2

定位：

- v2 主生产平台
- 第一优先级交付目标
- 多 client 能力的基准实现

原因：

- 现有生产实现已在此平台运行
- Durable Objects 与当前最小 generation 状态模型高度契合
- 迁移风险最低

目标结果：

- 一个 Worker 部署服务多个 Docker client
- Cloudflare 继续作为首个正式支持的平台

### 7.2 Deno Deploy PoC

定位：

- 第一优先级可移植性验证平台

原因：

- 运行时能力强
- 使用标准 Deno runtime
- 内置 `Deno KV`
- 适合验证平台无关 service-core 是否成立

PoC 目标：

- 在不修改 Docker 协议的前提下跑通 Bootstrap / Query / Refresh

PoC 不要求：

- 生产级运维完备性
- 与 Cloudflare 的全部功能对齐
- 最终性能调优

### 7.3 Fastly Compute PoC

定位：

- 第二优先级可移植性验证平台

原因：

- 强边缘执行模型
- 明确面向计算型边缘服务
- 支持 fetch 与边缘数据存储能力

PoC 目标：

- 验证 Worker 核心在 Wasm 风格边缘环境中可运行
- 验证二进制请求、DoH fetch、最小状态模型的可落地性

PoC 不要求：

- 全面生产级运维能力
- 与 Cloudflare 的部署工具链完全一致
- 发布级 SLA 承诺

## 8. 工作流与实施主线

v2 的实施不应同时多线大改，而应遵循“主线优先、适配验证后置”的顺序。

### W1. 架构重构

范围：

- 拆出 protocol-core
- 拆出 service-core
- 定义平台无关接口
- 降低 Cloudflare 特有耦合

产出：

- 清晰的核心模块边界
- 抽象接口定义
- 更新后的目录结构方案

### W2. Cloudflare 多 client 支持

范围：

- 引入 client registry
- 基于 `client_id_prefix` 路由请求
- client 级 generation 隔离
- 配置模型升级

产出：

- Cloudflare Workers v2 多 client 实现
- registry 配置方案
- 运维与迁移说明

### W3. Refresh 认证补强

范围：

- 将当前“只解析不强校验”的 refresh 字段升级为真正的校验边界
- 定义精确 refresh 验证规则
- 保持与 Docker 当前实现兼容

产出：

- refresh 校验规则文档
- 正常 / 异常路径测试
- 协议文档更新

### W4. 状态适配抽象

范围：

- 抽象 generation store
- 抽象 client registry backend
- 定义 Deno / Fastly 状态适配接口

产出：

- Cloudflare state adapter
- Deno state adapter
- Fastly state adapter

### W5. Deno Deploy PoC

范围：

- 实现 Deno runtime adapter
- 接入 Deno KV
- 跑通 Bootstrap / Query / Refresh

产出：

- 可运行 Deno PoC
- 部署说明
- 已知限制清单

### W6. Fastly Compute PoC

范围：

- 实现 Fastly runtime adapter
- 验证请求解析、DoH 转发、状态存储
- 校验现有 crypto / protocol 假设是否成立

产出：

- 可运行 Fastly PoC
- 平台说明
- 已知限制清单

### W7. 文档与迁移材料

范围：

- 更新架构文档
- 输出平台能力矩阵
- 输出 v1 -> v2 迁移说明

产出：

- `docs/v2-architecture.md`
- `docs/platform-matrix.md`
- `docs/migration-v1-to-v2.md`

## 9. 里程碑计划

### M0. 规划冻结

目标：

- 冻结 v2 范围、边界和设计原则

进入条件：

- 本开发计划评审通过

退出条件：

- 多 client 方案确认
- 平台清单确认
- 核心抽象方向确认

### M1. 核心重构

目标：

- 完成 protocol-core 与 service-core 的边界拆分

关键任务：

- 将协议、密码学、ticket 逻辑下沉到可复用核心
- 定义状态与运行时接口
- 保持 Cloudflare 现有行为不变

退出条件：

- Cloudflare 单 client 路径仍可正常工作
- 现有协议无行为回归
- 多平台 adapter 具备可实现基础

### M2. Cloudflare Workers v2 多 client

目标：

- 实现一个 Worker 部署服务多个 Docker client

关键任务：

- 增加 client registry
- 去除请求路径中对单一 `env.ROOT_SEED` 的硬编码依赖
- 按 client 上下文处理 Bootstrap / Query / Refresh
- 形成多 client 运维配置方式

退出条件：

- 一个 Worker 至少可稳定服务三个独立 Docker client
- client 之间 generation 不串扰
- Bootstrap / Query / Refresh 全链路隔离成立

### M3. Refresh 语义补强

目标：

- 让 refresh 预留字段成为真实安全边界的一部分

关键任务：

- 校验 `spent_bundle_gen`
- 校验 `spent_query_count`
- 校验 `refresh_proof`
- 明确失败语义与错误码策略

退出条件：

- refresh 保留字段正式参与判定
- 非法 refresh 请求被稳定拒绝

### M4. Deno Deploy PoC

目标：

- 验证 Deno Deploy 上的端到端可行性

关键任务：

- 实现 Deno 入口
- 实现 Deno KV 状态适配
- 跑通 Bootstrap / Query / Refresh

退出条件：

- Deno Deploy 上能完成完整加密查询流程
- 已知限制完成文档化

### M5. Fastly Compute PoC

目标：

- 验证 Fastly Compute 上的端到端可行性

关键任务：

- 实现 Fastly 入口
- 实现最小状态适配
- 验证二进制请求 / 响应与 DoH relay

退出条件：

- Fastly 上能完成完整加密查询流程
- 已知限制完成文档化

### M6. 文档收口

目标：

- 完成 v2 规划、实施、迁移与平台评估材料

关键任务：

- 更新架构文档
- 输出平台矩阵
- 输出迁移说明
- 输出实施分解文档

退出条件：

- 文档足以指导后续编码与评审

## 10. 目录演进建议

建议的目标结构如下：

```text
platform/
  worker/
    src/
      core/
        services/
      adapters/
        cloudflare/
    scripts/
    wrangler.toml
  deno/
    main.ts
    kv-store.ts
    config/
  fastly/
    index.ts
    store.ts
    config/
docs/
  v2-development-plan.md
  v2-architecture.md
  platform-matrix.md
  migration-v1-to-v2.md
```

此结构以 `platform/` 作为平台实现根目录；当前仓库已先落位 `platform/worker/`，后续可直接在同级继续推进 Deno / Fastly。

## 11. 测试策略

### 11.1 核心测试

必须覆盖：

- 协议编解码 round trip
- ticket 校验
- bootstrap proof 校验
- refresh proof 校验
- KeyBundle 兼容性

### 11.2 Cloudflare 多 client 测试

必须覆盖：

- 多 client 注册
- `client_id_prefix` 路由正确性
- 跨 client ticket 拒绝
- generation 隔离
- refresh 隔离

### 11.3 平台冒烟测试

对 Deno 和 Fastly PoC，至少应覆盖：

- bootstrap 成功
- 加密 query 成功
- refresh 成功
- 失败路径能正确返回错误

### 11.4 回归测试

必须保证：

- Docker 协议兼容
- 不持久化 DNS 内容
- 热路径仍保持轻量二进制协议

## 12. 验收标准

只有当以下条件全部满足时，v2 才可视为规划成功并具备实施基础：

- Cloudflare Workers 支持一个部署服务多个 Docker client
- Worker 侧状态仍然保持最小、按 client 隔离
- 未引入持久化 session table
- 未引入 DNS 查询历史存储
- Docker 部署方式仍保持轻量
- Deno Deploy PoC 完成 Bootstrap / Query / Refresh 全链路
- Fastly Compute PoC 完成 Bootstrap / Query / Refresh 全链路
- 平台差异被控制在 adapter 层

## 13. 主要风险

### R1. client 隔离错误

风险：

- 请求被错误路由到其他 client 上下文

缓解：

- 严格 client lookup 路径
- 跨 client 拒绝测试
- generation 状态隔离测试

### R2. refresh 语义漂移

风险：

- Docker 与 Worker 在 refresh 语义升级后出现不一致

缓解：

- 编码前先冻结 refresh 验证规则
- 对现有 Docker transport 做兼容测试

### R3. 平台状态语义差异

风险：

- Cloudflare DO、Deno KV、Fastly 存储的一致性和延迟语义不完全相同

缓解：

- 将状态契约保持极小
- 明确记录平台保证边界
- 避免把实现建立在强一致假设之上

### R4. 可移植性重构过大

风险：

- 抽象工作反而影响 Cloudflare 主线稳定性

缓解：

- 分阶段重构
- 始终以 Cloudflare 为第一参考实现
- 在 M2 稳定前不同时推进两个 PoC 的深入实现

### R5. 过度抽象

风险：

- 为未来平台预留过多抽象，反而提升复杂度

缓解：

- 接口只做窄而必要的抽象
- 不做投机性平台设计
- 始终只围绕已批准的三个平台推进

## 14. 建议交付顺序

推荐执行顺序：

1. 规划冻结
2. 核心重构
3. Cloudflare Workers v2 多 client
4. refresh 认证补强
5. Deno Deploy PoC
6. Fastly Compute PoC
7. 文档收口

这个顺序确保主业务价值优先落地，平台 PoC 不会阻塞核心目标。

## 15. 建议版本节奏

建议采用如下版本节奏：

- **v2.0**：Cloudflare Workers 多 client 正式支持
- **v2.1**：Deno Deploy 实验性 PoC / adapter
- **v2.2**：Fastly Compute 实验性 PoC / adapter

原因：

- 真正的产品价值首先来自现有主平台的多 client 升级
- Deno 与 Fastly 应先以验证性成果进入代码库

## 16. 后续规划文档

建议在本计划基础上继续补齐以下文档：

1. `docs/v2-architecture.md`
2. `docs/platform-matrix.md`
3. `docs/migration-v1-to-v2.md`
4. 里程碑级任务拆分文档

## 17. 最终结论

Trusted-DNS v2 的正确方向，不是做一次重型重构，而是：

- **先** 将现有 Cloudflare Worker 升级为多 client Worker
- **再** 通过 Deno Deploy 与 Fastly Compute PoC 验证核心架构可移植性
- **始终** 保持 v1 已验证成功的轻量化、无状态、最小持久状态原则
