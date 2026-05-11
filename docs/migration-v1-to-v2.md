# Trusted-DNS v1 到 v2 迁移说明

## 1. 文档目的

本文档用于说明 Trusted-DNS 从 v1 演进到 v2 的迁移策略。

本文档重点回答以下问题：

- v1 用户将面对什么变化
- v2 如何在不破坏现有部署哲学的前提下升级
- Cloudflare 主线应如何迁移到多 client 模式
- Deno Deploy 与 Fastly Compute 的 PoC 应如何定位
- 哪些内容要求兼容，哪些内容允许变化

本文档不是部署手册，而是迁移设计文档。

## 2. 迁移目标

v1 到 v2 的迁移目标不是“切换平台”，而是“升级能力”。

主目标如下：

- 将 Cloudflare 单 client Worker 升级为多 client Worker
- 保持 Docker 端部署方式尽量不变
- 保持现有协议主结构尽量不变
- 补强 refresh 认证语义
- 让服务核心能够被 Deno 和 Fastly PoC 复用

## 3. v1 与 v2 的本质区别

### 3.1 v1

v1 的本质是：

- 单 Worker 部署
- 单 `ROOT_SEED`
- 单 `client_id`
- 单 generation 命名空间

### 3.2 v2

v2 的本质是：

- 单 Worker 部署可承载多个 client
- 每个 client 有自己的 seed 材料
- 每个 client 有自己的 `client_id`
- 每个 client 有自己的 generation 命名空间

### 3.3 不变的部分

以下关键哲学在 v2 中仍保持不变：

- Docker 端仍保持轻量
- Worker 热路径仍保持无状态
- Worker 仍不维护持久 session table
- 仍不存储 DNS 查询历史
- 协议仍以二进制热路径为主

## 4. 迁移总策略

v1 到 v2 的迁移应遵循以下策略：

### 4.1 先完成 Cloudflare 主线迁移

Cloudflare 是现有主平台，因此迁移优先级最高。

v2 的第一阶段不应先迁移平台，而应先完成：

- 核心层抽离
- Cloudflare 多 client 化
- refresh 语义补强

### 4.2 PoC 与主线解耦

Deno Deploy 与 Fastly Compute 在 v2 中是 PoC 验证目标，而不是现有用户的迁移目标。

因此：

- v1 用户不会被要求迁移到 Deno 或 Fastly
- Deno / Fastly 的工作不应阻塞 Cloudflare 主线升级

### 4.3 配置迁移优先于协议扩张

在 v1 到 v2 的过渡中，应优先改变：

- Worker 侧配置模型
- client registry 引入方式
- 服务端 refresh 校验逻辑

而不是优先扩大协议结构或更换协议版本。

## 5. 兼容性原则

## 5.1 Docker 侧兼容性目标

对 Docker 端的兼容目标如下：

- 单个 Docker 节点的部署体验保持基本一致
- Docker 端仍只管理一个自身 client
- 现有三阶段协议仍保留
- Query 热路径的二进制格式不被重写

### 5.2 Worker 侧兼容性目标

对 Worker 端的兼容目标如下：

- 允许继续支持单 client 部署模式
- 在此基础上新增多 client 模式
- 尽量避免破坏现有请求入口与路径结构

### 5.3 协议兼容性目标

对协议的兼容目标如下：

- 保持现有 header 主结构
- 保持 Bootstrap / Query / Refresh 三阶段模型
- 优先复用已存在的 refresh 保留字段

## 6. 建议迁移路径

## 6.1 阶段一：代码结构迁移

这一阶段的核心是“先迁代码结构，不迁用户部署模式”。

需要完成：

- 拆分 protocol-core
- 拆分 service-core
- 抽象状态接口
- 抽象运行时接口

此阶段的目标是：

- 让 Cloudflare 现有单 client 行为不变
- 为后续多 client 与 PoC 准备稳定结构

对用户影响：

- 理论上无外部行为变化

## 6.2 阶段二：Cloudflare 多 client 迁移

这一阶段的核心是“从单 client Worker 升级为多 client Worker”。

需要完成：

- 引入 client registry
- 按 `client_id_prefix` 路由请求
- 将 generation 状态完全 client 化
- 保持单个 Docker 节点仍以独立 seed 接入

对用户影响：

- 新部署可选择单 client 或多 client 模式
- 现有 v1 用户可以继续按“一 Docker 对应一 client”的方式接入

## 6.3 阶段三：refresh 语义迁移

这一阶段的核心是：

- 将 `spent_bundle_gen`
- `spent_query_count`
- `refresh_proof`

从“仅为向前兼容而存在”升级为“真实参与 refresh 判定”。

需要完成：

- 明确验证规则
- 与 Docker 当前 refresh 请求行为做对齐测试
- 收紧错误语义

对用户影响：

- 行为会更严格
- 不正确的 refresh 请求将被更早拒绝

## 6.4 阶段四：Deno Deploy PoC

这一阶段不是现有用户迁移，而是开发验证。

其目标是：

- 证明 v2 核心架构不依赖 Cloudflare 独占实现
- 验证 `Deno KV` 是否能承载最小状态模型

对现有用户影响：

- 无直接影响

## 6.5 阶段五：Fastly Compute PoC

这一阶段同样不是现有用户迁移，而是开发验证。

其目标是：

- 验证 v2 架构能否进入更不同的边缘运行时
- 验证二进制协议与状态模型在 Fastly 环境中的适配可行性

对现有用户影响：

- 无直接影响

## 7. Cloudflare v1 到 v2 的迁移模型

## 7.1 v1 的部署模型

```text
Docker A <-> Worker A (ROOT_SEED_A)
Docker B <-> Worker B (ROOT_SEED_B)
```

## 7.2 v2 的部署模型

```text
Docker A (SEED_A) \
Docker B (SEED_B)  -> Worker X (multi-client)
Docker C (SEED_C) /
```

其中：

- 每个 Docker client 保持独立 seed
- Worker X 维护多个 client 的最小 registry
- 每个 client 在 Worker 内独立维护 generation 命名空间

## 7.3 v2 不推荐的模式

以下模式在 v2 中仍不推荐：

- 多个 Docker 节点共享一个 seed
- 通过复制 Docker 容器来模拟同一个逻辑 client 的多节点

原因：

- 会重新引入 `client_id` 冲突
- 会让 generation 与 seq 空间难以隔离

## 8. 配置迁移建议

## 8.1 Docker 侧

Docker 侧建议保持以下思路不变：

- 每个节点仍只配置自己的 Worker URL 与 seed
- 每个节点仍只感知自身作为一个独立 client

这意味着对大多数用户来说，Docker 侧不应出现明显复杂度提升。

## 8.2 Worker 侧

Worker 侧从 v1 到 v2 的主要配置变化应体现在：

- 从单一 `ROOT_SEED` 模型迁移到 client registry 模型
- 增加 client 注册与禁用能力
- 增加多 client 运维元数据

### 8.3 配置迁移原则

应优先满足以下要求：

- 能保留单 client 简化模式
- 能平滑进入多 client 模式
- 不要求用户理解复杂控制平面

## 9. 数据迁移与状态迁移

由于 v1 与 v2 都坚持最小状态模型，因此迁移成本相对可控。

### 9.1 generation 状态迁移

需要关注的核心状态只有：

- `latestBundleGen`

在 v2 中，该状态应被重新绑定到明确的 client 身份下。

### 9.2 无需迁移的数据

以下内容不需要迁移，因为系统本就不持久化它们：

- DNS 查询内容
- 历史 ticket 列表
- query 明细
- DoH 响应数据

### 9.3 状态迁移原则

迁移脚本或迁移逻辑必须保持最小化：

- 只迁移必要 generation 状态
- 不人为引入附加历史数据

## 10. 风险与兼容窗口

## 10.1 风险一：refresh 行为变严格

v2 的 refresh 校验会比 v1 更严格。

兼容风险：

- 某些之前“能混过去”的 refresh 行为将被拒绝

应对策略：

- 先完成 Docker 与 Worker 的对齐测试
- 在文档中明确 refresh 失败原因

## 10.2 风险二：client 路由错误

多 client 引入后，最重要的新风险是：

- 请求路由到错误 client

应对策略：

- 对 `client_id_prefix` lookup 做严格测试
- 对跨 client ticket 使用做拒绝测试

## 10.3 风险三：运维复杂度上升

v2 Worker 引入 client registry 后，运维侧天然比 v1 单 client 更复杂。

应对策略：

- 允许保留单 client 模式
- 提供最小运维模型
- 避免引入额外控制面

## 11. Deno 与 Fastly 的迁移定位

## 11.1 不是用户迁移目标

在 v2 阶段，Deno Deploy 与 Fastly Compute 不应被描述为“v1 用户必须迁移的新平台”。

更准确的表述应是：

- Deno 与 Fastly 是 v2 的 PoC 验证平台
- 它们用于验证架构可移植性
- 它们不影响现有 Cloudflare 用户的升级路径

## 11.2 未来可能的演进

如果 PoC 成功，未来可进一步演进为：

- 实验性 adapter
- 预览级支持
- 后续版本中的正式支持候选

但这些都不属于 v1 -> v2 的主迁移目标。

## 12. 推荐迁移顺序

推荐的迁移与实施顺序如下：

1. 保持 v1 现有 Docker 使用方式不变
2. 重构 Worker 内部结构
3. 在 Cloudflare 上落地多 client
4. 补强 refresh 校验
5. 再分别做 Deno 与 Fastly PoC

这个顺序的价值在于：

- 用户主线升级风险最低
- 平台 PoC 不会打断主线节奏
- 文档、代码、实现边界都更容易收口

## 13. 最终迁移结论

Trusted-DNS 从 v1 迁移到 v2 的正确理解应是：

- **不是** 从一个平台迁走
- **不是** 推翻 v1 重新设计
- **不是** 引入更重的状态模型

而是：

- 在 Cloudflare 主线上，把单 client 升级成多 client
- 在不改变轻量化、无状态原则的前提下，补强 refresh 认证
- 在此基础上，用 Deno 与 Fastly 验证架构的跨平台潜力
