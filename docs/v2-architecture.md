# Trusted-DNS v2 架构设计

## 1. 文档目的

本文档用于定义 Trusted-DNS v2 的目标架构。

它回答以下问题：

- v2 为什么需要架构重构
- v2 的多 client Worker 应该如何组织
- 哪些部分属于平台无关核心
- Cloudflare、Deno、Fastly 各自位于哪一层
- 如何在保持轻量化、无状态原则下完成演进

本文档是 `docs/v2-development-plan.md` 的架构细化文档。

## 2. 架构目标

v2 架构需要同时满足以下目标：

- 一个 Cloudflare Worker 部署服务多个 Docker client
- 保持 Worker 热路径无状态
- 持久状态仍保持最小化
- 不破坏 v1 已验证的协议与安全边界
- 为 Deno Deploy 和 Fastly Compute 提供 PoC 级适配空间

## 3. v1 架构问题

v1 的整体设计方向正确，但其实现结构仍然带有明显的单 client 假设。

主要问题如下：

- Worker 入口、请求处理、client 身份推导与状态访问耦合在一起
- `ROOT_SEED -> client_id` 的单 client 假设直接写入请求处理路径
- Cloudflare Durable Objects 的使用方式直接嵌入主流程
- 运行时依赖与业务逻辑缺少明确边界

这些问题不会影响 v1 的正确性，但会阻碍 v2 的多 client 支持与跨平台验证。

## 4. v2 架构原则

### 4.1 平台无关核心优先

凡是与协议、票据、密钥、刷新验证、generation 迁移相关的逻辑，应归入平台无关核心。

### 4.2 运行时依赖后置

请求入口、环境变量读取、状态后端绑定、部署配置等内容，应下沉到平台 adapter 层。

### 4.3 client 维度隔离

v2 的最基本隔离单位不再是“整个 Worker 部署”，而是“client 上下文”。

每个 client 上下文必须至少包含：

- client 身份
- 密钥派生能力
- generation 状态访问入口
- refresh 校验上下文

### 4.4 状态最小化

即使从单 client 升级为多 client，持久状态模型也必须保持极简。

v2 不允许引入：

- session 表
- ticket 表
- query 记录表
- DNS 请求历史

## 5. v2 总体分层

v2 建议采用以下三层架构：

```text
┌──────────────────────────────────────────────┐
│              平台适配层                      │
│ Cloudflare / Deno / Fastly Entrypoints      │
│ Config / Env / State Wiring / Deployment    │
└──────────────────────────────────────────────┘
                    │
                    ▼
┌──────────────────────────────────────────────┐
│               服务核心层                     │
│ Bootstrap / Query / Refresh / Client Route  │
│ Generation Transition / Resolver Orchestration │
└──────────────────────────────────────────────┘
                    │
                    ▼
┌──────────────────────────────────────────────┐
│               协议核心层                     │
│ Protocol / Crypto / Tickets / Bundle Logic  │
└──────────────────────────────────────────────┘
```

## 6. 协议核心层

协议核心层负责所有与平台无关、且在不同运行时中必须保持一致的逻辑。

### 6.1 职责

- 协议头编解码
- SessionTicket / RefreshTicket 编解码
- KeyBundle 序列化与反序列化
- HKDF 密钥派生
- AEAD 加解密
- HMAC ticket / proof 校验
- Bootstrap proof 计算与校验
- Refresh proof 计算与校验
- 协议错误响应构造

### 6.2 约束

协议核心层必须满足：

- 不直接依赖 Cloudflare API
- 不直接依赖 Deno KV
- 不直接依赖 Fastly SDK
- 不直接访问环境变量
- 不负责 HTTP 路由

### 6.3 价值

该层稳定后，Docker 端与 Worker 端的协议一致性会更容易验证，跨平台 PoC 也不需要反复复制业务逻辑。

## 7. 服务核心层

服务核心层是 v2 的真正中枢。

### 7.1 职责

- 处理 Bootstrap 请求
- 处理 Query 请求
- 处理 Refresh 请求
- 将请求路由到正确的 client 上下文
- 调用状态接口读取 / 推进 generation
- 调用 resolver 完成 DoH 转发
- 处理 refresh 认证与策略判定

### 7.2 服务核心层接口

建议至少定义以下接口。

#### `ClientRegistry`

职责：

- 根据 `client_id_prefix` 解析 client
- 返回 client descriptor

client descriptor 建议包含：

- `clientId`
- `clientIdPrefix`
- seed 材料或可派生密钥源
- 状态 / 启用标志

#### `GenerationStore`

职责：

- 获取当前 `latestBundleGen`
- 推进 generation
- 标记 generation 已使用

#### `ReplayGuard`

职责：

- 对 `(bundleGen, ticketId, seq)` 做短窗口 replay 防护
- 校验 seq 是否在允许窗口内

#### `Resolver`

职责：

- 将 DNS wire-format query 转发到 DoH upstream
- 返回 DNS wire-format response 与基础元信息

#### `Clock`

职责：

- 提供统一时间源
- 便于测试中注入时间

#### `Logger`

职责：

- 记录必要的错误与运行信息
- 不记录 DNS 内容

### 7.3 服务核心层约束

服务核心层不得直接依赖：

- Durable Object API
- `Deno.openKv()`
- Fastly 特有 `backend` 配置
- 平台特有的请求对象扩展能力

## 8. 平台适配层

平台适配层负责“把某个平台变成一个可以承载服务核心层的运行容器”。

### 8.1 职责

- 请求入口适配
- 环境变量与配置加载
- 状态存储实例绑定
- 平台级日志输出
- 平台级部署配置
- 将平台请求对象转为统一服务输入

### 8.2 Cloudflare 适配层

负责：

- `fetch(request, env, ctx)` 入口
- Durable Objects 绑定
- Worker 变量读取
- Cloudflare 特有部署配置

### 8.3 Deno 适配层

负责：

- Deno HTTP 入口
- `Deno KV` 接入
- 环境变量读取
- Deno Deploy 特有部署包装

### 8.4 Fastly 适配层

负责：

- Fastly Compute 请求入口
- Fastly 数据存储接口接入
- fetch / backend 配置封装
- Fastly 部署元信息整理

## 9. client 上下文模型

v2 中每个请求在进入服务核心层后，都应首先解析为一个 `ClientContext`。

建议的逻辑结构如下：

```text
Request
  -> decode header
  -> lookup client by client_id_prefix
  -> build client context
  -> execute bootstrap/query/refresh in that context
```

`ClientContext` 建议包含：

- `clientId`
- `clientIdPrefix`
- `derivedKeys`
- `generationStoreHandle`
- `clientPolicy`

这样可以避免在每个 handler 中散落 client 识别逻辑。

## 10. v2 请求流程

## 10.1 Bootstrap 流程

```text
Docker
  -> BootstrapReq
  -> 平台适配层解析 HTTP 请求
  -> 服务核心层解析 header
  -> ClientRegistry 解析 client
  -> 校验 bootstrap proof
  -> GenerationStore 获取并推进 generation
  -> 签发 KeyBundle
  -> 加密返回 BootstrapResp
```

关键点：

- 不再假设 Worker 只有一个 client
- generation 推进必须在 client 维度进行

## 10.2 Query 流程

```text
Docker
  -> QueryReq
  -> 平台适配层接收二进制请求
  -> 服务核心层解析 header 和 ticket
  -> ClientRegistry 定位 client
  -> GenerationStore 校验 generation
  -> ReplayGuard 校验 replay / seq
  -> 解密 DNS query
  -> Resolver 转发至 DoH
  -> 加密 DNS response
  -> 返回 QueryResp
```

关键点：

- Query 热路径仍然是无状态验证
- 不引入 per-query 持久写入

## 10.3 Refresh 流程

```text
Docker
  -> RefreshReq
  -> 平台适配层接收请求
  -> 服务核心层定位 client
  -> 校验 refresh ticket
  -> 校验 spent_bundle_gen / spent_query_count / refresh_proof
  -> GenerationStore 推进 generation
  -> 签发下一代 KeyBundle
  -> 返回 RefreshResp
```

关键点：

- v2 中 refresh 预留字段必须升级为真实校验边界
- refresh 不应再只是“ticket 有效就通过”

## 11. 状态模型

### 11.1 必须持久化的状态

v2 允许的核心持久状态依然非常少：

- 每个 client 的 `latestBundleGen`
- 可选的 `firstUsedAt`
- 最小 client registry

### 11.2 不应持久化的状态

以下内容在 v2 中仍然禁止持久化：

- query 内容
- QNAME / QTYPE
- DNS answers
- session ticket 使用明细
- replay 明细日志

### 11.3 状态规模约束

状态规模目标：

- 以 client 数量为主导
- 不随 query 总量增长
- 不随 ticket 使用次数增长

## 12. 目录演进建议

建议的代码布局如下：

```text
platform/
  worker/
    src/
      core/
      adapters/
    wrangler.toml
  deno/
  fastly/
```

说明：

- `platform/worker/src/core/` 用于放平台无关逻辑
- `platform/worker/src/adapters/` 用于放状态与运行时适配

如果后续仍需保留各平台独立入口，也可使用：

```text
platform/
  worker/
    src/
    wrangler.toml
  deno/
  fastly/
```

其中 `platform/` 作为各运行时实现的顶层目录，便于在 v2.1 继续加入 Deno / Fastly 入口与部署配置。

## 13. 三个平台在 v2 中的角色分工

### 13.1 Cloudflare

角色：

- 主实现平台
- 多 client 的正式落地平台

任务重点：

- 先完成正确性
- 再完成运维配置收口

### 13.2 Deno

角色：

- 第一可移植性验证平台

任务重点：

- 验证 service-core 是否真正摆脱 Cloudflare 耦合
- 验证 `Deno KV` 是否足以承载最小状态模型

### 13.3 Fastly

角色：

- 第二可移植性验证平台

任务重点：

- 验证 Wasm 风格边缘运行时能否容纳现有协议与二进制流
- 验证状态与 fetch 适配方式是否合理

## 14. 实施建议

### 14.1 先稳 Cloudflare，再做 PoC

v2 不能同时重构核心并全面推进三平台。

推荐顺序：

1. 提炼核心层
2. 完成 Cloudflare 多 client
3. 做 Deno PoC
4. 做 Fastly PoC

### 14.2 先冻结接口，再写 adapter

若没有稳定接口，三个平台 adapter 最终只会演变成三套相似但不可复用的实现。

### 14.3 不要提前为未选平台设计抽象

当前 v2 只支持：

- Cloudflare
- Deno
- Fastly

因此所有抽象只需要覆盖这三种需求，不做额外平台预留。

## 15. 验收视角

从架构角度看，v2 的成功标准不是“代码拆得漂亮”，而是以下三点同时成立：

- Cloudflare 多 client 成功落地
- 核心逻辑不再绑定单一平台
- Deno 和 Fastly PoC 可以复用同一套服务核心

## 16. 总结

Trusted-DNS v2 的架构升级，本质上是一件事情：

把 v1 已经正确的“无状态协议型 Worker”从 **单 client 实现** 演进为 **多 client 架构**，并在此基础上验证其跨平台可移植性。

正确的架构方向是：

- 保留 v1 的协议与状态哲学
- 收紧实现边界
- 将平台能力后置到 adapter 层
- 先做 Cloudflare 主线，再做 Deno / Fastly PoC
