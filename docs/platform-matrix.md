# Trusted-DNS v2 平台能力矩阵

## 1. 文档目的

本文档用于对比 Trusted-DNS v2 当前选定的三个平台：

- Cloudflare Workers
- Deno Deploy
- Fastly Compute

本文档的目标不是做泛泛的平台介绍，而是回答以下与 Trusted-DNS v2 直接相关的问题：

- 哪个平台适合作为主实现平台
- 哪个平台适合作为 PoC 验证平台
- 哪个平台在哪些能力上更贴近 Trusted-DNS 的需求
- 各平台在状态、请求体、二进制协议、加密、DoH 转发上的约束是什么

本文档与 `docs/v2-development-plan.md`、`docs/v2-architecture.md` 配套使用。

## 2. 评估范围

本次评估只覆盖 v2 已确认的三个平台：

1. Cloudflare Workers
2. Deno Deploy
3. Fastly Compute

以下平台明确不在本文评估范围内：

- Vercel Edge Functions
- Netlify Edge Functions
- AWS CloudFront Functions

## 3. Trusted-DNS v2 的平台需求

为了判断一个平台是否适合 Trusted-DNS v2，需要先明确系统的最低能力需求。

### 3.1 必需能力

Trusted-DNS Worker 至少需要具备以下能力：

- 接收二进制 HTTP POST 请求
- 读取请求体
- 返回二进制响应体
- 支持 `fetch`
- 支持 Web Crypto 或等价密码学能力
- 支持最小持久状态模型
- 支持环境变量或秘密配置
- 能完成 DoH 上游转发

### 3.2 强需求

以下能力不是绝对必需，但对 Trusted-DNS 非常重要：

- 较低冷启动成本
- 接近 Web 标准的请求 / 响应模型
- 便于承载平台无关 service-core
- 较自然的 client 级最小状态组织方式

### 3.3 弱需求

以下能力有帮助，但不应主导平台选择：

- 丰富的控制台体验
- 原生日志 / 监控增强功能
- 更强的框架生态

## 4. 结论摘要

### 4.1 总结结论

- **Cloudflare Workers**：最适合作为 v2 主实现平台
- **Deno Deploy**：最适合作为第一 PoC 平台
- **Fastly Compute**：最适合作为第二 PoC 平台

### 4.2 原因摘要

- Cloudflare 已有现成实现，迁移风险最低
- Deno 的运行时能力最完整，最适合验证平台无关核心是否成立
- Fastly 的边缘计算模型更接近“高性能协议型边缘服务”，适合验证长期可移植性

## 5. 总体能力矩阵

| 能力项 | Cloudflare Workers | Deno Deploy | Fastly Compute |
|---|---|---|---|
| 二进制请求体读取 | 强 | 强 | 强 |
| 二进制响应返回 | 强 | 强 | 强 |
| `fetch` 能力 | 强 | 强 | 强 |
| DoH 转发适配度 | 强 | 强 | 中强 |
| Web Crypto 适配度 | 强 | 强 | 中 |
| 最小持久状态模型适配度 | 强 | 强 | 中 |
| 多 client 主实现适配度 | 强 | 中强 | 中 |
| 冷启动与边缘执行模型 | 强 | 中强 | 强 |
| 运行时完整度 | 中 | 强 | 中 |
| 当前代码迁移成本 | 低 | 中 | 中高 |
| v2 角色建议 | 主平台 | 第一 PoC | 第二 PoC |

## 6. Cloudflare Workers

### 6.1 平台定位

Cloudflare Workers 在 v2 中的定位不是 PoC 平台，而是主平台。

原因很简单：

- v1 已在该平台完成实现
- 当前状态模型已经建立在 Durable Objects 上
- 现有实现中的主要问题是“单 client 假设”，而不是平台能力不足

### 6.2 对 Trusted-DNS 的适配优势

- 请求 / 响应模型与当前实现完全一致
- 二进制协议处理路径成熟
- Web Crypto 适配自然
- DoH 转发实现路径已验证
- Durable Objects 与 generation 状态模型匹配度高

### 6.3 对 Trusted-DNS 的适配风险

- 当前实现对单一 `ROOT_SEED` 假设绑定较深
- replay 与 isolate 语义仍有平台层限制
- 若不先抽离核心层，后续跨平台会持续被 Cloudflare API 绑住

### 6.4 v2 角色建议

Cloudflare Workers 应承担以下职责：

- v2 多 client 正式实现
- 核心流程正确性的基准版本
- 其他平台 PoC 的行为参考

### 6.5 总评

Cloudflare Workers 是 v2 的**主线平台**，不应与其他平台并列推进复杂度，而应优先完成：

- 多 client 架构
- refresh 语义补强
- 核心层抽离

## 7. Deno Deploy

### 7.1 平台定位

Deno Deploy 在 v2 中的定位是第一 PoC 平台。

它的价值不在于“替代 Cloudflare”，而在于验证：

- service-core 是否足够平台无关
- 最小状态模型是否能映射到 `Deno KV`
- 当前协议与加密逻辑是否真正依赖某个特定 Worker 运行时

### 7.2 对 Trusted-DNS 的适配优势

- 运行时能力完整
- 标准 Deno runtime，调试与本地开发路径更直接
- `Deno KV` 可承载最小状态模型
- 对 Web 标准与 TypeScript 友好
- 对抽离后的服务核心复用度预期较高

### 7.3 对 Trusted-DNS 的适配风险

- 运行时能力过强，容易诱导实现偏离“轻量化、无状态”原则
- 状态层虽然可用，但其语义与 Durable Objects 不完全相同
- 如果 PoC 目标不收敛，容易不自觉做成“另一套完整平台实现”

### 7.4 在 v2 中的正确使用方式

Deno Deploy PoC 应只回答三个问题：

1. Bootstrap 能否跑通
2. Query 能否跑通
3. Refresh 能否跑通

PoC 不应提前追求：

- 全套生产部署文档
- 复杂运维模型
- 全面对齐 Cloudflare 的控制面功能

### 7.5 总评

Deno Deploy 是最适合验证“平台无关核心是否成立”的平台，因此建议作为**第一 PoC 平台**。

## 8. Fastly Compute

### 8.1 平台定位

Fastly Compute 在 v2 中的定位是第二 PoC 平台。

它的价值主要在于验证：

- Worker 核心能否适应 Wasm 风格边缘运行时
- 二进制协议与高性能边缘计算模式是否天然兼容
- 最小状态模型能否被合理映射到 Fastly 数据能力

### 8.2 对 Trusted-DNS 的适配优势

- 边缘执行模型强
- 面向计算型边缘工作负载
- 支持 fetch
- 支持边缘数据存储能力
- 适合长期探索“协议型边缘服务”的另一种落地方式

### 8.3 对 Trusted-DNS 的适配风险

- 与当前 Cloudflare 代码结构差异更大
- 状态能力的映射方式需要更谨慎设计
- 某些 fetch / backend 语义属于平台特有概念
- 实现复杂度高于 Deno PoC

### 8.4 在 v2 中的正确使用方式

Fastly PoC 应聚焦于：

- 请求入口可行性
- 二进制流处理可行性
- DoH relay 可行性
- 最小状态持久化可行性

PoC 不应追求：

- 全功能生产支持
- 第一期就做完复杂运维与观测整合

### 8.5 总评

Fastly Compute 是最适合作为“第二层可移植性验证”的平台，建议在 Cloudflare 主线稳定、Deno PoC 跑通之后推进。

## 9. 关键能力拆项对比

## 9.1 请求模型

| 项目 | Cloudflare | Deno | Fastly |
|---|---|---|---|
| 标准 `Request/Response` 风格 | 强 | 强 | 中强 |
| 二进制 body 处理 | 强 | 强 | 强 |
| 当前代码迁移阻力 | 低 | 中 | 中高 |

结论：

- Cloudflare 与 Deno 最接近当前实现风格
- Fastly 可以适配，但需要更清晰的 adapter 边界

## 9.2 密码学能力

| 项目 | Cloudflare | Deno | Fastly |
|---|---|---|---|
| Web Crypto 风格适配 | 强 | 强 | 中 |
| 与现有 TS crypto 逻辑贴合度 | 强 | 强 | 中 |
| 需要平台特化封装的可能性 | 低 | 低 | 中 |

结论：

- Cloudflare 和 Deno 对现有 TypeScript crypto 路径更自然
- Fastly 需要更明确的 crypto 适配验证

## 9.3 状态模型适配

| 项目 | Cloudflare | Deno | Fastly |
|---|---|---|---|
| 最小 generation 状态适配度 | 强 | 强 | 中 |
| client registry 承载适配度 | 强 | 强 | 中 |
| 当前实现迁移成本 | 低 | 中 | 中高 |

结论：

- Cloudflare 是最顺手的主实现
- Deno 是最适合做“状态模型迁移验证”的 PoC
- Fastly 更适合验证“是否可做”，而不是第一阶段追求工程完整度

## 9.4 DoH relay 能力

| 项目 | Cloudflare | Deno | Fastly |
|---|---|---|---|
| 直接 `fetch` DoH upstream | 强 | 强 | 强 |
| 与当前 resolver 策略贴合度 | 强 | 强 | 中强 |
| 需要平台特化处理 | 低 | 低 | 中 |

结论：

- 三个平台都具备 DoH relay 基础能力
- Fastly 需要更仔细处理其平台特有网络抽象

## 10. 迁移与实施难度比较

| 维度 | Cloudflare | Deno | Fastly |
|---|---|---|---|
| 代码迁移难度 | 低 | 中 | 中高 |
| 状态后端替换难度 | 低 | 中 | 中高 |
| 运行时差异适配难度 | 低 | 中 | 中高 |
| 文档与运维模型新增工作量 | 中 | 中 | 高 |

结论：

- Cloudflare 适合先做正式交付
- Deno 适合先做轻量 PoC
- Fastly 适合在核心层稳定后再推进

## 11. v2 角色建议

### 11.1 Cloudflare

建议角色：

- 正式实现
- 第一发布目标
- 行为基准平台

### 11.2 Deno

建议角色：

- 第一 PoC
- 架构可移植性验证平台

### 11.3 Fastly

建议角色：

- 第二 PoC
- 高性能边缘运行时验证平台

## 12. 推荐推进顺序

推荐的实施顺序如下：

1. 完成 Cloudflare 主线的多 client 设计与实现
2. 在此基础上提炼平台无关核心
3. 使用 Deno Deploy 验证核心层的第一轮可移植性
4. 使用 Fastly Compute 验证第二轮可移植性

不建议：

- 三个平台并行大改
- 在 Cloudflare 主线未稳定前就重压 PoC

## 13. 最终判断

站在 Trusted-DNS v2 的目标上看，三个平台不是“谁替代谁”的关系，而是分工不同：

- **Cloudflare Workers**：负责把 v2 真正做出来
- **Deno Deploy**：负责证明 v2 核心不是 Cloudflare 专属实现
- **Fastly Compute**：负责证明 v2 核心具备进入更强边缘计算环境的潜力

因此，平台策略的正确表达应是：

- **主平台唯一**
- **PoC 平台有限**
- **实现节奏分层**
