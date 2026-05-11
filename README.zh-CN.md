# Trusted-DNS

[English](README.md) | [简体中文](README.zh-CN.md)

**Trusted-DNS** 是一个专为受污染网络环境设计的开源 DNS 系统。它通过在本地 Docker 节点和 Cloudflare Worker 之间建立安全的加密私有协议，将 DNS 查询路由到受信任的 DoH（DNS over HTTPS）上游解析器，从而有效缓解本地 ISP 的 DNS 污染问题。

## 架构概览

Trusted-DNS 采用 **Cloudflare Worker + 本地 Docker 节点** 的双侧架构。Docker 节点接管本地的 `53/UDP` 端口，使用紧凑的二进制协议加密 DNS 查询，并通过 HTTPS 发送给 Worker。Worker 负责验证票据、管理代际状态，并将标准的 DNS 报文转发给符合 [RFC 8484](https://datatracker.ietf.org/doc/html/rfc8484) 规范的 DoH 上游。

```text
┌─────────────────────────────┐
│        局域网 / 主机客户端     │
│   手机、浏览器、存根解析器       │
└──────────────┬──────────────┘
               │ 标准 DNS (53/UDP)
               ▼
┌─────────────────────────────┐
│      Trusted-DNS Docker     │
│  DNS 监听器                  │
│  会话管理器                   │
│  安全传输层                   │
│  探测引擎                     │
│  响应重排器                   │
└──────────────┬──────────────┘
               │ HTTPS + 二进制密文
               ▼
┌─────────────────────────────┐
│     Trusted-DNS Worker      │
│  引导 / 查询 / 刷新 API       │
│  票据验证器                   │
│  代际状态存储 (DO)            │
└──────────────┬──────────────┘
               │ DoH (HTTP POST)
               ▼
┌─────────────────────────────┐
│      DoH 上游解析器           │
│   Google / Cloudflare 等    │
└─────────────────────────────┘
```

## 当前范围（v1）

Trusted-DNS v1 当前有意限定为 **单 Docker 节点 ↔ 单 Worker 部署** 的系统：

- Worker 从自身配置的 `ROOT_SEED` 派生唯一稳定的 `client_id`
- Docker 节点必须与该 Worker 部署使用相同的 `ROOT_SEED`
- 一个 Worker 部署当前只管理一个客户端命名空间和一条代际生命周期

协议中已经预留了 `spent_bundle_gen`、`spent_query_count`、`refresh_proof` 等字段用于向前兼容，但在 v1 中它们是为未来 **一个 Worker 服务多个 client** 的升级路径预埋的保留字段。当前实现中，刷新阶段的权威凭据仍然是 `refresh ticket`。

## 核心特性

**安全与隐私**

- **抗 DPI 审查 (v1.1)**: 动态随机 Payload 填充与 HTTP 头伪装，有效绕过深度包检测与流量特征识别。
- Docker 与 Worker 之间的通信使用 AES-256-GCM 加密，密钥通过 HKDF 派生且按用途隔离
- 基于票据的会话管理，支持代际轮转（Worker 端无需维护持久化会话表）
- 短窗口防重放保护，结合序列号验证
- 零 DNS 查询历史：绝不持久化存储 QNAME、QTYPE 或应答内容
- 极简状态：每个客户端仅在 Durable Object 中存储 `client_id → latest_bundle_gen`
- 稳健传输：细粒度的连接超时与 Context 控制，彻底解决跨网静默丢包与半开连接问题。

**性能优化**

- 热路径查询使用轻量级 HMAC 票据验证（无需每次查询都进行完整握手）
- “主备竞速 + 三级回退”的上游策略，确保最佳延迟和高可用性
- 可选的 A/AAAA 记录探测与重排功能，提升实际连接质量
- 紧凑的二进制协议（热路径上无 JSON 解析开销）

**部署便捷**

- Docker 镜像支持 **多架构** 构建（amd64 / arm64）
- 单一 `docker-compose.yml` 即可完成部署，配置极简
- Worker 端一键部署至 Cloudflare Workers，利用 Durable Objects 管理状态

## 验证测试

以下端到端测试基于一个已部署的 Worker 实例和一个实际运行的 Docker 节点完成。Bootstrap 握手一次成功，所有加密查询/响应往返均无错误。

```text
$ docker run -d --name trusted-dns \
  -p 53:53/udp \
  -e WORKER_URL="https://your-worker.example.com" \
  -e ROOT_SEED="$(openssl rand -hex 32)" \
  ghcr.io/neon9809/trusted-dns-docker:latest

$ docker logs trusted-dns
[main] Trusted-DNS Docker node starting...
[main] client_id_prefix: 4a545d971cb4372e
[transport] starting bootstrap...
[transport] bootstrap success: gen=1, tickets=5
[session] installed bundle gen=1 with 5 tickets, budget=1000
[listener] DNS listener started on 0.0.0.0:53
[main] Trusted-DNS Docker node ready
```

```text
$ dig @127.0.0.1 google.com A +short
142.251.140.238

$ dig @127.0.0.1 cloudflare.com A +short
104.16.132.229
104.16.133.229

$ dig @127.0.0.1 github.com A +short
140.82.121.3

$ dig @127.0.0.1 baidu.com A +short
110.242.74.102
124.237.177.164
111.63.65.247
111.63.65.103

$ dig @127.0.0.1 google.com AAAA +short
2a00:1450:4003:818::200e

$ dig @127.0.0.1 gmail.com MX +short
5 gmail-smtp-in.l.google.com.
10 alt1.gmail-smtp-in.l.google.com.
20 alt2.gmail-smtp-in.l.google.com.
30 alt3.gmail-smtp-in.l.google.com.
40 alt4.gmail-smtp-in.l.google.com.
```

所有记录类型（A、AAAA、MX）均正确解析。响应重排器还对多记录应答进行了重排，以提升实际连接质量。

## 日志解读

Docker 节点不会为每一次 DNS 查询都打印一条 `rewriter` 日志。
`[rewriter] reordered N records` 只会在某一次 DNS 响应中包含多个
A/AAAA 应答记录，并且重排器完成探测与重排后才打印。它**不是**
“处理了 N 次查询”的意思，也不能拿来当作会话刷新阈值的计数器。

| 查询 / 响应形态 | 是否消耗一次 query budget / ticket sequence | 是否打印 `[rewriter] reordered N records` | 说明 |
|---|---|---|---|
| 只有一个 IP 的 A 或 AAAA 响应 | 是 | 否 | 请求仍然会经过 Worker，并消耗一次查询序号，但没有可重排的地址。 |
| 包含多个 IP 的 A 或 AAAA 响应 | 是 | 通常会 | 探测引擎会对返回地址做排序，重排器会为这一次响应打印一条日志，其中 `N` 是被重排的应答记录数。 |
| MX / CNAME / TXT / 其他非 A/AAAA 应答 | 是 | 否 | 这些请求同样会消耗查询额度，但重排器只处理 A/AAAA 地址排序。 |
| 没有 answer 的 DNS 响应 | 是 | 否 | 只要请求已经通过 Worker 发出，即使响应为空，也会消耗一次查询序号。 |
| 由于 `totalQueries >= threshold` 触发 refresh | 日志本身不会额外消耗新查询 | 否 | Refresh 走的是独立的 refresh 请求。触发依据是内部 `totalQueries` 计数，而不是你能看到的 `rewriter` 日志条数。 |
| 由于 `approaching expiration` 触发 refresh | 日志本身不会额外消耗新查询 | 否 | 即使你只看到很少几条 `rewriter` 日志，也可能因为 bundle 即将过期而触发 refresh。时间阈值与查询条数是独立判断的。 |

简而言之，如果只盯着 `docker logs` 里的 `rewriter` 行，通常会明显低估
真实 DNS 请求量。很多成功查询不会打印 `rewriter` 日志，但它们依然会
消耗 ticket/query 额度，也依然可能推动会话进入 refresh。

## 快速开始

### 前置要求

- 一个启用了 Workers 和 Durable Objects 的 Cloudflare 账号
- 本地机器或网关上已安装 Docker 和 Docker Compose
- 一个共享密钥（ROOT_SEED）：可使用 `openssl rand -hex 32` 生成

### 1. 部署 Worker

**选项 A：一键部署（推荐）**

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/neon9809/trusted-DNS/tree/main/platform/worker)

*注意：部署过程中会提示输入 `ROOT_SEED`。请使用 `openssl rand -hex 32` 生成一个 64 字符的十六进制字符串。*

**选项 B：手动部署**

```bash
cd platform/worker
cp ../../examples/worker.env.example .env

# 在 wrangler.toml 中配置你的 ROOT_SEED 和 DoH 上游
pnpm install
pnpm deploy
```

在 `wrangler.toml` 或 Worker Secrets 中配置以下变量：

```toml
[vars]
ROOT_SEED = "你的-64字符-十六进制-密钥"
DOH_UPSTREAMS = '["https://dns.google/dns-query","https://cloudflare-dns.com/dns-query","https://1.1.1.1/dns-query"]'
```

### 2. 部署 Docker 节点

```bash
cp examples/docker-compose.example.yml docker-compose.yml

# 在 docker-compose.yml 中填入你的 Worker URL 和 ROOT_SEED
docker compose up -d
```

或者直接从 GitHub Container Registry 拉取镜像：

```bash
docker pull ghcr.io/neon9809/trusted-dns-docker:latest
```

### 3. 配置设备

将设备的 DNS 设置指向 Docker 节点的 IP 地址。例如，如果 Docker 节点运行在 `192.168.1.100`：

- **路由器**：将主 DNS 设置为 `192.168.1.100`
- **个人设备**：将 DNS 服务器设置为 `192.168.1.100`

## 配置说明

### Docker 节点环境变量

| 变量 | 是否必填 | 默认值 | 说明 |
|---|---|---|---|
| `WORKER_URL` | 是 | — | Cloudflare Worker 的访问地址 |
| `ROOT_SEED` | 是 | — | 共享的 64 字符十六进制密钥 |
| `PROBE_MODE` | 否 | `tcp443` | 探测模式：`none`, `tcp443`, `icmp`, `icmp,tcp443` |
| `LISTEN_ADDR` | 否 | `0.0.0.0:53` | DNS 监听地址 |
| `PROTOCOL_PATH` | 否 | `/dns-query` | 自定义协议端点路径（必须与 Worker 端一致） |

### Worker 环境变量

| 变量 | 是否必填 | 默认值 | 说明 |
|---|---|---|---|
| `ROOT_SEED` | 是 | — | 共享的 64 字符十六进制密钥（必须与 Docker 端一致） |
| `DOH_UPSTREAMS` | 是 | — | DoH 上游 URL 的 JSON 数组 |
| `DOH_TIMEOUT_MS` | 否 | `5000` | 每个上游的超时时间（毫秒） |
| `PROTOCOL_PATH` | 否 | `/dns-query` | 自定义协议端点路径（必须与 Docker 端一致） |

## 部署范围与多节点说明

**Trusted-DNS v1 当前支持一个 Worker 部署对应一个 Docker 节点。** Worker 只会从自身配置的 `ROOT_SEED` 派生出一个活动 `client_id`，因此今天支持的拓扑是：

```text
Docker 节点 A  <->  Worker 部署 A  (ROOT_SEED_A)
Docker 节点 B  <->  Worker 部署 B  (ROOT_SEED_B)
```

下面这几种组合需要区分清楚：

| 场景 | 结果 |
|---|---|
| **两个 Docker 节点共享同一个 `ROOT_SEED` 且连接同一个 Worker** | 两个节点会派生出相同的 `client_id`，在引导、查询序列空间和刷新代际状态上发生碰撞。 |
| **两个 Docker 节点使用不同 `ROOT_SEED` 但连接同一个 Worker 部署** | 认证会失败，因为 Worker 只会基于自身配置的 `ROOT_SEED` 派生密钥和 `client_id`，当前并不会在同一部署内复用多个客户端命名空间。 |
| **两个 Docker 节点分别使用独立 Worker 部署和独立 `ROOT_SEED`** | 这是当前 v1 的受支持部署方式。 |

如果今天要运行多个节点，应为每个节点分别部署一个 Worker，并单独生成对应的 `ROOT_SEED`：

```bash
# 节点 A
ROOT_SEED=$(openssl rand -hex 32)

# 节点 B
ROOT_SEED=$(openssl rand -hex 32)
```

未来版本可能会允许一个 Worker 部署同时服务多个 client。协议里已经保留了刷新认证相关字段作为这条升级路径的扩展位，但 v1 还没有启用这一模式。

## 协议概述

Trusted-DNS 使用三阶段协议模型：

| 阶段 | 目的 | 频率 |
|---|---|---|
| **Bootstrap (引导)** | 初始身份验证并签发首个 KeyBundle | 低 |
| **Query (查询)** | 使用会话票据进行加密 DNS 查询 | 高 |
| **Refresh (刷新)** | 获取下一代 KeyBundle | 中低 |

每个 `KeyBundle` 包含 **5 张会话票据**（每张可查询 200 次）和 **1 张刷新票据**，每代总计提供 **1000 次查询额度**。这种设计避免了热路径上的完整握手，同时保持了清晰的安全语义。

在当前 v1 实现中，Refresh 请求里的 `spent_bundle_gen`、`spent_query_count`、`refresh_proof` 属于向前兼容字段，预留给未来的多 client Worker 模式使用；它们目前还不是独立决定是否接受刷新请求的强制条件。

详细的协议规范请参阅 [docs/protocol.md](docs/protocol.md)。

## 安全模型

Trusted-DNS 的设计目标是 **降低最直接、最现实的污染和篡改风险**，而不是实现绝对的不可观测性。关键安全属性包括：

- **防污染**：DNS 查询完全绕过本地明文 DNS 路径
- **链路机密性**：Docker 到 Worker 的流量经过加密
- **链路完整性**：AEAD 认证防止静默篡改
- **会话短暂性**：票据和密钥仅驻留在内存中
- **代际失效**：新的引导/刷新会使旧代际失效
- **基础防重放**：序列号和短窗口去重

当前安全边界基于 **单 Docker 节点配对单 Worker 部署** 的前提建立。同一 Worker 部署内的多 client 隔离被明确留到未来版本实现。

完整的威胁模型请参阅 [docs/threat-model.md](docs/threat-model.md)。

## 许可证

本项目基于 [MIT License](LICENSE) 开源。

## 致谢

本项目的初始方向、功能约束和安全边界源自 **neon9809** 围绕以下问题的持续探索与迭代：如何对抗本地 ISP 的 DNS 污染；如何将系统拆分为 Worker 侧和 Docker 侧；以及如何在 Cloudflare Worker 的平台限制下，将这些目标收敛为一个真正可部署的开源项目。本项目的文档、协议规范、架构设计和代码实现均由 **Manus AI** 基于上述需求系统性开发完成。
