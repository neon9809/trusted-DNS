# Trusted-DNS

[English](README.md) | [简体中文](README.zh-CN.md)

**Trusted-DNS** 是一个专为受污染网络环境设计的开源 DNS 系统。它通过在本地 Docker 节点和 Cloudflare Worker 之间建立安全的加密私有协议，将 DNS 查询路由到受信任的 DoH（DNS over HTTPS）上游解析器，从而有效缓解本地 ISP 的 DNS 污染问题。

## 架构概览

Trusted-DNS 采用 **Cloudflare Worker + 本地 Docker 节点** 的双侧架构。Docker 节点接管本地的 `53/UDP` 端口，使用紧凑的二进制协议加密 DNS 查询，并通过 HTTPS 发送给 Worker。Worker 负责验证票据、管理代际状态，并将标准的 DNS 报文转发给符合 [RFC 8484](https://datatracker.ietf.org/doc/html/rfc8484) 规范的 DoH 上游。

```text
┌─────────────────────────────┐
│        局域网 / 主机客户端    │
│   手机、浏览器、存根解析器    │
└──────────────┬──────────────┘
               │ 标准 DNS (53/UDP)
               ▼
┌─────────────────────────────┐
│      Trusted-DNS Docker      │
│  DNS 监听器                  │
│  会话管理器                  │
│  安全传输层                  │
│  探测引擎                    │
│  响应重排器                  │
└──────────────┬──────────────┘
               │ HTTPS + 二进制密文
               ▼
┌─────────────────────────────┐
│     Trusted-DNS Worker       │
│  引导 / 查询 / 刷新 API      │
│  票据验证器                  │
│  代际状态存储 (DO)           │
└──────────────┬──────────────┘
               │ DoH (HTTP POST)
               ▼
┌─────────────────────────────┐
│      DoH 上游解析器          │
│   Google / Cloudflare 等     │
└─────────────────────────────┘
```

## 核心特性

**安全与隐私**

- Docker 与 Worker 之间的通信使用 AES-256-GCM 加密，密钥通过 HKDF 派生且按用途隔离
- 基于票据的会话管理，支持代际轮转（Worker 端无需维护持久化会话表）
- 短窗口防重放保护，结合序列号验证
- 零 DNS 查询历史：绝不持久化存储 QNAME、QTYPE 或应答内容
- 极简状态：每个客户端仅在 Durable Object 中存储 `client_id → latest_bundle_gen`

**性能优化**

- 热路径查询使用轻量级 HMAC 票据验证（无需每次查询都进行完整握手）
- “主备竞速 + 三级回退”的上游策略，确保最佳延迟和高可用性
- 可选的 A/AAAA 记录探测与重排功能，提升实际连接质量
- 紧凑的二进制协议（热路径上无 JSON 解析开销）

**部署便捷**

- Docker 镜像支持 **多架构** 构建（amd64 / arm64）
- 单一 `docker-compose.yml` 即可完成部署，配置极简
- Worker 端一键部署至 Cloudflare Workers，利用 Durable Objects 管理状态

## 快速开始

### 前置要求

- 一个启用了 Workers 和 Durable Objects 的 Cloudflare 账号
- 本地机器或网关上已安装 Docker 和 Docker Compose
- 一个共享密钥（ROOT_SEED）：可使用 `openssl rand -hex 32` 生成

### 1. 部署 Worker

**选项 A：一键部署（推荐）**

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/neon9809/trusted-DNS/tree/main/worker)

*注意：部署过程中会提示输入 `ROOT_SEED`。请使用 `openssl rand -hex 32` 生成一个 64 字符的十六进制字符串。*

**选项 B：手动部署**

```bash
cd worker
cp ../examples/worker.env.example .env

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

### Worker 环境变量

| 变量 | 是否必填 | 默认值 | 说明 |
|---|---|---|---|
| `ROOT_SEED` | 是 | — | 共享的 64 字符十六进制密钥（必须与 Docker 端一致） |
| `DOH_UPSTREAMS` | 是 | — | DoH 上游 URL 的 JSON 数组 |
| `DOH_TIMEOUT_MS` | 否 | `5000` | 每个上游的超时时间（毫秒） |

## 协议概述

Trusted-DNS 使用三阶段协议模型：

| 阶段 | 目的 | 频率 |
|---|---|---|
| **Bootstrap (引导)** | 初始身份验证并签发首个 KeyBundle | 低 |
| **Query (查询)** | 使用会话票据进行加密 DNS 查询 | 高 |
| **Refresh (刷新)** | 获取下一代 KeyBundle | 中低 |

每个 `KeyBundle` 包含 **5 张会话票据**（每张可查询 200 次）和 **1 张刷新票据**，每代总计提供 **1000 次查询额度**。这种设计避免了热路径上的完整握手，同时保持了清晰的安全语义。

详细的协议规范请参阅 [docs/protocol.md](docs/protocol.md)。

## 安全模型

Trusted-DNS 的设计目标是 **降低最直接、最现实的污染和篡改风险**，而不是实现绝对的不可观测性。关键安全属性包括：

- **防污染**：DNS 查询完全绕过本地明文 DNS 路径
- **链路机密性**：Docker 到 Worker 的流量经过加密
- **链路完整性**：AEAD 认证防止静默篡改
- **会话短暂性**：票据和密钥仅驻留在内存中
- **代际失效**：新的引导/刷新会使旧代际失效
- **基础防重放**：序列号和短窗口去重

完整的威胁模型请参阅 [docs/threat-model.md](docs/threat-model.md)。

## 许可证

本项目基于 [MIT License](LICENSE) 开源。

## 致谢

本项目的初始方向、功能约束和安全边界源自 **neon9809** 围绕以下问题的持续探索与迭代：如何对抗本地 ISP 的 DNS 污染；如何将系统拆分为 Worker 侧和 Docker 侧；以及如何在 Cloudflare Worker 的平台限制下，将这些目标收敛为一个真正可部署的开源项目。本项目的文档、协议规范、架构设计和代码实现均由 **Manus AI** 基于上述需求系统性开发完成。
