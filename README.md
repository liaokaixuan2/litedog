# LiteDog · 轻量级网站检测工具

受 [itdog.cn](https://www.itdog.cn/) 启发的轻量级网站检测工具：单文件前端 + 零依赖 Node.js 后端，可一键部署到 Render 等平台。

## 功能

- **网站测速**：对目标 URL 发起真实 HTTP 请求，给出 DNS / TCP / TLS / 首字节 / 下载 各阶段耗时与总耗时；支持浏览器本地节点对照
- **Ping 测试**：基于 TCP 握手的 Ping（可指定端口），流式实时输出每次结果与丢包率
- **DNS 查询**：A / AAAA / CNAME / MX / NS / TXT / SOA / CAA 记录
- **端口检测**：20 个常用端口批量检测，或自定义端口（最多 12 个）
- **HTTP 检测**：状态码、重定向链、TLS 信息、完整响应头

## 本地运行

```bash
node server.js
# 打开 http://localhost:3000
```

## 部署到 Render

1. 将本仓库推送到 GitHub
2. 在 Render 创建 Web Service，运行时选择 Node
3. Build Command: `npm install`，Start Command: `npm start`

免费实例闲置约 15 分钟会休眠，首次访问需等待唤醒。

## 安全说明

- 后端对目标地址做了 SSRF 防护：拒绝解析到私有/保留 IP 的目标
- 响应体超过 2MB 截断，单次请求超时 10 秒

仅用于网络诊断与学习，请勿用于非法用途。
