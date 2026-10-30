# LiteDog

轻量级网站 / 网络检测工具箱，零依赖 Node.js 实现，部署于 Vercel（免费 Hobby 计划）。

在线访问：https://ping00.cc.cd

## 功能

- **IP 检测**：出口 IPv4/IPv6、归属地（国家 / 地区 / 城市 / 经纬度 / 时区）、Vercel 边缘节点
- **网站测速**：HTTP 测速，DNS / TCP / TLS / TTFB / 下载 分阶段耗时
- **Ping 测试**：TCP 握手模拟 Ping，丢包率与延迟统计
- **DNS 查询**：A / AAAA / CNAME / MX / NS / TXT / SOA / CAA
- **端口检测**：常用端口与自定义端口扫描
- **HTTP 检测**：状态码、响应头、重定向链、TLS 信息
- **分流测试**：多端点出口 IP 对比，判断代理 / 分流
- **WebRTC 泄露检测**：浏览器本地收集候选 IP 并分类
- **IP 质量检测**：默认检测访客出口 IP，也支持在顶部查询框输入任意 IP 或域名（`/api/ipcheck?host=`）。基于 IPinfo + ip-api.com + Scamalytics，识别 IP 类型（机房 / 住宅 / 移动 / 代理）、风控值、Scamalytics 欺诈值、CIDR 网段、原生/广播、共享人数、场景评分

## 项目结构

```
.
├── vercel.json          # Vercel 配置（函数 maxDuration）
├── package.json
├── lib/
│   ├── core.js          # 核心逻辑（原 server.js），导出 route
│   └── handler.js       # Vercel Serverless Function 包装
├── api/                 # Vercel Serverless Functions
│   ├── ip.js
│   ├── http.js
│   ├── ping.js
│   ├── dns.js
│   ├── port.js
│   ├── headers.js
│   └── nodeinfo.js
└── public/
    └── index.html       # 前端单页
```

## 部署

- Vercel 项目设置：`framework = null`、`outputDirectory = public`
  （避免 Vercel 把根目录误判为 Node.js Server 入口）
- 已连接 GitHub，`main` 分支 push 即自动部署
- 函数最长执行 60s（`vercel.json` 的 `maxDuration`）
- 环境变量 `IPINFO_TOKEN`（IPinfo 访问令牌，用于 IP 质量检测）

## 本地运行

```bash
node lib/core.js            # 默认监听 3000 端口
# 或
PORT=3333 node lib/core.js
```

本地调试 IP 质量检测时，可设置 `LITEDOG_TEST_IP` 模拟公网客户端 IP（否则本机 127.0.0.1 会被判为私有 IP 拒绝检测）：

```bash
LITEDOG_TEST_IP=8.8.8.8 node lib/core.js
```

## 界面

- 默认黑夜模式，右上角 ☀️/🌙 可切换白天/黑夜并记住选择（localStorage）
- IP 质量检测卡片采用描边徽章 + 纯净度渐变条（参考 ping0.cc 风格），纯净度优先基于 Scamalytics 欺诈值计算
- 检测详情以竖排行式展示（图标 + 标签 + 值），全站字号为大号字体

## 说明

- 零第三方依赖，全部基于 Node.js 内置模块
- 检测结果仅供参考