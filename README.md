# LiteDog

轻量级网站 / 网络检测工具箱，零依赖 Node.js 实现，部署于 Vercel（免费 Hobby 计划）。

在线访问：https://ping00.cc.cd

## 功能

- **IP 检测**：出口 IPv4/IPv6、归属地（国家 / 地区 / 城市 / 经纬度 / 时区）、Vercel 边缘节点
- **网站测速**：HTTP 测速，DNS / TCP / TLS / TTFB / 下载 分阶段耗时
- **Ping 测试**：基于 Globalping 探针的拨测，支持 ICMP Ping（4 包，延迟 / 丢包率）与网站测速（HTTP 分阶段耗时 / 状态码）；可切换「全国测试」（中国区探针，默认）/「全球测试」（全球探针），进入 Ping 标签页自动用访客出口 IP 发起全国测试，结果逐探针实时刷新
- **延迟地图**：全国测试显示中国省份地图、全球测试显示世界地图（ECharts 5，本地自托管于 `public/vendor/`），按区域着色：≤50ms 深绿 / 51-100 绿 / 101-200 黄绿 / 201-250 黄 / >250 橙 / 全超时红 / 无探针灰，支持缩放拖动与悬停查看区域聚合详情
- **DNS 查询**：A / AAAA / CNAME / MX / NS / TXT / SOA / CAA
- **端口检测**：常用端口与自定义端口扫描
- **HTTP 检测**：状态码、响应头、重定向链、TLS 信息
- **分流测试**：多端点出口 IP 对比，判断代理 / 分流
- **WebRTC 泄露检测**：浏览器本地收集候选 IP 并分类
- **访客统计**（可选，需配置 Upstash）：每次页面加载自动记录访客 IP / UA / 来源到 Upstash Redis（按北京时间切日，保留 30 天）。访问 `/stats`（需密钥）查看每日独立访客数、访问次数与 IP 明细列表（含归属地 / 运营商 / ASN，经 ip-api.com 查询并缓存）。未配置环境变量时统计自动空转，不影响任何功能
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
│   ├── globalping.js
│   ├── dns.js
│   ├── port.js
│   ├── headers.js
│   ├── nodeinfo.js
│   ├── stats.js         # 访客统计读取(需 STATS_KEY)
│   └── ipgeo.js         # IP 归属地查询(需 STATS_KEY)
├── stats.html           # 访客统计管理页(/stats,需密钥)
└── public/
    ├── index.html       # 前端单页
    ├── stats.html       # 同 stats.html(Vercel 静态服务用)
    └── vendor/          # 本地静态资源（echarts.min.js / china.json / world.json 地图数据）
```

## 部署

- Vercel 项目设置：`framework = null`、`outputDirectory = public`
  （避免 Vercel 把根目录误判为 Node.js Server 入口）
- 已连接 GitHub，`main` 分支 push 即自动部署
- 函数最长执行 60s（`vercel.json` 的 `maxDuration`）
- 环境变量 `IPINFO_TOKEN`（IPinfo 访问令牌，用于 IP 质量检测）
- 环境变量 `GLOBALPING_TOKEN`（Globalping API 令牌，用于评测标签页；未设置时使用代码内内置 token）
- 环境变量 `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN`（Upstash Redis REST 凭据，用于访客统计存储；免费版即可）
- 环境变量 `STATS_KEY`（访客统计页 `/stats` 的访问密钥，自定义任意字符串；未设置时统计接口返回 403）
- 访客统计开启步骤：upstash.com 免费注册（GitHub 登录）→ Create Database（REST API 区域任意）→ 把 REST URL 与 REST TOKEN 填入 Vercel 环境变量 → 自定义 `STATS_KEY` → Redeploy 后访问 `https://ping00.cc.cd/stats`。免费版每日约 1 万条命令（每次访问消耗 5 条），超出后统计自动静默停止，不影响网站

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
- 检测详情以双列信息行展示（图标 + 标签 + 值），结果全自动翻译为中文（ip-api 中文数据 + Google 翻译兜底），整页紧凑单屏展示
- 全站各测试输入框默认自动填入访客出口 IP（网址类输入框自动补 `http://` 前缀；仅填空框，不打断手动输入）

## 说明

- 零第三方依赖，全部基于 Node.js 内置模块
- 检测结果仅供参考