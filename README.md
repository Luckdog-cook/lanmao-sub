> ## ⚠️ 刺猬VPN（HedgeVPN）分区：节点无法在第三方客户端使用
>
> 服务端在 VLESS 协议层加入了 **HedgeAuth 设备认证**（定制 xray 分支 `Xray-core-26.5.3`，
> `proxy/vless.IsHedgeAuthEnabled` + `libxray.SetHedgeDeviceId` + 本地 XHTTP/UNIX socket 隧道，
> 需要 device secret）。**标准客户端（Clash Meta / sing-box / Bettbox / v2rayN / 原版 xray）
> 无法通过认证，连接必然超时**，与配置无关。
>
> 下面的脚本与订阅文件仅作协议研究留存，**实际不可连接**。定时任务已停用。

# 星链 VPN 订阅自动更新

自动从星连 VPN API 实时抓取最新国内 + 国际节点，生成三种格式的配置文件，并通过 GitHub Actions 定时更新。

## 功能特性

- 实时获取最新节点（每次运行都重新请求 API）
- 同时支持 **国内 (CN)** 和 **国际 (Global)** 节点
- 输出三种格式：
  - `safevpn_sub.txt` — 纯 VLESS / Hysteria2 订阅链接（通用）
  - `clash.yaml` — Clash Meta / Mihomo 配置
  - `sing-box.json` — sing-box 配置
- Token / Device ID 支持环境变量覆盖，方便随时更新
- GitHub Actions 每 2 小时自动更新，有变化才提交

## 文件说明

| 文件 | 说明 |
|------|------|
| `星链.py` | 主脚本 |
| `safevpn_sub.txt` | 纯订阅文本（可直接导入大多数客户端） |
| `clash.yaml` | Clash Meta 完整配置 |
| `sing-box.json` | sing-box 完整配置 |
| `.github/workflows/update-sub.yml` | 自动更新工作流 |

## 快速使用（本地）

### 1. 安装依赖

```bash
pip install pycryptodome pyyaml
# 或者只用 cryptography（脚本会自动回退）
```

### 2. 运行

```bash
python 星链.py
```

运行后会在当前目录（或 Android 的 Download 目录）生成三个文件。

### 3. 自定义 Token / 输出目录

```bash
export SINGLINK_TOKEN="你的新Token"
export SINGLINK_DEVICE="你的设备ID"
export OUTPUT_DIR="."          # 强制输出到当前目录
python 星链.py
```

## 部署到 GitHub（推荐）

### 步骤 1：创建仓库

1. 在 GitHub 新建一个**公开或私有**仓库（建议私有）
2. 把本项目的以下文件上传上去：
   - `星链.py`
   - `.github/workflows/update-sub.yml`
   - `README.md`（可选）

### 步骤 2：配置 Secrets

进入仓库 **Settings → Secrets and variables → Actions**，添加：

| Name | 必填 | 说明 |
|------|------|------|
| `SINGLINK_TOKEN` | 是 | 你的 JWT Token |
| `SINGLINK_DEVICE` | 否 | 设备 ID（有默认值） |

> Token 过期或失效时，只需更新这个 Secret，下次运行就会自动使用新 Token。

### 步骤 3：启用 Actions

1. 进入仓库 **Actions** 页面
2. 选择 **Update SingLink Subscription** 工作流
3. 点击 **Run workflow** 手动跑一次，确认成功

之后会每 **2 小时**自动更新一次。只有节点真正发生变化时才会提交新 commit。

### 步骤 4：获取订阅地址

更新成功后，可直接使用以下 Raw 地址：

```
https://raw.githubusercontent.com/<你的用户名>/<仓库名>/main/safevpn_sub.txt
https://raw.githubusercontent.com/<你的用户名>/<仓库名>/main/clash.yaml
https://raw.githubusercontent.com/<你的用户名>/<仓库名>/main/sing-box.json
```

把它们填入客户端即可。

## 客户端导入示例

### Clash / Mihomo / Clash Meta

直接订阅 `clash.yaml` 地址，或本地打开文件。

### sing-box

使用 `sing-box.json`，或通过 `sing-box run -c sing-box.json` 启动。

### v2rayN / Nekobox / Shadowrocket 等

使用 `safevpn_sub.txt` 作为订阅源。

## 更新频率调整

编辑 `.github/workflows/update-sub.yml` 中的 cron：

```yaml
- cron: '0 */2 * * *'   # 每 2 小时（当前）
- cron: '0 * * * *'     # 每小时
- cron: '0 */6 * * *'   # 每 6 小时
```

## 注意事项

1. 本脚本使用的是星连 VPN 的私有接口，长期高频请求可能触发风控或违反服务条款，请自行承担风险。
2. Token 目前有效期很长，但仍建议定期检查是否还能正常返回节点。
3. 节点列表会随服务端变化，脚本每次都会获取**当时最新**的配置。
4. 建议仓库设为 **Private**，避免订阅链接被公开滥用。

## 常见问题

**Q: 运行后提示“未获取到任何节点”？**  
A: Token 可能已失效，请更新 `SINGLINK_TOKEN` Secret 后重新运行。

**Q: Clash 配置没有生成？**  
A: 需要安装 `pyyaml`：`pip install pyyaml`。

**Q: 想改成只输出某一种格式？**  
A: 直接修改脚本末尾的保存逻辑，或通过环境变量控制输出文件名。

---

仅供学习与个人研究使用。

---

## 飞梭加速器（FaysoVPN）订阅

由 `fayso.py` 抓取，GitHub Actions 每 2 小时自动更新（UTC 偶数整点）。

| 文件 | 适用客户端 |
|------|------------|
| `fayso_clash.yaml` | **Bettbox / FlClash / Clash Verge / CFW（Mihomo 内核）** |
| `fayso_singbox.json` | sing-box 官方客户端 / Hiddify / Karing / NekoBox（SFA 内核） |
| `fayso_sub.txt` | 纯 `hysteria2://` 链接，通用客户端 |
| `fayso_sub_b64.txt` | base64 订阅，v2rayN / Shadowrocket 标准格式 |
| `fayso_nodes.json` | 节点元数据（含延迟、容量） |

> 注意：**Bettbox 是基于 Mihomo 内核的 FlClash 分支，不是 sing-box 客户端**，
> 导入 `fayso_singbox.json` 会显示无节点、无规则，请使用 `fayso_clash.yaml`。

订阅地址（国内可访问）：

```
Bettbox / Clash : https://fastly.jsdelivr.net/gh/Luckdog-cook/lanmao-sub@main/fayso_clash.yaml
sing-box        : https://fastly.jsdelivr.net/gh/Luckdog-cook/lanmao-sub@main/fayso_singbox.json
通用链接        : https://fastly.jsdelivr.net/gh/Luckdog-cook/lanmao-sub@main/fayso_sub.txt
base64 订阅     : https://fastly.jsdelivr.net/gh/Luckdog-cook/lanmao-sub@main/fayso_sub_b64.txt
GitHub Pages    : https://luckdog-cook.github.io/lanmao-sub/fayso_clash.yaml
```

> jsDelivr 对分支引用有 12 小时 CDN 缓存（`s-maxage=43200`），工作流每次更新后会调用
> purge 接口刷新，但边缘节点仍可能滞后。要求立即生效时，在地址末尾加 `?v=2` 换一个缓存键，
> 或用 `cdn.jsdelivr.net` / `fastly.jsdelivr.net` 等镜像交叉验证。

可选 Secrets（不配则每次自动匿名注册试用设备）：
`FAYSO_TOKEN` / `FAYSO_USERNAME` / `FAYSO_PASSWORD`

---

## 极点加速器（jidianvpn.com）订阅

由 `jidian.py` 抓取，GitHub Actions 每 2 小时自动更新（UTC 偶数整点 +30 分）。

| 文件 | 适用客户端 |
|------|------------|
| `jidian_clash.yaml` | **Bettbox / FlClash / Clash Verge（Mihomo 内核）**，含官方 374 条分流规则 |
| `jidian_singbox.json` | sing-box 系（anytls / ss-ws 按真实协议转换） |
| `jidian_sub.txt` | 纯链接（anytls:// / ss://） |
| `jidian_sub_b64.txt` | base64 订阅，v2rayN 等 |

```
Bettbox / Clash : https://gcore.jsdelivr.net/gh/Luckdog-cook/lanmao-sub@main/jidian_clash.yaml
sing-box        : https://gcore.jsdelivr.net/gh/Luckdog-cook/lanmao-sub@main/jidian_singbox.json
通用链接        : https://gcore.jsdelivr.net/gh/Luckdog-cook/lanmao-sub@main/jidian_sub.txt
base64 订阅     : https://gcore.jsdelivr.net/gh/Luckdog-cook/lanmao-sub@main/jidian_sub_b64.txt
```

> 走的是游客（guest）账号，只有「免费体验套餐」的 2 条线路，流量额度为 0。
> 想要完整节点列表（香港/日本/美国等线路）需要自己的付费账号：
> 在仓库 Secrets 里配置 `JIDIAN_DEVICE_ID` 之外，还需把 `jidian.py` 的 `guest_login`
> 换成 `/api/public/user/login` 并填入账号密码。

---

## 刺猬VPN（HedgeVPN）

自动注册 60 分钟试用账号，抓取全部 21 个地区的节点（28 个节点 / 55 条链路，每个节点含
Reality-TCP 与 mKCP 两种传输），每 40 分钟刷新一次。

**订阅链接（固定）：**

| 格式 | 链接 |
|------|------|
| Base64 订阅（通用 / Bettbox） | `https://cdn.jsdelivr.net/gh/Luckdog-cook/lanmao-sub@main/hedgevpn_sub_b64.txt` |
| 明文链接 | `https://cdn.jsdelivr.net/gh/Luckdog-cook/lanmao-sub@main/hedgevpn_nodes.txt` |
| sing-box（Bettbox 内核） | `https://cdn.jsdelivr.net/gh/Luckdog-cook/lanmao-sub@main/hedgevpn_singbox.json` |
| Clash Meta | `https://cdn.jsdelivr.net/gh/Luckdog-cook/lanmao-sub@main/hedgevpn_clash.yaml` |

GitHub Pages 备份：

```
https://luckdog-cook.github.io/lanmao-sub/hedgevpn_sub_b64.txt
https://luckdog-cook.github.io/lanmao-sub/hedgevpn_singbox.json
https://luckdog-cook.github.io/lanmao-sub/hedgevpn_clash.yaml
```

**说明：**

- 脚本 `hedgevpn.py`，工作流 `.github/workflows/update-hedgevpn.yml`
- 每次运行自动注册新号（无需邮箱、无验证码），试用期 60 分钟全地区可用
- 试用期内 `vipLevel` 仍为 0，判据是 `vipExpireAt > now`
- 想用固定账号：仓库 Secrets 里配 `HEDGE_ACCOUNT` / `HEDGE_PASSWORD`
- 节点 UUID 随账号轮换，**订阅每 40 分钟自动更新，客户端设为定时更新即可**

### sing-box 分流规则（Bettbox）

导入 `hedgevpn_singbox.json` 后内置以下分流，无需手动配置：

**策略组**

| 组名 | 类型 | 用途 |
|------|------|------|
| `PROXY` | selector | 总出口，默认跟随 AUTO |
| `AUTO` | urltest | 自动测速择优（3 分钟一次，容差 50ms） |
| `STREAMING` | selector | Netflix / Disney / HBO / PrimeVideo / Spotify / TikTok / YouTube |
| `AI` | selector | OpenAI / Anthropic / Gemini |
| `TELEGRAM` | selector | Telegram 专用出口 |
| `GAME` | selector | 游戏平台，默认直连 |

**分流顺序（15 条规则）**

1. `protocol=dns` → 内部 dns 出站
2. `ip_is_private` → DIRECT（局域网/私有地址）
3. `geosite-category-ads-all` → REJECT（广告拦截）
4. 端口 123（NTP）→ DIRECT
5. `geosite-cn` + `geosite-geolocation-cn` → DIRECT
6. `geoip-cn` → DIRECT
7. `geosite-apple` → DIRECT（国内 CDN 更快）
8. `geosite-microsoft` → DIRECT
9. Netflix / Disney / HBO / PrimeVideo / Spotify / TikTok → STREAMING
10. `geosite-youtube` → STREAMING
11. OpenAI / Anthropic / Gemini → AI
12. `geosite-telegram` → TELEGRAM
13. `geosite-category-games` → GAME
14. `geosite-google` → PROXY
15. `geosite-geolocation-!cn` → PROXY
16. 兜底 → PROXY

**DNS 分流**

- 国内域名/IP → `223.5.5.5`（UDP）
- 流媒体 / AI / Telegram → `https://1.1.1.1/dns-query`（走代理 DoH）
- 广告域名 → 直接 reject
- 其余 → 远程 DoH

规则集全部走 jsDelivr 镜像（`SagerNet/sing-geosite`、`sing-geoip` 的 `.srs` 二进制格式），
国内可直连，20 个规则集均实测可下载；本地有 `cache_file` 缓存，规则集每天更新一次。

### Clash 配置（mihomo 内核，推荐）

完整配置，**直接导入即用**，已通过 `mihomo -t` 官方二进制校验：

```
https://cdn.jsdelivr.net/gh/Luckdog-cook/lanmao-sub@main/hedgevpn_clash.yaml
```

适用客户端：**Clash Verge Rev / Mihomo Party / Clash Meta for Android / FlClash / OpenClash / ClashX Meta**

> 注意：必须用 Meta 系内核（支持 VLESS + Reality），原版 Clash / Clash for Windows 不支持。

**8 个策略组**

| 组名 | 类型 | 说明 |
|------|------|------|
| 🚀 节点选择 | select | 总出口，默认 ♻️ 自动选择 |
| ♻️ 自动选择 | url-test | 每 5 分钟测速，容差 50ms |
| 🎬 流媒体 | select | Netflix / Disney / HBO / PrimeVideo / Spotify / TikTok / YouTube |
| 🤖 AI服务 | select | OpenAI / ChatGPT / Claude / Gemini / Perplexity / Midjourney |
| 📲 电报消息 | select | Telegram |
| 🎮 游戏平台 | select | 游戏平台，默认直连 |
| 🎯 直连 | select | 强制直连 |
| 🛑 广告拦截 | select | REJECT / DIRECT 可切换 |

**68 条分流规则**（按顺序）

1. 本地域名 + 7 个私有网段 → DIRECT
2. NTP（UDP 123）→ DIRECT
3. `GEOSITE,category-ads-all` → 🛑 广告拦截
4. AI 全套（含 `gemini.google.com` 前置，避免被 google 规则抢走）→ 🤖 AI服务
5. 流媒体全套（域名 + GEOSITE 双保险）→ 🎬 流媒体
6. Telegram → 📲 电报消息
7. `GEOSITE,category-games` → 🎮 游戏平台
8. Apple / Microsoft → DIRECT（国内 CDN 更快）
9. `GEOSITE,cn` + `geolocation-cn` + `GEOIP,CN` → DIRECT
10. Google / `geolocation-!cn` → 🚀 节点选择
11. `MATCH` → 🚀 节点选择

**DNS 分流**

- 国内域名 / 私有域 → 阿里 DoH + 腾讯 DoH
- 流媒体 / AI / Telegram → `1.1.1.1` + `8.8.8.8` DoH（走代理解析，避免拿到国内 CDN）
- fake-ip 模式，`198.18.0.1/16`，局域网与 NTP 域名加入白名单

**geodata**：自动从 jsDelivr 下载 `geosite.dat` / `geoip.dat` / `country.mmdb`，24 小时自动更新。

**节点**：55 条（27 个 Reality-TCP + 28 个 mKCP），按地区命名（`Hong Kong-1.2.3.4`）。

### ⚠️ 订阅地址选择（重要）

jsDelivr 对 `@main` 这类**分支引用**的缓存极难刷新（官方策略最长 12 小时，purge 只清部分边缘节点，
实测会出现不同请求返回不同版本）。节点 UUID 每 30 分钟轮换，所以**不要用 jsDelivr 做订阅源**。

| 通道 | 地址 | 更新时效 | 建议 |
|------|------|---------|------|
| **GitHub Pages** | `https://luckdog-cook.github.io/lanmao-sub/hedgevpn_clash.yaml` | 提交后 1–2 分钟 | ✅ 首选 |
| raw | `https://raw.githubusercontent.com/Luckdog-cook/lanmao-sub/main/hedgevpn_clash.yaml` | 实时 | ✅ 备用 |
| jsDelivr | `https://cdn.jsdelivr.net/gh/Luckdog-cook/lanmao-sub@main/hedgevpn_clash.yaml` | 数十分钟~数小时 | ⚠️ 仅应急 |

完整路径（把文件名替换即可）：

```
hedgevpn_clash.yaml       Clash Meta 配置
hedgevpn_sub_b64.txt      Base64 订阅
hedgevpn_nodes.txt        明文链接
hedgevpn_singbox.json     sing-box 配置
hedgevpn_meta.json        当前账号与更新时间（可用于自查是否更新）
```

**自查方法**：拉 `hedgevpn_meta.json`，看 `updated` 是否是最近 30 分钟内。
