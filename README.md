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
Bettbox / Clash : https://gcore.jsdelivr.net/gh/Luckdog-cook/lanmao-sub@main/fayso_clash.yaml
sing-box        : https://gcore.jsdelivr.net/gh/Luckdog-cook/lanmao-sub@main/fayso_singbox.json
通用链接        : https://gcore.jsdelivr.net/gh/Luckdog-cook/lanmao-sub@main/fayso_sub.txt
base64 订阅     : https://gcore.jsdelivr.net/gh/Luckdog-cook/lanmao-sub@main/fayso_sub_b64.txt
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
