# tg-video-dl — TG 视频 / 文档下载器

[![build-fpk](https://github.com/shaoweiluo17-lang/tg-video-dl/actions/workflows/build-fpk.yml/badge.svg)](https://github.com/shaoweiluo17-lang/tg-video-dl/actions/workflows/build-fpk.yml)

自己发现内容 → 转发到 Telegram **收藏夹** → 自动下载到 NAS。

飞牛 fnOS 应用（fpk · 统一网关）· telethon 用户号 · 内置 xray 客户端

- **视频**：转发即下载（路径模板 `{date}/{filename}`）
- **文档**（TXT/EPUB/PDF/MOBI/AZW3，可配置后缀白名单）：可单独落到文档目录

## 快速上手

请看 **[`docs/使用说明-接收方版.md`](docs/使用说明-接收方版.md)** —— 从安装 fpk、申请 `api_id`、配 v2ray 节点到上手验收清单，照着做即可。

> 本仓库只发布**程序本体 + 使用说明**；内部开发文档（可行性调研、实施方案、真机排障记录）不公开。

## 三条铁律（决定了整个架构）

1. Bot API 下载上限 **20MB** → 下载必须走 telethon **用户号**（2GB）
2. 国内 NAS **直连不了 Telegram**（实测）→ 代理不是可选项，应用内置 xray 客户端
3. 打包走 fnOS **fpk + 统一网关**，不是 Docker

## 工作原理

```
Telegram 收藏夹 ──(telethon 用户号 + xray 出站)──▶ 监听转发 ──▶ 下载队列 ──▶ 断点续传写盘
                                                              └─▶ 进度回报 / 失败重试 / 面板可视化
```

- 登录态、`api_id`/`api_hash`、节点链接：**AES-GCM 加密落盘**（文件权限 600），日志脱敏、面板不回显明文
- 要写你自己的目录时走 fnOS **目录授权**，不满足会明确报 `need_auth`，不静默失败
- 内置看门狗 + 内存守卫：长时间运行不泄漏、卡死任务会被回收

## 范围

✅ 收藏夹转发 → 自动下载 ｜ ❌ 不做 TG 搜索/发现、多站点解析、yt-dlp、bot

## 开发

```bash
python3 -m venv .venv
.venv/bin/pip install -r deploy/fpk/app/server/requirements.txt
.venv/bin/pytest -q          # 369 个用例（含登录态轮换、去重、看门狗等回归用例）
```

打包：`scripts/build_fpk.sh`（会先由 `scripts/fetch_xray.py` 拉取 xray 二进制；需要官方 `fnpack`）。

## 自动构建（GitHub Actions）

`.github/workflows/build-fpk.yml`：

| 触发 | 做什么 |
|---|---|
| 推 `main` / 开 PR | 跑测试 → 构建 `.fpk`，产物放 Actions 的 **Artifacts**（可直接下载试用） |
| 推 `v*` tag | 额外创建 **Release**，把 `tg-video-dl-<版本>.fpk` + `SHA256SUMS.txt` 挂上去 |
| Actions 页面手动 Run | 同上，不建 Release |

发布一个新版本（三处版本号必须同改，构建脚本与 workflow 都会校验）：

```bash
# deploy/fpk/manifest · deploy/fpk/app/server/__init__.py · pyproject.toml
git commit -am "release: v0.4.6"
git tag v0.4.6
git push origin main --tags     # tag 与 manifest 不一致会被 workflow 直接拒绝
```

## 免责声明

本项目是**个人自用工具**，仅供学习与技术研究：

- 它只在**你自己的** Telegram 账号与**你自己的** NAS 之间搬运你有权访问的内容，不含内容搜索/发现、破解或分发能力。
- 下载、保存与再传播受版权保护的内容可能违反法律或平台条款，请自行确认所在地法律与 Telegram 服务条款；使用本项目的一切后果由使用者自负。
- 仓库**不含**任何 `api_id` / `api_hash` / 账号会话 / 代理节点：需自行到 [my.telegram.org](https://my.telegram.org) 申请，并自备可用节点；代理与登录态只落在你自己的设备上。
- 作者不对账号受限、下载失败、数据丢失或任何间接损失负责。

## 许可

[MIT](LICENSE) © 2026 shaoweiluo17-lang

## 致谢

代理解析（vmess/vless → xray 出站配置）的思路参考了 `feiying` 项目中 **MIT 许可**的公开实现。
