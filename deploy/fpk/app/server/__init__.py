"""tg-video-dl 服务端包。

模块地图：
- `config.py`        配置读写（机密加密 + 防脱敏污染）
- `paths.py`         落盘路径模板与安全校验（防目录穿越）
- `proxy_uri.py`     v2ray 分享链接解析 → ProxyEndpoint
- `xray_outbound.py` 内置 xray-core 子进程管理（暴露本机 socks5 出口）
- `tg_client.py`     telethon 用户号：登录流程 + session 加密持久化 + 收藏夹监听
- `downloader.py`    媒体识别（视频/文档白名单）+ 按类型路由落盘 + 流式下载 + 原子落盘 + 断点续传
- `queue.py`         任务队列 + 并发控制 + flood-wait 退避 + worker 级看门狗
- `notify.py`        TG 进度回报（编辑同一条消息；通知调用一律限时，绝不拖死 worker）
- `db.py`            SQLite：任务/历史/去重
- `aio_guard.py`     异步看门狗工具（不依赖取消的限时等待，全项目复用）
- `memguard.py`      进程 RSS 观测（/api/health 暴露 + 超阈值告警）
- `main.py`          FastAPI 入口 + 统一网关 + 任务/日志/目录预检 API
"""

__version__ = "0.4.5"
