#!/usr/bin/env bash
# ============================================================
# tg-video-dl · 统一命令入口（Linux / NAS）
# ============================================================
set -euo pipefail
cd "$(dirname "$0")/.."
APPDIR="$PWD/deploy/fpk/app"
PY="${PY:-.venv/bin/python}"
[ -x "$PY" ] || PY=python3

case "${1:-help}" in
  install)
    python3 -m venv .venv
    .venv/bin/python -m pip install -e ".[dev,server]"
    .venv/bin/python scripts/fetch_xray.py
    ;;
  xray)    "$PY" scripts/fetch_xray.py ;;
  icons)   "$PY" scripts/gen_icons.py ;;
  dev)     (cd "$APPDIR" && "../../../$PY" -m uvicorn server.main:app --host 127.0.0.1 --port "${PORT:-8010}" --reload) ;;
  start)   (cd "$APPDIR" && "../../../$PY" -m uvicorn server.main:app --host "${HOST:-0.0.0.0}" --port "${PORT:-8010}") ;;
  test)    "$PY" -m pytest ;;
  lint)    "$PY" -m ruff check . ;;
  stop)    pkill -f "uvicorn server.main" || true ;;
  *)
    cat <<'USAGE'
用法: scripts/run.sh <命令>
  install  建 venv + 装依赖 + 拉 xray
  xray     仅拉取/校验 xray 二进制（幂等）
  icons    重新生成应用图标
  dev      本地开发模式（8010，热重载）
  start    生产启动
  test     跑单测
  lint     ruff 检查
  stop     停止本地服务
USAGE
    ;;
esac
