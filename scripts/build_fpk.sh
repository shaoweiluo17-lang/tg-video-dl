#!/usr/bin/env bash
# ============================================================
# tg-video-dl · fpk 构建（带前置清理与校验）
#
# 为什么需要这个脚本而不是直接 fnpack build：
#   1. fnpack 会把源码树里的 __pycache__/*.pyc 原样打进包。开发机是 py311，
#      而应用运行时是 manifest 指定的 python312 —— pyc 的 magic number 不匹配，
#      运行时不会加载，属于「既占体积又误导排障」的垃圾，必须构建前清掉。
#   2. xray 二进制（37MB）不入库，构建前必须确保已拉取，否则打出的包缺出网能力。
#   3. 配置文件（config.yaml / .secrets.yaml）绝不能进包（可能含真实凭据）。
# ============================================================
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
FPK_DIR="deploy/fpk"

echo "==> 1/5 清理构建垃圾（__pycache__ / *.pyc / 历史 .fpk）"
find "$FPK_DIR" -name "__pycache__" -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "$FPK_DIR" -name "*.pyc" -delete 2>/dev/null || true
rm -f "$FPK_DIR"/*.fpk

echo "==> 2/5 校验版本号三处一致（防'包新面板旧'错位）"
python3 "$ROOT/scripts/check_version.py"

echo "==> 3/5 检查是否混入机密配置（严重问题，直接失败）"
if [ -f "$FPK_DIR/app/config/.secrets.yaml" ] || [ -f "$FPK_DIR/app/config/config.yaml" ]; then
  echo "✗ 检测到 $FPK_DIR/app/config/ 下存在配置文件，可能含真实凭据！" >&2
  echo "  请先移除：rm -rf $FPK_DIR/app/config/" >&2
  exit 1
fi

echo "==> 4/5 确保 xray 二进制就位（37MB，不入库）"
if [ ! -f "$FPK_DIR/app/bin/xray" ]; then
  echo "  未找到 xray，尝试拉取（需网络可达镜像）..."
  python3 scripts/fetch_xray.py
fi
[ -x "$FPK_DIR/app/bin/xray" ] || { echo "✗ xray 不可执行，构建会产出无法出网的包" >&2; exit 1; }
echo "  xray: $("$FPK_DIR/app/bin/xray" version 2>/dev/null | head -1)"

echo "==> 5/5 fnpack build"
ROOT="$PWD"
(cd "$FPK_DIR" && fnpack build)

echo
echo "==> 产物校验"
# ⚠️ 上面在子 shell 里 cd 过，校验必须用绝对路径，否则相对路径失效（已踩过）
OUT="$ROOT/$FPK_DIR/tg-video-dl.fpk"
[ -f "$OUT" ] || { echo "✗ 未生成 fpk：$OUT" >&2; exit 1; }
INNER="$(tar -xzf "$OUT" -O app.tgz 2>/dev/null | tar -tzf - 2>/dev/null || true)"
# 包内不得有 pyc
if echo "$INNER" | grep -q "__pycache__"; then
  echo "✗ 包内仍含 __pycache__，构建异常" >&2; exit 1
fi
echo "✓ 包内无 __pycache__ 污染"
# 包内必须有 xray（否则装到 NAS 无法出网）
if ! echo "$INNER" | grep -qx "bin/xray"; then
  echo "✗ 包内缺 bin/xray，应用将无法连接 Telegram" >&2; exit 1
fi
echo "✓ 包内含 bin/xray（出网能力就位）"
ls -lh "$OUT" | awk '{print "✓ 产物: "$9" ("$5")"}'

# 版本化副本（用户约定 2026-10-08）：
# 交付给用户安装的包必须**文件名带版本号**，避免"这个包是哪个版本"分不清；
# 同时每次交付都要 +1 版本号，应用中心「手动安装」才能识别成新版本直接覆盖，
# 不必先卸载（同版本号才是「假升级」）。
VERSION="$(grep -E '^version=' "$FPK_DIR/manifest" | head -1 | cut -d= -f2 | tr -d '[:space:]')"
VERSIONED="$ROOT/$FPK_DIR/tg-video-dl-$VERSION.fpk"
cp -f "$OUT" "$VERSIONED"
MD5="$(md5sum "$VERSIONED" | awk '{print $1}')"
echo "✓ 版本化产物: $VERSIONED"
echo "✓ md5: $MD5（版本 $VERSION）"
