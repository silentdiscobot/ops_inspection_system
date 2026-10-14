#!/bin/sh
set -eu

DATA_DIR=/app/data
SESSION_KEY_FILE="$DATA_DIR/.ops_session_key"
AES_KEY_FILE="${OPS_AES_KEY_FILE:-$DATA_DIR/.ops_aes_key}"

mkdir -p "$DATA_DIR" /app/logs /app/reports /app/skills /home/ops/.ssh
mkdir -p "$(dirname "$AES_KEY_FILE")"

# 首次启动自动生成密钥；data 是持久化目录，容器重建后仍会沿用。
if [ ! -s "$SESSION_KEY_FILE" ]; then
    umask 077
    python -c "import secrets,sys; open(sys.argv[1], 'w', encoding='ascii').write(secrets.token_hex(32))" "$SESSION_KEY_FILE"
fi

if [ ! -s "$AES_KEY_FILE" ]; then
    umask 077
    if [ -s "$DATA_DIR/ops.db" ]; then
        # 兼容从未配置过 OPS_AES_KEY 的旧部署；已有自定义密钥时应在启动前恢复到此文件。
        printf '%s' '0123456789abcdef0123456789abcdef' > "$AES_KEY_FILE"
        echo "WARNING: existing database found; using the legacy development AES key" >&2
    else
        python -c "import os,sys; open(sys.argv[1], 'wb').write(os.urandom(32))" "$AES_KEY_FILE"
    fi
fi

AES_KEY_BYTES="$(wc -c < "$AES_KEY_FILE" | tr -d ' ')"
case "$AES_KEY_BYTES" in
    16|24|32) ;;
    *)
        echo "AES key file must contain 16, 24 or 32 raw bytes: $AES_KEY_FILE" >&2
        exit 1
        ;;
esac

if [ -z "${OPS_SECRET_KEY:-}" ]; then
    OPS_SECRET_KEY="$(cat "$SESSION_KEY_FILE")"
    export OPS_SECRET_KEY
fi
export OPS_AES_KEY_FILE="$AES_KEY_FILE"

# bind mount 可能由 root 创建，启动阶段修正权限后再降权运行应用。
chown -R ops:ops "$DATA_DIR" /app/logs /app/reports /app/skills /home/ops
chmod 600 "$SESSION_KEY_FILE" "$AES_KEY_FILE"

exec gosu ops "$@"
