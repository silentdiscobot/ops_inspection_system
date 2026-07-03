# 运维巡检系统

- 单机运行，巡检多台服务器
- 左侧菜单：首页 / 服务器日常巡检 / 服务器管理
- 服务器管理：分组、增删服务器（密码AES-GCM加密存储）
- 巡检：选择分组、填写项目名称与巡检人，进度实时显示（Socket.IO），完成后可下载按模板生成的 Word 报告
- 日志：所有运行日志输出到 `logs/app.log`
- 配置：端口/路径/阈值/AES 密钥等均在 `config.py`

## 快速启动

```bash
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# 可选：设置 AES 密钥（建议生产环境）
# export OPS_AES_KEY=$(python - <<'PY'\nimport os,base64;print(base64.b64encode(os.urandom(32)).decode())\nPY)

python app.py
# 浏览器打开 http://localhost:1999
```

## 说明

- 阈值默认为 80%，可通过环境变量调整：`OPS_CPU_THRESHOLD`/`OPS_MEM_THRESHOLD`/`OPS_DISK_THRESHOLD`。
- 服务器密码采用 AES-GCM 加密存储，密钥从 `OPS_AES_KEY`（base64/hex）或 `OPS_AES_KEY_FILE` 读取，均未设置时使用内置开发密钥（请勿用于生产）。
- Linux 巡检优先读取 `/proc/uptime`、`/proc/stat`、`/proc/meminfo`，并使用 `top`、`free` 等命令兼容回退；磁盘通过 `df -hP` 获取全部挂载点，不做过滤，主表展示最高使用率，异常详情逐条展示超过阈值的挂载点。
- 生成的报告输出目录：`reports/`。
