# 运维巡检系统

- 单机运行，巡检多台服务器
- 左侧菜单：首页 / 可视化大屏 / 服务器巡检 / AI智能运维 / 资源管理项 / 资源总览表 / 运维变更单 / 历史报告单 / 系统管理项
- 资源管理项与资源总览表：维护环境、系统、服务器和服务信息（密码 AES-GCM 加密存储），并集中查看服务器列表与服务信息表；服务器“查看”弹窗展示最近一次记录的硬件参数（不再每次实时查询），首次记录后只在参数增减变化时更新，采集失败保留上次参数并提示原因
- 巡检：选择分组、填写项目名称与巡检人，进度实时显示（Socket.IO），完成后可下载按模板生成的 Excel/PDF 报告
- 磁盘检查（不需要在目标机装任何软件）：除了原有的使用率阈值，还会与历史基线比对，判定**相比昨天是否掉盘**（挂载点/块设备消失、阵列降级）、**是否有损坏迹象**（只读重挂载、ext4 与 SCSI 错误计数增长、内核 `dmesg` 新增 I/O 错误、`df` 报错）、**是否增长异常**（短时突增、日均超标、写满天数预测、异常下降），结论写入报告的“异常问题详情”，扩容/新增盘等变化写入“磁盘变更记录”小节
- 磁盘检查的前提：**第一次巡检只建立基线**（报告里会写明“首次采集磁盘基线”），第二次起才有比对结论；两次巡检间隔要在 12–48 小时之间才能判断掉盘与增长趋势（每天跑一次或更频繁都没问题，间隔超过 48 小时会只记录新基线并提示）
- 资源变更表：CPU 核数、内存总量和磁盘结构使用“已确认基线”。未经计划的扩容、缩容、增盘、减盘或挂载变化默认按异常处理，必须在“运维变更单 → 资源变更表”填写理由并确认；也可提前登记带时间窗的计划，实际配置完全匹配时自动更新基线且不报异常。计划变更不会屏蔽磁盘 I/O、只读、阵列降级等真实故障。
- AI 智能运维（可选）：先在「AI智能运维 → 模型配置」里填 OpenAI 兼容接口（地址填到 `/v1`）、模型名称和 API Key，之后就能用一句中文查服务器资产、查巡检结果、查磁盘审计发现、查服务台账；AI 只能通过**结构化工具调用**拿这些数据，正文里写什么都不会被执行
  - 支持在对话中纳管服务器、使用固定只读采集器发现 systemd/Docker/PM2/监听端口服务，并经确认后批量导入服务台账；服务器和服务会自动关联所选环境
  - SSH 密码/私钥只在本地确认卡片中临时输入并直接交给后端加密，不进入模型请求、AI 消息、待确认参数或审计详情；不要在聊天正文里粘贴凭据
  - 会话可选“限制访问 / 变更访问 / 完全访问”；需要确认时，对应会话会突出显示，点击会话即可确认或拒绝。确认操作 10 分钟内未处理自动过期，重复确认不会执行两次
  - 远程命令不使用命令或参数白名单：限制访问、变更访问均需确认，完全访问直接执行；固定只读服务发现仅在限制访问时确认。登记服务器和导入发现结果始终要求人工确认
  - API Key 用 AES-GCM 加密入库，接口只回显掩码（如 `sk-****cdef`），**没有任何接口能取回明文**；模型只能看到工具返回的运维数据，看不到任何凭据
  - 危险操作、被拒绝的操作、被拦下的工具调用都会写审计日志（`/api/audit_logs` 可查，管理员可见）
  - 可通过 `OPS_AI_MCP_CONFIG` 指向的 JSON 配置 MCP Server；每个 Server 必须显式配置 `allowed_tools`，未列入白名单的扩展工具默认拒绝。能力清单会展示 Server、工具名称、风险级别和启用状态，示例见 [docs/mcp_servers.example.json](docs/mcp_servers.example.json)
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

## Docker 部署

Compose 只负责运行本机已有镜像，不负责构建或拉取。先在源码/构建机中单独生成镜像：

```bash
docker build -t ops-inspection-new:v1.1 .
```

也可以在构建机导出、再复制到运行服务器导入：

```bash
docker save -o ops-inspection-new-v1.1.tar ops-inspection-new:v1.1
# 运行服务器：docker load -i ops-inspection-new-v1.1.tar
```

运行服务器确认镜像存在后直接启动：

```bash
docker image inspect ops-inspection-new:v1.1 >/dev/null
docker compose up -d
docker compose ps
```

容器首次启动会在持久化的 `data/` 目录自动生成 Session 密钥和 AES 密钥，并自动修正挂载目录权限；无需手工创建 `.env` 或密钥文件。默认管理员密码仍为 `Admin@123`，登录后请立即修改，也可以复制 `.env.example` 为 `.env` 后预先设置 `OPS_ADMIN_PASSWORD`。

从旧版本升级时，如果已有 `data/ops.db` 且过去没有配置过 AES 密钥，启动脚本会自动沿用旧版内置密钥，确保已有凭据仍可解密；过去配置过自定义密钥的部署，应先把原始密钥恢复为 `data/.ops_aes_key`。

生产容器使用 Gunicorn 单 worker、多线程模式。单 worker 是有意设置：巡检队列、定时调度器和状态监控都是进程内线程，多 worker 会重复启动这些后台服务。`data/.ops_aes_key` 必须与 `data/ops.db` 一起备份，容器重建时会自动沿用。

## 说明

- 阈值默认为 80%，可通过环境变量调整：`OPS_CPU_THRESHOLD`/`OPS_MEM_THRESHOLD`/`OPS_DISK_THRESHOLD`。磁盘巡检的阈值与开关另有一组 `OPS_DISK_*` 环境变量（增长量、突增、写满天数、inode、基线时长、快照保留天数、排除名单等），默认值见 `config.py` 与 [docs/磁盘巡检增强方案.md](docs/磁盘巡检增强方案.md) §7。
- 服务器密码采用 AES-GCM 加密存储，密钥从 `OPS_AES_KEY`（base64/hex）或 `OPS_AES_KEY_FILE` 读取，均未设置时使用内置开发密钥（请勿用于生产）。
- Linux 巡检优先读取 `/proc/uptime`、`/proc/stat`、`/proc/meminfo`，并使用 `top`、`free` 等命令兼容回退；磁盘通过一条复合命令采集（`df -Pk`、`/proc/mounts`、`/proc/partitions`、`lsblk`、`/proc/mdstat`、`/sys` 内核计数器、`/dev/disk/by-*`、`dmesg`，全部只读、不装工具），主表展示最高使用率，异常详情逐条展示超过阈值的挂载点，另附磁盘巡检结论。
- 生成的报告输出目录：`reports/`。
- AI 智能运维用标准库 `urllib` 直连 OpenAI 兼容接口（`/chat/completions`、`/models`），**不新增任何 Python 依赖**，换厂商只要改 `base_url`。流式输出是“服务端内存缓冲 + 前端按 offset 轮询”（不用 SSE/WebSocket），刷新页面或断线后能接着显示，也可以点“停止生成”。
- AI 的全部开关都在 `OPS_AI_*` 环境变量里（是否启用、允许使用的角色、是否允许云端模型、单日 token 上限、并发上限、上下文条数、工具轮数、远程命令超时、操作过期时间、IP 脱敏、代理与自签证书等），默认值与取舍见 [docs/系统说明文档.md](docs/系统说明文档.md) §8 与 [docs/AI智能运维方案.md](docs/AI智能运维方案.md)（含安全边界与「实际落地与偏差」）。
