# 系统测试与修复记录（2026-11-05）

## 已修复

- CSRF：非 ASCII 请求头触发 compare_digest 类型异常；现在拒绝并返回 403。
- JSON 输入：写接口收到数组、标量或 null 时可能触发属性访问异常；统一要求 JSON 对象并返回 400。六个接口共 36 组输入验证通过。
- 用户管理：用户名、显示名、联系方式直接拼接 HTML 和内联事件，存在存储型 XSS。改用 textContent 和事件监听器；恶意 HTML 和多用户操作目标测试通过。
- 报告列表：文件名和时间直接拼接 HTML；已转义，并编码删除事件参数中的单引号。

## 验证

- 后端全量回归：266 项全部通过，耗时 390.077 秒；见 logs/regression_latest.log。后续新增的全路由冒烟测试另行通过。覆盖账户/会话/权限、服务器凭据、服务台账、硬件采集、巡检任务/队列/调度、磁盘审计、资源变更、报告生成、AI 配置/会话/工具/审批/审计。
- WholeSystemPageSmokeTests：全部无路径参数 GET 路由，admin/operator/viewer 页面与 API 不出现 500，匿名请求受保护；通过。此检查不等价于完整角色权限矩阵。
- JsonBodyBoundaryTests、CsrfHeaderBoundaryTests、启动初始化断言：通过。
- node test_ui_security.cjs：通过。
- node test_report_security.cjs：通过。
- node test_dashboard_batch.cjs：720 个场景及附加库存、点击测试通过。
- python -m pip check：通过。只检查依赖兼容性，不代表没有依赖漏洞。

## 范围与限制

本轮以本地回归、临时数据库、Flask 客户端和 Node DOM/画布模拟测试为主。没有完成真实浏览器端到端测试、生产并发压测、真实服务器 SSH 联调、外部 AI/MCP 服务联调或依赖 CVE 全量扫描。不能据此保证系统不存在其他漏洞。保留工作区原有大屏修改。
