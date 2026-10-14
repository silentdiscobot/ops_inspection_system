# 服务器纳管核对清单

- [ ] 已用 list_groups / list_servers 查询，确认无重复登记
- [ ] upsert_server 已提交并经人工确认
- [ ] 新凭据通过 secure_input_required 安全录入，对话中无明文
- [ ] （可选）test_server_connection 连通性测试通过
- [ ] discover_server_services 扫描完成，取得 scan_id 与候选列表
- [ ] 已向用户概括候选服务清单并取得导入确认
- [ ] import_discovered_services 已提交并经人工确认
- [ ] list_services 验证导入结果，已向用户汇报成功/跳过清单
