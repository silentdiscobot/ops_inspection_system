---
name: "server_onboarding"
description: "服务器纳管与服务导入标准流程：服务器登记 → 凭据安全录入 → 服务发现 → 人工确认 → 批量导入 → 结果验证。"
---

# Instructions

# 服务器纳管与服务导入流程（Server Onboarding & Service Import）

适用场景：把一台新服务器纳入巡检系统，并完成其业务服务的发现、确认与登记。

## 流程总览

1. 服务器登记
2. 凭据安全录入
3. 服务发现
4. 人工确认
5. 批量导入
6. 结果验证

## 第 1 步：服务器登记

- 先用 list_groups / list_servers 获取真实分组 ID 与已有服务器，避免重复登记
- 用 upsert_server 登记资产：名称、IP、SSH 端口、用户名、认证方式、分组、资源类型、操作系统等
- 硬性规则：不得在对话或参数中提供密码/私钥；需要新凭据时 credential_mode 必须填 secure_input_required，由用户在本地安全确认卡片中录入
- 该操作始终需要人工确认

## 第 2 步：凭据安全录入

- 用户在本地确认卡片中填写密码或私钥，模型与对话中不可见
- 录入后可用 test_server_connection 验证连通性（可选但推荐）

## 第 3 步：服务发现

- 用 discover_server_services 扫描，只传 server_id（必须来自 list_servers），不接受模型提供的 Shell 命令
- include_system_services 通常为 false，默认不采集基础系统服务
- 不得用 run_remote_command 代替服务发现流程

## 第 4 步：人工确认

- 向用户概括候选服务清单：服务名、类型、运行方式、端口、部署目录
- 明确询问用户要导入哪些业务服务，等待确认后再导入
- 默认不导入基础系统服务

## 第 5 步：批量导入

- 用 import_discovered_services 导入，candidate_ids 只能引用同一次扫描（同一 scan_id）里的候选
- strategy 二选一：skip_existing（跳过已存在）/ update_discovered_fields（更新已发现字段）
- 该操作始终需要人工确认

## 第 6 步：结果验证

- 用 list_services（按 server_id 过滤）核对导入结果
- 向用户输出：成功导入的服务列表、跳过/失败项及原因
- 如有异常（连接失败、导入失败），说明原因并给出建议

## 红线

- 绝不在对话中输出或索要密码、私钥、令牌、API Key
- 变更操作必须走对应工具并等待人工确认
- 只依据工具返回的数据回答，不编造数据
