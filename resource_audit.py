# -*- coding: utf-8 -*-
"""CPU/内存容量与磁盘结构的已确认基线、计划变更和人工确认。"""
import copy
import hashlib
import json

import models
from disk_audit import visible_mounts


HARDWARE_FIELDS = (('cpu', 'CPU'), ('memory', '内存'), ('storage', '物理磁盘总容量'))
OPEN_STATUSES = ('pending', 'confirmed_abnormal', 'recovered_pending')


def _clean_text(value):
    text = str(value or '').strip()
    return '' if text in ('未知', '采集失败') else text


def disk_structure(snapshot):
    """从完整磁盘采样中只保留需要人工确认的稳定结构字段。"""
    if not snapshot:
        return None
    filesystems = {
        item.get('mount'): item for item in snapshot.get('filesystems') or []
        if item.get('mount')
    }
    mounts = []
    for item in visible_mounts(snapshot.get('mounts') or []):
        df_item = filesystems.get(item.get('mount')) or {}
        mounts.append({
            'mount': item.get('mount') or '',
            'device': item.get('device') or '',
            'fstype': item.get('fstype') or '',
            'size_kb': int(df_item.get('size_kb') or 0),
        })
    devices = []
    for item in snapshot.get('devices') or []:
        if item.get('type') != 'disk':
            continue
        devices.append({
            'name': item.get('name') or '',
            'uuid': item.get('uuid') or '',
            'size_bytes': int(item.get('size_bytes') or item.get('size') or 0),
        })
    return {
        'mounts': sorted(mounts, key=lambda item: item['mount']),
        'devices': sorted(devices, key=lambda item: (item['uuid'], item['name'])),
    }


def build_resource_payload(hardware=None, disk_snapshot=None, base_payload=None):
    payload = copy.deepcopy(base_payload or {})
    if hardware:
        normalized = {}
        for field, _label in HARDWARE_FIELDS:
            value = _clean_text(hardware.get(field))
            if value:
                normalized[field] = value
        if normalized:
            payload['hardware'] = normalized
    structure = disk_structure(disk_snapshot)
    if structure is not None:
        payload['disk'] = structure
    return normalize_payload(payload)


def normalize_payload(payload):
    payload = copy.deepcopy(payload or {})
    hardware = payload.get('hardware') or {}
    payload['hardware'] = {
        field: _clean_text(hardware.get(field))
        for field, _label in HARDWARE_FIELDS if _clean_text(hardware.get(field))
    }
    disk = payload.get('disk')
    if disk is not None:
        payload['disk'] = {
            'mounts': sorted(disk.get('mounts') or [], key=lambda item: item.get('mount') or ''),
            'devices': sorted(
                disk.get('devices') or [],
                key=lambda item: (item.get('uuid') or '', item.get('name') or ''),
            ),
        }
    if not payload.get('hardware'):
        payload.pop('hardware', None)
    return payload


def _device_identity(item):
    return item.get('uuid') or item.get('name') or ''


def compare_resource_payload(baseline, current):
    baseline = normalize_payload(baseline)
    current = normalize_payload(current)
    changes = []
    old_hw, new_hw = baseline.get('hardware') or {}, current.get('hardware') or {}
    for field, label in HARDWARE_FIELDS:
        old, new = old_hw.get(field), new_hw.get(field)
        if old and new and old != new:
            changes.append(f'{label} {old} → {new}')

    old_disk, new_disk = baseline.get('disk'), current.get('disk')
    if old_disk is not None and new_disk is not None:
        old_mounts = {item.get('mount'): item for item in old_disk.get('mounts') or []}
        new_mounts = {item.get('mount'): item for item in new_disk.get('mounts') or []}
        for mount in sorted(set(old_mounts) - set(new_mounts)):
            changes.append(f'删除挂载点 {mount}')
        for mount in sorted(set(new_mounts) - set(old_mounts)):
            item = new_mounts[mount]
            changes.append(f'新增挂载点 {mount}（{item.get("device") or "未知设备"}）')
        for mount in sorted(set(old_mounts) & set(new_mounts)):
            old, new = old_mounts[mount], new_mounts[mount]
            if int(old.get('size_kb') or 0) != int(new.get('size_kb') or 0):
                old_gb = int(old.get('size_kb') or 0) / 1024 / 1024
                new_gb = int(new.get('size_kb') or 0) / 1024 / 1024
                changes.append(f'挂载点 {mount} 容量 {old_gb:.1f} GB → {new_gb:.1f} GB')
            if (old.get('fstype') or '') != (new.get('fstype') or ''):
                changes.append(
                    f'挂载点 {mount} 文件系统 {old.get("fstype") or "未知"} → '
                    f'{new.get("fstype") or "未知"}'
                )

        old_devices = {_device_identity(item): item for item in old_disk.get('devices') or []}
        new_devices = {_device_identity(item): item for item in new_disk.get('devices') or []}
        for key in sorted(set(old_devices) - set(new_devices)):
            changes.append(f'减少物理磁盘 {old_devices[key].get("name") or key}')
        for key in sorted(set(new_devices) - set(old_devices)):
            changes.append(f'新增物理磁盘 {new_devices[key].get("name") or key}')
        for key in sorted(set(old_devices) & set(new_devices)):
            old, new = old_devices[key], new_devices[key]
            if int(old.get('size_bytes') or 0) != int(new.get('size_bytes') or 0):
                changes.append(
                    f'物理磁盘 {new.get("name") or key} 容量 '
                    f'{int(old.get("size_bytes") or 0) / 1000**3:.1f} GB → '
                    f'{int(new.get("size_bytes") or 0) / 1000**3:.1f} GB'
                )
    return changes


def payload_matches(expected, current):
    expected = copy.deepcopy(expected or {})
    current = normalize_payload(current)
    expected_hardware = expected.get('hardware') or {}
    current_hardware = current.get('hardware') or {}
    for field, value in expected_hardware.items():
        if _clean_text(value) and _clean_text(current_hardware.get(field)) != _clean_text(value):
            return False

    has_criteria = 'disk_expectation' in expected
    criteria = expected.get('disk_expectation')
    if has_criteria and criteria is None:
        return True
    if criteria is not None:
        current_disk = current.get('disk') or {}
        devices = current_disk.get('devices') or []
        mounts = current_disk.get('mounts') or []
        if criteria.get('device_count') not in (None, ''):
            if len(devices) != int(criteria['device_count']):
                return False
        if criteria.get('mount_count') not in (None, ''):
            if len(mounts) != int(criteria['mount_count']):
                return False
        current_mounts = {item.get('mount'): item for item in mounts}
        expected_mounts = criteria.get('mounts') or []
        if expected_mounts and set(current_mounts) != {
                item.get('mount') for item in expected_mounts if item.get('mount')}:
            return False
        for item in expected_mounts:
            mount = item.get('mount')
            expected_gb = item.get('size_gb')
            if not mount or expected_gb in (None, ''):
                continue
            actual_gb = int((current_mounts.get(mount) or {}).get('size_kb') or 0) / 1024 / 1024
            if abs(actual_gb - float(expected_gb)) > max(1.0, float(expected_gb) * 0.02):
                return False
        return True
    return normalize_payload(expected) == current


def fingerprint(payload):
    raw = json.dumps(normalize_payload(payload), ensure_ascii=False, sort_keys=True,
                     separators=(',', ':'))
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def evaluate_resource_configuration(server_id, current_payload, at=None):
    """返回资源状态；pending/abnormal/recovered_pending 均必须计入报告异常。"""
    current = normalize_payload(current_payload)
    if not current:
        return {'status': 'normal', 'changes': []}
    baseline_row = models.get_resource_baseline(server_id)
    if not baseline_row:
        models.save_resource_baseline(server_id, current, source='initial', accepted_at=at)
        return {'status': 'initial', 'changes': []}

    baseline = normalize_payload(baseline_row.get('payload'))
    augmented = copy.deepcopy(baseline)
    changed_baseline = False
    for component in ('hardware', 'disk'):
        if component not in augmented and component in current:
            augmented[component] = copy.deepcopy(current[component])
            changed_baseline = True
    if changed_baseline:
        models.save_resource_baseline(
            server_id, augmented, source=baseline_row.get('source') or 'initial',
            accepted_by=baseline_row.get('accepted_by') or '',
            accepted_reason=baseline_row.get('accepted_reason') or '', accepted_at=at,
        )
        baseline = augmented

    changes = compare_resource_payload(baseline, current)
    active_event = models.get_open_resource_change_event(server_id)
    if not changes:
        if active_event:
            models.mark_resource_event_recovered(active_event['id'], at)
            return {
                'status': 'recovered_pending', 'changes': active_event.get('change_detail') or [],
                'event_id': active_event['id'],
            }
        return {'status': 'normal', 'changes': []}

    plan = models.get_active_resource_plan(server_id, at)
    if plan and payload_matches(plan.get('expected_payload'), current):
        if active_event:
            models.decide_resource_change_event(
                active_event['id'], 'normal', plan.get('reason') or '计划变更匹配',
                plan.get('created_by') or '',
            )
        models.save_resource_baseline(
            server_id, current, source='planned', accepted_by=plan.get('created_by') or '',
            accepted_reason=plan.get('reason') or '', accepted_at=at,
        )
        models.finish_resource_change_plan(plan['id'], 'matched', at)
        return {'status': 'planned', 'changes': changes, 'plan_id': plan['id']}

    event_id = models.upsert_resource_change_event(
        server_id, fingerprint(current), baseline, current, changes, at,
    )
    event = models.get_open_resource_change_event(server_id) or {}
    status = event.get('status') or 'pending'
    return {'status': status, 'changes': changes, 'event_id': event_id}


def result_finding(result):
    status = (result or {}).get('status')
    if status not in OPEN_STATUSES:
        return None
    changes = result.get('changes') or []
    detail = '；'.join(changes[:8]) or '资源配置与已确认基线不一致'
    if len(changes) > 8:
        detail += f'；另有 {len(changes) - 8} 项变化'
    if status == 'recovered_pending':
        text = f'此前的资源配置变化已恢复，但尚未人工确认关闭：{detail}。'
    elif status == 'confirmed_abnormal':
        text = f'资源配置变化已人工确认为异常，尚未解决：{detail}。'
    else:
        text = f'检测到未经确认的资源配置变化：{detail}。确认并填写理由前按异常处理。'
    return {'severity': 'severe', 'category': '资源配置变更', 'text': text}
