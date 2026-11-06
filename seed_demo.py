"""生成本地演示数据：python seed_demo.py（重复运行不会重复插入）。"""
import json
import random
from datetime import datetime, timedelta

import models
from config import load_aes_key
from crypto_utils import aes_gcm_encrypt

ROOM = '测试机房-01'
MARKER = 'demo-room-01-v1'


def main():
    models.init_db()
    rng = random.Random(20261105)
    now = datetime.now().replace(microsecond=0)
    stamp = now.isoformat(sep=' ')
    password = aes_gcm_encrypt(load_aes_key(), 'DemoOnly-NotARealCredential!')
    conn = models.get_conn()
    try:
        with conn:
            if conn.execute('SELECT 1 FROM servers WHERE notes=? LIMIT 1', (MARKER,)).fetchone():
                print('演示数据已存在，跳过。')
                return
            if conn.execute('SELECT 1 FROM servers WHERE room_affiliation=? LIMIT 1', (ROOM,)).fetchone():
                raise RuntimeError('目标机房已存在，请修改 ROOM 后重试，避免混入已有资产。')
            def insert(table, **values):
                columns = ','.join(values)
                placeholders = ','.join('?' for _ in values)
                return conn.execute(f'INSERT INTO {table} ({columns}) VALUES ({placeholders})', tuple(values.values())).lastrowid

            environments = []
            for name in ('演示-生产环境', '演示-测试环境', '演示-开发环境'):
                conn.execute('INSERT OR IGNORE INTO service_environments(name) VALUES (?)', (name,))
                eid = conn.execute('SELECT id FROM service_environments WHERE name=?', (name,)).fetchone()[0]
                conn.execute('INSERT OR IGNORE INTO server_groups(id,name) VALUES (?,?)', (eid, name))
                environments.append(eid)
            systems = []
            for name in ('演示-门户系统', '演示-订单系统', '演示-监控平台', '演示-数据平台'):
                conn.execute('INSERT OR IGNORE INTO service_systems(name) VALUES (?)', (name,))
                systems.append(conn.execute('SELECT id FROM service_systems WHERE name=?', (name,)).fetchone()[0])
            servers = []
            for rack in range(1, 21):
                for host in range(1, 11):
                    physical = f'198.18.{rack}.{host}'
                    for vm in range(4):
                        ip = physical if vm == 0 else f'198.19.{rack}.{(host-1)*3+vm}'
                        sid = insert('servers', name=f'DEMO-R{rack:02}-H{host:02}' + (f'-VM{vm}' if vm else ''),
                                     ip=ip, physical_ip=physical, resource_type='虚拟机' if vm else '物理机',
                                     os_type=('Ubuntu' if host % 2 else 'Centos'), rack_number=f'A{rack:02}',
                                     room_affiliation=ROOM, rack_level=f'U{host:02}', port=22,
                                     username='demo', enc_password=password, notes=MARKER)
                        env = environments[(host + vm) % 3]
                        insert('server_group_memberships', server_id=sid, group_id=env)
                        insert('server_hardware_snapshots', server_id=sid, cpu='8核' if vm else '64核',
                               memory='16 GB' if vm else '256 GB', storage='200 GB' if vm else '4 TB',
                               gpu='无', collected_at=stamp, checked_at=stamp)
                        servers.append(ip)
                        for name, port, version in (('nginx', 80, '1.24.0'), ('业务应用', 8080, '2.6.1')):
                            service = insert('service_infos', name=name, server_id=sid,
                                             service_type='应用服务', run_mode='systemd', version=version,
                                             ports=str(port), deploy_dir=f'/opt/demo/{name}',
                                             owner='演示运维组', status='已停止' if sid % 19 == 0 else '运行中',
                                             auto_start=1, notes=MARKER, created_by='demo-seed', created_at=stamp)
                            insert('service_environment_memberships', service_id=service, environment_id=env)
                            insert('service_system_memberships', service_id=service, system_id=systems[(rack+host) % 4])
            task = insert('inspection_tasks', name='演示-每日全量巡检', project_name=ROOM,
                          inspector='演示巡检员', enable_schedule=0, created_at=stamp)
            for day in range(30):
                time = (now - timedelta(days=day)).isoformat(sep=' ')
                run = f'{MARKER}-day-{day:02}'
                insert('inspection_runs', run_id=run, task_id=task, task_name='演示-每日全量巡检',
                       source='manual', payload=json.dumps({'demo': True}), status='success', progress=100,
                       message='模拟巡检完成', created_at=time, started_at=time, finished_at=time)
                for index, ip in enumerate(servers):
                    failed = (index + day) % 37 == 0
                    insert('inspection_results', run_id=run, server_ip=ip, ok=int(not failed),
                           uptime=f'{30 + index % 180} days', cpu=round(rng.uniform(5, 98), 1),
                           mem=round(rng.uniform(15, 96), 1), disk=round(rng.uniform(10, 95), 1),
                           error='模拟 SSH 连接超时' if failed else None, created_at=time)
            assert not conn.execute('PRAGMA foreign_key_check').fetchall()
        print('已生成：1 个机房 / 20 个机柜 / 200 台物理机 / 600 台虚拟机 / 1600 条服务 / 30 次巡检 / 24000 条结果。')
    finally:
        conn.close()


if __name__ == '__main__':
    main()
