import hashlib
import io
import os
import tempfile
import unittest
from datetime import datetime
from unittest.mock import Mock, patch

import app
import models
import paramiko
from inspection import compact_uptime, connect_ssh, inspect_server, parse_cpu, parse_disk, parse_disks, parse_mem, parse_proc_cpu, parse_private_key, sanitize_curl_command
from report_utils import build_report_filename


class CpuParserTests(unittest.TestCase):
    def test_parses_all_disk_mounts_without_filtering(self):
        output = """Filesystem 1024-blocks Used Available Capacity Mounted on
/dev/sda1 100 70 30 70% /
/dev/sdb1 100 91 9 91% /data
tmpfs 100 99 1 99% /run
/dev/loop0 100 100 0 100% /snap/core/1
"""
        self.assertEqual(parse_disks(output), [
            {"filesystem": "/dev/sda1", "mount": "/", "usage": 70.0},
            {"filesystem": "/dev/sdb1", "mount": "/data", "usage": 91.0},
            {"filesystem": "tmpfs", "mount": "/run", "usage": 99.0},
            {"filesystem": "/dev/loop0", "mount": "/snap/core/1", "usage": 100.0},
        ])
        self.assertEqual(parse_disk(output), 100.0)

    def test_uptime_keeps_only_largest_unit(self):
        self.assertEqual(compact_uptime("up 4 weeks, 6 days, 3 hours, 12 minutes"), "4周")
        self.assertEqual(
            compact_uptime("21:54 up 8 days, 3:19, 2 users, load averages: 1.0 2.0 3.0"),
            "8天",
        )
        self.assertEqual(compact_uptime("22:00  1 user, load averages: 2.84 2.42 2.50"), "不足1分钟")
        self.assertEqual(compact_uptime("90061.25 120.00"), "1天")

    def test_parses_proc_cpu_snapshots(self):
        output = "cpu  100 0 100 800 0 0 0 0\ncpu  120 0 120 860 0 0 0 0"
        self.assertEqual(parse_proc_cpu(output), 40.0)

    def test_parses_proc_meminfo(self):
        output = "MemTotal:       1000000 kB\nMemAvailable:    250000 kB\n"
        self.assertEqual(parse_mem(output), 75.0)

    def test_parses_common_procps_top_format(self):
        output = "%Cpu(s):  4.0 us,  1.5 sy,  0.0 ni, 94.0 id, 0.5 wa"
        self.assertEqual(parse_cpu(output), 6.0)

    def test_parses_legacy_top_percent_format(self):
        output = "Cpu(s): 12.3%us, 3.4%sy, 0.0%ni, 84.3%id"
        self.assertEqual(parse_cpu(output), 15.7)

    def test_parses_mpstat_all_line(self):
        output = "Average: all 2.00 0.00 3.00 0.00 0.00 0.00 0.00 0.00 95.00"
        self.assertEqual(parse_cpu(output), 5.0)

    def test_proxy_command_blocks_shell_injection(self):
        with self.assertRaises(ValueError):
            sanitize_curl_command("curl https://example.com; cat /etc/passwd")
        with self.assertRaises(ValueError):
            sanitize_curl_command("curl -d @/etc/passwd https://example.com")
        safe = sanitize_curl_command("curl -s https://example.com/health")
        self.assertEqual(safe, "curl -s https://example.com/health")

    @patch("inspection.inspect_local_server")
    def test_loopback_uses_local_inspection_without_ssh(self, local_inspection):
        local_inspection.return_value = {"ok": True, "cpu": 12.5}
        result = inspect_server("127.0.0.1", 22, "local", "unused")
        self.assertTrue(result["ok"])
        local_inspection.assert_called_once_with("127.0.0.1", True, True, True)


class SshKeyTests(unittest.TestCase):
    def setUp(self):
        key = paramiko.RSAKey.generate(1024)
        buffer = io.StringIO()
        key.write_private_key(buffer)
        self.private_key = buffer.getvalue()

    def test_private_key_is_parsed_in_memory(self):
        parsed = parse_private_key(self.private_key)
        self.assertIsInstance(parsed, paramiko.RSAKey)

    def test_key_connection_disables_implicit_local_credentials(self):
        ssh = Mock()
        connect_ssh(ssh, "server.example", 22, "root", private_key=self.private_key)
        args, kwargs = ssh.connect.call_args
        self.assertEqual(args, ("server.example",))
        self.assertEqual(kwargs["username"], "root")
        self.assertIsInstance(kwargs["pkey"], paramiko.RSAKey)
        self.assertFalse(kwargs["allow_agent"])
        self.assertFalse(kwargs["look_for_keys"])


class SchedulerTests(unittest.TestCase):
    @patch("app.enqueue_inspection")
    @patch("app.update_task_last_run")
    @patch("app.list_inspection_tasks")
    def test_dispatches_due_task_once_per_minute(self, list_tasks, update_last_run, enqueue):
        task = {
            "id": 7, "name": "daily", "project_name": "ops", "inspector": "tester",
            "report_format": "excel", "resource_group_id": None, "check_cpu": True,
            "check_mem": True, "check_disk": True, "enable_proxy": False,
            "proxy_rules": [], "enable_schedule": True, "schedule_time": "09:30",
            "last_run": "2026-06-26 09:30:00"
        }
        list_tasks.return_value = [task]
        enqueue.return_value = ("run-7", True)

        count = app.dispatch_scheduled_tasks(datetime(2026, 6, 27, 9, 30, 15))

        self.assertEqual(count, 1)
        update_last_run.assert_called_once_with(7)
        enqueue.assert_called_once()

        task["last_run"] = "2026-06-27 09:30:15"
        count = app.dispatch_scheduled_tasks(datetime(2026, 6, 27, 9, 30, 40))
        self.assertEqual(count, 0)


class DurableQueueTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.old_path = models.SQLITE_PATH
        models.SQLITE_PATH = os.path.join(self.temp_dir.name, "queue.db")
        models.init_db()

    def tearDown(self):
        models.SQLITE_PATH = self.old_path
        self.temp_dir.cleanup()

    def test_queue_claim_progress_and_completion_are_persistent(self):
        payload = {"task_name": "daily", "project_name": "ops"}
        self.assertTrue(models.create_inspection_run("run-1", "daily", "manual", payload))
        job = models.claim_next_inspection_run()
        self.assertEqual(job["run_id"], "run-1")
        self.assertEqual(job["attempts"], 1)

        models.update_inspection_run_progress("run-1", "working", 45)
        models.finish_inspection_run("run-1", "/reports/daily.xlsx")
        run = models.get_inspection_run("run-1")
        self.assertEqual(run["status"], "success")
        self.assertEqual(run["progress"], 100)

    def test_dedupe_and_restart_recovery(self):
        payload = {"task_name": "daily"}
        self.assertTrue(models.create_inspection_run(
            "run-1", "daily", "scheduled", payload, dedupe_key="daily:1"
        ))
        self.assertFalse(models.create_inspection_run(
            "run-2", "daily", "scheduled", payload, dedupe_key="daily:1"
        ))
        models.claim_next_inspection_run()
        self.assertEqual(models.recover_interrupted_inspection_runs(), 1)
        self.assertEqual(models.get_inspection_run("run-1")["status"], "queued")


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.client = app.app.test_client()
        with self.client.session_transaction() as session:
            session["username"] = "admin"
            session["role"] = "admin"
            session["csrf_token"] = "test-csrf-token"

    def test_password_hash_is_salted_and_legacy_hash_still_verifies(self):
        first = app.hash_password("Admin123")
        second = app.hash_password("Admin123")
        self.assertNotEqual(first, second)
        self.assertTrue(app.verify_password(first, "Admin123")[0])
        legacy = hashlib.sha256(b"Admin123").hexdigest()
        self.assertEqual(app.verify_password(legacy, "Admin123"), (True, True))

    def test_session_expires_after_two_hours_idle(self):
        now = app.time.time()
        with self.client.session_transaction() as session:
            session["login_at"] = now - app.SESSION_IDLE_SECONDS - 1
            session["last_activity_at"] = now - app.SESSION_IDLE_SECONDS - 1
        response = self.client.get("/api/servers")
        self.assertEqual(response.status_code, 401)

    def test_active_session_has_no_absolute_time_limit(self):
        now = app.time.time()
        with self.client.session_transaction() as session:
            session["login_at"] = now - 30 * 24 * 60 * 60
            session["last_activity_at"] = now
        response = self.client.get("/api/servers")
        self.assertEqual(response.status_code, 200)

    def test_server_api_does_not_expose_encrypted_credentials(self):
        response = self.client.get("/api/servers")
        self.assertEqual(response.status_code, 200)
        for server in response.get_json():
            self.assertNotIn("enc_password", server)
            self.assertNotIn("enc_private_key", server)
            self.assertNotIn("enc_key_passphrase", server)

    def test_wsgi_server_banner_does_not_expose_runtime_versions(self):
        handler = app.VersionlessWSGIRequestHandler
        self.assertNotIn("Werkzeug", handler.server_version)
        self.assertNotIn("Python", handler.sys_version)
        self.assertEqual(handler.version_string(handler), handler.server_version)

    def test_server_health_monitor_timing_policy(self):
        self.assertEqual(app.SERVER_HEALTH_INTERVAL, 5 * 60)
        self.assertEqual(app.SERVER_OFFLINE_AFTER, app.SERVER_HEALTH_INTERVAL * 2)
        self.assertGreater(app.SERVER_OFFLINE_AFTER, app.SERVER_HEALTH_INTERVAL)

    def test_dashboard_page_renders_health_timing_policy(self):
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("自动探测周期 5 分钟", html)
        self.assertIn("连续 10 分钟未成功即判定掉线", html)

    @patch("app.add_server")
    def test_server_api_accepts_encrypted_ssh_key(self, add_server):
        key = paramiko.RSAKey.generate(1024)
        buffer = io.StringIO()
        key.write_private_key(buffer)
        response = self.client.post(
            "/api/servers",
            headers={"X-CSRFToken": "test-csrf-token"},
            json={
                "ip": "server.example", "port": 22, "username": "root",
                "auth_type": "key", "private_key": buffer.getvalue(),
                "key_passphrase": "", "group_ids": [], "notes": "",
            },
        )
        self.assertEqual(response.status_code, 200)
        kwargs = add_server.call_args.kwargs
        self.assertEqual(kwargs["auth_type"], "key")
        self.assertTrue(kwargs["enc_private_key"])
        self.assertIsNone(kwargs["enc_key_passphrase"])

    @patch("app.connect_ssh")
    @patch("app.create_ssh_client")
    def test_server_connection_uses_current_form_credentials(self, create_client, connect_ssh):
        ssh = Mock()
        create_client.return_value = ssh
        response = self.client.post(
            "/api/servers/test-connection",
            headers={"X-CSRFToken": "test-csrf-token"},
            json={
                "ip": "server.example", "port": 2222, "username": "root",
                "auth_type": "password", "password": "secret",
            },
        )
        self.assertEqual(response.status_code, 200)
        connect_ssh.assert_called_once_with(
            ssh, "server.example", 2222, "root", password="secret",
            private_key=None, key_passphrase=None, timeout=10,
        )
        ssh.close.assert_called_once()

    @patch("app.aes_gcm_decrypt", return_value="saved-secret")
    @patch("app.get_server")
    @patch("app.connect_ssh")
    @patch("app.create_ssh_client")
    def test_edit_connection_uses_saved_password_when_blank(
        self, create_client, connect_ssh, get_server, decrypt
    ):
        ssh = Mock()
        create_client.return_value = ssh
        get_server.return_value = {
            "id": 9, "auth_type": "password", "enc_password": "encrypted-old",
            "enc_private_key": None, "enc_key_passphrase": None,
        }
        response = self.client.post(
            "/api/servers/test-connection",
            headers={"X-CSRFToken": "test-csrf-token"},
            json={
                "id": 9, "ip": "edited.example", "port": 22, "username": "ops",
                "auth_type": "password", "password": "",
            },
        )
        self.assertEqual(response.status_code, 200)
        connect_ssh.assert_called_once_with(
            ssh, "edited.example", 22, "ops", password="saved-secret",
            private_key=None, key_passphrase=None, timeout=10,
        )

    @patch("app.update_server")
    @patch("app.get_server")
    def test_server_edit_keeps_password_when_left_blank(self, get_server, update_server):
        get_server.return_value = {
            "id": 9, "auth_type": "password", "enc_password": "encrypted-old",
            "enc_private_key": None, "enc_key_passphrase": None,
        }
        response = self.client.put(
            "/api/servers",
            headers={"X-CSRFToken": "test-csrf-token"},
            json={
                "id": 9, "ip": "new.example", "port": 22, "username": "ops",
                "auth_type": "password", "password": "", "notes": "updated",
                "group_ids": [1, 2],
            },
        )
        self.assertEqual(response.status_code, 200)
        args = update_server.call_args.args
        self.assertEqual(args[0:5], (9, "new.example", 22, "ops", "encrypted-old"))
        self.assertEqual(args[5], [1, 2])

    def test_mutation_without_csrf_is_rejected(self):
        response = self.client.post("/api/toggle_schedule", json={"id": 1})
        self.assertEqual(response.status_code, 403)

    def test_mutation_with_csrf_is_allowed(self):
        response = self.client.post(
            "/api/logout", headers={"X-CSRFToken": "test-csrf-token"}
        )
        self.assertEqual(response.status_code, 200)

    def test_report_download_cannot_escape_report_directory(self):
        response = self.client.get("/api/download_report", query_string={"path": __file__})
        self.assertEqual(response.status_code, 404)

    def test_security_headers_are_present(self):
        response = self.client.get("/")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])


class ReportNamingTests(unittest.TestCase):
    def test_report_filename_uses_sanitized_task_name(self):
        name = build_report_filename(
            ' 日常/巡检:生产环境 ', 'xlsx', datetime(2026, 6, 27, 9, 30, 0)
        )
        self.assertEqual(name, '日常_巡检_生产环境_20260627_093000.xlsx')


if __name__ == "__main__":
    unittest.main()
