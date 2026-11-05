# SPDX-License-Identifier: MIT
"""Offline actual-shell state/daemon tests. No network, reboot or watchdog calls."""
from pathlib import Path
import argparse
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[2]
FILES = BASE / "packages/be6l-recovery-guard/files"
SHELL = os.environ.get("BE6L_TEST_SHELL", "sh")
BOOT = "00000000-0000-4000-8000-000000000001"

spec = importlib.util.spec_from_file_location("heartbeat", Path(__file__).with_name("ssh_heartbeat.py"))
heartbeat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(heartbeat)


def shell(code, *args):
    env = dict(os.environ)
    parent = str(Path(SHELL).parent)
    if parent != ".":
        env["PATH"] = parent + os.pathsep + env.get("PATH", "")
    return subprocess.run([SHELL, "-c", code, "test", *map(str, args)],
                          text=True, capture_output=True, timeout=10, env=env)


def library(code, *args):
    return shell('. "$1"; shift\n' + code, (FILES / "state.sh").as_posix(), *args)


class StateTests(unittest.TestCase):
    def test_deadline_boundaries(self):
        cases = [(0, -1, "wait", 600), (599, -1, "wait", 600), (600, -1, "reboot", 600),
                 (601, -1, "reboot", 600), (599, 10, "wait", 600),
                 (600, 500, "wait", 800), (799, 500, "wait", 800),
                 (800, 500, "reboot", 800), (801, 500, "reboot", 800),
                 (800, 799, "wait", 1099)]
        for now, last, action, deadline in cases:
            with self.subTest(now=now, last=last):
                result = library('guard_step "$1" 600 300 "$2" || exit 1; printf "%s %s" "$GUARD_ACTION" "$GUARD_DEADLINE"', now, last)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, f"{action} {deadline}")

    def test_invalid_arithmetic(self):
        for value in ("", "-1", "+1", "00", "08", "1 2", "1;exit 0", "$(echo 1)", "9999999999"):
            with self.subTest(value=value):
                self.assertNotEqual(library('guard_uint "$1"', value).returncode, 0)

    def test_config_bounds(self):
        for config in ((600, 300, 5, 30), (60, 60, 1, 5), (3600, 3600, 30, 30)):
            self.assertEqual(library('guard_config "$@"', *config).returncode, 0)
        for config in ((0, 300, 5, 30), (600, 0, 5, 30), (600, 3601, 5, 30),
                       (600, 300, 0, 30), (600, 300, 31, 30), (600, 300, 5, 31)):
            with self.subTest(config=config):
                self.assertNotEqual(library('guard_config "$@"', *config).returncode, 0)

    def test_heartbeat_identity_and_future_time(self):
        for boot, stamp, extra, expected in ((BOOT, "500", "", 0), (BOOT, "600", "", 0),
                                             ("old-boot", "500", "", 1), (BOOT, "601", "", 1),
                                             (BOOT, "", "", 1), (BOOT, "500", "junk", 1)):
            with self.subTest(boot=boot, stamp=stamp, extra=extra):
                result = library('guard_accept_heartbeat "$1" "$2" "$3" "$4" 600', boot, stamp, extra, BOOT)
                self.assertEqual(result.returncode == 0, expected == 0)

    def test_future_trusted_stamp_rejected(self):
        self.assertNotEqual(library('guard_step 600 600 300 601').returncode, 0)


class DaemonTests(unittest.TestCase):
    def invoke(self, scenario):
        with tempfile.TemporaryDirectory(prefix="be6l-guard-") as folder:
            root = Path(folder)
            source = (FILES / "be6l-recovery-guard").read_text()
            source = source.replace('. /usr/lib/be6l-recovery-guard/state.sh',
                                    '. "' + (FILES / "state.sh").as_posix() + '"', 1)
            source = source.rsplit('\nmain "$@"\n', 1)[0]
            # Only platform, clock and effects are substituted. The shipped
            # heartbeat parsing, CLI, expiry loop and firing logic run intact.
            source += '''
GUARD_DIR=$1
GUARD_BOOT=$2
NOW=595
guard_platform() { return 0; }
guard_prepare() { return 0; }
guard_clock() { GUARD_NOW=$NOW; }
guard_log() { printf '%s\n' "$*" >> "$GUARD_DIR/log"; }
guard_reboot() { printf 'reboot %s\n' "$*" >> "$GUARD_DIR/actions"; }
guard_sleep() {
    wait
    [ "$1" = 30 ] && return 0
    NOW=$((NOW + 5))
    [ "$NOW" -lt 620 ] || exit 0
}
'''
            source += scenario
            result = shell(source, root.as_posix(), BOOT)
            self.assertEqual(result.returncode, 0, result.stderr)
            return {name: (root / name).read_text() if (root / name).is_file() else None
                    for name in ("actions", "log", "heartbeat", "disarmed", "observed")}

    def test_expiry_and_single_forced_fallback(self):
        data = self.invoke('guard_run 600 300 5 30\n')
        self.assertEqual(data["actions"].splitlines(), ["reboot ", "reboot -f"])

    def test_disarmed_does_not_reboot(self):
        data = self.invoke(': > "$GUARD_DIR/disarmed"\nguard_run 600 300 5 30\n')
        self.assertIsNone(data["actions"])

    def test_reconnected_heartbeat_extends_deadline(self):
        data = self.invoke('SSH_CONNECTION="authenticated-test"\nmain heartbeat >/dev/null\nguard_run 600 300 5 30\n')
        self.assertIsNone(data["actions"])
        self.assertEqual(data["heartbeat"].strip(), BOOT + " 595")

    def test_daemon_restart_preserves_expired_deadline(self):
        data = self.invoke('printf "%s 100\\n" "$GUARD_BOOT" > "$GUARD_DIR/heartbeat"\nNOW=600\nguard_run 600 300 5 30\n')
        self.assertEqual(len(data["actions"].splitlines()), 2)

    def test_stale_boot_heartbeat_cannot_hold_recovery(self):
        data = self.invoke('printf "old-boot 595\\n" > "$GUARD_DIR/heartbeat"\nguard_run 600 300 5 30\n')
        self.assertEqual(len(data["actions"].splitlines()), 2)

    def test_future_heartbeat_cannot_hold_recovery(self):
        data = self.invoke('printf "%s 9999\\n" "$GUARD_BOOT" > "$GUARD_DIR/heartbeat"\nguard_run 600 300 5 30\n')
        self.assertEqual(len(data["actions"].splitlines()), 2)

    def test_fired_marker_prevents_respawn_reboot(self):
        data = self.invoke('mkdir "$GUARD_DIR/fired"\nguard_run 600 300 5 30\n')
        self.assertIsNone(data["actions"])

    def test_no_ssh_context_is_rejected(self):
        data = self.invoke('SSH_CONNECTION=\nif main heartbeat; then exit 1; fi\n')
        self.assertIsNone(data["heartbeat"])

    def test_disarmed_heartbeat_cannot_silently_rearm(self):
        data = self.invoke(': > "$GUARD_DIR/disarmed"\nSSH_CONNECTION=test\nif main heartbeat; then exit 1; fi\n')
        self.assertIsNone(data["heartbeat"])
        self.assertIsNotNone(data["disarmed"])

    def test_explicit_arm_writes_heartbeat_before_enabling(self):
        data = self.invoke(': > "$GUARD_DIR/disarmed"\nSSH_CONNECTION=test\nmain arm >/dev/null\nguard_run 600 300 5 30\n')
        self.assertIsNone(data["disarmed"])
        self.assertIsNone(data["actions"])
        self.assertEqual(data["heartbeat"].strip(), BOOT + " 595")

    def test_old_atomic_write_cannot_regress_live_heartbeat(self):
        data = self.invoke('''
GUARD_LAST=590
GUARD_NOW=600
printf '%s 580\n' "$GUARD_BOOT" > "$GUARD_DIR/heartbeat"
guard_load_heartbeat
printf '%s' "$GUARD_LAST" > "$GUARD_DIR/observed"
''')
        self.assertEqual(data["observed"], "590")

    def test_invalid_timing_never_reboots(self):
        data = self.invoke('if guard_run 600 0 5 30; then exit 1; fi\n')
        self.assertIsNone(data["actions"])


class HostTests(unittest.TestCase):
    def test_strict_ssh_command(self):
        args = SimpleNamespace(ssh="ssh", host="192.0.2.1", port=22, known_hosts=None)
        args_list = heartbeat.command(args, "heartbeat")
        self.assertIn("StrictHostKeyChecking=yes", args_list)
        self.assertIn("BatchMode=yes", args_list)
        self.assertEqual(args_list[-1], "/usr/sbin/be6l-recovery-guard heartbeat")

    def test_only_exact_receipt_accepted(self):
        self.assertEqual(heartbeat.receipt(f"BE6L_HEARTBEAT {BOOT} 595\n"), (BOOT, 595))
        for output in ("", "success", f"BE6L_HEARTBEAT {BOOT} 595\nextra", f"BE6L_HEARTBEAT {BOOT} -1"):
            with self.subTest(output=output), self.assertRaises(ValueError):
                heartbeat.receipt(output)

    def test_target_validation(self):
        for value in ("192.0.2.1", "2001:db8::1", "router.lan"):
            self.assertEqual(heartbeat.target(value), value)
        for value in ("-oProxyCommand=bad", "x;reboot", "a b", ""):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                heartbeat.target(value)

    def test_boot_change_stops_helper(self):
        args = SimpleNamespace(duration=60, expected_boot_id=BOOT, arm=False, interval=20,
                               ssh="ssh", host="192.0.2.1", port=22, known_hosts=None)
        response = SimpleNamespace(returncode=0, stdout="BE6L_HEARTBEAT 00000000-0000-4000-8000-000000000002 1\n")
        with patch.object(heartbeat.subprocess, "run", return_value=response) as remote:
            self.assertEqual(heartbeat.run(args), 3)
            self.assertEqual(remote.call_count, 1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    options = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromModule(__import__(__name__))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if options.report:
        options.report.write_text(json.dumps({"tests": result.testsRun,
            "failures": len(result.failures), "errors": len(result.errors),
            "passed": result.wasSuccessful(), "shell": SHELL,
            "hardware_qualified": False, "effects": "reboot, clock and platform mocked"}, indent=2) + "\n")
    raise SystemExit(0 if result.wasSuccessful() else 1)
