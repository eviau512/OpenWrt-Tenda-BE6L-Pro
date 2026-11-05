# SPDX-License-Identifier: MIT
"""Send bounded, authenticated SSH recovery heartbeats; never reboot a host.

Use a previously verified SSH host key. This helper does not accept passwords,
disable host-key checks, change routes, or install anything on the router.
Stopping heartbeats leaves the router's configured recovery deadline in force.
"""
import argparse
import ipaddress
import re
import subprocess
import time
import uuid


def target(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if len(value) <= 253 and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", value):
            return value
        raise argparse.ArgumentTypeError("Use a literal IP address or DNS hostname") from None


def command(args, operation):
    result = [args.ssh, "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
              "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
              "-o", "ConnectTimeout=5", "-o", "ServerAliveInterval=5",
              "-o", "ServerAliveCountMax=1", "-p", str(args.port)]
    if args.known_hosts:
        result += ["-o", "UserKnownHostsFile=" + str(args.known_hosts)]
    if getattr(args, "identity_file", None):
        result += ["-i", str(args.identity_file), "-o", "IdentitiesOnly=yes"]
    result += ["root@" + args.host, "/usr/sbin/be6l-recovery-guard " + operation]
    return result


def receipt(output):
    match = re.fullmatch(r"BE6L_HEARTBEAT ([0-9a-f-]{36}) ([0-9]{1,9})\r?\n?", output)
    if not match:
        raise ValueError("Missing recovery heartbeat receipt")
    boot = str(uuid.UUID(match[1]))
    if boot != match[1]:
        raise ValueError("Noncanonical boot ID")
    return boot, int(match[2])


def run(args):
    end = time.monotonic() + args.duration
    expected_boot = args.expected_boot_id
    operation = "arm" if args.arm else "heartbeat"
    accepted = 0
    while time.monotonic() < end:
        try:
            result = subprocess.run(command(args, operation), capture_output=True,
                                    text=True, timeout=15, check=False)
            if result.returncode:
                raise ValueError("SSH or recovery command failed, exit=" + str(result.returncode))
            boot, uptime = receipt(result.stdout)
            if expected_boot is not None and boot != expected_boot:
                print("Boot changed; heartbeats stopped. Requalify the device before continuing.", flush=True)
                return 3
            expected_boot = boot
            operation = "heartbeat"
            accepted += 1
            print("Heartbeat accepted: boot=" + boot + " uptime=" + str(uptime), flush=True)
        except (OSError, subprocess.TimeoutExpired, ValueError) as error:
            print(type(error).__name__ + ": " + str(error), flush=True)
        remaining = end - time.monotonic()
        if remaining > 0:
            time.sleep(min(args.interval, remaining))
    print("Heartbeat helper finished; router recovery remains armed unless explicitly disarmed.", flush=True)
    return 0 if accepted else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, type=target)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--ssh", default="ssh")
    parser.add_argument("--known-hosts")
    parser.add_argument("--identity-file", help="Existing private SSH key; never copied or logged")
    parser.add_argument("--expected-boot-id", type=lambda value: str(uuid.UUID(value)))
    parser.add_argument("--duration", type=int, default=3600)
    parser.add_argument("--interval", type=int, default=20)
    parser.add_argument("--arm", action="store_true", help="Explicitly rearm a disarmed RAM boot")
    args = parser.parse_args()
    if not (1 <= args.port <= 65535 and 1 <= args.duration <= 86400 and 5 <= args.interval <= 30):
        parser.error("Port 1..65535, duration 1..86400 seconds, interval 5..30 seconds required")
    try:
        return run(args)
    except KeyboardInterrupt:
        print("Heartbeats stopped; the router recovery deadline remains in force.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
