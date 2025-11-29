"""
Traffic Controller - Block and limit device bandwidth.

When MITM via ARP spoofing, we can:
- Block: Drop packets using iptables FORWARD chain
- Limit: Rate limit using tc (traffic control) with HTB qdisc

Requires root privileges.
"""

import subprocess
import os
from typing import Optional
from dataclasses import dataclass
from enum import Enum


class ControlMethod(Enum):
    IPTABLES = "iptables"
    TC = "tc"


@dataclass
class TrafficRule:
    """Active traffic control rule."""
    ip: str
    action: str  # "block" or "limit"
    limit_kbps: Optional[int] = None
    rule_id: Optional[str] = None


class TrafficController:
    """Controls network traffic using iptables and tc."""

    def __init__(self, interface: Optional[str] = None):
        self.interface = interface or "wlan0"
        self.rules: dict[str, TrafficRule] = {}
        self._tc_initialized = False

        if os.geteuid() != 0:
            print("[!] Warning: Requires root privileges")

    def _run_command(self, command: list[str], check: bool = True) -> tuple[bool, str]:
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=check)
            return True, result.stdout
        except subprocess.CalledProcessError as e:
            return False, e.stderr
        except Exception as e:
            return False, str(e)

    def enable_ip_forwarding(self) -> bool:
        """Enable kernel IP forwarding (required for MITM)."""
        print("[*] Enabling IP forwarding...")
        success, _ = self._run_command(["sysctl", "-w", "net.ipv4.ip_forward=1"])
        if success:
            print("[+] IP forwarding enabled")
        return success

    def disable_ip_forwarding(self) -> bool:
        """Disable IP forwarding."""
        print("[*] Disabling IP forwarding...")
        success, _ = self._run_command(["sysctl", "-w", "net.ipv4.ip_forward=0"])
        return success

    def block_device(self, ip: str) -> bool:
        """Block device by dropping FORWARD chain packets."""
        print(f"[*] Blocking: {ip}")

        success1, _ = self._run_command([
            "iptables", "-A", "FORWARD", "-s", ip, "-j", "DROP"
        ])
        success2, _ = self._run_command([
            "iptables", "-A", "FORWARD", "-d", ip, "-j", "DROP"
        ])
        
        if success1 and success2:
            self.rules[ip] = TrafficRule(ip=ip, action="block")
            print(f"[+] Blocked: {ip}")
            return True
        print(f"[!] Failed to block {ip}")
        return False

    def unblock_device(self, ip: str) -> bool:
        """Remove iptables block rules."""
        print(f"[*] Unblocking: {ip}")

        self._run_command([
            "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"
        ], check=False)
        self._run_command([
            "iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP"
        ], check=False)

        if ip in self.rules:
            del self.rules[ip]
        print(f"[+] Unblocked: {ip}")
        return True

    def _init_tc(self):
        """Initialize HTB qdisc for rate limiting."""
        if self._tc_initialized:
            return True

        print(f"[*] Initializing tc on {self.interface}")

        self._run_command([
            "tc", "qdisc", "del", "dev", self.interface, "root"
        ], check=False)

        success, _ = self._run_command([
            "tc", "qdisc", "add", "dev", self.interface,
            "root", "handle", "1:", "htb", "default", "999"
        ])

        if success:
            self._run_command([
                "tc", "class", "add", "dev", self.interface,
                "parent", "1:", "classid", "1:999",
                "htb", "rate", "100mbit"
            ])
            self._tc_initialized = True
            print("[+] tc initialized")
        return success

    def limit_bandwidth(self, ip: str, limit_kbps: int) -> bool:
        """Limit device bandwidth using tc HTB class."""
        print(f"[*] Limiting {ip} to {limit_kbps} Kbps")

        if not self._init_tc():
            print("[!] Failed to initialize tc")
            return False

        class_id = int(ip.split('.')[-1])

        self._run_command([
            "tc", "class", "del", "dev", self.interface,
            "parent", "1:", "classid", f"1:{class_id}"
        ], check=False)

        success, _ = self._run_command([
            "tc", "class", "add", "dev", self.interface,
            "parent", "1:", "classid", f"1:{class_id}",
            "htb", "rate", f"{limit_kbps}kbit", "ceil", f"{limit_kbps}kbit"
        ])

        if not success:
            print(f"[!] Failed to create tc class for {ip}")
            return False

        self._run_command([
            "tc", "filter", "add", "dev", self.interface,
            "protocol", "ip", "parent", "1:", "prio", "1",
            "u32", "match", "ip", "src", ip, "flowid", f"1:{class_id}"
        ])
        self._run_command([
            "tc", "filter", "add", "dev", self.interface,
            "protocol", "ip", "parent", "1:", "prio", "1",
            "u32", "match", "ip", "dst", ip, "flowid", f"1:{class_id}"
        ])

        self.rules[ip] = TrafficRule(
            ip=ip, action="limit", limit_kbps=limit_kbps, rule_id=str(class_id)
        )
        print(f"[+] Limited: {ip} = {limit_kbps} Kbps")
        return True

    def remove_limit(self, ip: str) -> bool:
        """Remove bandwidth limit."""
        if ip not in self.rules:
            return True

        rule = self.rules[ip]
        if rule.action != "limit":
            return False

        self._run_command([
            "tc", "class", "del", "dev", self.interface,
            "parent", "1:", "classid", f"1:{rule.rule_id}"
        ], check=False)

        del self.rules[ip]
        print(f"[+] Limit removed: {ip}")
        return True

    def cleanup(self):
        """Remove all rules and restore traffic flow."""
        print("[*] Cleaning up traffic rules...")

        for ip, rule in list(self.rules.items()):
            if rule.action == "block":
                self.unblock_device(ip)
            elif rule.action == "limit":
                self.remove_limit(ip)

        self._run_command([
            "tc", "qdisc", "del", "dev", self.interface, "root"
        ], check=False)

        self._tc_initialized = False
        self.rules.clear()
        print("[+] Cleanup complete")

    def get_device_status(self, ip: str) -> Optional[TrafficRule]:
        return self.rules.get(ip)

    def list_rules(self) -> list[TrafficRule]:
        return list(self.rules.values())


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Requires root: sudo python traffic.py")
    else:
        print("Traffic controller ready")
