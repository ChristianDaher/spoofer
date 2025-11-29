"""
Network Spoofer - Main application controller.

Orchestrates: Scanner -> Spoofer -> Monitor -> Controller

Usage:
1. scan_network() - discover devices
2. add_target(ip) - select devices to monitor
3. start() - begin ARP spoofing and monitoring
4. block_device(ip) / limit_device(ip, kbps) - control traffic
5. stop() - cleanup and restore network
"""

import signal
import sys
from typing import Optional
from dataclasses import dataclass, asdict

from core.scanner import NetworkScanner, NetworkDevice, NetworkInfo
from core.spoofer import ARPSpoofer, SpoofTarget, DeviceStatus
from core.bandwidth import BandwidthMonitor, BandwidthStats
from core.traffic import TrafficController


@dataclass
class DeviceState:
    """Complete state of a monitored device."""
    ip: str
    mac: str
    hostname: Optional[str]
    is_gateway: bool
    status: str
    bandwidth_limit_kbps: Optional[int]
    download_rate_mbps: float
    upload_rate_mbps: float
    total_download_mb: float
    total_upload_mb: float


class NetworkSpoofer:
    """Main application controller (Facade pattern)."""

    def __init__(self, interface: Optional[str] = None):
        self.interface = interface
        self.scanner = NetworkScanner(interface)
        self.spoofer = ARPSpoofer(interface)
        self.monitor = BandwidthMonitor(interface)
        self.controller = TrafficController(interface)
        self.network_info: Optional[NetworkInfo] = None
        self.devices: list[NetworkDevice] = []
        self._running = False

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        print("\n[!] Shutting down...")
        self.stop()
        sys.exit(0)

    def initialize(self) -> NetworkInfo:
        """Initialize and gather network info."""
        print("[*] Initializing...")
        self.network_info = self.scanner.get_network_info()

        self.spoofer.set_gateway(
            self.network_info.gateway_ip,
            self.network_info.gateway_mac
        )
        self.monitor.set_gateway(self.network_info.gateway_ip)

        print(f"[+] Interface: {self.network_info.interface}")
        print(f"[+] IP: {self.network_info.ip}")
        print(f"[+] Gateway: {self.network_info.gateway_ip}")
        print(f"[+] Network: {self.network_info.network}")
        return self.network_info

    def scan_network(self) -> list[NetworkDevice]:
        """Scan for devices on the network."""
        if not self.network_info:
            self.initialize()
        print("[*] Scanning network...")
        self.devices = self.scanner.scan()
        return self.devices

    def add_target(self, ip: str) -> bool:
        """Add a device to monitor."""
        device = next((d for d in self.devices if d.ip == ip), None)

        if not device:
            print(f"[!] {ip} not found. Run scan first.")
            return False
        if device.is_gateway:
            print("[!] Cannot target gateway")
            return False

        self.spoofer.add_target(ip, device.mac)
        self.monitor.add_target(ip, device.mac)
        return True

    def remove_target(self, ip: str):
        self.spoofer.remove_target(ip)
        self.monitor.remove_target(ip)
        self.controller.unblock_device(ip)
        self.controller.remove_limit(ip)

    def start(self) -> bool:
        """Start spoofing and monitoring."""
        if self._running:
            return True
        if not self.spoofer.targets:
            print("[!] No targets. Use add_target() first.")
            return False

        print("[*] Starting...")
        self.controller.enable_ip_forwarding()
        self.spoofer.start_spoofing()
        self.monitor.start_monitoring()

        self._running = True
        print("[+] Running - traffic flows through this machine")
        return True

    def stop(self):
        """Stop and restore network."""
        if not self._running:
            return

        print("[*] Stopping...")
        self.monitor.stop_monitoring()
        self.spoofer.stop_spoofing()
        self.controller.cleanup()
        self.controller.disable_ip_forwarding()

        self._running = False
        print("[+] Stopped")

    def block_device(self, ip: str) -> bool:
        """Block device internet access."""
        if ip not in self.spoofer.targets:
            print(f"[!] {ip} not monitored. Add as target first.")
            return False
        self.spoofer.set_target_status(ip, DeviceStatus.BLOCKED)
        return self.controller.block_device(ip)

    def unblock_device(self, ip: str) -> bool:
        if ip in self.spoofer.targets:
            self.spoofer.set_target_status(ip, DeviceStatus.SPOOFED)
        return self.controller.unblock_device(ip)

    def limit_device(self, ip: str, limit_kbps: int) -> bool:
        """Limit device bandwidth (Kbps)."""
        if ip not in self.spoofer.targets:
            print(f"[!] {ip} not monitored. Add as target first.")
            return False
        self.spoofer.set_target_status(ip, DeviceStatus.LIMITED, limit_kbps)
        return self.controller.limit_bandwidth(ip, limit_kbps)

    def remove_limit(self, ip: str) -> bool:
        if ip in self.spoofer.targets:
            self.spoofer.set_target_status(ip, DeviceStatus.SPOOFED)
        return self.controller.remove_limit(ip)

    def get_device_states(self) -> list[DeviceState]:
        """Get current state of all monitored devices."""
        states = []
        for ip, target in self.spoofer.targets.items():
            stats = self.monitor.get_stats(ip)
            device = next((d for d in self.devices if d.ip == ip), None)

            state = DeviceState(
                ip=ip,
                mac=target.mac,
                hostname=device.hostname if device else None,
                is_gateway=False,
                status=target.status.value,
                bandwidth_limit_kbps=target.bandwidth_limit_kbps,
                download_rate_mbps=stats.download_rate_mbps if stats else 0,
                upload_rate_mbps=stats.upload_rate_mbps if stats else 0,
                total_download_mb=stats.total_download_mb if stats else 0,
                total_upload_mb=stats.total_upload_mb if stats else 0
            )
            states.append(state)
        return states

    def get_network_info_dict(self) -> dict:
        if not self.network_info:
            return {}
        return asdict(self.network_info)

    def is_running(self) -> bool:
        return self._running


if __name__ == "__main__":
    print("Network Spoofer")
    print("Use on networks you own or have permission to test.\n")

    spoofer = NetworkSpoofer()

    try:
        info = spoofer.initialize()
        devices = spoofer.scan_network()

        print("\nDevices:")
        for i, d in enumerate(devices):
            marker = " [GW]" if d.is_gateway else ""
            print(f"  {i+1}. {d.ip:15} {d.mac}{marker}")

        print("\nUse API (api.py) for full interface")

    except KeyboardInterrupt:
        spoofer.stop()
    except Exception as e:
        print(f"Error: {e}")
        spoofer.stop()
