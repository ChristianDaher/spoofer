"""
Network Scanner - ARP-based device discovery.

Sends ARP requests to discover devices on the local network.
ARP maps IP addresses to MAC addresses at Layer 2.
"""

import socket
import struct
from typing import Optional
from dataclasses import dataclass
from scapy.all import ARP, Ether, srp, conf, get_if_addr, get_if_hwaddr
import netifaces


@dataclass
class NetworkDevice:
    """A device discovered on the network."""
    ip: str
    mac: str
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    is_gateway: bool = False


@dataclass
class NetworkInfo:
    """Current network interface information."""
    interface: str
    ip: str
    mac: str
    gateway_ip: str
    gateway_mac: str
    netmask: str
    network: str


class NetworkScanner:
    """Scans the local network using ARP to discover devices."""

    def __init__(self, interface: Optional[str] = None):
        self.interface = interface or str(conf.iface)
        conf.verb = 0

    def get_network_info(self) -> NetworkInfo:
        """Gather network interface, gateway, and subnet information."""
        our_ip = get_if_addr(self.interface)
        our_mac = get_if_hwaddr(self.interface)
        
        gateways = netifaces.gateways()
        default_gateway = gateways.get('default', {}).get(netifaces.AF_INET)

        if not default_gateway:
            raise RuntimeError("Could not find default gateway")

        gateway_ip = default_gateway[0]
        gateway_mac = self._get_mac(gateway_ip)

        addrs = netifaces.ifaddresses(self.interface)
        netmask = addrs[netifaces.AF_INET][0]['netmask']
        network = self._calculate_network(our_ip, netmask)

        return NetworkInfo(
            interface=self.interface,
            ip=our_ip,
            mac=our_mac,
            gateway_ip=gateway_ip,
            gateway_mac=gateway_mac,
            netmask=netmask,
            network=network
        )

    def _calculate_network(self, ip: str, netmask: str) -> str:
        """Calculate CIDR network address from IP and netmask."""
        ip_parts = [int(x) for x in ip.split('.')]
        mask_parts = [int(x) for x in netmask.split('.')]

        network_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
        network_addr = '.'.join(map(str, network_parts))

        mask_binary = ''.join(format(x, '08b') for x in mask_parts)
        cidr = mask_binary.count('1')

        return f"{network_addr}/{cidr}"

    def _get_mac(self, ip: str) -> str:
        """Get MAC address for an IP using ARP request."""
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        answered, _ = srp(arp_request, timeout=2, iface=self.interface)

        if answered:
            return answered[0][1].hwsrc
        raise RuntimeError(f"Could not get MAC for {ip}")

    def scan(self, network: Optional[str] = None) -> list[NetworkDevice]:
        """Scan network and return list of discovered devices."""
        if network is None:
            info = self.get_network_info()
            network = info.network
            gateway_ip = info.gateway_ip
        else:
            gateway_ip = None

        print(f"[*] Scanning: {network}")

        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
        answered, _ = srp(arp_request, timeout=3, iface=self.interface)

        devices = []
        for sent, received in answered:
            device = NetworkDevice(
                ip=received.psrc,
                mac=received.hwsrc,
                hostname=self._resolve_hostname(received.psrc),
                is_gateway=(received.psrc == gateway_ip)
            )
            devices.append(device)

        devices.sort(key=lambda d: [int(x) for x in d.ip.split('.')])
        print(f"[+] Found {len(devices)} devices")
        return devices

    def _resolve_hostname(self, ip: str) -> Optional[str]:
        """Attempt reverse DNS lookup for hostname."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except socket.herror:
            return None


if __name__ == "__main__":
    scanner = NetworkScanner()
    info = scanner.get_network_info()
    print(f"Interface: {info.interface}, IP: {info.ip}, Gateway: {info.gateway_ip}")
    
    devices = scanner.scan()
    for d in devices:
        marker = " [GW]" if d.is_gateway else ""
        print(f"  {d.ip:15} {d.mac}{marker}")
