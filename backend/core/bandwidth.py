"""
Bandwidth Monitor - Packet sniffing to measure device traffic.

When ARP spoofing, all target traffic flows through us.
We capture packets and count bytes to measure bandwidth per device.
"""

import time
import threading
from typing import Optional, Callable
from dataclasses import dataclass, field
from collections import defaultdict
from scapy.all import sniff, IP, Ether, conf, get_if_hwaddr
import queue


@dataclass
class BandwidthStats:
    """Bandwidth statistics for a single device."""
    ip: str
    mac: str
    
    # Current rates (bytes per second)
    download_rate: float = 0.0
    upload_rate: float = 0.0
    
    # Totals
    total_download: int = 0
    total_upload: int = 0
    packet_count: int = 0
    
    # Last update timestamp
    last_updated: float = field(default_factory=time.time)
    
    @property
    def download_rate_kbps(self) -> float:
        """Download rate in Kilobits per second."""
        return (self.download_rate * 8) / 1000
    
    @property
    def upload_rate_kbps(self) -> float:
        """Upload rate in Kilobits per second."""
        return (self.upload_rate * 8) / 1000
    
    @property
    def download_rate_mbps(self) -> float:
        """Download rate in Megabits per second."""
        return (self.download_rate * 8) / 1_000_000
    
    @property
    def upload_rate_mbps(self) -> float:
        """Upload rate in Megabits per second."""
        return (self.upload_rate * 8) / 1_000_000
    
    @property
    def total_download_mb(self) -> float:
        """Total download in Megabytes."""
        return self.total_download / (1024 * 1024)
    
    @property
    def total_upload_mb(self) -> float:
        """Total upload in Megabytes."""
        return self.total_upload / (1024 * 1024)


class BandwidthMonitor:
    """Monitors bandwidth using packet sniffing with sliding window rates."""

    def __init__(self, interface: Optional[str] = None):
        """
        Initialize the bandwidth monitor.
        
        Args:
            interface: Network interface to monitor
        """
        # conf.iface may return a NetworkInterface object, so convert to string
        self.interface = interface or str(conf.iface)
        self.our_mac = get_if_hwaddr(self.interface)
        
        # Statistics per IP address
        self.stats: dict[str, BandwidthStats] = {}
        
        # For rate calculation - track bytes in time windows
        self._download_window: dict[str, list[tuple[float, int]]] = defaultdict(list)
        self._upload_window: dict[str, list[tuple[float, int]]] = defaultdict(list)
        self._window_size = 2.0  # 2 second window for rate calculation
        
        # Known targets (IPs we're monitoring)
        self._target_ips: set[str] = set()
        self._target_macs: dict[str, str] = {}  # ip -> mac mapping
        
        # Gateway info
        self.gateway_ip: Optional[str] = None
        
        # Control
        self._monitoring = False
        self._sniff_thread: Optional[threading.Thread] = None
        
        # Callback for real-time updates
        self._on_update: Optional[Callable[[BandwidthStats], None]] = None
        
        # Disable verbose
        conf.verb = 0
        
    def set_gateway(self, gateway_ip: str):
        """Set the gateway IP address."""
        self.gateway_ip = gateway_ip
        
    def add_target(self, ip: str, mac: str):
        """
        Add a device to monitor.
        
        EDUCATIONAL NOTE:
        -----------------
        We need to know which IPs to track. Packets for other
        devices might also pass through (especially broadcast),
        but we only count traffic for registered targets.
        """
        self._target_ips.add(ip)
        self._target_macs[ip] = mac
        
        if ip not in self.stats:
            self.stats[ip] = BandwidthStats(ip=ip, mac=mac)
            
        print(f"[+] Monitoring bandwidth for: {ip}")
        
    def remove_target(self, ip: str):
        """Remove a device from monitoring."""
        self._target_ips.discard(ip)
        self._target_macs.pop(ip, None)
        # Keep stats for history, don't delete
        
    def on_update(self, callback: Callable[[BandwidthStats], None]):
        """
        Set callback for real-time bandwidth updates.
        
        Args:
            callback: Function called with BandwidthStats when traffic is detected
        """
        self._on_update = callback
        
    def _process_packet(self, packet):
        """
        Process a captured packet and update bandwidth stats.
        
        EDUCATIONAL NOTE:
        -----------------
        Packet structure when we're the man-in-the-middle:
        
        Download (Gateway -> Target, through us):
            Ether: src=gateway_mac, dst=our_mac
            IP: src=external_ip, dst=target_ip
            
        Upload (Target -> Gateway, through us):
            Ether: src=target_mac, dst=our_mac
            IP: src=target_ip, dst=external_ip
            
        We determine direction by looking at the IP layer addresses.
        """
        # We only care about IP packets
        if not packet.haslayer(IP):
            return
            
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        packet_size = len(packet)
        current_time = time.time()
        
        # Check if this packet involves one of our targets
        if src_ip in self._target_ips:
            # Upload: Target is sending data
            self._record_upload(src_ip, packet_size, current_time)
            
        if dst_ip in self._target_ips:
            # Download: Target is receiving data
            self._record_download(dst_ip, packet_size, current_time)
            
    def _record_download(self, ip: str, size: int, timestamp: float):
        """Record a download data point."""
        if ip not in self.stats:
            return
            
        stats = self.stats[ip]
        stats.total_download += size
        stats.packet_count += 1
        stats.last_updated = timestamp
        
        # Add to window for rate calculation
        self._download_window[ip].append((timestamp, size))
        
        # Calculate rate and notify
        self._update_rates(ip)
        
    def _record_upload(self, ip: str, size: int, timestamp: float):
        """Record an upload data point."""
        if ip not in self.stats:
            return
            
        stats = self.stats[ip]
        stats.total_upload += size
        stats.packet_count += 1
        stats.last_updated = timestamp
        
        # Add to window for rate calculation
        self._upload_window[ip].append((timestamp, size))
        
        # Calculate rate and notify
        self._update_rates(ip)
        
    def _update_rates(self, ip: str):
        """
        Calculate current bandwidth rates using sliding window.
        
        EDUCATIONAL NOTE:
        -----------------
        We use a sliding window to calculate rates:
        1. Keep track of (timestamp, bytes) for recent packets
        2. Remove entries older than window_size
        3. Sum bytes and divide by time elapsed
        
        This gives a smoothed rate that's more stable than
        measuring single packets.
        """
        current_time = time.time()
        window_start = current_time - self._window_size
        
        # Clean old entries and sum recent bytes
        download_bytes = self._clean_and_sum(self._download_window[ip], window_start)
        upload_bytes = self._clean_and_sum(self._upload_window[ip], window_start)
        
        # Calculate rates (bytes per second)
        stats = self.stats[ip]
        stats.download_rate = download_bytes / self._window_size
        stats.upload_rate = upload_bytes / self._window_size
        
        # Notify callback
        if self._on_update:
            self._on_update(stats)
            
    def _clean_and_sum(self, window: list[tuple[float, int]], 
                        cutoff: float) -> int:
        """Remove old entries and sum remaining bytes."""
        # Remove entries older than cutoff
        while window and window[0][0] < cutoff:
            window.pop(0)
            
        # Sum remaining bytes
        return sum(size for _, size in window)
    
    def _sniffing_loop(self):
        """
        Main packet sniffing loop.
        
        EDUCATIONAL NOTE:
        -----------------
        We use Scapy's sniff() function with a filter.
        The filter uses BPF (Berkeley Packet Filter) syntax:
        - "ip" = only IP packets (not ARP, etc.)
        
        The prn= parameter specifies a callback for each packet.
        store=0 means don't keep packets in memory (saves RAM).
        """
        print(f"[*] Starting packet capture on {self.interface}")
        
        # Build filter for our target IPs
        # This is more efficient than filtering in Python
        if self._target_ips:
            ip_filter = " or ".join(f"host {ip}" for ip in self._target_ips)
            bpf_filter = f"ip and ({ip_filter})"
        else:
            bpf_filter = "ip"
            
        print(f"[*] BPF Filter: {bpf_filter}")
        
        # Start sniffing
        sniff(
            iface=self.interface,
            prn=self._process_packet,
            filter=bpf_filter,
            store=0,  # Don't store packets in memory
            stop_filter=lambda p: not self._monitoring
        )
        
        print("[*] Packet capture stopped")
        
    def start_monitoring(self):
        """Start monitoring bandwidth."""
        if self._monitoring:
            print("[!] Already monitoring")
            return
            
        if not self._target_ips:
            print("[!] No targets to monitor. Add targets first.")
            return
            
        self._monitoring = True
        self._sniff_thread = threading.Thread(target=self._sniffing_loop, daemon=True)
        self._sniff_thread.start()
        
        print(f"[+] Bandwidth monitoring started for {len(self._target_ips)} device(s)")
        
    def stop_monitoring(self):
        """Stop monitoring bandwidth."""
        if not self._monitoring:
            print("[!] Not monitoring")
            return
            
        print("[*] Stopping bandwidth monitor...")
        self._monitoring = False
        
        # Sniff thread will stop on next packet due to stop_filter
        # We can also send a dummy packet to trigger it
        
        if self._sniff_thread:
            self._sniff_thread.join(timeout=3)
            
        print("[+] Bandwidth monitoring stopped")
        
    def get_stats(self, ip: Optional[str] = None) -> dict[str, BandwidthStats] | BandwidthStats:
        """
        Get bandwidth statistics.
        
        Args:
            ip: Specific IP to get stats for, or None for all
            
        Returns:
            BandwidthStats for specific IP, or dict of all stats
        """
        if ip:
            return self.stats.get(ip)
        return self.stats.copy()
    
    def get_all_stats(self) -> list[BandwidthStats]:
        """Get stats for all monitored devices."""
        return list(self.stats.values())
    
    def reset_stats(self, ip: Optional[str] = None):
        """Reset statistics for one or all devices."""
        if ip:
            if ip in self.stats:
                self.stats[ip] = BandwidthStats(ip=ip, mac=self._target_macs.get(ip, ""))
        else:
            for ip in self.stats:
                self.stats[ip] = BandwidthStats(ip=ip, mac=self._target_macs.get(ip, ""))


# Quick test if run directly
if __name__ == "__main__":
    print("=" * 60)
    print("Bandwidth Monitor - Educational Tool")
    print("=" * 60)
    print("\nThis module should be used with the ARP spoofer.")
    print("Traffic only flows through us when we're spoofing!")
