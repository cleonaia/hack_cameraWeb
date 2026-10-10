#!/usr/bin/env python3
"""
Camera Recon & IoT Video Stream Scanner (2026 Edition)
High-performance asynchronous reconnaissance tool for IP Cameras, NVRs, and RTSP/ONVIF devices.
"""

import argparse
import asyncio
import ipaddress
import json
import math
import socket
import ssl
import sys
import time
from typing import Dict, List, Optional, Tuple

try:
    from .lab_scope import parse_lab_ipv4
except ImportError:  # Direct ``python tools/camera_recon.py`` invocation.
    from lab_scope import parse_lab_ipv4

# ANSI terminal colors
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_RED = "\033[31m"
C_GREEN = "\033[32m"
C_YELLOW = "\033[33m"
C_BLUE = "\033[34m"
C_CYAN = "\033[36m"
C_MAGENTA = "\033[35m"
C_GRAY = "\033[90m"

BANNER = f"""{C_CYAN}{C_BOLD}
   ██████╗ █████╗ ███╗   ███╗███████╗██████╗  █████╗ 
  ██╔════╝██╔══██╗████╗ ████║██╔════╝██╔══██╗██╔══██╗
  ██║     ███████║██╔████╔██║█████╗  ██████╔╝███████║
  ██║     ██╔══██║██║╚██╔╝██║██╔══╝  ██╔══██╗██╔══██║
  ╚██████╗██║  ██║██║ ╚═╝ ██║███████╗██║  ██║██║  ██║
   ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
   Camera & IoT Stream Discovery Engine [2026]
{C_RESET}"""

COMMON_CAMERA_PORTS = [80, 443, 554, 8000, 8080, 8554, 8899, 5000, 10554, 1935]
MAX_TARGETS = 4096
MAX_CONCURRENCY = 512


async def close_writer(writer) -> None:
    if writer is None:
        return
    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionError, OSError):
        pass

COMMON_RTSP_PATHS = [
    "/live/ch0",
    "/h264Preview_01_main",
    "/onvif1",
    "/stream1",
    "/unicast",
    "/mjpeg/ch1",
    "/axis-media/media.amp",
    "/cam/realmonitor?channel=1&subtype=0",
    "/ch01.264",
    "/videoMain"
]

VENDOR_SIGNATURES = {
    "Hikvision": ["hikvision", "webLib", "app-webs", "hik-vision", "ds-2cd", "dvr", "nvr"],
    "Dahua / Amcrest": ["dahua", "amcrest", "dh_web", "rpc2_login", "general_video"],
    "Axis Communications": ["axis", "vapix", "axis-cgi", "axis video server"],
    "Reolink": ["reolink", "reolink camera"],
    "Foscam": ["foscam", "ipcamera", "foscam web"],
    "Mobotix": ["mobotix", "mxpeg"],
    "Uniview (UNV)": ["uniview", "unv", "ipcam-uniview"],
    "Hanwha / Samsung": ["samsung", "hanwha", "wisepay", "techwin"],
    "ESP32-CAM / DIY": ["esp32-cam", "espressif", "mjpeg stream", "esp_http_server"],
}

class CameraScanner:
    def __init__(self, targets: List[str], ports: List[int], concurrency: int = 100, timeout: float = 2.0, verbose: bool = False):
        self.targets = targets
        self.ports = ports
        self.concurrency = concurrency
        self.timeout = timeout
        self.verbose = verbose
        self.semaphore = asyncio.Semaphore(concurrency)
        self.discovered_cameras: List[Dict] = []

    async def scan_port(self, host: str, port: int) -> bool:
        async with self.semaphore:
            writer = None
            try:
                conn = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                return True
            except Exception:
                return False
            finally:
                if writer is not None:
                    await close_writer(writer)

    async def probe_http(self, host: str, port: int, use_tls: bool = False) -> Optional[Tuple[str, str, Dict[str, str]]]:
        async with self.semaphore:
            writer = None
            try:
                if use_tls:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    conn = asyncio.open_connection(host, port, ssl=ctx)
                else:
                    conn = asyncio.open_connection(host, port)

                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                req = f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: CameraScanner/2026\r\nConnection: close\r\n\r\n"
                writer.write(req.encode('latin1'))
                await writer.drain()

                raw_data = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
                writer.close()
                await writer.wait_closed()

                text = raw_data.decode('latin1', errors='ignore')
                headers = {}
                body = ""
                parts = text.split("\r\n\r\n", 1)
                header_lines = parts[0].split("\r\n")
                status_line = header_lines[0] if header_lines else ""

                for line in header_lines[1:]:
                    if ": " in line:
                        k, v = line.split(": ", 1)
                        headers[k.lower()] = v

                if len(parts) > 1:
                    body = parts[1]

                server = headers.get("server", "")
                title = ""
                if "<title>" in body.lower():
                    try:
                        title = body.lower().split("<title>")[1].split("</title>")[0].strip()
                    except IndexError:
                        pass

                return (server, title, headers)
            except Exception:
                return None
            finally:
                if writer is not None:
                    await close_writer(writer)

    async def probe_rtsp(self, host: str, port: int) -> Optional[str]:
        async with self.semaphore:
            writer = None
            try:
                conn = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                req = f"OPTIONS rtsp://{host}:{port} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: CameraScanner/2026\r\n\r\n"
                writer.write(req.encode('latin1'))
                await writer.drain()

                raw = await asyncio.wait_for(reader.read(2048), timeout=self.timeout)
                writer.close()
                await writer.wait_closed()

                text = raw.decode('latin1', errors='ignore')
                if "RTSP/1.0 200 OK" in text or "Public:" in text:
                    for line in text.split("\r\n"):
                        if line.lower().startswith("server:"):
                            return line.split(":", 1)[1].strip()
                    return "Standard RTSP Server"
                elif "401 Unauthorized" in text:
                    return "RTSP Server (Auth Required)"
            except Exception:
                pass
            finally:
                if writer is not None:
                    await close_writer(writer)
            return None

    def fingerprint_vendor(self, banner_text: str) -> str:
        lower = banner_text.lower()
        for vendor, patterns in VENDOR_SIGNATURES.items():
            for pat in patterns:
                if pat.lower() in lower:
                    return vendor
        if "rtsp" in lower or "onvif" in lower or "camera" in lower or "dvr" in lower or "nvr" in lower:
            return "Generic IP Camera / NVR"
        return "Unknown Device / IoT"

    async def scan_host(self, host: str):
        open_ports = []
        for port in self.ports:
            if await self.scan_port(host, port):
                open_ports.append(port)

        if not open_ports:
            return

        camera_info = {
            "host": host,
            "open_ports": open_ports,
            "vendor": "Unknown",
            "services": [],
            "rtsp_available": False,
            "rtsp_banner": None,
            "web_title": None,
            "server_header": None
        }

        all_banners = []

        # Check HTTP / HTTPS
        for p in open_ports:
            if p in (80, 8080, 8000, 8899, 5000):
                res = await self.probe_http(host, p, use_tls=False)
                if res:
                    server, title, headers = res
                    all_banners.append(f"{server} {title}")
                    camera_info["services"].append(f"HTTP:{p} ({server})")
                    if title:
                        camera_info["web_title"] = title
                    if server:
                        camera_info["server_header"] = server

            elif p == 443:
                res = await self.probe_http(host, p, use_tls=True)
                if res:
                    server, title, headers = res
                    all_banners.append(f"{server} {title}")
                    camera_info["services"].append(f"HTTPS:{p} ({server})")

            # Check RTSP
            if p in (554, 8554, 10554):
                rtsp_res = await self.probe_rtsp(host, p)
                if rtsp_res:
                    camera_info["rtsp_available"] = True
                    camera_info["rtsp_banner"] = rtsp_res
                    camera_info["services"].append(f"RTSP:{p} ({rtsp_res})")
                    all_banners.append(rtsp_res)

        full_banner_text = " ".join(all_banners)
        camera_info["vendor"] = self.fingerprint_vendor(full_banner_text)

        # Print result to console
        is_cam = camera_info["rtsp_available"] or camera_info["vendor"] != "Unknown Device / IoT" or any(p in [554, 8554, 8899] for p in open_ports)
        if is_cam or self.verbose:
            self.discovered_cameras.append(camera_info)
            tag = f"{C_GREEN}[CAMERA FOUND]{C_RESET}" if is_cam else f"{C_BLUE}[OPEN HOST]{C_RESET}"
            print(f" {tag} {C_BOLD}{host}{C_RESET} | Vendor: {C_YELLOW}{camera_info['vendor']}{C_RESET}")
            print(f"    ├─ Open Ports: {', '.join(map(str, open_ports))}")
            if camera_info['services']:
                print(f"    ├─ Services: {', '.join(camera_info['services'])}")
            if camera_info['web_title']:
                print(f"    ├─ Web Title: {camera_info['web_title']}")
            if camera_info['rtsp_available']:
                print(f"    └─ RTSP Stream: {C_GREEN}Available (Port 554/8554){C_RESET}")
            print()

    async def run(self):
        tasks = [self.scan_host(t) for t in self.targets]
        await asyncio.gather(*tasks)

def expand_targets(target_spec: str) -> List[str]:
    targets = []
    seen = set()

    def add_target(value: str) -> None:
        address = str(parse_lab_ipv4(value))
        if address not in seen:
            seen.add(address)
            targets.append(address)
            if len(targets) > MAX_TARGETS:
                raise ValueError(f"target scope exceeds the {MAX_TARGETS}-host limit")

    for spec in target_spec.split(","):
        spec = spec.strip()
        if not spec:
            continue
        if "/" in spec:
            net = ipaddress.ip_network(spec, strict=False)
            if not isinstance(net, ipaddress.IPv4Network):
                raise ValueError("only IPv4 target networks are supported")
            if net.num_addresses > MAX_TARGETS + 2:
                raise ValueError(f"target network exceeds the {MAX_TARGETS}-host limit")
            for ip in net.hosts():
                add_target(str(ip))
        elif "-" in spec:
            base, end = spec.rsplit("-", 1)
            try:
                base_ip = parse_lab_ipv4(base)
                end_n = int(end, 10)
            except ValueError as exc:
                raise ValueError(f"invalid address range '{spec}'") from exc
            start_n = int(str(base_ip).rsplit(".", 1)[1])
            if not 0 <= end_n <= 255 or end_n < start_n:
                raise ValueError(f"invalid address range '{spec}'")
            if end_n - start_n + 1 > MAX_TARGETS:
                raise ValueError(f"target range exceeds the {MAX_TARGETS}-host limit")
            prefix = str(base_ip).rsplit(".", 1)[0]
            for last_octet in range(start_n, end_n + 1):
                add_target(f"{prefix}.{last_octet}")
        else:
            add_target(spec)
    return targets


def serialize_results(results: List[Dict]) -> str:
    """Stable UTF-8 JSON representation used by the existing -o interface."""
    return json.dumps(results, indent=2, ensure_ascii=False) + "\n"

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Camera Recon - Asynchronous IP Camera & Video Stream Scanner (2026)")
    parser.add_argument("-t", "--target", required=True, help="Target IP, subnet (e.g. 192.168.1.0/24), or range (e.g. 192.168.1.1-50)")
    parser.add_argument("-p", "--ports", default=",".join(map(str, COMMON_CAMERA_PORTS)), help="Comma-separated ports to scan (default: common camera/RTSP ports)")
    parser.add_argument("-c", "--concurrency", type=int, default=100, help="Maximum concurrent connections (default: 100)")
    parser.add_argument("-w", "--timeout", type=float, default=1.5, help="Socket timeout in seconds (default: 1.5)")
    parser.add_argument("-o", "--output", help="Output JSON results to specified file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Display all active hosts regardless of camera match")

    args = parser.parse_args()

    try:
        targets = expand_targets(args.target)
    except ValueError as exc:
        parser.error(str(exc))
    if not targets:
        parser.error("no valid target IP addresses found")

    try:
        ports = [int(p.strip(), 10) for p in args.ports.split(",")]
    except ValueError:
        parser.error("ports must be comma-separated integers")
    if not ports or any(port < 1 or port > 65535 for port in ports):
        parser.error("ports must be between 1 and 65535")
    if not 1 <= args.concurrency <= MAX_CONCURRENCY:
        parser.error(f"concurrency must be between 1 and {MAX_CONCURRENCY}")
    if not math.isfinite(args.timeout) or not 0 < args.timeout <= 60:
        parser.error("timeout must be greater than 0 and no more than 60 seconds")

    print(f"[*] Loaded {C_BOLD}{len(targets)}{C_RESET} target host(s) across {len(ports)} port(s).")
    print(f"[*] Concurrency limit: {args.concurrency} | Timeout: {args.timeout}s\n")

    t_start = time.perf_counter()
    scanner = CameraScanner(targets, ports, concurrency=args.concurrency, timeout=args.timeout, verbose=args.verbose)
    asyncio.run(scanner.run())
    t_total = time.perf_counter() - t_start

    print(f"{C_CYAN}═══════════════════════════════════════════════════════════════{C_RESET}")
    print(f"[*] Scan finished in {t_total:.2f} seconds.")
    print(f"[*] Total cameras/devices identified: {C_GREEN}{len(scanner.discovered_cameras)}{C_RESET}")

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(serialize_results(scanner.discovered_cameras))
        except OSError as exc:
            parser.error(f"cannot write output file: {exc}")
        print(f"[+] Results saved to {args.output}")

if __name__ == "__main__":
    main()
