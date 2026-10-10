#!/usr/bin/env python3
"""Open an explicitly scoped RTSP camera stream in VLC using its own auth prompt."""

import argparse
import ipaddress
import shutil
import subprocess
import sys
from urllib.parse import urlsplit, urlunsplit

try:
    from .tls_shell import parse_allowed_scopes, validate_scoped_ipv4
except ImportError:  # Direct ``python tools/camera_view.py`` invocation.
    from tls_shell import parse_allowed_scopes, validate_scoped_ipv4


def validate_rtsp_url(url: str, allowed_scopes) -> str:
    """Validate a credential-free RTSP URL and pin it to an authorized IPv4."""
    scopes = parse_allowed_scopes(allowed_scopes)
    if any(ord(char) < 32 or ord(char) == 127 for char in url):
        raise ValueError("the RTSP URL cannot contain control characters")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid RTSP URL or port") from exc
    if parsed.scheme.lower() not in ("rtsp", "rtsps"):
        raise ValueError("URL must use rtsp:// or rtsps://")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("provide a camera URL without embedded username or password")
    if parsed.fragment:
        raise ValueError("RTSP URLs cannot include a fragment")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise ValueError("use the camera's numeric IPv4 address to prevent DNS rebinding") from exc
    if not isinstance(address, ipaddress.IPv4Address):
        raise ValueError("only IPv4 camera URLs are supported")
    pinned_ip = validate_scoped_ipv4(str(address), scopes)
    netloc = pinned_ip if port is None else f"{pinned_ip}:{port}"
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))


def open_camera(url: str, allowed_scopes, player="vlc") -> int:
    """Launch VLC without a shell; VLC prompts for credentials when required."""
    safe_url = validate_rtsp_url(url, allowed_scopes)
    executable = shutil.which(player)
    if not executable:
        raise RuntimeError("VLC is not installed or 'vlc' is not available in PATH")
    print("VLC abrirá el flujo. Si la cámara requiere acceso, introduce allí tus credenciales válidas.")
    return subprocess.run([executable, "--no-one-instance", safe_url], check=False).returncode


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Abre un flujo RTSP de una cámara propia dentro de un alcance de laboratorio explícito"
    )
    parser.add_argument("--url", required=True, help="URL RTSP sin credenciales, por ejemplo rtsp://10.42.0.20:554/ruta")
    parser.add_argument("--allowed-scope", action="append", required=True,
                        help="IPv4/subred de laboratorio autorizada; se puede repetir")
    args = parser.parse_args()
    try:
        result = open_camera(args.url, args.allowed_scope)
    except (OSError, RuntimeError, ValueError) as exc:
        parser.error(str(exc))
    raise SystemExit(result)


if __name__ == "__main__":
    main()
