#!/usr/bin/env python3
"""Authenticated TLS 1.3 command and file-transfer service for an isolated lab."""

import argparse
import base64
import getpass
import hashlib
import hmac
import ipaddress
import os
import platform
import re
import secrets
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
from typing import Optional, Tuple

try:
    from .lab_scope import LAB_NETWORKS, parse_lab_ipv4
except ImportError:  # Direct ``python tools/tls_shell.py`` invocation.
    from lab_scope import LAB_NETWORKS, parse_lab_ipv4

MAX_FRAME_SIZE = 32 * 1024 * 1024
MAX_FILE_SIZE = 16 * 1024 * 1024
AUTH_TIMEOUT = 15
SESSION_TIMEOUT = 120
AUTH_DOMAIN = b"ft-malcolm-client-auth-v1\0"
ALLOWED_COMMANDS = {
    "date": ["date", "-u"],
    "id": ["id"],
    "uname": ["uname", "-a"],
    "whoami": ["whoami"],
}


def send_frame(sock: socket.socket, payload: bytes) -> None:
    if len(payload) > MAX_FRAME_SIZE:
        raise ValueError("message exceeds the 32 MiB protocol limit")
    sock.sendall(len(payload).to_bytes(4, "big") + payload)


def recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = sock.recv(length - len(chunks))
        if not chunk:
            raise EOFError("connection closed while reading a protocol frame")
        chunks.extend(chunk)
    return bytes(chunks)


def recv_frame(sock: socket.socket) -> bytes:
    header = bytearray()
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            if not header:
                return b""
            raise EOFError("connection closed in a protocol frame header")
        header.extend(chunk)
    length = int.from_bytes(header, "big")
    if length > MAX_FRAME_SIZE:
        raise ValueError("peer announced a frame larger than 32 MiB")
    return recv_exact(sock, length)


def parse_allowed_scopes(values) -> Tuple[ipaddress.IPv4Network, ...]:
    """Parse explicit lab destinations; RFC1918 membership alone is insufficient."""
    if not values:
        raise ValueError("configure at least one --allowed-scope destination or subnet")
    scopes = []
    for value in values:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid allowed scope: {value}") from exc
        if not isinstance(network, ipaddress.IPv4Network):
            raise ValueError("allowed scopes must be IPv4 destinations or subnets")
        if not any(network.subnet_of(lab) for lab in LAB_NETWORKS):
            raise ValueError(f"allowed scope {network} is outside private/local lab ranges")
        scopes.append(network)
    return tuple(scopes)


def validate_scoped_ipv4(value: str, scopes) -> str:
    address = parse_lab_ipv4(value)
    if not any(address in network for network in scopes):
        raise ValueError(f"{address} is not included in configured --allowed-scope")
    return str(address)


def validate_lab_host(host: str, allowed_scopes) -> str:
    """Resolve once, validate every A record, and return the pinned in-scope IP."""
    scopes = parse_allowed_scopes(allowed_scopes)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        records = socket.getaddrinfo(
            host, None, family=socket.AF_INET, type=socket.SOCK_STREAM
        )
        addresses = sorted({validate_scoped_ipv4(row[4][0], scopes) for row in records})
        if not addresses:
            raise ValueError("host did not resolve to an address in configured lab scope")
        return addresses[0]
    return validate_scoped_ipv4(host, scopes)


def validate_auth_token(token) -> bytes:
    if isinstance(token, str):
        token = token.encode("utf-8")
    if not isinstance(token, bytes) or len(token) < 32:
        raise ValueError("authentication token must contain at least 32 UTF-8 bytes")
    return token


def load_auth_token() -> bytes:
    token = validate_auth_token(os.environ.get("FT_MALCOLM_TOKEN", ""))
    return token


def authenticate_server(sock: socket.socket, token: bytes) -> None:
    token = validate_auth_token(token)
    challenge = secrets.token_bytes(32)
    send_frame(sock, challenge)
    response = recv_frame(sock)
    expected = hmac.digest(token, AUTH_DOMAIN + challenge, "sha256")
    if not hmac.compare_digest(response, expected):
        send_frame(sock, b"AUTH_FAILED")
        raise PermissionError("client authentication failed")
    send_frame(sock, b"AUTH_OK")


def authenticate_client(sock: socket.socket, token: bytes) -> None:
    token = validate_auth_token(token)
    challenge = recv_frame(sock)
    if len(challenge) != 32:
        raise PermissionError("invalid server authentication challenge")
    response = hmac.digest(token, AUTH_DOMAIN + challenge, "sha256")
    send_frame(sock, response)
    if recv_frame(sock) != b"AUTH_OK":
        raise PermissionError("server rejected client authentication")


def generate_self_signed_cert() -> Tuple[str, str]:
    """Generate an ephemeral server certificate without invoking a shell."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".crt") as cert:
        cert_file = cert.name
    with tempfile.NamedTemporaryFile(delete=False, suffix=".key") as key:
        key_file = key.name
    try:
        subprocess.run(
            ["openssl", "req", "-new", "-newkey", "rsa:2048", "-days", "2",
             "-nodes", "-x509", "-keyout", key_file, "-out", cert_file,
             "-subj", "/CN=ft-malcolm-lab"],
            check=True, capture_output=True, timeout=30,
        )
        os.chmod(key_file, 0o600)
    except (OSError, subprocess.SubprocessError) as exc:
        for path in (cert_file, key_file):
            try:
                os.unlink(path)
            except OSError:
                pass
        raise RuntimeError(f"unable to create the temporary TLS certificate: {exc}") from exc
    return cert_file, key_file


def open_transfer_root(path: str) -> int:
    os.makedirs(path, mode=0o700, exist_ok=True)
    resolved = os.path.realpath(path)
    flags = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
             | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    fd = os.open(resolved, flags)
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077
            or info.st_uid != os.geteuid()):
        os.close(fd)
        raise PermissionError("--file-root must be a directory private to the current user (mode 0700)")
    return fd


def safe_transfer_name(name: str) -> str:
    if (not name or name in (".", "..") or "/" in name or "\\" in name
            or "\0" in name or os.path.basename(name) != name):
        raise ValueError("transfers accept a single filename inside --file-root")
    if any(ord(char) < 32 or ord(char) == 127 for char in name):
        raise ValueError("control characters are not allowed in transfer filenames")
    return name


def read_transfer_file(root_fd: int, name: str) -> bytes:
    name = safe_transfer_name(name)
    flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
    fd = os.open(name, flags, dir_fd=root_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("transfer source must be a regular file")
        if info.st_nlink != 1:
            raise ValueError("transfer source must not have other hard links")
        if info.st_size > MAX_FILE_SIZE:
            raise ValueError(f"file exceeds {MAX_FILE_SIZE // (1024 * 1024)} MiB limit")
        chunks = bytearray()
        while True:
            chunk = os.read(fd, min(65536, MAX_FILE_SIZE + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
            if len(chunks) > MAX_FILE_SIZE:
                raise ValueError(f"file exceeds {MAX_FILE_SIZE // (1024 * 1024)} MiB limit")
        return bytes(chunks)
    finally:
        os.close(fd)


def create_transfer_file(root_fd: int, name: str, content: bytes) -> None:
    name = safe_transfer_name(name)
    if len(content) > MAX_FILE_SIZE:
        raise ValueError(f"file exceeds {MAX_FILE_SIZE // (1024 * 1024)} MiB limit")
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
             | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    fd = os.open(name, flags, 0o600, dir_fd=root_fd)
    try:
        view = memoryview(content)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write while creating transfer file")
            view = view[written:]
        os.fsync(fd)
    except Exception:
        os.close(fd)
        try:
            os.unlink(name, dir_fd=root_fd)
        except OSError:
            pass
        raise
    else:
        os.close(fd)


def execute_allowed_command(name: str) -> bytes:
    argv = ALLOWED_COMMANDS.get(name)
    if argv is None:
        raise ValueError("command is not allowed")
    result = subprocess.run(argv, capture_output=True, timeout=30, check=False)
    output = result.stdout + result.stderr
    return output[:MAX_FRAME_SIZE]


def run_listener(port: int, bind_ip: str = "127.0.0.1", cert_file: str = None,
                 key_file: str = None, file_root: str = "./tls-transfer",
                 allowed_scopes=()) -> None:
    scopes = parse_allowed_scopes(allowed_scopes)
    validate_scoped_ipv4(bind_ip, scopes)
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    token = load_auth_token()
    if bool(cert_file) != bool(key_file):
        raise ValueError("--cert and --key must be supplied together")

    temp_cert = False
    if not cert_file:
        cert_file, key_file = generate_self_signed_cert()
        temp_cert = True
    transfer_fd = None
    bind_sock = None
    raw_sock = None
    tls_sock = None
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        with open(cert_file, "r", encoding="ascii") as cert_stream:
            fingerprint = hashlib.sha256(
                ssl.PEM_cert_to_DER_cert(cert_stream.read())
            ).hexdigest()
        transfer_fd = open_transfer_root(file_root)
        bind_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bind_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bind_sock.bind((bind_ip, port))
        bind_sock.listen(1)
        print(f"[*] TLS 1.3 listener on {bind_ip}:{port}")
        print(f"[*] Required server SHA-256 fingerprint: {fingerprint}")
        print(f"[*] File transfer root: {os.path.realpath(file_root)}")
        raw_sock, addr = bind_sock.accept()
        validate_scoped_ipv4(addr[0], scopes)
        raw_sock.settimeout(AUTH_TIMEOUT)
        tls_sock = context.wrap_socket(raw_sock, server_side=True)
        authenticate_server(tls_sock, token)
        tls_sock.settimeout(SESSION_TIMEOUT)
        print(f"[+] Authenticated lab agent {addr[0]}:{addr[1]}")
        print("Commands: !sysinfo, !pwd, !list, !exec <date|id|uname|whoami>, !download <remote> <local>, !upload <local> <remote>, !exit")

        while True:
            cmd = input(f"malcolm-shell [{addr[0]}]> ").strip()
            if not cmd:
                continue
            if cmd == "!exit":
                send_frame(tls_sock, b"!exit\n")
                break
            if cmd.startswith("!download "):
                parts = cmd.split(maxsplit=2)
                if len(parts) != 3:
                    print("Usage: !download <remote_file> <local_file>")
                    continue
                send_frame(tls_sock, f"!get {safe_transfer_name(parts[1])}\n".encode())
                response = recv_frame(tls_sock).decode("utf-8", errors="replace")
                if response.startswith("FILE:"):
                    payload = base64.b64decode(response[5:].strip(), validate=True)
                    create_transfer_file(transfer_fd, parts[2], payload)
                    print(f"[+] Downloaded to {parts[2]}")
                else:
                    print(response.strip())
                continue
            if cmd.startswith("!upload "):
                parts = cmd.split(maxsplit=2)
                if len(parts) != 3:
                    print("Usage: !upload <local_file> <remote_file>")
                    continue
                payload = read_transfer_file(transfer_fd, parts[1])
                encoded = base64.b64encode(payload).decode("ascii")
                send_frame(tls_sock, f"!put {safe_transfer_name(parts[2])} {encoded}\n".encode())
                print(recv_frame(tls_sock).decode("utf-8", errors="replace").strip())
                continue
            if cmd in ("!sysinfo", "!pwd", "!list") or cmd.startswith("!exec "):
                if cmd.startswith("!exec ") and cmd[6:] not in ALLOWED_COMMANDS:
                    print("Allowed commands: " + ", ".join(sorted(ALLOWED_COMMANDS)))
                    continue
                send_frame(tls_sock, (cmd + "\n").encode())
                print(recv_frame(tls_sock).decode("utf-8", errors="replace"), end="")
                continue
            print("Command not allowed; use !sysinfo, !pwd, !list, !exec <allowed>, file transfer, or !exit.")
    finally:
        for sock in (tls_sock, raw_sock, bind_sock):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        if transfer_fd is not None:
            os.close(transfer_fd)
        if temp_cert:
            for path in (cert_file, key_file):
                try:
                    os.unlink(path)
                except OSError:
                    pass


def run_agent(host: str, port: int, fingerprint: str, allowed_scopes,
              file_root: str = "./tls-transfer") -> None:
    pinned_ip = validate_lab_host(host, allowed_scopes)
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if not re.fullmatch(r"(?:[0-9a-fA-F]{2}:?){32}", fingerprint):
        raise ValueError("--fingerprint must contain 32 hexadecimal bytes")
    token = load_auth_token()
    transfer_fd = open_transfer_root(file_root)
    raw_sock = None
    sock = None
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(AUTH_TIMEOUT)
        raw_sock.connect((pinned_ip, port))
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        sock = context.wrap_socket(raw_sock, server_hostname=pinned_ip)
        actual = hashlib.sha256(sock.getpeercert(binary_form=True)).hexdigest()
        expected = fingerprint.replace(":", "").lower()
        if not hmac.compare_digest(actual, expected):
            raise ssl.SSLError("server certificate fingerprint mismatch")
        authenticate_client(sock, token)
        sock.settimeout(SESSION_TIMEOUT)
        print(f"[+] Authenticated to TLS 1.3 listener at {pinned_ip}:{port}")

        while True:
            frame = recv_frame(sock)
            line = frame.decode("utf-8", errors="replace") if frame else ""
            if not line:
                break
            line = line.strip()
            if line == "!exit":
                break
            if line == "!sysinfo":
                response = (
                    f"OS: {platform.system()} {platform.release()} ({platform.machine()})\n"
                    f"Node: {platform.node()}\n"
                    f"User: {getpass.getuser()} (UID: {os.getuid() if hasattr(os, 'getuid') else 'N/A'})\n"
                    f"Python: {platform.python_version()}\n"
                ).encode()
            elif line == "!pwd":
                response = (os.path.realpath(os.getcwd()) + "\n").encode()
            elif line == "!list":
                response = ("\n".join(sorted(os.listdir(transfer_fd))) + "\n").encode()
            elif line.startswith("!exec "):
                name = line[6:]
                argv = ALLOWED_COMMANDS.get(name)
                if argv is None:
                    response = b"ERROR: command is not allowed\n"
                else:
                    response = execute_allowed_command(name)
            elif line.startswith("!get "):
                try:
                    payload = read_transfer_file(transfer_fd, line[5:].strip())
                    response = b"FILE:" + base64.b64encode(payload) + b"\n"
                except (OSError, ValueError) as exc:
                    response = f"ERROR: {exc}\n".encode()
            elif line.startswith("!put "):
                parts = line.split(" ", 2)
                try:
                    if len(parts) != 3:
                        raise ValueError("invalid arguments")
                    payload = base64.b64decode(parts[2], validate=True)
                    create_transfer_file(transfer_fd, parts[1], payload)
                    response = b"[+] File uploaded successfully\n"
                except (OSError, ValueError) as exc:
                    response = f"ERROR: {exc}\n".encode()
            else:
                response = b"ERROR: command is not allowed\n"
            send_frame(sock, response)
    finally:
        if sock is not None:
            sock.close()
        elif raw_sock is not None:
            raw_sock.close()
        os.close(transfer_fd)


def main() -> None:
    parser = argparse.ArgumentParser(description="Authenticated TLS 1.3 laboratory command and file-transfer service")
    subparsers = parser.add_subparsers(dest="mode", required=True)
    listen = subparsers.add_parser("listen", help="Start the TLS listener")
    listen.add_argument("-p", "--port", type=int, default=4444)
    listen.add_argument("-b", "--bind", default="127.0.0.1")
    listen.add_argument("--cert")
    listen.add_argument("--key")
    listen.add_argument("--file-root", default="./tls-transfer")
    listen.add_argument("--allowed-scope", action="append", required=True,
                        help="Authorized IPv4 destination/subnet; may be repeated")
    connect = subparsers.add_parser("connect", help="Connect to the TLS listener as an agent")
    connect.add_argument("-H", "--host", required=True)
    connect.add_argument("-p", "--port", type=int, default=4444)
    connect.add_argument("--fingerprint", required=True)
    connect.add_argument("--file-root", default="./tls-transfer")
    connect.add_argument("--allowed-scope", action="append", required=True,
                         help="Authorized IPv4 destination/subnet; may be repeated")
    args = parser.parse_args()
    try:
        if args.mode == "listen":
            run_listener(args.port, args.bind, args.cert, args.key, args.file_root,
                         args.allowed_scope)
        else:
            run_agent(args.host, args.port, args.fingerprint, args.allowed_scope,
                      args.file_root)
    except (OSError, RuntimeError, ValueError, PermissionError, ssl.SSLError,
            subprocess.SubprocessError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
