import unittest
import socket
import hashlib
import json
import os
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest import mock

from tools.camera_recon import expand_targets, serialize_results
from tools.lab_scope import parse_lab_ipv4
from tools import tls_shell
from tools.tls_shell import (
    authenticate_client, authenticate_server, create_transfer_file,
    execute_allowed_command, generate_self_signed_cert, open_transfer_root, read_transfer_file,
    recv_frame, safe_transfer_name, send_frame, validate_lab_host,
)
from tools.arp_poison import (
    create_arp_packet, ip_to_bytes, mac_to_bytes, preserved_ip_forwarding,
    run_forwarding_session,
    validate_direct_lab_route,
)


class LabScopeTests(unittest.TestCase):
    def test_accepts_private_and_loopback_addresses(self):
        self.assertEqual(str(parse_lab_ipv4("10.42.0.20")), "10.42.0.20")
        self.assertEqual(str(parse_lab_ipv4("127.0.0.1")), "127.0.0.1")

    def test_rejects_public_and_non_ipv4_addresses(self):
        for address in ("8.8.8.8", "2001:db8::1", "not-an-ip"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                parse_lab_ipv4(address)

    def test_expands_local_cidr_and_range(self):
        self.assertEqual(expand_targets("10.42.0.0/30"), ["10.42.0.1", "10.42.0.2"])
        self.assertEqual(expand_targets("10.42.0.3-4"), ["10.42.0.3", "10.42.0.4"])

    def test_rejects_large_or_external_scope(self):
        with self.assertRaises(ValueError):
            expand_targets("10.0.0.0/8")
        with self.assertRaises(ValueError):
            expand_targets("8.8.8.8")

    def test_result_json_schema_and_utf8_output_are_stable(self):
        result = {
            "host": "10.42.0.20", "open_ports": [554], "vendor": "Cámara",
            "services": ["RTSP:554 (lab)"], "rtsp_available": True,
            "rtsp_banner": "lab", "web_title": None, "server_header": None,
        }
        encoded = serialize_results([result])
        self.assertIn('"rtsp_available": true', encoded)
        self.assertIn('Cámara', encoded)
        self.assertNotIn("\\u00e1", encoded)
        self.assertEqual(list(json.loads(encoded)[0]), list(result))


class TlsProtocolTests(unittest.TestCase):
    ROOT = Path(__file__).resolve().parents[1]

    def test_length_prefixed_frames_round_trip(self):
        sender, receiver = socket.socketpair()
        try:
            send_frame(sender, b"message split safely")
            self.assertEqual(recv_frame(receiver), b"message split safely")
            send_frame(sender, b"")
            self.assertEqual(recv_frame(receiver), b"")
        finally:
            sender.close()
            receiver.close()

    def test_rejects_oversized_frame_before_reading_payload(self):
        sender, receiver = socket.socketpair()
        try:
            sender.sendall((32 * 1024 * 1024 + 1).to_bytes(4, "big"))
            with self.assertRaises(ValueError):
                recv_frame(receiver)
        finally:
            sender.close()
            receiver.close()

    def test_tls_host_scope_is_local(self):
        self.assertEqual(validate_lab_host("127.0.0.1", ["127.0.0.0/8"]), "127.0.0.1")
        with self.assertRaisesRegex(ValueError, "configured --allowed-scope"):
            validate_lab_host("10.99.0.1", ["10.42.0.0/24"])
        with self.assertRaises(ValueError):
            validate_lab_host("8.8.8.8", ["10.42.0.0/24"])

    def test_dns_is_resolved_once_and_pinned_to_an_allowed_address(self):
        allowed = (None, None, None, None, ("10.42.0.20", 0))
        with mock.patch("tools.tls_shell.socket.getaddrinfo", return_value=[allowed]) as resolver:
            self.assertEqual(validate_lab_host("camera.lab", ["10.42.0.0/24"]), "10.42.0.20")
            resolver.assert_called_once()
        public = (None, None, None, None, ("8.8.8.8", 0))
        with mock.patch("tools.tls_shell.socket.getaddrinfo", return_value=[allowed, public]):
            with self.assertRaises(ValueError):
                validate_lab_host("mixed.lab", ["10.42.0.0/24"])

    def test_mutual_authentication_accepts_valid_token_and_rejects_wrong_token(self):
        for client_token, succeeds in ((b"L" * 32, True), (b"W" * 32, False)):
            server, client = socket.socketpair()
            failures = []

            def server_auth():
                try:
                    authenticate_server(server, b"L" * 32)
                except Exception as exc:
                    failures.append(exc)

            thread = threading.Thread(target=server_auth)
            thread.start()
            try:
                if succeeds:
                    authenticate_client(client, client_token)
                else:
                    challenge = recv_frame(client)
                    import hmac
                    from tools.tls_shell import AUTH_DOMAIN
                    send_frame(client, hmac.digest(client_token, AUTH_DOMAIN + challenge, "sha256"))
                    self.assertEqual(recv_frame(client), b"AUTH_FAILED")
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
                self.assertEqual(not failures, succeeds)
            finally:
                server.close()
                client.close()

    def test_authentication_token_must_be_long_enough(self):
        with mock.patch.dict(os.environ, {"FT_MALCOLM_TOKEN": "short"}):
            with self.assertRaises(ValueError):
                tls_shell.load_auth_token()

    def test_authentication_helpers_reject_missing_empty_and_short_tokens(self):
        for token in (None, b"", "", b"S" * 31):
            for helper in (authenticate_server, authenticate_client):
                with self.subTest(helper=helper.__name__, token=token):
                    sock = mock.Mock()
                    with self.assertRaises(ValueError):
                        helper(sock, token)
                    sock.sendall.assert_not_called()
                    sock.recv.assert_not_called()

    def test_authentication_helpers_accept_minimum_length_token(self):
        token = "é" * 16
        self.assertEqual(tls_shell.validate_auth_token(token), token.encode("utf-8"))

    def test_fifo_transfer_is_rejected_without_blocking(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO creation is unavailable on this platform")
        with tempfile.TemporaryDirectory(dir=self.ROOT) as root:
            fifo = os.path.join(root, "blocked.fifo")
            os.mkfifo(fifo)
            root_fd = open_transfer_root(root)
            try:
                started = time.monotonic()
                with self.assertRaisesRegex(ValueError, "regular file"):
                    read_transfer_file(root_fd, "blocked.fifo")
                self.assertLess(time.monotonic() - started, 1.0)
            finally:
                os.close(root_fd)
                os.unlink(fifo)

    def test_file_size_limit_applies_to_reads_and_writes(self):
        with tempfile.TemporaryDirectory(dir=self.ROOT) as root:
            root_fd = open_transfer_root(root)
            try:
                create_transfer_file(root_fd, "small", b"123")
                with mock.patch("tools.tls_shell.MAX_FILE_SIZE", 2):
                    with self.assertRaises(ValueError):
                        read_transfer_file(root_fd, "small")
                    with self.assertRaises(ValueError):
                        create_transfer_file(root_fd, "large", b"123")
            finally:
                os.close(root_fd)

    def test_remote_command_dispatch_is_fixed_and_never_uses_a_shell(self):
        completed = subprocess.CompletedProcess(["uname", "-a"], 0, b"Darwin\n", b"")
        with mock.patch("tools.tls_shell.subprocess.run", return_value=completed) as run:
            self.assertEqual(execute_allowed_command("uname"), b"Darwin\n")
            run.assert_called_once_with(["uname", "-a"], capture_output=True, timeout=30, check=False)
        with self.assertRaises(ValueError):
            execute_allowed_command("uname; touch forbidden")

    def test_tls13_socketpair_session_and_certificate_pin(self):
        with tempfile.TemporaryDirectory(dir=self.ROOT) as temp_dir:
            previous_tempdir = tempfile.tempdir
            tempfile.tempdir = temp_dir
            cert_file = key_file = None
            try:
                cert_file, key_file = generate_self_signed_cert()
                server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                server_context.minimum_version = ssl.TLSVersion.TLSv1_3
                server_context.maximum_version = ssl.TLSVersion.TLSv1_3
                server_context.load_cert_chain(cert_file, key_file)
                client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                client_context.check_hostname = False
                client_context.verify_mode = ssl.CERT_NONE
                client_context.minimum_version = ssl.TLSVersion.TLSv1_3
                client_context.maximum_version = ssl.TLSVersion.TLSv1_3

                server_sock, client_sock = socket.socketpair()
                server_sock.settimeout(5)
                client_sock.settimeout(5)
                server_errors = []

                def serve_once():
                    try:
                        with server_context.wrap_socket(server_sock, server_side=True) as tls_server:
                            authenticate_server(tls_server, b"T" * 32)
                            self.assertEqual(recv_frame(tls_server), b"!sysinfo\n")
                            send_frame(tls_server, b"local-lab-ok")
                    except Exception as exc:  # surfaced in the test thread
                        server_errors.append(exc)

                thread = threading.Thread(target=serve_once, daemon=True)
                thread.start()
                with client_context.wrap_socket(client_sock, server_hostname="localhost") as tls_client:
                    cert_der = ssl.PEM_cert_to_DER_cert(Path(cert_file).read_text())
                    expected = hashlib.sha256(cert_der).digest()
                    actual = hashlib.sha256(tls_client.getpeercert(binary_form=True)).digest()
                    self.assertEqual(actual, expected)
                    authenticate_client(tls_client, b"T" * 32)
                    send_frame(tls_client, b"!sysinfo\n")
                    self.assertEqual(recv_frame(tls_client), b"local-lab-ok")
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive(), "TLS test server did not finish")
                self.assertEqual(server_errors, [])
            finally:
                tempfile.tempdir = previous_tempdir

    def test_agent_closes_socket_after_bad_fingerprint_authentication_or_timeout(self):
        certificate = b"local test certificate"
        fingerprint = hashlib.sha256(certificate).hexdigest()
        for failure in ("fingerprint", "token", "timeout"):
            with self.subTest(failure=failure):
                raw = mock.Mock()
                tls = mock.Mock()
                tls.getpeercert.return_value = certificate
                context = mock.Mock()
                context.wrap_socket.return_value = tls
                if failure == "timeout":
                    raw.connect.side_effect = socket.timeout("simulated local timeout")
                if failure == "token":
                    challenge = b"C" * 32
                    frames = (len(challenge).to_bytes(4, "big") + challenge
                              + len(b"AUTH_FAILED").to_bytes(4, "big") + b"AUTH_FAILED")
                    chunks = [frames[:4], frames[4:36], frames[36:40], frames[40:]]
                    tls.recv.side_effect = chunks
                    with mock.patch.dict(os.environ, {"FT_MALCOLM_TOKEN": "T" * 32}), \
                         mock.patch("tools.tls_shell.validate_lab_host", return_value="10.42.0.10"), \
                         mock.patch("tools.tls_shell.open_transfer_root", return_value=44), \
                         mock.patch("tools.tls_shell.os.close"), \
                         mock.patch("tools.tls_shell.socket.socket", return_value=raw), \
                         mock.patch("tools.tls_shell.ssl.create_default_context", return_value=context):
                        with self.assertRaisesRegex(PermissionError, "rejected"):
                            tls_shell.run_agent("lab", 4444, fingerprint, ["10.42.0.0/24"])
                    tls.close.assert_called_once()
                elif failure == "fingerprint":
                    with mock.patch.dict(os.environ, {"FT_MALCOLM_TOKEN": "T" * 32}), \
                         mock.patch("tools.tls_shell.validate_lab_host", return_value="10.42.0.10"), \
                         mock.patch("tools.tls_shell.open_transfer_root", return_value=44), \
                         mock.patch("tools.tls_shell.os.close"), \
                         mock.patch("tools.tls_shell.socket.socket", return_value=raw), \
                         mock.patch("tools.tls_shell.ssl.create_default_context", return_value=context):
                        with self.assertRaisesRegex(ssl.SSLError, "fingerprint mismatch"):
                            tls_shell.run_agent("lab", 4444, "00" * 32, ["10.42.0.0/24"])
                    tls.close.assert_called_once()
                else:
                    with mock.patch.dict(os.environ, {"FT_MALCOLM_TOKEN": "T" * 32}), \
                         mock.patch("tools.tls_shell.validate_lab_host", return_value="10.42.0.10"), \
                         mock.patch("tools.tls_shell.open_transfer_root", return_value=44), \
                         mock.patch("tools.tls_shell.os.close"), \
                         mock.patch("tools.tls_shell.socket.socket", return_value=raw):
                        with self.assertRaises(socket.timeout):
                            tls_shell.run_agent("lab", 4444, fingerprint, ["10.42.0.0/24"])
                    raw.close.assert_called_once()
                if failure != "timeout":
                    raw.connect.assert_called_once_with(("10.42.0.10", 4444))

    def test_transfer_root_blocks_traversal_symlinks_and_overwrites(self):
        with tempfile.TemporaryDirectory(dir=self.ROOT) as root:
            root_fd = open_transfer_root(root)
            try:
                create_transfer_file(root_fd, "sample.bin", b"lab")
                self.assertEqual(read_transfer_file(root_fd, "sample.bin"), b"lab")
                with self.assertRaises(FileExistsError):
                    create_transfer_file(root_fd, "sample.bin", b"replace")
                for name in ("../outside", "sub/file", "..", "a\\b"):
                    with self.subTest(name=name), self.assertRaises(ValueError):
                        safe_transfer_name(name)
                os.symlink("sample.bin", os.path.join(root, "link.bin"))
                with self.assertRaises(OSError):
                    read_transfer_file(root_fd, "link.bin")
                os.link(os.path.join(root, "sample.bin"), os.path.join(root, "hardlink.bin"))
                with self.assertRaises(ValueError):
                    read_transfer_file(root_fd, "hardlink.bin")
                with self.assertRaises(ValueError):
                    safe_transfer_name("bad\nname")
            finally:
                os.close(root_fd)

    def test_transfer_root_rejects_group_or_world_access(self):
        with tempfile.TemporaryDirectory(dir=self.ROOT) as root:
            os.chmod(root, 0o755)
            with self.assertRaises(PermissionError):
                open_transfer_root(root)


class PythonCliTests(unittest.TestCase):
    ROOT = Path(__file__).resolve().parents[1]

    def run_cli(self, script, *args):
        return subprocess.run(
            [sys.executable, str(self.ROOT / "tools" / script), *args],
            cwd=self.ROOT, capture_output=True, text=True, timeout=10,
        )

    def test_help_options_are_available_without_network_access(self):
        for script, args in (
            ("camera_recon.py", "--help"),
            ("arp_poison.py", "--help"),
            ("tls_shell.py", "--help"),
        ):
            with self.subTest(script=script):
                result = self.run_cli(script, args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("usage:", result.stdout.lower())

    def test_network_clis_reject_public_targets_before_io(self):
        camera = self.run_cli("camera_recon.py", "-t", "8.8.8.8")
        self.assertEqual(camera.returncode, 2)
        self.assertIn("outside the private/local lab", camera.stderr)
        agent = self.run_cli(
            "tls_shell.py", "connect", "--host", "8.8.8.8", "--fingerprint", "00" * 32,
            "--allowed-scope", "10.42.0.0/24",
        )
        self.assertEqual(agent.returncode, 2)
        self.assertIn("outside the private/local lab", agent.stderr)
        arp = self.run_cli("arp_poison.py", "--target", "8.8.8.8", "--gateway", "10.42.0.1")
        self.assertEqual(arp.returncode, 2)
        self.assertIn("outside the private/local lab", arp.stderr)

    def test_tls_cli_requires_server_pin(self):
        result = self.run_cli("tls_shell.py", "connect", "--host", "10.42.0.20")
        self.assertEqual(result.returncode, 2)
        self.assertIn("--fingerprint", result.stderr)


class ArpPacketTests(unittest.TestCase):
    def test_forwarding_is_restored_after_all_failure_phases(self):
        phases = ("enable", "packet construction", "packet send", "sleep", "arp restoration")
        for phase in phases:
            with self.subTest(phase=phase):
                state = ["0"]
                writes = []

                def setter(value):
                    writes.append(value)
                    state[0] = value
                    if phase == "enable" and value == "1":
                        raise RuntimeError("simulated partial sysctl failure")

                cleaned = []

                def operation():
                    if phase != "enable":
                        raise RuntimeError(f"simulated {phase} failure")

                def cleanup():
                    cleaned.append(True)
                    if phase == "arp restoration":
                        raise RuntimeError("simulated arp restoration failure")

                try:
                    run_forwarding_session(operation, cleanup, lambda: state[0], setter)
                except RuntimeError:
                    pass
                self.assertEqual(state[0], "0")
                self.assertEqual(writes[-1], "0")
                self.assertEqual(bool(cleaned), phase != "enable")

    def test_address_validation_and_packet_construction(self):
        source_mac = mac_to_bytes("aa:bb:cc:dd:ee:10")
        target_mac = mac_to_bytes("aa-bb-cc-dd-ee-20")
        source_ip = ip_to_bytes("10.42.0.1")
        target_ip = ip_to_bytes("10.42.0.20")
        packet = create_arp_packet(2, source_mac, source_ip, target_mac, target_ip)
        self.assertEqual(len(packet), 42)
        self.assertEqual(packet[12:14], b"\x08\x06")
        self.assertEqual(packet[20:22], b"\x00\x02")

    def test_rejects_bad_mac_and_public_ip(self):
        with self.assertRaises(ValueError):
            mac_to_bytes("aa:bb:cc:dd:ee")
        with self.assertRaises(ValueError):
            ip_to_bytes("8.8.8.8")

    def test_arp_targets_must_be_directly_connected(self):
        class RouteTable:
            routes = {
                "10.42.0.20": ("eth0", "10.42.0.100", "0.0.0.0"),
                "10.42.0.1": ("eth0", "10.42.0.100", "0.0.0.0"),
                "192.168.1.1": ("eth0", "192.168.1.10", "192.168.1.254"),
            }

            def route(self, address):
                return self.routes[address]

        routes = RouteTable()
        self.assertEqual(validate_direct_lab_route(routes, "10.42.0.20", "10.42.0.1"), "eth0")
        with self.assertRaises(ValueError):
            validate_direct_lab_route(routes, "10.42.0.20", "192.168.1.1")
        with self.assertRaises(ValueError):
            validate_direct_lab_route(routes, "10.42.0.20", "10.42.0.1", "en0")


if __name__ == "__main__":
    unittest.main()
