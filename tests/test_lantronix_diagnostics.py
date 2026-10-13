import socket
import unittest
from unittest.mock import patch

from eip_tool.lantronix_diagnostics import read_lantronix_diagnostics


class FakeTelnetSocket:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.sent = []
        self.timeout = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def settimeout(self, timeout):
        self.timeout = timeout

    def recv(self, size):
        if not self.chunks:
            raise socket.timeout()
        chunk = self.chunks.pop(0)
        if isinstance(chunk, Exception):
            raise chunk
        return chunk

    def sendall(self, data):
        self.sent.append(data)


class LantronixDiagnosticsTests(unittest.TestCase):
    def test_sends_only_enter_after_setup_prompt_and_returns_clean_menu(self):
        fake = FakeTelnetSocket([
            b"\xff\xfb\x01\xff\xfb\x03Modbus/TCP Bridge\r\x00\n"
            b"MAC address 0080A3D7B7F5\r\x00\nPress Enter for Setup Mode \n",
            b"Model: Device Server Plus+ (Firmware Code: YM)\r\x00\n"
            b"Modbus/TCP Bridge Setup\r\x00\nIP Address ................. 192.168.20.200\r\x00\n",
            socket.timeout(),
        ])
        with patch("eip_tool.lantronix_diagnostics.socket.create_connection",
                   return_value=fake) as connect:
            result = read_lantronix_diagnostics("192.168.20.200")
        connect.assert_called_once_with(("192.168.20.200", 9999), timeout=4.0)
        self.assertEqual(fake.sent, [b"\r"])
        self.assertIn("Model: Device Server Plus+", result)
        self.assertIn("192.168.20.200", result)
        self.assertNotIn("\xff", result)

    def test_missing_setup_prompt_is_reported_without_sending_input(self):
        fake = FakeTelnetSocket([b"Unrecognized service\r\n", b""])
        with patch("eip_tool.lantronix_diagnostics.socket.create_connection",
                   return_value=fake):
            with self.assertRaisesRegex(RuntimeError, "did not present a Lantronix setup prompt"):
                read_lantronix_diagnostics("192.168.20.200")
        self.assertEqual(fake.sent, [])

    def test_connection_errors_include_target_address(self):
        with patch("eip_tool.lantronix_diagnostics.socket.create_connection",
                   side_effect=OSError("connection refused")):
            with self.assertRaisesRegex(RuntimeError, r"192.168.20.200:9999"):
                read_lantronix_diagnostics("192.168.20.200")

    def test_connection_refused_explains_telnet_may_be_disabled(self):
        with patch("eip_tool.lantronix_diagnostics.socket.create_connection",
                   side_effect=ConnectionRefusedError(10061, "connection refused")):
            with self.assertRaisesRegex(RuntimeError, "setup/Telnet access may be disabled"):
                read_lantronix_diagnostics("192.168.20.200")


if __name__ == "__main__":
    unittest.main()
