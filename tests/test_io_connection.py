import socket
import struct
import threading
import time
import unittest
from types import SimpleNamespace

from eip_tool.io_connection import (
    IOConnection, IOConnectionConfig, IOConnectionError, build_forward_close,
    build_forward_open, build_output_packet, connection_path, cpf_sockaddrs,
    parse_forward_open_reply, parse_input_packet,
)


def reply(service, status=0, extended=(), data=b"", extra_items=b"", extra_count=0):
    cip = bytes((service | 0x80, 0, status, len(extended)))
    cip += struct.pack(f"<{len(extended)}H", *extended) + data
    raw = bytearray(30)
    raw += struct.pack("<H", 2 + extra_count)
    raw += struct.pack("<HH", 0, 0) + struct.pack("<HH", 0xB2, len(cip))
    return bytes(raw) + cip + extra_items


def open_reply(o_t_id=0x11111111, t_o_id=0x22222222, **kwargs):
    data = struct.pack("<IIHHIIIBB", o_t_id, t_o_id, 1, 0xFFFE, 2, 100000, 100000, 0, 0)
    return reply(0x54, data=data, **kwargs)


class FakeDriver:
    def __init__(self, replies):
        self.replies = list(replies)
        self.requests = []
        self.closed = False

    def __call__(self, address):
        return self

    def open(self):
        return True

    def close(self):
        self.closed = True

    def generic_message(self, **kwargs):
        self.requests.append(kwargs)
        raw = self.replies.pop(0)
        return SimpleNamespace(value=SimpleNamespace(raw=raw), error=None)


class ProtocolTests(unittest.TestCase):
    def test_forward_open_layout(self):
        config = IOConnectionConfig(input_size=24, output_size=16, rpi_ms=100)
        request = build_forward_open(config, t_o_id=0x01020304, serial=0x0506,
                                     originator_serial=0x0708090A)
        self.assertEqual(request[:2], b"\x0a\x0e")
        self.assertEqual(struct.unpack_from("<II", request, 2), (0, 0x01020304))
        self.assertEqual(struct.unpack_from("<HHI", request, 10), (0x0506, 0xFFFE, 0x0708090A))
        self.assertEqual(request[18], 2)
        o_t_rpi, o_t_params, t_o_rpi, t_o_params = struct.unpack_from("<IHIH", request, 22)
        self.assertEqual((o_t_rpi, t_o_rpi), (100000, 100000))
        self.assertEqual(o_t_params, 0x4800 | (16 + 6))   # point-to-point, scheduled, run/idle
        self.assertEqual(t_o_params, 0x4800 | (24 + 2))   # modeless input
        self.assertEqual(request[34], 0x01)               # class 1, cyclic
        self.assertEqual(request[35], 4)
        self.assertEqual(request[36:], b"\x20\x04\x24\x80\x2c\x66\x2c\x65")
        multicast = build_forward_open(config, 1, 1, 1, multicast=True)
        self.assertEqual(struct.unpack_from("<H", multicast, 32)[0], 0x2800 | 26)

    def test_connection_path_uses_16_bit_segments_for_large_instances(self):
        config = IOConnectionConfig(input_instance=0x0301, output_instance=150,
                                    config_instance=1)
        self.assertEqual(connection_path(config),
                         b"\x20\x04\x24\x01\x2c\x96\x2d\x00\x01\x03")

    def test_forward_close_layout(self):
        request = build_forward_close(IOConnectionConfig(), serial=7, originator_serial=9)
        self.assertEqual(struct.unpack_from("<BBHHIBx", request), (0x0A, 0x0E, 7, 0xFFFE, 9, 4))

    def test_parse_forward_open_reply(self):
        info = parse_forward_open_reply(open_reply())
        self.assertEqual((info["o_t_id"], info["t_o_id"]), (0x11111111, 0x22222222))
        with self.assertRaisesRegex(IOConnectionError,
                                    r"0x0109 \(invalid connection size\); device supports 26"):
            parse_forward_open_reply(reply(0x54, status=0x01, extended=(0x0109, 26)))

    def test_sockaddr_items_are_parsed(self):
        item = struct.pack("<HH", 0x8001, 16) + struct.pack(">HH", 2, 2222)
        item += socket.inet_aton("239.192.1.2") + bytes(8)
        raw = open_reply(extra_items=item, extra_count=1)
        self.assertEqual(cpf_sockaddrs(raw), {0x8001: ("239.192.1.2", 2222)})
        self.assertEqual(parse_forward_open_reply(raw)["sockaddrs"][0x8001][0], "239.192.1.2")

    def test_packet_round_trip(self):
        packet = build_output_packet(0xABCD, 5, 6, b"\x01\x02", run=True)
        self.assertEqual(parse_input_packet(packet, 0xABCD, header=True), (6, b"\x01\x02"))
        self.assertEqual(struct.unpack_from("<I", packet, 20)[0], 1)
        self.assertIsNone(parse_input_packet(packet, 0x1234))
        self.assertIsNone(parse_input_packet(b"\x02\x00", 0xABCD))
        modeless = build_output_packet(0xABCD, 5, 6, b"\x03", run=False, header=False)
        self.assertEqual(parse_input_packet(modeless, 0xABCD), (6, b"\x03"))

    def test_config_validation(self):
        with self.assertRaises(ValueError):
            IOConnectionConfig(input_size=600).validate()
        with self.assertRaises(ValueError):
            IOConnectionConfig(rpi_ms=0).validate()
        with self.assertRaises(ValueError):
            IOConnectionConfig(config_instance=0).validate()


class ConnectionTests(unittest.TestCase):
    def test_cyclic_exchange_with_loopback_device(self):
        device = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        device.bind(("127.0.0.1", 0))
        device.settimeout(2)
        self.addCleanup(device.close)
        driver = FakeDriver([open_reply(), reply(0x4E)])
        received, outputs = [], []
        config = IOConnectionConfig(input_size=4, output_size=2, rpi_ms=20)
        connection = IOConnection("192.168.0.10", config, on_data=received.append,
                                  driver_factory=driver, local_port=0,
                                  target_port=device.getsockname()[1])
        connection.address = "127.0.0.1"
        connection.set_output(b"\x05")
        connection.set_run(True)

        def device_loop():
            for sequence in range(1, 4):
                packet, source = device.recvfrom(2048)
                outputs.append(parse_input_packet(packet, 0x11111111, header=True))
                device.sendto(build_output_packet(
                    0x22222222, sequence, sequence, b"\x0a\x0b\x0c\x0d", run=False,
                    header=False), source)

        thread = threading.Thread(target=device_loop)
        connection.start()
        thread.start()
        thread.join(timeout=3)
        deadline = time.monotonic() + 2
        while len(received) < 3 and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(connection.stop())
        self.assertEqual(received[:3], [b"\x0a\x0b\x0c\x0d"] * 3)
        self.assertEqual(outputs[0], (1, b"\x05\x00"))
        self.assertGreaterEqual(connection.rx_count, 3)
        self.assertEqual([r["service"] for r in driver.requests], [0x54, 0x4E])
        self.assertTrue(driver.closed)
        self.assertFalse(connection.running)

    def test_falls_back_to_multicast_when_point_to_point_is_rejected(self):
        group = struct.pack("<HH", 0x8001, 16) + struct.pack(">HH", 2, 2222)
        group += socket.inet_aton("239.192.10.20") + bytes(8)
        driver = FakeDriver([reply(0x54, status=1, extended=(0x0124,)),
                             open_reply(extra_items=group, extra_count=1), reply(0x4E)])
        connection = IOConnection("192.168.0.10", IOConnectionConfig(), driver_factory=driver,
                                  local_port=0)
        try:
            connection.start()
        except IOConnectionError as error:
            # Joining a multicast group can fail on hosts without a usable interface.
            self.assertIn("UDP port", str(error))
        else:
            self.assertTrue(connection.multicast)
            connection.stop()
        requests = driver.requests
        self.assertEqual(struct.unpack_from("<H", requests[0]["request_data"], 32)[0] >> 13, 2)
        self.assertEqual(struct.unpack_from("<H", requests[1]["request_data"], 32)[0] >> 13, 1)

    def test_rejected_forward_open_closes_session(self):
        driver = FakeDriver([reply(0x54, status=1, extended=(0x0106,))])
        connection = IOConnection("192.168.0.10", IOConnectionConfig(), driver_factory=driver,
                                  local_port=0)
        with self.assertRaisesRegex(IOConnectionError, "ownership conflict"):
            connection.start()
        self.assertTrue(driver.closed)
        self.assertFalse(connection.running)


if __name__ == "__main__":
    unittest.main()
