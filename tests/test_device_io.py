import os
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from pycomm3 import Services

from eip_tool.device_io import (
    CIPDeviceIOError,
    PRESETS,
    format_hexdump,
    format_raw_hex,
    format_word_view,
    parse_data_input,
    read_cip_data,
    write_cip_data,
)


class DeviceIOTests(unittest.TestCase):
    def test_read_cip_data_success(self):
        fake_data = bytes(range(108))  # 54 words
        mock_tag = SimpleNamespace(value=fake_data, error=None)
        mock_driver = Mock()
        mock_driver.generic_message.return_value = mock_tag
        mock_driver_cm = Mock(__enter__=Mock(return_value=mock_driver), __exit__=Mock(return_value=False))

        with patch("eip_tool.device_io.CIPDriver", return_value=mock_driver_cm):
            data = read_cip_data("192.168.0.30", class_code=0x04, instance=101, attribute=3)

        self.assertEqual(data, fake_data)
        mock_driver.generic_message.assert_called_once_with(
            service=Services.get_attribute_single,
            class_code=0x04,
            instance=101,
            attribute=3,
            connected=False,
            unconnected_send=False,
            route_path=False,
            name="Read Class 0x4 Inst 101 Attr 3",
        )

    def test_read_cip_data_cip_error(self):
        mock_tag = SimpleNamespace(value=None, error="Path segment error")
        mock_driver = Mock()
        mock_driver.generic_message.return_value = mock_tag
        mock_driver_cm = Mock(__enter__=Mock(return_value=mock_driver), __exit__=Mock(return_value=False))

        with patch("eip_tool.device_io.CIPDriver", return_value=mock_driver_cm):
            with self.assertRaisesRegex(CIPDeviceIOError, "Path segment error"):
                read_cip_data("192.168.0.30", class_code=0x04, instance=101, attribute=3)

    def test_read_cip_data_invalid_ip(self):
        with self.assertRaisesRegex(ValueError, "Invalid or unusable target IPv4"):
            read_cip_data("not-an-ip")

    def test_write_cip_data_success(self):
        write_bytes = bytes([0xAA, 0xBB, 0xCC, 0xDD])
        mock_tag = SimpleNamespace(value=None, error=None)
        mock_driver = Mock()
        mock_driver.generic_message.return_value = mock_tag
        mock_driver_cm = Mock(__enter__=Mock(return_value=mock_driver), __exit__=Mock(return_value=False))

        with patch("eip_tool.device_io.CIPDriver", return_value=mock_driver_cm):
            write_cip_data("192.168.0.30", write_bytes, class_code=0x04, instance=102, attribute=3)

        mock_driver.generic_message.assert_called_once_with(
            service=Services.set_attribute_single,
            class_code=0x04,
            instance=102,
            attribute=3,
            request_data=write_bytes,
            connected=False,
            unconnected_send=False,
            route_path=False,
            name="Write Class 0x4 Inst 102 Attr 3",
        )

    def test_write_cip_data_error(self):
        mock_tag = SimpleNamespace(value=None, error="Privilege violation")
        mock_driver = Mock()
        mock_driver.generic_message.return_value = mock_tag
        mock_driver_cm = Mock(__enter__=Mock(return_value=mock_driver), __exit__=Mock(return_value=False))

        with patch("eip_tool.device_io.CIPDriver", return_value=mock_driver_cm):
            with self.assertRaisesRegex(CIPDeviceIOError, "Privilege violation"):
                write_cip_data("192.168.0.30", b"\x00\x01", class_code=0x04, instance=102, attribute=3)

    def test_format_hexdump(self):
        data = b"Hello EtherNetIP"
        dump = format_hexdump(data)
        self.assertIn("0000", dump)
        self.assertIn("48 65 6C 6C 6F", dump)
        self.assertIn("|Hello EtherNetIP|", dump)
        self.assertEqual(format_hexdump(b""), "(empty response / 0 bytes)")

    def test_format_word_view(self):
        # Two words: 0x0100 (256) and 0x0002 (2) in little-endian
        data = bytes([0x00, 0x01, 0x02, 0x00])
        view = format_word_view(data, little_endian=True)
        self.assertIn("4 bytes", view)
        self.assertIn("Word 000 (0x00)   0x0100       256", view)
        self.assertIn("Word 001 (0x02)   0x0002       2", view)
        self.assertEqual(format_word_view(b""), "(empty response / 0 bytes)")

        # With annotations
        view_annotated = format_word_view(data, little_endian=True, annotations={1: "Special Status"})
        self.assertIn("<-- Special Status", view_annotated)

    def test_format_raw_hex(self):
        self.assertEqual(format_raw_hex(b"\x01\x0A\xFF"), "01 0A FF")
        self.assertEqual(format_raw_hex(b""), "(empty response / 0 bytes)")

    def test_parse_data_input(self):
        self.assertEqual(parse_data_input("00 01 02 0A FF"), bytes([0, 1, 2, 10, 255]))
        self.assertEqual(parse_data_input("0x0001, 0x0203"), bytes([0, 1, 2, 3]))
        self.assertEqual(parse_data_input("[01, 02; 03]"), bytes([1, 2, 3]))
        self.assertEqual(parse_data_input(""), b"")


@unittest.skipUnless(os.environ.get("DISPLAY") or os.name == "nt", "GUI requires a display")
class DeviceIODialogTests(unittest.TestCase):
    def setUp(self):
        import tkinter as tk
        from eip_tool.device_io import DeviceIOTestDialog
        self.root = tk.Tk()
        self.root.withdraw()
        self.dialog = DeviceIOTestDialog(
            self.root, "00:20:4a:87:12:ed", "192.168.0.30", "XPort-EIP-MB | rev 1.13")
        self.addCleanup(self.dialog.close)
        self.addCleanup(self.root.destroy)

    def test_dialog_initial_state_and_presets(self):
        self.assertEqual(self.dialog.class_var.get(), "0x04")
        self.assertEqual(self.dialog.inst_var.get(), "101")
        self.assertEqual(self.dialog.attr_var.get(), "3")
        self.assertIn("54 words", self.dialog.expected_label_var.get())

        # Select Output Assembly preset
        self.dialog.preset_combo.set(PRESETS[1]["name"])
        self.dialog._on_preset_selected()
        self.assertEqual(self.dialog.inst_var.get(), "102")
        self.assertIn("16 words", self.dialog.expected_label_var.get())

    def test_dialog_read_success_updates_display(self):
        import time
        test_payload = bytes([0x01, 0x02, 0x03, 0x04])
        with patch("eip_tool.device_io.read_cip_data", return_value=test_payload) as mock_read:
            self.dialog.read_once()
            for _ in range(30):
                self.dialog._poll_event_queue()
                self.dialog.window.update()
                if self.dialog.last_data == test_payload:
                    break
                time.sleep(0.05)
        self.assertEqual(self.dialog.last_data, test_payload)
        self.assertIn("Success", self.dialog.read_status_var.get())
        text_content = self.dialog.data_text.get("1.0", "end")
        self.assertIn("Word 000", text_content)

    def test_dialog_fill_buttons_and_write(self):
        self.dialog._fill_zeroes_16()
        self.assertEqual(len(parse_data_input(self.dialog.write_text.get())), 32)

        with patch("eip_tool.device_io.messagebox.askyesno", return_value=True), \
                patch("eip_tool.device_io.write_cip_data") as mock_write, \
                patch("eip_tool.device_io.messagebox.showinfo"):
            self.dialog.write_data()
            for _ in range(30):
                self.dialog._poll_event_queue()
                self.dialog.window.update()
                if mock_write.called:
                    break
                import time; time.sleep(0.05)
        mock_write.assert_called_once()
        self.assertEqual(mock_write.call_args.args[0], "192.168.0.30")
        self.assertEqual(len(mock_write.call_args.args[1]), 32)

    def test_dialog_close_stops_polling(self):
        self.dialog.polling = True
        self.dialog.close()
        self.assertFalse(self.dialog.polling)

    def test_dialog_tracks_alive_counter_at_word_27(self):
        # 54 words (108 bytes). Word 27 is byte offset 54..55.
        payload1 = bytearray(108)
        struct.pack_into("<H", payload1, 54, 100)
        payload2 = bytearray(108)
        struct.pack_into("<H", payload2, 54, 105)

        self.dialog._on_read_success(bytes(payload1))
        self.assertIn("100 (0x0064)", self.dialog.alive_val_var.get())
        self.assertIn("Initial read", self.dialog.alive_status_var.get())

        self.dialog._on_read_success(bytes(payload2))
        self.assertIn("105 (0x0069)", self.dialog.alive_val_var.get())
        self.assertIn("Ticking! (+5", self.dialog.alive_status_var.get())
        self.assertEqual(self.dialog.alive_tick_count, 1)

        # Check that word annotations appear in the text display
        text_content = self.dialog.data_text.get("1.0", "end")
        self.assertIn("Alive Counter", text_content)

    def test_device_model_presets_and_short_assemblies(self):
        # Test MAI 114 / 314 preset
        mai_preset = next(p for p in PRESETS if "MAI 114 / 314" in p["name"] and "Input" in p["name"])
        self.dialog.preset_combo.set(mai_preset["name"])
        self.dialog._on_preset_selected()
        self.assertEqual(self.dialog.inst_var.get(), "101")
        self.assertIn("8 words", self.dialog.expected_label_var.get())
        self.assertIn("Word 7", self.dialog.alive_title_var.get())

        # An 8-word (16-byte) read for MAI 114 / 314 should track alive counter at Word 7 (bytes 14-15)
        payload1 = bytearray(16)
        struct.pack_into("<H", payload1, 14, 42)
        self.dialog._on_read_success(bytes(payload1))
        self.assertIn("42 (0x002A)", self.dialog.alive_val_var.get())
        self.assertIn("Initial read", self.dialog.alive_status_var.get())

        payload2 = bytearray(16)
        struct.pack_into("<H", payload2, 14, 43)
        self.dialog._on_read_success(bytes(payload2))
        self.assertIn("43 (0x002B)", self.dialog.alive_val_var.get())
        self.assertIn("Ticking! (+1", self.dialog.alive_status_var.get())

        # Text view should annotate Word 7
        text_content = self.dialog.data_text.get("1.0", "end")
        self.assertIn("Alive Counter (Word 7", text_content)

        # Test MAI 315 preset
        mai_315_preset = next(p for p in PRESETS if "MAI 315" in p["name"] and "Input" in p["name"])
        self.dialog.preset_combo.set(mai_315_preset["name"])
        self.dialog._on_preset_selected()
        self.assertEqual(self.dialog.inst_var.get(), "101")
        self.assertIn("12 words", self.dialog.expected_label_var.get())
        self.assertIn("Word 7", self.dialog.alive_title_var.get())

        # A 12-word (24-byte) read for MAI 315 should also track alive counter at Word 7 (bytes 14-15)
        payload_315 = bytearray(24)
        struct.pack_into("<H", payload_315, 14, 99)
        self.dialog._on_read_success(bytes(payload_315))
        self.assertIn("99 (0x0063)", self.dialog.alive_val_var.get())

        # Test fill expected zeroes for MAI 315 Output (8 words = 16 bytes)
        mai_315_out = next(p for p in PRESETS if "MAI 315" in p["name"] and "Output" in p["name"])
        self.dialog.preset_combo.set(mai_315_out["name"])
        self.dialog._on_preset_selected()
        self.dialog._fill_expected_zeroes()
        self.assertEqual(len(parse_data_input(self.dialog.write_text.get())), 16)


if __name__ == "__main__":
    unittest.main()
