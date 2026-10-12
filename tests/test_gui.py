import os
import unittest
from unittest.mock import patch


@unittest.skipUnless(os.environ.get("DISPLAY") or os.name == "nt", "GUI requires a display")
class GuiTests(unittest.TestCase):
    def setUp(self):
        import tkinter as tk
        from eip_tool.gui import Application
        self.root = tk.Tk()
        self.root.withdraw()
        self.app = Application(self.root)
        self.addCleanup(self.root.destroy)

    def test_live_device_events_update_one_row_per_mac(self):
        row = ("00:00:bc:01:02:03", "", "169.254.5.6 (probe)",
               "Rockwell Automation", "ARP", "", 1234)
        self.app.events.put(("device", row))
        self.app.poll()
        self.assertEqual(len(self.app.table.get_children()), 1)
        self.app.events.put(("device", (row[0], "169.254.5.6", "", *row[3:])))
        self.app.poll()
        self.assertEqual(len(self.app.table.get_children()), 1)
        self.assertEqual(self.app.table.item(row[0], "values")[1], "169.254.5.6")

    def test_start_stop_and_service_default(self):
        self.assertFalse(self.app.serve.get())
        with patch("eip_tool.gui.Workbench") as worker:
            self.app.start()
            worker.return_value.start.assert_called_once()
            self.assertEqual(str(self.app.start_button["state"]), "disabled")
            self.app.events.put(("status", "Listening — ready"))
            self.app.poll()
            self.assertEqual(str(self.app.scan_button["state"]), "normal")
            self.app.stop()
            worker.return_value.stop.assert_called_once()
            self.app.events.put(("stopped", None))
            self.app.poll()
            self.assertIsNone(self.app.worker)
            self.assertEqual(str(self.app.start_button["state"]), "normal")


if __name__ == "__main__":
    unittest.main()
