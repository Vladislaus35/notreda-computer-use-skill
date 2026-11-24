import ctypes
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import computer_use_cli as cu


class TestComputerUseSafetyAndEngine(unittest.TestCase):
    def test_win32_input_struct_size(self):
        if cu.IS_WINDOWS and ctypes.sizeof(ctypes.c_void_p) == 8:
            self.assertEqual(ctypes.sizeof(cu.INPUT), 40)

    def test_blocked_apps(self):
        for app in ("cmd", "powershell.exe", "pwsh", "regedit", "shutdown", "calc; whoami"):
            with self.assertRaises(cu.PolicyError):
                cu.validate_app_name_safety(app)
        self.assertEqual(cu.validate_app_name_safety("notepad"), "notepad")

    def test_blocked_key_combos(self):
        with self.assertRaises(cu.PolicyError):
            cu.validate_key_combo_safety("delete", ["ctrl", "alt"])
        with self.assertRaises(cu.PolicyError):
            cu.validate_key_combo_safety("r", ["win"])
        with self.assertRaises(cu.PolicyError):
            cu.validate_key_combo_safety("esc", ["ctrl", "shift"])
        cu.validate_key_combo_safety("c", ["ctrl"])

    def test_url_and_ssrf_guards(self):
        for bad in ("javascript:alert(1)", "file:///C:/Windows/win.ini", "ms-msdt:id", "data:text/html,hi"):
            with self.assertRaises(cu.PolicyError):
                cu.validate_safe_url(bad)
        self.assertEqual(cu.validate_safe_url("example.com"), "https://example.com")
        self.assertTrue(cu.is_forbidden_metadata_host("169.254.169.254"))
        self.assertTrue(cu.is_forbidden_metadata_host("metadata.google.internal"))
        self.assertFalse(cu.is_forbidden_metadata_host("example.com"))

    def test_sensitive_windows_turkish_safe(self):
        for title in ("KeePassXC", "1Password", "Bitwarden", "ŞİFRE Yöneticisi", "PAROLA", "Oturum Aç", "Sign in"):
            self.assertTrue(cu.is_sensitive_window_label(title), f"Expected sensitive: {title}")
        self.assertFalse(cu.is_sensitive_window_label("Visual Studio Code"))

    def test_secret_redaction(self):
        sample = "key=sk-1234567890abcdefghij tok=ghp_1234567890abcdefghij12345"
        redacted = cu.redact_generic_secrets(sample)
        self.assertNotIn("sk-1234", redacted)
        self.assertNotIn("ghp_1234", redacted)

    def test_desktop_sandbox(self):
        for bad_path in ("../escape.txt", "run.exe", "payload.ps1", ".env", "C:/Windows/test.txt"):
            with self.assertRaises(cu.PolicyError):
                cu.resolve_safe_desktop_path(bad_path, [], is_file=True)

    def test_coordinate_spaces(self):
        cu.save_last_capture_dims(1280, 720, 2560, 1440)
        self.assertEqual(cu.resolve_coords(640, 360, "scaled"), (1280, 720))
        self.assertEqual(cu.resolve_coords(500, 500, "normalized"), (1280, 720))
        self.assertEqual(cu.resolve_coords(100, 200, "physical"), (100, 200))

    def test_allowlists(self):
        with self.assertRaises(cu.PolicyError):
            cu.app_matches_allowlist("chrome", ["notepad", "calc"])
        cu.app_matches_allowlist("Notepad", ["notepad", "calc"])
        with self.assertRaises(cu.PolicyError):
            cu.domain_matches_allowlist("https://evil.com", ["example.com"])
        cu.domain_matches_allowlist("https://docs.example.com/a", ["example.com"])

    def test_png_encoder_valid_header(self):
        rgb = bytes([255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 255])
        png = cu.encode_rgb_png(2, 2, rgb)
        self.assertTrue(png.startswith(b"\x89PNG\r\n\x1a\n"))
        self.assertIn(b"IHDR", png)
        self.assertIn(b"IDAT", png)
        self.assertIn(b"IEND", png)


if __name__ == "__main__":
    unittest.main()
