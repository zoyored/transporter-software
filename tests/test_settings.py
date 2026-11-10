import tempfile
import unittest
from pathlib import Path

from settings import DEFAULT_CONFIG, load_cipher, load_settings


class SettingsTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name) / ".rattlegram-audio"

    def test_creates_defaults_and_preserves_overrides(self):
        defaults = load_settings(self.directory)
        config = self.directory / "config.ini"
        self.assertEqual(config.read_text(), DEFAULT_CONFIG)
        self.assertEqual(defaults.codec_args(), ["8000", "16", "0", "4"])

        custom = "[audio]\nRATE = 48000\nBITS = 24\nCHANNEL = 2\nMAPPING = 8\n"
        config.write_text(custom)
        loaded = load_settings(self.directory)
        self.assertEqual(loaded.codec_args(), ["48000", "24", "2", "8"])
        self.assertEqual(loaded.noise_symbols, 1)
        self.assertIn("--format=s24le", loaded.pacat_args())
        self.assertIn("--channels=2", loaded.pacat_args())
        self.assertEqual(config.read_text(), custom)

    def test_invalid_setting(self):
        load_settings(self.directory)
        (self.directory / "config.ini").write_text("[audio]\nRATE = 44100\n")
        with self.assertRaisesRegex(ValueError, "RATE"):
            load_settings(self.directory)

    def test_rejects_unsafe_key_permissions_and_symlinks(self):
        load_settings(self.directory)
        key = self.directory / "key"
        key.write_bytes(b"x" * 32)
        for mode in (0o400, 0o644, 0o660):
            with self.subTest(mode=mode):
                key.chmod(mode)
                with self.assertRaisesRegex(ValueError, "Erwartet 600"):
                    load_cipher(self.directory)
        other = key.rename(self.directory / "other")
        other.chmod(0o600)
        key.symlink_to(other)
        with self.assertRaisesRegex(ValueError, "Symlink"):
            load_cipher(self.directory)


if __name__ == "__main__":
    unittest.main()
