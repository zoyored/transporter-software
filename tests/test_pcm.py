import subprocess
import unittest
from pathlib import Path


BIN = Path(__file__).resolve().parents[1] / "bin"


class PcmTest(unittest.TestCase):
    @unittest.skipUnless((BIN / "send-pcm").is_file() and (BIN / "listen-pcm").is_file(),
                         "Run make to build the PCM codecs")
    def test_consecutive_qam_packets(self):
        # A second packet exercises decoder state after demapping the first.
        params = ["48000", "24", "2", "16"]
        messages = ["A" * 170, "B" * 170, "C" * 85]
        audio = b"".join(subprocess.check_output(
            [BIN / "send-pcm", message, "ZOYO", *params, "3", "1800"])
            for message in messages)
        decoded = subprocess.check_output([BIN / "listen-pcm", "--frames", *params],
                                          input=audio)
        self.assertEqual(decoded, b"".join(message.encode() + b"\0" for message in messages))


if __name__ == "__main__":
    unittest.main()
