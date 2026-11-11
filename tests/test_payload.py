import base64
import struct
import unittest
import zlib

import base91
from payload import CHUNK_SIZE, MAX_FILE, PREFIX, Reassembler, file_packets, packets


def replace_byte(frame, offset):
    data = bytearray(base91.decode(frame[len(PREFIX):]))
    data[offset] ^= 1
    return PREFIX + base91.encode(data)


class PayloadTest(unittest.TestCase):
    def test_single_packet_capacity(self):
        frame, = packets("x" * 117)
        self.assertLessEqual(len(frame), 170)
        self.assertEqual(Reassembler().receive(frame).data, "x" * 117)
        with self.assertRaises(ValueError):
            list(packets("x" * 118))

    def test_out_of_order_file_and_duplicate(self):
        data = bytes(range(256))
        first, second, third = file_packets(data)
        receiver = Reassembler()
        self.assertIsNone(receiver.receive(third))
        self.assertIsNone(receiver.receive(first))
        self.assertIsNone(receiver.receive(first))
        self.assertEqual(receiver.receive(second).data, data)

    def test_file_start_and_sender_scoped_reassembly(self):
        starts = []
        data = b"file data" * 20
        first, second = file_packets(data)
        receiver = Reassembler(on_file_start=lambda *args: starts.append(args))
        self.assertIsNone(receiver.receive(first, "SENDER1"))
        self.assertEqual(len(starts), 1)
        self.assertEqual(starts[0][0], "SENDER1")
        self.assertEqual(starts[0][2], 2)
        self.assertIsNone(receiver.receive(first, "SENDER1"))
        self.assertIsNone(receiver.receive(second, "SENDER2"))
        self.assertEqual(len(starts), 1)
        self.assertEqual(receiver.receive(second, "SENDER1").data, data)

    def test_corrupt_payload_and_unknown_flags(self):
        frame, = packets("text")
        for offset in (0, 1, 13):
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                Reassembler().receive(replace_byte(frame, offset))

    def test_inconsistent_fragments(self):
        first, second = file_packets(b"x" * (CHUNK_SIZE + 1))
        receiver = Reassembler()
        self.assertIsNone(receiver.receive(first))
        with self.assertRaises(ValueError):
            receiver.receive(replace_byte(second, 12))

    def test_compressed_text(self):
        text = "Grüße\n" * 300
        frame, = packets(text, compress=True, fragment=True)
        self.assertEqual(Reassembler().receive(frame).data, text)

    def test_encrypted_header_authentication_and_mixed_listener(self):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        except ImportError:
            self.skipTest("cryptography is unavailable")
        cipher = ChaCha20Poly1305(ChaCha20Poly1305.generate_key())
        plain, = packets("plain")
        encrypted, = packets("encrypted", cipher=cipher)
        mixed = Reassembler(cipher)
        self.assertEqual(mixed.receive(plain).data, "plain")
        self.assertEqual(mixed.receive(encrypted).data, "encrypted")
        for listener, frame in ((Reassembler(), encrypted),
                                (Reassembler(cipher, True), plain),
                                (mixed, replace_byte(encrypted, 1))):
            with self.assertRaises(ValueError):
                listener.receive(frame)

    def test_base91_known_vector(self):
        encoded = b">OwJh>Io0Tv!8PE"
        self.assertEqual(base91.encode(b"Hello World!"), encoded)
        self.assertEqual(base91.decode(encoded), b"Hello World!")

    def test_rg2_base64(self):
        prefix = b"~RG2:"
        transfer_id = b"12345678"
        header = struct.pack("!B8sHH", 0, transfer_id, 0, 1)
        metadata = prefix + struct.pack("!B8sH", 0, transfer_id, 1)
        data = b"RG2 text"
        body = data + struct.pack("!I", zlib.crc32(metadata + data))
        frame = prefix + base64.b64encode(header + body)
        self.assertEqual(Reassembler().receive(frame).data, "RG2 text")

    def test_legacy_text_and_file(self):
        receiver = Reassembler()
        self.assertEqual(receiver.receive(b"raw text").data, "raw text")
        compressed = b"~RG11:" + base64.b85encode(zlib.compress(b"legacy text"))
        self.assertEqual(receiver.receive(compressed).data, "legacy text")
        data = b"\x00\xff" * 100
        body = b"~RG14:" + base64.b64encode(data)
        transfer_id = b"0123456789abcdef"
        fragments = [b"~RG1F:" + transfer_id + f"{i:04x}0002".encode() + chunk
                     for i, chunk in enumerate((body[:140], body[140:]))]
        self.assertIsNone(receiver.receive(fragments[0]))
        self.assertEqual(receiver.receive(fragments[1]).data, data)

    def test_file_size_limit(self):
        with self.assertRaises(ValueError):
            list(file_packets(b"x" * (MAX_FILE + 1)))
        frame, = file_packets(b"")
        self.assertEqual(Reassembler().receive(frame).data, b"")


if __name__ == "__main__":
    unittest.main()
