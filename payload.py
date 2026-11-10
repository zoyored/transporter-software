"""Versioned message envelope carried in a Rattlegram payload."""

import base64
import os
import re
import struct
import time
import zlib
from functools import partial
from typing import NamedTuple, Optional, Union

MAX_PAYLOAD = 170
LEGACY_PREFIX = b"~RG1"
PREFIX = b"~RG2:"
VERSION_PREFIX = re.compile(rb"~RG[0-9]+:")
HEADER = struct.Struct("!B8sHH")
AUTH_HEADER = struct.Struct("!B8sH")
CRC = struct.Struct("!I")
CHUNK_SIZE = (MAX_PAYLOAD - len(PREFIX)) // 4 * 3 - HEADER.size
COMPRESSED = 1
ENCRYPTED = 2
FILE = 4
KNOWN_FLAGS = COMPRESSED | ENCRYPTED | FILE
NONCE_SIZE = 12
TAG_SIZE = 16
MAX_MESSAGE = 64 * 1024
MAX_WIRE = 2 * MAX_MESSAGE
MAX_FILE = 1024 * 1024
FILE_HEADERS = (b"~RG14:", b"~RG16:")
MAX_FILE_WIRE = len(FILE_HEADERS[0]) + 4 * ((MAX_FILE + NONCE_SIZE + TAG_SIZE + 2) // 3)
LEGACY_FRAGMENT_PREFIX = b"~RG1F:"
LEGACY_FRAGMENT_HEADER = re.compile(rb"~RG1F:([0-9a-f]{16})([0-9a-f]{4})([0-9a-f]{4})")
LEGACY_CHUNK_SIZE = MAX_PAYLOAD - 30
MAX_PENDING = 8
FRAGMENT_TIMEOUT = 30


def load_cipher(path):
    # Plain and compressed-only operation work without cryptography installed.
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    with open(path, "rb") as key_file:
        key = key_file.read(33)
    if len(key) != 32:
        raise ValueError("Die Schlüsseldatei muss genau 32 rohe Bytes enthalten.")
    return ChaCha20Poly1305(key)


def encrypt_data(data, header, cipher):
    if cipher is None:
        return data
    nonce = os.urandom(NONCE_SIZE)
    return nonce + cipher.encrypt(nonce, data, header)


def decrypt_data(data, header, cipher):
    if cipher is None:
        return data
    from cryptography.exceptions import InvalidTag

    if len(data) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("Verschlüsseltes Paket ist zu kurz.")
    try:
        return cipher.decrypt(data[:NONCE_SIZE], data[NONCE_SIZE:], header)
    except InvalidTag as exc:
        raise ValueError("Authentifizierung fehlgeschlagen.") from exc


def unpack_legacy_text(packet, cipher, limit):
    wire_limit = MAX_PAYLOAD if limit == MAX_PAYLOAD else MAX_WIRE
    if not 1 <= len(packet) <= wire_limit:
        raise ValueError("Ungültige Paketlänge.")
    if not packet.startswith(LEGACY_PREFIX):
        if cipher:
            raise ValueError("Unverschlüsselte Nachricht verworfen.")
        if len(packet) > limit or b"\0" in packet:
            raise ValueError("Ungültiger Nachrichteninhalt.")
        return packet.decode("utf-8")

    header = packet[:6]
    if header not in (b"~RG11:", b"~RG12:", b"~RG13:"):
        raise ValueError("Ungültiger Paketkopf.")
    flags = int(header[4:5])
    encrypted = bool(flags & ENCRYPTED)
    if encrypted != bool(cipher):
        raise ValueError("Schlüssel erforderlich." if encrypted
                         else "Unverschlüsselte Nachricht verworfen.")

    encoded = packet[len(header):]
    data = base64.b85decode(encoded)
    if base64.b85encode(data) != encoded:
        raise ValueError("Ungültige Base85-Daten.")
    data = decrypt_data(data, header, cipher)

    return decode_text(data, flags, limit)


def decode_text(data, flags, limit):
    if flags & COMPRESSED:
        decoder = zlib.decompressobj()
        try:
            data = decoder.decompress(data, limit + 1)
        except zlib.error as exc:
            raise ValueError("Ungültige Kompression.") from exc
        if not decoder.eof or decoder.unused_data:
            raise ValueError("Ungültiger oder zu großer komprimierter Inhalt.")
    if not 1 <= len(data) <= limit or b"\0" in data:
        raise ValueError("Ungültiger Nachrichteninhalt.")
    return data.decode("utf-8")


def packets(message, compress=False, cipher=None, fragment=False):
    data = message.encode("utf-8")
    limit = MAX_MESSAGE if fragment else MAX_PAYLOAD
    if not 1 <= len(data) <= limit or b"\0" in data:
        raise ValueError(f"Die Nachricht braucht 1 bis {limit} UTF-8-Bytes ohne Nullbyte.")
    flags = COMPRESSED if compress else 0
    if compress:
        data = zlib.compress(data, level=9)
    return encode_packets(data, flags, cipher, fragment)


def file_packets(data, cipher=None):
    if len(data) > MAX_FILE:
        raise ValueError(f"Die Datei überschreitet das Limit von {MAX_FILE} Bytes.")
    return encode_packets(data, FILE, cipher, fragment=True)


def encode_packets(data, flags, cipher, fragment):
    if cipher is not None:
        flags |= ENCRYPTED
    overhead = NONCE_SIZE + TAG_SIZE if cipher is not None else CRC.size
    count = (len(data) + overhead + CHUNK_SIZE - 1) // CHUNK_SIZE
    if count > 1 and not fragment:
        raise ValueError("Die Nachricht passt nicht in ein Funkpaket. --no-length-limit verwenden.")

    transfer_id = os.urandom(8)
    aad = PREFIX + AUTH_HEADER.pack(flags, transfer_id, count)
    if cipher is not None:
        body = encrypt_data(data, aad, cipher)
    else:
        body = data + CRC.pack(zlib.crc32(data, zlib.crc32(aad)))

    for index in range(count):
        start = index * CHUNK_SIZE
        header = HEADER.pack(flags, transfer_id, index, count)
        yield PREFIX + base64.b64encode(header + body[start:start + CHUNK_SIZE])


class Transfer(NamedTuple):
    data: Union[str, bytes]
    transfer_id: Optional[str] = None


def unpack_legacy_file(packet, cipher):
    header = packet[:6]
    encrypted = header == FILE_HEADERS[1]
    if encrypted != (cipher is not None):
        raise ValueError("Schlüssel erforderlich." if encrypted
                         else "Unverschlüsselte Datei verworfen.")
    if len(packet) > MAX_FILE_WIRE:
        raise ValueError("Ungültige Dateipaketlänge.")
    encoded = packet[len(header):]
    data = base64.b64decode(encoded, validate=True)
    data = decrypt_data(data, header, cipher)
    if len(data) > MAX_FILE:
        raise ValueError("Die empfangene Datei ist zu groß.")
    return data


def decode_header(packet):
    encoded = packet[len(PREFIX):]
    frame = base64.b64decode(encoded, validate=True)
    if base64.b64encode(frame) != encoded or len(frame) <= HEADER.size:
        raise ValueError("Ungültiger RG2-Paketkopf.")
    flags, transfer_id, index, count = HEADER.unpack_from(frame)
    if flags & ~KNOWN_FLAGS or (flags & FILE and flags & COMPRESSED):
        raise ValueError("Ungültige RG2-Flags.")
    return flags, transfer_id, index, count, frame[HEADER.size:]


def decode_body(body, flags, transfer_id, count, cipher):
    aad = PREFIX + AUTH_HEADER.pack(flags, transfer_id, count)
    if flags & ENCRYPTED:
        data = decrypt_data(body, aad, cipher)
    else:
        data, checksum = body[:-CRC.size], body[-CRC.size:]
        if checksum != CRC.pack(zlib.crc32(data, zlib.crc32(aad))):
            raise ValueError("Prüfsumme stimmt nicht.")
    if flags & FILE:
        if len(data) > MAX_FILE:
            raise ValueError("Die empfangene Datei ist zu groß.")
        return Transfer(data, transfer_id.hex())
    return Transfer(decode_text(data, flags, MAX_MESSAGE))


class Reassembler:
    """Collect bounded sets of fragments and decode only complete transfers."""

    def __init__(self, cipher=None, require_encryption=False, on_file_start=None):
        self.pending = {}
        self.cipher = cipher
        self.require_encryption = require_encryption
        self.on_file_start = on_file_start

    def select_cipher(self, encrypted):
        if encrypted and self.cipher is None:
            raise ValueError("Schlüssel erforderlich.")
        if not encrypted and self.require_encryption:
            raise ValueError("Unverschlüsselte Übertragung verworfen.")
        return self.cipher if encrypted else None

    def receive(self, packet, sender=None):
        if not 1 <= len(packet) <= MAX_PAYLOAD:
            raise ValueError("Ungültige Funkpaketlänge.")
        if packet.startswith(PREFIX):
            flags, transfer_id, index, count, chunk = decode_header(packet)
            cipher = self.select_cipher(flags & ENCRYPTED)
            limit = (MAX_FILE + NONCE_SIZE + TAG_SIZE) if flags & FILE else MAX_WIRE
            start = None
            if index == 0 and flags & FILE and self.on_file_start is not None:
                start = partial(self.on_file_start, sender, transfer_id.hex(), count)
            body = self.assemble((sender, PREFIX, transfer_id), flags, index, count,
                                 chunk, CHUNK_SIZE, limit, start)
            if body is not None:
                return decode_body(body, flags, transfer_id, count, cipher)
            return None
        if packet.startswith(LEGACY_FRAGMENT_PREFIX):
            header = LEGACY_FRAGMENT_HEADER.match(packet)
            if not header:
                raise ValueError("Ungültiger Fragmentkopf.")
            transfer_id, index, count = header.groups()
            transfer_id = transfer_id.decode("ascii")
            index, count = int(index, 16), int(count, 16)
            chunk = packet[header.end():]
            start = None
            if index == 0 and chunk[:6] in FILE_HEADERS and self.on_file_start is not None:
                start = partial(self.on_file_start, sender, transfer_id, count)
            packet = self.assemble((sender, LEGACY_FRAGMENT_PREFIX, transfer_id), 0,
                                   index, count, chunk, LEGACY_CHUNK_SIZE, MAX_FILE_WIRE, start)
            if packet is None:
                return None
            return self.decode_legacy(packet, MAX_MESSAGE, transfer_id)
        if VERSION_PREFIX.match(packet) and not packet.startswith(LEGACY_PREFIX):
            raise ValueError("Unbekannte Rattlegram-Protokollversion.")
        if packet[:6] in FILE_HEADERS and self.on_file_start is not None:
            self.on_file_start(sender, None, 1)
        return self.decode_legacy(packet, MAX_PAYLOAD)

    def decode_legacy(self, packet, limit, transfer_id=None):
        header = packet[:6]
        cipher = self.select_cipher(header in (b"~RG12:", b"~RG13:", FILE_HEADERS[1]))
        if header in FILE_HEADERS:
            return Transfer(unpack_legacy_file(packet, cipher), transfer_id)
        return Transfer(unpack_legacy_text(packet, cipher, limit))

    def assemble(self, key, flags, index, count, chunk, chunk_size, limit, start=None):
        max_count = (limit + chunk_size - 1) // chunk_size
        if not 0 <= index < count <= max_count or not 1 <= len(chunk) <= chunk_size:
            raise ValueError("Ungültige Fragmentnummer oder -länge.")
        if index < count - 1 and len(chunk) != chunk_size:
            raise ValueError("Ungültige Fragmentlänge.")
        if index == count - 1 and index * chunk_size + len(chunk) > limit:
            raise ValueError("Die Übertragung ist zu groß.")
        now = time.monotonic()
        self.pending = {
            k: state for k, state in self.pending.items()
            if now - state[0] < FRAGMENT_TIMEOUT
        }
        previous, expected_flags, expected_count, parts = self.pending.pop(
            key, (now, flags, count, {}))
        if (flags, count) != (expected_flags, expected_count):
            raise ValueError("Widersprüchliche Fragmentköpfe.")
        if start is not None and index == 0 and index not in parts:
            start()
        if count == 1:
            return chunk
        if index in parts:
            if parts[index] != chunk:
                raise ValueError("Widersprüchliche Fragmentdaten.")
            now = previous

        parts[index] = chunk
        if len(parts) == count:
            return b"".join(parts[i] for i in range(count))
        if len(self.pending) == MAX_PENDING:
            del self.pending[next(iter(self.pending))]
        self.pending[key] = now, flags, count, parts
        return None
