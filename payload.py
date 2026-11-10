"""Versioned message envelope carried in a Rattlegram payload."""

import base64
import os
import re
import time
import zlib

MAX_PAYLOAD = 170
PREFIX = b"~RG1"
COMPRESSED = 1
ENCRYPTED = 2
NONCE_SIZE = 12
TAG_SIZE = 16
MAX_MESSAGE = 64 * 1024
MAX_WIRE = 2 * MAX_MESSAGE
MAX_FILE = 1024 * 1024
FILE_HEADERS = (b"~RG14:", b"~RG16:")
MAX_FILE_WIRE = len(FILE_HEADERS[0]) + 4 * ((MAX_FILE + NONCE_SIZE + TAG_SIZE + 2) // 3)
FRAGMENT_PREFIX = b"~RG1F:"
FRAGMENT_HEADER = re.compile(rb"~RG1F:([0-9a-f]{16})([0-9a-f]{4})([0-9a-f]{4})")
FRAGMENT_SIZE = MAX_PAYLOAD - 30
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


def pack(message, compress=False, cipher=None, limit=MAX_PAYLOAD):
    data = message.encode("utf-8")
    if not 1 <= len(data) <= limit or b"\0" in data:
        raise ValueError(f"Die Nachricht braucht 1 bis {limit} UTF-8-Bytes ohne Nullbyte.")
    flags = (COMPRESSED if compress else 0) | (ENCRYPTED if cipher else 0)
    if not flags:
        if data.startswith(PREFIX):
            raise ValueError("Das Präfix ~RG1 ist für erweiterte Nachrichten reserviert.")
        return data

    header = PREFIX + str(flags).encode("ascii") + b":"
    if compress:
        data = zlib.compress(data, level=9)
    data = encrypt_data(data, header, cipher)
    packet = header + base64.b85encode(data)
    if limit == MAX_PAYLOAD and len(packet) > MAX_PAYLOAD:
        raise ValueError("Die Nachricht passt mit diesen Optionen nicht in 170 Funkbytes.")
    return packet


def unpack(packet, cipher=None, limit=MAX_PAYLOAD):
    wire_limit = MAX_PAYLOAD if limit == MAX_PAYLOAD else MAX_WIRE
    if not 1 <= len(packet) <= wire_limit:
        raise ValueError("Ungültige Paketlänge.")
    if not packet.startswith(PREFIX):
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
    limit = MAX_MESSAGE if fragment else MAX_PAYLOAD
    packet = pack(message, compress, cipher, limit)
    if len(packet) <= MAX_PAYLOAD and len(message.encode("utf-8")) <= MAX_PAYLOAD:
        yield packet
        return

    yield from fragment_packet(packet)


def file_packets(data, cipher=None):
    if len(data) > MAX_FILE:
        raise ValueError(f"Die Datei überschreitet das Limit von {MAX_FILE} Bytes.")
    header = FILE_HEADERS[cipher is not None]
    packet = header + base64.b64encode(encrypt_data(data, header, cipher))
    if len(packet) <= MAX_PAYLOAD:
        yield packet
    else:
        yield from fragment_packet(packet)


def unpack_file(packet, cipher):
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


def fragment_packet(packet):
    transfer_id = os.urandom(8).hex()
    count = (len(packet) + FRAGMENT_SIZE - 1) // FRAGMENT_SIZE
    for index in range(count):
        start = index * FRAGMENT_SIZE
        header = FRAGMENT_PREFIX + f"{transfer_id}{index:04x}{count:04x}".encode("ascii")
        yield header + packet[start:start + FRAGMENT_SIZE]


class Reassembler:
    """Track a small number of incomplete, sequential transfers."""

    def __init__(self, receive_files=False):
        self.pending = {}
        self.receive_files = receive_files
        wire_limit = MAX_FILE_WIRE if receive_files else MAX_WIRE
        self.max_fragments = (wire_limit + FRAGMENT_SIZE - 1) // FRAGMENT_SIZE

    def decode(self, packet, cipher, limit):
        if packet[:6] in FILE_HEADERS:
            if not self.receive_files:
                raise ValueError("Für Dateiempfang listen --output DATEI verwenden.")
            return unpack_file(packet, cipher)
        if not self.receive_files:
            return unpack(packet, cipher, limit)
        return None

    def receive(self, packet, cipher=None):
        if not packet.startswith(FRAGMENT_PREFIX):
            return self.decode(packet, cipher, MAX_PAYLOAD)

        header = FRAGMENT_HEADER.match(packet)
        if not header or not header.end() < len(packet) <= MAX_PAYLOAD:
            raise ValueError("Ungültiger Fragmentkopf.")
        transfer_id, index, count = header.groups()
        index, count = int(index, 16), int(count, 16)
        data = packet[header.end():]
        if not 0 <= index < count <= self.max_fragments or (
                index < count - 1 and len(data) != FRAGMENT_SIZE):
            raise ValueError("Ungültige Fragmentnummer oder -länge.")

        now = time.monotonic()
        self.pending = {
            key: state for key, state in self.pending.items()
            if now - state[0] < FRAGMENT_TIMEOUT
        }
        state = self.pending.pop(transfer_id, None)
        if index == 0:
            parts = []
        elif state is not None and state[1] == count and len(state[2]) == index:
            parts = state[2]
        else:
            raise ValueError("Ein vorheriges Fragment fehlt.")

        parts.append(data)
        if len(parts) == count:
            return self.decode(b"".join(parts), cipher, MAX_MESSAGE)
        if len(self.pending) == MAX_PENDING:
            del self.pending[next(iter(self.pending))]
        self.pending[transfer_id] = now, count, parts
        return None
