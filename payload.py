"""Versioned text envelope carried in a Rattlegram payload."""

import base64
import os
import zlib

MAX_PAYLOAD = 170
PREFIX = b"~RG1"
COMPRESSED = 1
ENCRYPTED = 2
NONCE_SIZE = 12
TAG_SIZE = 16


def load_cipher(path):
    # Plain and compressed-only operation work without cryptography installed.
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    with open(path, "rb") as key_file:
        key = key_file.read(33)
    if len(key) != 32:
        raise ValueError("Die Schlüsseldatei muss genau 32 rohe Bytes enthalten.")
    return ChaCha20Poly1305(key)


def pack(message, compress=False, cipher=None):
    data = message.encode("utf-8")
    if not 1 <= len(data) <= MAX_PAYLOAD or b"\0" in data:
        raise ValueError("Die Nachricht braucht 1 bis 170 UTF-8-Bytes ohne Nullbyte.")
    flags = (COMPRESSED if compress else 0) | (ENCRYPTED if cipher else 0)
    if not flags:
        if data.startswith(PREFIX):
            raise ValueError("Das Präfix ~RG1 ist für erweiterte Nachrichten reserviert.")
        return data

    header = PREFIX + str(flags).encode("ascii") + b":"
    if compress:
        data = zlib.compress(data, level=9)
    if cipher:
        nonce = os.urandom(NONCE_SIZE)
        data = nonce + cipher.encrypt(nonce, data, header)
    packet = header + base64.b85encode(data)
    if len(packet) > MAX_PAYLOAD:
        raise ValueError("Die Nachricht passt mit diesen Optionen nicht in 170 Funkbytes.")
    return packet


def unpack(packet, cipher=None):
    if not 1 <= len(packet) <= MAX_PAYLOAD:
        raise ValueError("Ungültige Paketlänge.")
    if not packet.startswith(PREFIX):
        if cipher:
            raise ValueError("Unverschlüsselte Nachricht verworfen.")
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
    if encrypted:
        from cryptography.exceptions import InvalidTag

        if len(data) <= NONCE_SIZE + TAG_SIZE:
            raise ValueError("Verschlüsseltes Paket ist zu kurz.")
        try:
            data = cipher.decrypt(data[:NONCE_SIZE], data[NONCE_SIZE:], header)
        except InvalidTag as exc:
            raise ValueError("Authentifizierung fehlgeschlagen.") from exc

    if flags & COMPRESSED:
        decoder = zlib.decompressobj()
        try:
            data = decoder.decompress(data, MAX_PAYLOAD + 1)
        except zlib.error as exc:
            raise ValueError("Ungültige Kompression.") from exc
        if not decoder.eof or decoder.unused_data:
            raise ValueError("Ungültiger oder zu großer komprimierter Inhalt.")
    if not 1 <= len(data) <= MAX_PAYLOAD or b"\0" in data:
        raise ValueError("Ungültiger Nachrichteninhalt.")
    return data.decode("utf-8")
