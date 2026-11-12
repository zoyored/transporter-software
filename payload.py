"""Versioned message envelope carried in a Rattlegram payload."""

import base64
import os
import re
import struct
import time
import zlib
from functools import partial
from typing import NamedTuple, Optional, Union

import base91
import gpg_transport

MAX_PAYLOAD = 170
LEGACY_PREFIX = b"~RG1"
RG2_PREFIX = b"~RG2:"
PREFIX = b"~RG3:"
PARITY_PREFIX = b"~RG4:"
VERSION_PREFIX = re.compile(rb"~RG[0-9]+:")
HEADER = struct.Struct("!B8sHH")
AUTH_HEADER = struct.Struct("!B8sH")
CRC = struct.Struct("!I")
RG2_CHUNK_SIZE = 110
CHUNK_SIZE = 121
COMPRESSED = 1
ENCRYPTED = 2
FILE = 4
RG2_FLAGS = COMPRESSED | ENCRYPTED | FILE
GPG_ENCRYPTED = 8
GPG_SIGNED = 16
GPG_FLAGS = GPG_ENCRYPTED | GPG_SIGNED
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
        raise ValueError("Encrypted packet is too short.")
    try:
        return cipher.decrypt(data[:NONCE_SIZE], data[NONCE_SIZE:], header)
    except InvalidTag as exc:
        raise ValueError("Authentication failed.") from exc


def unpack_legacy_text(packet, cipher, limit):
    wire_limit = MAX_PAYLOAD if limit == MAX_PAYLOAD else MAX_WIRE
    if not 1 <= len(packet) <= wire_limit:
        raise ValueError("Invalid packet length.")
    if not packet.startswith(LEGACY_PREFIX):
        if cipher:
            raise ValueError("Unencrypted message rejected.")
        if len(packet) > limit or b"\0" in packet:
            raise ValueError("Invalid message content.")
        return packet.decode("utf-8")

    header = packet[:6]
    if header not in (b"~RG11:", b"~RG12:", b"~RG13:"):
        raise ValueError("Invalid packet header.")
    flags = int(header[4:5])
    encrypted = bool(flags & ENCRYPTED)
    if encrypted != bool(cipher):
        raise ValueError("Key required." if encrypted
                         else "Unencrypted message rejected.")

    encoded = packet[len(header):]
    data = base64.b85decode(encoded)
    if base64.b85encode(data) != encoded:
        raise ValueError("Invalid Base85 data.")
    data = decrypt_data(data, header, cipher)

    return decode_text(data, flags, limit)


def decode_text(data, flags, limit):
    if flags & COMPRESSED:
        decoder = zlib.decompressobj()
        try:
            data = decoder.decompress(data, limit + 1)
        except zlib.error as exc:
            raise ValueError("Invalid compressed data.") from exc
        if not decoder.eof or decoder.unused_data:
            raise ValueError("Invalid or oversized compressed payload.")
    if not 1 <= len(data) <= limit or b"\0" in data:
        raise ValueError("Invalid message content.")
    return data.decode("utf-8")


def packets(message, compress=False, cipher=None, fragment=False, recipient=None, signer=None,
            parity=False):
    fragment = fragment or bool(recipient or signer)
    data = message.encode("utf-8")
    limit = MAX_MESSAGE if fragment else MAX_PAYLOAD
    if not 1 <= len(data) <= limit or b"\0" in data:
        raise ValueError(f"Message must contain 1 to {limit} UTF-8 bytes and no null bytes.")
    flags = COMPRESSED if compress else 0
    if compress:
        data = zlib.compress(data, level=9)
    return encode_packets(data, flags, cipher, fragment, recipient, signer, parity)


def file_packets(data, cipher=None, recipient=None, signer=None, parity=False):
    if len(data) > MAX_FILE:
        raise ValueError(f"File exceeds the {MAX_FILE}-byte limit.")
    return encode_packets(data, FILE, cipher, True, recipient, signer, parity)


def gpg_metadata(flags, transfer_id):
    return PREFIX + bytes((flags,)) + transfer_id


def encode_packets(data, flags, cipher, fragment, recipient, signer, parity):
    if cipher is not None:
        if recipient:
            raise ValueError("Choose either shared-key or GPG encryption.")
        flags |= ENCRYPTED
    if recipient:
        flags |= GPG_ENCRYPTED
    if signer:
        flags |= GPG_SIGNED

    transfer_id = os.urandom(8)
    if flags & GPG_FLAGS:
        limit = (MAX_FILE if flags & FILE else MAX_WIRE) + gpg_transport.MAX_OVERHEAD
        data = gpg_transport.protect(data, gpg_metadata(flags, transfer_id),
                                     recipient, signer, limit)
    overhead = NONCE_SIZE + TAG_SIZE if cipher is not None else CRC.size
    count = (len(data) + overhead + CHUNK_SIZE - 1) // CHUNK_SIZE
    if count > 1 and not fragment:
        raise ValueError("Message does not fit in one radio packet. Use --no-length-limit.")

    aad = PREFIX + AUTH_HEADER.pack(flags, transfer_id, count)
    if cipher is not None:
        body = encrypt_data(data, aad, cipher)
    else:
        body = data + CRC.pack(zlib.crc32(data, zlib.crc32(aad)))

    parity_bits = 0
    for index in range(count):
        start = index * CHUNK_SIZE
        chunk = body[start:start + CHUNK_SIZE]
        header = HEADER.pack(flags, transfer_id, index, count)
        yield PREFIX + base91.encode(header + chunk)
        if parity and count > 1:
            parity_bits ^= int.from_bytes(chunk, "little")

    if parity and count > 1:
        last_length = len(body) - (count - 1) * CHUNK_SIZE
        header = HEADER.pack(flags, transfer_id, last_length, count)
        yield PARITY_PREFIX + base91.encode(header + parity_bits.to_bytes(CHUNK_SIZE, "little"))


class Transfer(NamedTuple):
    data: Union[str, bytes]
    transfer_id: Optional[str] = None
    signers: tuple = ()


def unpack_legacy_file(packet, cipher):
    header = packet[:6]
    encrypted = header == FILE_HEADERS[1]
    if encrypted != (cipher is not None):
        raise ValueError("Key required." if encrypted
                         else "Unencrypted file rejected.")
    if len(packet) > MAX_FILE_WIRE:
        raise ValueError("Invalid file packet length.")
    encoded = packet[len(header):]
    data = base64.b64decode(encoded, validate=True)
    data = decrypt_data(data, header, cipher)
    if len(data) > MAX_FILE:
        raise ValueError("Received file exceeds the size limit.")
    return data


def decode_header(packet, prefix):
    encoded = packet[len(prefix):]
    if prefix == RG2_PREFIX:
        frame = base64.b64decode(encoded, validate=True)
        canonical = base64.b64encode(frame)
        allowed = RG2_FLAGS
    else:
        frame = base91.decode(encoded)
        canonical = base91.encode(frame)
        allowed = RG2_FLAGS | GPG_FLAGS
    if canonical != encoded or len(frame) <= HEADER.size:
        raise ValueError("Invalid radio packet header.")
    flags, transfer_id, index, count = HEADER.unpack_from(frame)
    if (flags & ~allowed or (flags & FILE and flags & COMPRESSED) or
            (flags & ENCRYPTED and flags & GPG_ENCRYPTED)):
        raise ValueError("Invalid radio packet flags.")
    return flags, transfer_id, index, count, frame[HEADER.size:]


def decode_body(body, prefix, flags, transfer_id, count, cipher):
    aad = prefix + AUTH_HEADER.pack(flags, transfer_id, count)
    if flags & ENCRYPTED:
        data = decrypt_data(body, aad, cipher)
    else:
        data, checksum = body[:-CRC.size], body[-CRC.size:]
        if checksum != CRC.pack(zlib.crc32(data, zlib.crc32(aad))):
            raise ValueError("Checksum mismatch.")
    signers = ()
    if flags & GPG_FLAGS:
        limit = (MAX_FILE if flags & FILE else MAX_WIRE) + gpg_transport.MAX_OVERHEAD
        data, signers = gpg_transport.unprotect(data, gpg_metadata(flags, transfer_id),
                                                flags & GPG_ENCRYPTED, flags & GPG_SIGNED, limit)
    if flags & FILE:
        if len(data) > MAX_FILE:
            raise ValueError("Received file exceeds the size limit.")
        return Transfer(data, transfer_id.hex(), signers)
    return Transfer(decode_text(data, flags, MAX_MESSAGE), signers=signers)


class Reassembler:
    """Collect bounded sets of fragments and decode only complete transfers."""

    def __init__(self, cipher=None, require_encryption=False, on_file_start=None):
        self.pending = {}
        self.completed_rg3 = {}
        self.cipher = cipher
        self.require_encryption = require_encryption
        self.on_file_start = on_file_start

    def select_cipher(self, encrypted):
        if encrypted and self.cipher is None:
            raise ValueError("Key required.")
        if not encrypted and self.require_encryption:
            raise ValueError("Unencrypted transfer rejected.")
        return self.cipher if encrypted else None

    def receive(self, packet, sender=None):
        if not 1 <= len(packet) <= MAX_PAYLOAD:
            raise ValueError("Invalid radio packet length.")
        prefix = packet[:len(PREFIX)]
        if prefix in (PREFIX, RG2_PREFIX, PARITY_PREFIX):
            flags, transfer_id, index, count, chunk = decode_header(packet, prefix)
            parity = prefix == PARITY_PREFIX
            if parity:
                prefix = PREFIX
            chunk_size = RG2_CHUNK_SIZE if prefix == RG2_PREFIX else CHUNK_SIZE
            cipher = self.select_cipher(flags & ENCRYPTED)
            limit = (MAX_FILE + NONCE_SIZE + TAG_SIZE) if flags & FILE else MAX_WIRE
            if flags & GPG_FLAGS:
                limit += gpg_transport.MAX_OVERHEAD + CRC.size
            start = None
            if index == 0 and flags & FILE and self.on_file_start is not None:
                start = partial(self.on_file_start, sender, transfer_id.hex(), count)
            key = (sender, prefix, transfer_id)
            now = time.monotonic()
            if prefix == PREFIX:
                self.completed_rg3 = {k: t for k, t in self.completed_rg3.items()
                                      if now - t < FRAGMENT_TIMEOUT}
                if key in self.completed_rg3:
                    return None
            body = self.assemble(key, flags, index, count, chunk, chunk_size, limit,
                                 start, parity=parity)
            if body is None:
                return None
            transfer = decode_body(body, prefix, flags, transfer_id, count, cipher)
            if prefix == PREFIX and count > 1:
                self.pending.pop(key, None)
                if len(self.completed_rg3) == 64:
                    del self.completed_rg3[next(iter(self.completed_rg3))]
                self.completed_rg3[key] = now
            return transfer
        if packet.startswith(LEGACY_FRAGMENT_PREFIX):
            header = LEGACY_FRAGMENT_HEADER.match(packet)
            if not header:
                raise ValueError("Invalid fragment header.")
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
            raise ValueError("Unknown Rattlegram protocol version.")
        if packet[:6] in FILE_HEADERS and self.on_file_start is not None:
            self.on_file_start(sender, None, 1)
        return self.decode_legacy(packet, MAX_PAYLOAD)

    def decode_legacy(self, packet, limit, transfer_id=None):
        header = packet[:6]
        cipher = self.select_cipher(header in (b"~RG12:", b"~RG13:", FILE_HEADERS[1]))
        if header in FILE_HEADERS:
            return Transfer(unpack_legacy_file(packet, cipher), transfer_id)
        return Transfer(unpack_legacy_text(packet, cipher, limit))

    def assemble(self, key, flags, index, count, chunk, chunk_size, limit,
                 start=None, parity=False):
        max_count = (limit + chunk_size - 1) // chunk_size
        if parity:
            if (not 2 <= count <= max_count or not 1 <= index <= chunk_size or
                    len(chunk) != chunk_size or (count - 1) * chunk_size + index > limit):
                raise ValueError("Invalid parity packet.")
            chunk = bytes((index,)) + chunk
            index = count
        else:
            if not 0 <= index < count <= max_count or not 1 <= len(chunk) <= chunk_size:
                raise ValueError("Invalid fragment index or length.")
            if index < count - 1 and len(chunk) != chunk_size:
                raise ValueError("Invalid fragment length.")
            if index == count - 1 and index * chunk_size + len(chunk) > limit:
                raise ValueError("Transfer exceeds the size limit.")
        now = time.monotonic()
        self.pending = {
            k: state for k, state in self.pending.items()
            if now - state[0] < FRAGMENT_TIMEOUT
        }
        previous, expected_flags, expected_count, parts = self.pending.pop(
            key, (now, flags, count, {}))
        if (flags, count) != (expected_flags, expected_count):
            raise ValueError("Conflicting fragment headers.")
        if start is not None and index == 0 and index not in parts:
            start()
        if count == 1:
            return chunk
        if index in parts:
            if parts[index] != chunk:
                raise ValueError("Conflicting fragment data.")
            now = previous

        parts[index] = chunk
        if len(parts) - (count in parts) == count:
            return b"".join(parts[i] for i in range(count))
        if len(self.pending) == MAX_PENDING:
            del self.pending[next(iter(self.pending))]
        self.pending[key] = now, flags, count, parts
        if count in parts and len(parts) == count:
            return recover_body(parts, count, chunk_size)
        return None


def recover_body(parts, count, chunk_size):
    parity = parts[count]
    last_length = parity[0]
    if count - 1 in parts and len(parts[count - 1]) != last_length:
        raise ValueError("Parity packet does not match the last fragment.")
    missing = next(index for index in range(count) if index not in parts)
    recovered = int.from_bytes(parity[1:], "little")
    for index, chunk in parts.items():
        if index != count:
            recovered ^= int.from_bytes(chunk, "little")
    length = last_length if missing == count - 1 else chunk_size
    replacement = recovered.to_bytes(chunk_size, "little")[:length]
    return b"".join(replacement if index == missing else parts[index]
                    for index in range(count))
