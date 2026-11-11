"""Binary OpenPGP processing through the user's GnuPG keyring."""

import re
import struct
import subprocess
import tempfile
from pathlib import Path

MAX_OVERHEAD = 64 * 1024
SIGNATURE_SIZE = struct.Struct("!I")


def fingerprint(value):
    value = value.strip()
    if len(value) >= 2 and value[0] in ('"', "'") and value[-1] == value[0]:
        value = value[1:-1]
    normalized = "".join(value.split())
    if not re.fullmatch(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", normalized):
        raise ValueError("Specify the full GPG fingerprint (40 or 64 hexadecimal digits).")
    return normalized.upper()


def run_gpg(arguments, data=b"", max_output=MAX_OVERHEAD):
    with tempfile.TemporaryFile() as status:
        fd = status.fileno()
        try:
            result = subprocess.run(
                ["gpg", "--no-options", "--batch", "--no-tty", "--no-auto-key-retrieve",
                 "--status-fd", str(fd), "--max-output", str(max_output), *arguments],
                input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                pass_fds=(fd,), timeout=60)
        except FileNotFoundError as exc:
            raise ValueError("GPG is required for OpenPGP transfers.") from exc
        except subprocess.TimeoutExpired as exc:
            raise ValueError("GPG operation timed out.") from exc
        status.seek(0)
        records = [line[len(b"[GNUPG:] "):].decode("ascii", errors="replace").split()
                   for line in status if line.startswith(b"[GNUPG:] ")]
    if result.returncode:
        code = next((record[0] for record in records if record and record[0] in
                     {"NO_SECKEY", "NO_PUBKEY", "INV_RECP", "INV_SGNR", "BADSIG",
                      "ERRSIG", "BAD_PASSPHRASE", "DECRYPTION_FAILED"}), None)
        detail = f" ({code})" if code else ""
        raise ValueError(f"GPG operation failed{detail}.")
    return result.stdout, records


def protect(data, metadata, recipient, signer, limit):
    body = metadata + data
    if signer:
        signature, _ = run_gpg(["--local-user", fingerprint(signer), "--output", "-",
                                "--detach-sign"], body)
        body = SIGNATURE_SIZE.pack(len(signature)) + signature + body
    if recipient:
        body, _ = run_gpg(["--recipient", fingerprint(recipient), "--compress-algo", "none",
                           "--set-filename", "", "--output", "-", "--encrypt"],
                          body, limit)
    if len(body) > limit:
        raise ValueError("OpenPGP payload exceeds the size limit.")
    return body


def unprotect(body, metadata, encrypted, signed, limit):
    if encrypted:
        body, records = run_gpg(["--output", "-", "--decrypt"], body, limit)
        if not any(record and record[0] == "DECRYPTION_OKAY" for record in records):
            raise ValueError("GPG did not confirm decryption.")

    signers = ()
    if signed:
        if len(body) < SIGNATURE_SIZE.size:
            raise ValueError("Missing OpenPGP signature.")
        length, = SIGNATURE_SIZE.unpack_from(body)
        end = SIGNATURE_SIZE.size + length
        if not 1 <= length <= MAX_OVERHEAD or end >= len(body):
            raise ValueError("Invalid OpenPGP signature length.")
        signature, body = body[SIGNATURE_SIZE.size:end], body[end:]
        with tempfile.TemporaryDirectory() as directory:
            signature_path = Path(directory) / "signature"
            signature_path.write_bytes(signature)
            _, records = run_gpg(["--verify", str(signature_path), "-"], body)

        valid = [record for record in records if record and record[0] == "VALIDSIG"]
        invalid = {"BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG"}
        if (len(valid) != 1 or len(valid[0]) < 10 or valid[0][9] != "00" or
                any(record and record[0] in invalid for record in records)):
            raise ValueError("GPG did not confirm a valid signature.")
        record = valid[0]
        signers = (fingerprint(record[1]),)
        if len(record) > 10:
            signers += (fingerprint(record[10]),)

    if not body.startswith(metadata):
        raise ValueError("OpenPGP metadata does not match the radio header.")
    return body[len(metadata):], signers
