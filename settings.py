"""Load the local audio settings and validate the shared key."""

import configparser
from dataclasses import dataclass
import errno
import os
from pathlib import Path
import stat
import tempfile

DEFAULT_CONFIG = """[audio]
NOISE_SYMBOLS = 1
CARRIER_FREQUENCY = 1500
RATE = 8000
BITS = 16
CHANNEL = 0
MAPPING = 4
"""


@dataclass(frozen=True)
class AudioSettings:
    noise_symbols: int
    carrier_frequency: int
    rate: int
    bits: int
    channel: int
    mapping: int

    def codec_args(self):
        return list(map(str, (self.rate, self.bits, self.channel, self.mapping)))

    def pacat_args(self):
        sample_format = "u8" if self.bits == 8 else f"s{self.bits}le"
        channels = 1 if self.channel == 0 else 2
        return ["pacat", "--raw", f"--rate={self.rate}", f"--format={sample_format}",
                f"--channels={channels}"]


def initialize(config_path):
    config_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if config_path.exists():
        return
    with tempfile.TemporaryDirectory(dir=config_path.parent) as temporary:
        staged = Path(temporary) / "config.ini"
        staged.write_text(DEFAULT_CONFIG, encoding="utf-8")
        try:
            os.link(staged, config_path)
        except FileExistsError:
            pass


def load_settings(directory):
    config_path = directory / "config.ini"
    initialize(config_path)
    config = configparser.ConfigParser(interpolation=None)
    config.read_string(DEFAULT_CONFIG)
    try:
        with config_path.open(encoding="utf-8") as source:
            config.read_file(source)
        audio = config["audio"]
        return AudioSettings(
            read_number(audio, "NOISE_SYMBOLS", range(33), "0–32"),
            read_number(audio, "CARRIER_FREQUENCY", range(900, 3101), "900–3100"),
            read_number(audio, "RATE", (8000, 48000), "8000 oder 48000"),
            read_number(audio, "BITS", (8, 16, 24, 32), "8, 16, 24 oder 32"),
            read_number(audio, "CHANNEL", range(5), "0–4"),
            read_number(audio, "MAPPING", (2, 4, 8, 16), "2, 4, 8 oder 16"),
        )
    except (ValueError, configparser.Error) as exc:
        raise ValueError(f"Ungültige Konfiguration in {config_path}: {exc}") from exc


def read_number(section, name, allowed, description):
    try:
        value = section.getint(name)
    except ValueError:
        value = None
    if value not in allowed:
        raise ValueError(f"{name} muss {description} sein.")
    return value


def load_cipher(directory):
    path = directory / "key"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except PermissionError as exc:
        raise ValueError(f"{path} ist nicht lesbar. Erwartet werden Rechte 600 "
                         "und der aktuelle Benutzer als Eigentümer.") from exc
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError(f"Die Schlüsseldatei {path} darf kein Symlink sein.") from exc
        raise

    with os.fdopen(fd, "rb") as key_file:
        info = os.fstat(key_file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError(f"{path} muss eine reguläre Datei im Eigentum des Benutzers sein.")
        mode = stat.S_IMODE(info.st_mode)
        if mode != 0o600:
            raise ValueError(f"Unsichere Rechte für {path}: {mode:o}. Erwartet 600. "
                             "Bitte chmod 600 auf die Schlüsseldatei anwenden.")
        key = key_file.read(33)
    if len(key) != 32:
        raise ValueError(f"{path} muss genau 32 rohe Schlüsselbytes enthalten.")

    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    return ChaCha20Poly1305(key)
