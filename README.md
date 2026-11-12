# Rattlegram Audio for Linux

## Build

You need Python 3.8 or later, GNU Make, a C++17 compiler, and `pacat` from
`pulseaudio-utils`. Audio playback and recording use PulseAudio or PipeWire's
PulseAudio interface.

```sh
git clone https://github.com/zoyored/transporter-software.git
cd transporter-software
make
```

## Configuration

The first `send` or `listen` creates `~/.rattlegram-audio/config.ini` if it
does not exist. Edit the file to change the audio settings used by both
commands. Existing settings are retained across runs. Missing entries use
the defaults below.

```ini
[audio]
NOISE_SYMBOLS = 1
CARRIER_FREQUENCY = 1500
RATE = 8000
BITS = 16
CHANNEL = 0
MAPPING = 4
```

| Setting | Supported values |
| --- | --- |
| `NOISE_SYMBOLS` | 0–32 leading noise symbols per transmitted packet |
| `CARRIER_FREQUENCY` | 900–3100 Hz, transmitter carrier |
| `RATE` | 8000 or 48000 Hz |
| `BITS` | 8-bit unsigned PCM, or 16-, 24-, or 32-bit signed little-endian PCM. The codec processes 16-bit samples internally. |
| `CHANNEL` | 0 mono, 1 stereo left, 2 stereo right, 3 dual mono with stereo mix on receive, 4 stereo I/Q |
| `MAPPING` | 2 BPSK, 4 QPSK, 8 8-PSK, 16 16-QAM |

Use matching mappings on both sides. Select the channel mode appropriate
for each audio connection.

## Receive

```sh
./rattlegram-audio listen
```

The receiver listens on the system's default audio input and writes each
successfully decoded message to stdout immediately as `CALLSIGN: message`,
followed by a newline. The call sign comes from the radio preamble and
does not authenticate the sender. Press Ctrl+C to stop. To process or save messages, redirect stdout or pipe it
into another command, such as `./rattlegram-audio listen | tee received.txt`.

## Send

```sh
./rattlegram-audio send "Hello from Rattlegram!" DL1ABC
```

A plain text message can contain up to 117 UTF-8 bytes in one packet. For
longer text, use `--no-length-limit`. The call sign must contain 1 to 9
ASCII letters or digits. The sender pipes PCM samples directly to `pacat`,
which plays them through the system's default audio output.

### Transfer a file

Start the receiver, then send the file.

```sh
# On DN1ABC (receiver)
./rattlegram-audio listen

# On DL1ABC (sender)
./rattlegram-audio send --file "document.pdf" DL1ABC
```

The listener detects files automatically and saves them byte for byte as
`~/.rattlegram-audio/receieved/rattlegram-<transfer-id>.bin`. Use `--receive-dir DIR` to choose
another directory or `--output PATH` to save one file under a specific name
and exit. Existing files are never overwritten. The listener reports the
sender and packet count when it receives the first file packet. It reports
the final path after verification and saving. File status and errors go to
stderr.

Use `listen -v` or `listen --verbose` to report the number of corrected
payload bits per decoded radio packet on stderr. A lower count means
the decoder needed fewer corrections. This count is separate from signal
strength or SNR.

Files up to 1 MiB are supported. The sender automatically splits larger
payloads into multiple radio packets. Missing fragments are never requested
again. Large files can take many minutes to transmit. Compression is
unavailable for `--file`. To encrypt a file, add `--encrypt` to the send
command and configure the same key on the listener.

## Test locally without an audio device

```sh
./bin/send-pcm "Hello from Rattlegram!" DL1ABC | ./bin/listen-pcm
```

The standalone codecs default to 8 kHz mono, signed 16-bit little-endian
PCM and QPSK (mapping 4). The sender defaults to a 1500 Hz carrier. The audio pipeline
runs without WAV files.

The encoder and decoder come from
[bastibl/rattlegram-cli](https://github.com/bastibl/rattlegram-cli).
The included license applies to that code.

## Compression and encryption

You can enable either option independently when sending. The receiver
automatically detects compressed packets.

```sh
./rattlegram-audio send --compress "Repeat repeat repeat" DL1ABC
./rattlegram-audio send --encrypt "Confidential message" DL1ABC
./rattlegram-audio send --compress --encrypt "Both options" DL1ABC
```

Encryption requires the Python package `cryptography`. Both devices use the
same 32-byte binary key at `~/.rattlegram-audio/key`. Generate it once, then
copy it securely to the other device and set mode `600` on both.

```sh
mkdir -p -m 700 ~/.rattlegram-audio
(umask 077; set -C; openssl rand 32 > ~/.rattlegram-audio/key)
chmod 600 ~/.rattlegram-audio/key
./rattlegram-audio listen --encrypt
```

The key must be a regular file owned by the current user with exactly mode
`600`. The program rejects insecure permissions and symbolic links.
Encryption options no longer take a key path.

The listener automatically loads the key if it exists, and reads the
encryption flag on each packet. Plain `listen` accepts encrypted and
unencrypted traffic. Use `listen --key-file` to require the key at startup
while accepting both kinds of traffic, or `listen --encrypt` to require
authenticated transfers. The call sign and frame header remain visible.

One RG3 packet holds up to 117 uncompressed plaintext bytes, or 93 with
shared-key encryption. With compression, capacity depends on how well the text
compresses. A payload that does not fit in one packet requires
`--no-length-limit`.

### OpenPGP

Install GnuPG and use full fingerprints from your GnuPG keyring.
Fingerprints may contain the spaces shown by GnuPG. When passing a grouped
fingerprint on the command line, quote it so the shell passes it as one argument.
The sender needs the recipient's public key for encryption and its own
private key for signing. The listener uses its private key to decrypt and
the signer's public key to verify. GnuPG handles private keys and passphrases
through its normal keyring and agent.

#### Create a key and find its fingerprint

Run `gpg --full-generate-key` and select a key type that supports both
signing and encryption, such as **RSA and RSA**. Follow the prompts to
set an expiration date, enter a user ID, and protect the private key with
a passphrase.

```sh
gpg --full-generate-key
gpg --fingerprint
```

In the output, copy the entire hexadecimal fingerprint under the primary
`pub` entry. A short key ID is insufficient. You can also list a specific
key by passing its email address to `gpg --fingerprint`. An `[E]` subkey
indicates encryption capability. GnuPG selects that subkey when you
encrypt using the primary fingerprint.

Use your own fingerprint as `signer_fingerprint` for signing and the
recipient's fingerprint as `recipient_fingerprint` for encryption. To
test encryption to yourself, use your own fingerprint for both.
The recipient's public key must be in your GnuPG keyring.

#### Send and receive

```sh
# On DL1ABC (sender), use DN1ABC's fingerprint as recipient_fingerprint
./rattlegram-audio send --gpg-encrypt "$recipient_fingerprint" "Private message" DL1ABC
./rattlegram-audio send --gpg-sign "$signer_fingerprint" "Signed message" DL1ABC
./rattlegram-audio send --gpg-sign "$signer_fingerprint" --gpg-encrypt "$recipient_fingerprint" --file document.pdf DL1ABC

# On DN1ABC (receiver)
./rattlegram-audio listen
```

To use names instead of fingerprints on the command line, add entries to
`[gpg]` in `~/.rattlegram-audio/config.ini`. Replace the example fingerprints
with the full fingerprints from your GnuPG keyring.

```ini
[gpg]
DL1ABC = 0123456789ABCDEF0123456789ABCDEF01234567
DN1ABC = FEDCBA9876543210FEDCBA9876543210FEDCBA98
```

With `-s` alone, the sender looks up its call sign in `[gpg]`.
Use `-g NAME` to choose the recipient. Names are case-insensitive, and
both options also accept a full fingerprint directly. Use `--` before
a positional message when `-s` has no argument.

```sh
./rattlegram-audio send -s -- "Signed message" DL1ABC
./rattlegram-audio send -s -g DN1ABC "Signed and encrypted message" DL1ABC
./rattlegram-audio send -s -g DN1ABC -f document.pdf DL1ABC
```

Existing `signer_fingerprint` and `recipient_fingerprint` entries in
`[gpg]` still work as fallbacks. For receive-side signature requirements,
configure `[gpg_signers]` separately.

OpenPGP automatically enables fragmentation. Text can be compressed before
GPG processing. File transfers disable both zlib and GPG compression.
`--gpg-encrypt` and shared-key `--encrypt` are mutually exclusive when
sending. `listen --encrypt` still requires the shared-key mode.

The listener verifies announced signatures before printing or saving
anything and reports the verified fingerprint on stderr. To check signed
transfers for a call sign against a specific key, add its full fingerprint to
`~/.rattlegram-audio/config.ini`.

```ini
[gpg_signers]
DL1ABC = 0123456789ABCDEF0123456789ABCDEF01234567
```

The example fingerprint is a placeholder. Signed transfers for that call
sign must match the configured fingerprint. Unsigned transfers are accepted
and identified on stderr when a fingerprint is configured. A valid
signature without a pin identifies the key that signed the data.

## Longer messages

Use `--no-length-limit` to lift the single-packet limit.

```sh
./rattlegram-audio send --no-length-limit --compress "A long message passed as an argument" DL1ABC
```

The sender splits longer messages into numbered fragments. The receiver
reassembles them automatically and outputs the message once it is complete.
Compression and encryption remain independently configurable and apply to
the full message before fragmentation. Both sides need a version that
supports fragmentation.

Each radio packet still has a 170-byte limit. With this option, the program
handles up to 64 KiB of UTF-8 text per message. Missing fragments are never
requested again. When another fragment arrives, the receiver discards any
incomplete transfers that have made no progress for 30 seconds.

## Recover a missing packet

Add `-p` or `--parity` when sending a fragmented message or file. The sender adds
one XOR parity packet for the entire transfer. The listener can recover
one missing data packet if it receives the parity packet and all other
data packets. Single-packet transfers send only their data packet.

```sh
./rattlegram-audio send --parity -c -s DL1ABC "Signed channel test" DL1ABC
```

Six data packets plus one parity packet add roughly 17% to the packet
count. The listener still applies the usual integrity and signature
checks after recovery. The listener needs parity support to use the extra
packet. The data packets use the regular RG3 format.

## Short options

| Short | Long | Command |
| --- | --- | --- |
| `-c` | `--compress` | `send` |
| `-e` | `--encrypt` | `send`, `listen` |
| `-g` | `--gpg-encrypt [NAME_OR_FINGERPRINT]` | `send` |
| `-s` | `--gpg-sign [NAME_OR_FINGERPRINT]` | `send` |
| `-f` | `--file PATH` | `send` |
| `-n` | `--no-length-limit` | `send` |
| `-p` | `--parity` | `send` |
| `-k` | `--key-file` | `listen` |
| `-o` | `--output PATH` | `listen` |
| `-d` | `--receive-dir DIR` | `listen` |
| `-v` | `--verbose` | `listen` |
| `-h` | `--help` | All commands |

## RG3 wire format

New sends use RG3. The listener also accepts RG2 Base64 packets, legacy RG1
packets, and raw Rattlegram text. Older listeners need an upgrade to read RG3.

Each radio payload is the five ASCII bytes `~RG3:` followed by standard
basE91 with no padding or line breaks. The decoded bytes contain a 13-byte
header and up to 121 bytes of the transfer body. RG2 used 110 body bytes per
packet. Integers are unsigned and big-endian.

| Field | Size | Meaning |
| --- | ---: | --- |
| Flags | 1 byte | `0x01` compressed, `0x02` shared-key encrypted, `0x04` file, `0x08` GPG encrypted, `0x10` GPG signed. Other bits are reserved. |
| Transfer ID | 8 bytes | Random bytes shared by all fragments of a transfer. |
| Fragment index | 2 bytes | Zero-based index. |
| Fragment count | 2 bytes | Total fragments. One indicates a single-packet transfer. |

The sender applies optional zlib compression to text, processes any
OpenPGP options, and then protects the body before splitting it into
121-byte chunks. All chunks except the last have exactly 121 bytes.

For OpenPGP, the inner metadata is the literal `~RG3:` prefix, flags, and
transfer ID, followed by the payload. Signing prepends a four-byte
signature length and a binary detached signature over the inner metadata
and payload. GPG encryption wraps the result after signing. The receiver
checks that the inner metadata matches the radio header.

The outer metadata consists of the literal prefix, flags, transfer ID,
and fragment count in that order. The fragment index restores byte order.

- With shared-key encryption, the body is a 12-byte nonce followed by
  ChaCha20-Poly1305 ciphertext and a 16-byte tag. The outer metadata is
  authenticated as associated data.
- Otherwise, the body ends with a big-endian CRC-32 over the outer metadata
  and the body bytes preceding the CRC. This detects accidental corruption.

The receiver bounds reassembly, accepts out-of-order fragments, and
validates the full transfer before printing or saving it.

### Parity packet

The optional parity packet uses `~RG4:` followed by basE91. The header
contains the RG3 flags, transfer ID, final data chunk length in place
of the fragment index, and data fragment count. The body is the XOR of
all 121-byte data chunks, with the final chunk padded with zero bytes.
The receiver restores the original final chunk length before checking
the completed transfer.
