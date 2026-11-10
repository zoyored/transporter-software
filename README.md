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

A plain text message can contain up to 106 UTF-8 bytes in one packet. For
longer text, use `--no-length-limit`. The call sign must contain 1 to 9
ASCII letters or digits. The sender pipes PCM samples directly to `pacat`,
which plays them through the system's default audio output.

### Transfer a file

Start the receiver, then send the file.

```sh
# On the receiver
./rattlegram-audio listen

# On the sender
./rattlegram-audio send --file "document.pdf" DL1ABC
```

The listener detects files automatically and saves them byte for byte as
`received/rattlegram-<transfer-id>.bin`. Use `--receive-dir DIR` to choose
another directory or `--output PATH` to save one file under a specific name
and exit. Existing files are never overwritten. The listener reports the
sender and packet count when it receives the first file packet. It reports
the final path after verification and saving. File status and errors go to
stderr.

Reception quality also goes to stderr as the number of corrected payload
bits per decoded radio packet. A lower count means the decoder needed
fewer corrections. This count is separate from signal strength or SNR.

Files up to 1 MiB are supported. The sender automatically splits larger
payloads into multiple radio packets. Missing fragments are never requested
again. Large files can take many minutes to transmit. Compression is
unavailable for `--file`. To encrypt a file, use `send --encrypt rattlegram.key`
and supply the same key to the listener.

## Test locally without an audio device

```sh
./bin/send-pcm "Hello from Rattlegram!" DL1ABC | ./bin/listen-pcm
```

Both directions use 8 kHz mono, signed 16-bit PCM in native byte order and
QPSK (mapping 4). The sender uses a 1500 Hz carrier. The audio pipeline
runs without WAV files.

The encoder and decoder come from
[bastibl/rattlegram-cli](https://github.com/bastibl/rattlegram-cli).
The included license applies to that code.

## Compression and encryption

You can enable either option independently when sending. The receiver
automatically detects compressed packets.

```sh
./rattlegram-audio send --compress "Repeat repeat repeat" DL1ABC
./rattlegram-audio send --encrypt rattlegram.key "Confidential message" DL1ABC
./rattlegram-audio send --compress --encrypt rattlegram.key "Both options" DL1ABC
```

Encryption requires the Python package `cryptography`. Generate a random key
once and use the same key file on both devices. The file contains exactly
32 raw bytes.

```sh
(umask 077; set -C; openssl rand 32 > rattlegram.key)
./rattlegram-audio listen --encrypt rattlegram.key
```

The listener reads the encryption flag automatically. Use
`listen --key-file rattlegram.key` to receive both encrypted and unencrypted
traffic, or `listen --encrypt rattlegram.key` to require authentication.
Encrypted transfers need a matching key. The call sign and frame header
remain visible.

One RG2 packet holds up to 106 uncompressed plaintext bytes, or 82 with
encryption. With compression, capacity depends on how well the text
compresses. A payload that does not fit in one packet requires
`--no-length-limit`.

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

## RG2 wire format

New sends use RG2. The listener also accepts raw Rattlegram text and legacy
RG1 text, file, encryption, and fragmentation formats. Older listeners
need an upgrade to interpret RG2.

Each radio payload is the five ASCII bytes `~RG2:` followed by standard
padded Base64 with no line breaks. The decoded bytes contain a 13-byte
header followed by up to 110 bytes of the transfer body. Integers are
unsigned and big-endian.

| Field | Size | Meaning |
| --- | ---: | --- |
| Flags | 1 byte | `0x01` compressed, `0x02` encrypted, `0x04` file. Other bits are reserved. |
| Transfer ID | 8 bytes | Random bytes shared by all fragments of a transfer. |
| Fragment index | 2 bytes | Zero-based index. |
| Fragment count | 2 bytes | Total fragments. One indicates a single-packet transfer. |

The sender applies zlib compression to text when requested. Then it protects
the entire body before splitting it into 110-byte chunks. All chunks except
the last have exactly 110 bytes. Files cannot set the compressed flag.

The common metadata bytes are the literal `~RG2:` prefix, flags, transfer ID,
and big-endian fragment count in that order. The fragment index is used to
restore the original byte order.

- **Unencrypted** bodies contain the payload followed by a big-endian
  CRC-32 over the common metadata and payload. This detects accidental
  corruption.
- **Encrypted** bodies contain a random 12-byte nonce followed by
  ChaCha20-Poly1305 ciphertext and its 16-byte tag. The common metadata
  is authenticated as associated data.

The receiver bounds reassembly, checks consistent headers, and verifies
the full transfer before decompressing, printing, or saving it. Fragments
may arrive out of order. No partial files are published.
