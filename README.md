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
successfully decoded message to stdout immediately, followed by a newline.
Press Ctrl+C to stop. To process or save messages, redirect stdout or pipe it
into another command, such as `./rattlegram-audio listen | tee received.txt`.

## Send

```sh
./rattlegram-audio send "Hello from Rattlegram!" DL1ABC
```

A message can contain 1 to 170 UTF-8 bytes. The call sign must contain 1 to 9
ASCII letters or digits. The sender pipes PCM samples directly to `pacat`,
which plays them through the system's default audio output.

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

With `listen --encrypt`, the receiver outputs only packets that authenticate
with the supplied key. Without a key, it accepts plaintext and
compression-only packets. Diagnostics for discarded packets go to stderr.
The call sign remains visible in the Rattlegram packet header.

By default, the sender transmits standard Rattlegram text packets with up
to 170 UTF-8 bytes. The `~RG1` prefix is reserved for extended packets.
With encryption alone, a single packet holds up to 103 UTF-8 bytes.
With compression, the capacity depends on how well the text compresses.
If the encoded packet exceeds 170 bytes, the sender exits with an error.
Both sides need this program to use extended packets.

Extended packets consist of `~RG1<flags>:` followed by Base85 data. Flag 1
indicates zlib, flag 2 indicates ChaCha20-Poly1305, and flag 3 enables both.
With flag 3, compression runs before encryption. The encrypted Base85
data contains a random 12-byte nonce, the ciphertext, and a 16-byte tag.
The packet header is authenticated as associated data.

## Longer messages

Use `--no-length-limit` to lift the single-packet limit.

```sh
./rattlegram-audio send --no-length-limit --compress "$(cat message.txt)" DL1ABC
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
