# Rattlegram Audio für Linux

## Bauen

Benötigt werden Python 3.8 oder neuer, GNU Make, ein C++17-Compiler und `pacat` aus
`pulseaudio-utils`. Die Audiowiedergabe und -aufnahme laufen über PulseAudio
oder über die PulseAudio-Schnittstelle von PipeWire.

```sh
make
```

## Empfangen

```sh
./rattlegram-audio listen
```

Der Empfänger hört auf der Standardquelle des Systems und schreibt jede
erfolgreich decodierte Nachricht sofort mit abschließendem Zeilenumbruch
auf stdout. Mit Strg+C beenden. Für die Weiterverarbeitung oder Aufzeichnung
lässt sich stdout umleiten, etwa mit `./rattlegram-audio listen | tee empfang.txt`.

## Senden

```sh
./rattlegram-audio send "Hallo, Grüße!" DL1ABC
```

Die Nachricht darf 1 bis 170 UTF-8-Bytes lang sein. Das Rufzeichen besteht aus
1 bis 9 ASCII-Buchstaben oder Ziffern. Der Sender pipet die PCM-Samples direkt
an `pacat`, das sie über die Standardausgabe des Audiosystems abspielt.

## Lokaler Test ohne Audiogerät

```sh
./bin/send-pcm "Hallo, Grüße!" DL1ABC | ./bin/listen-pcm
```

Beide Richtungen arbeiten mit 8 kHz, Mono, vorzeichenbehaftetem 16-Bit-PCM in
nativer Byte-Reihenfolge und QPSK (Mapping 4). Der Sender verwendet 1500 Hz
Trägerfrequenz. Die Audio-Pipeline benötigt keine WAV-Dateien.

Der Encoder und der Decoder stammen aus
[bastibl/rattlegram-cli](https://github.com/bastibl/rattlegram-cli).
Die mitgelieferte Lizenz gilt für diesen übernommenen Code.

## Kompression und Verschlüsselung

Die Schalter lassen sich beim Senden unabhängig kombinieren. Der Empfänger
erkennt komprimierte Pakete automatisch.

```sh
./rattlegram-audio send --compress "Wiederholung Wiederholung" DL1ABC
./rattlegram-audio send --encrypt rattlegram.key "Vertraulicher Text" DL1ABC
./rattlegram-audio send --compress --encrypt rattlegram.key "Beide Optionen" DL1ABC
```

Für Verschlüsselung muss das Python-Paket `cryptography` installiert sein.
Einmal einen zufälligen Schlüssel erzeugen und dieselbe Datei auf beiden
Geräten verwenden. Die Datei enthält genau 32 rohe Bytes.

```sh
(umask 077; set -C; openssl rand 32 > rattlegram.key)
./rattlegram-audio listen --encrypt rattlegram.key
```

Mit `listen --encrypt` werden ausschließlich Pakete ausgegeben, die sich mit
dem angegebenen Schlüssel authentifizieren lassen. Ohne Schlüssel werden
Klartext und komprimierte Pakete empfangen. Meldungen zu verworfenen Paketen
gehen an stderr. Das Rufzeichen bleibt im Rattlegram-Funkkopf sichtbar.

Ohne Schalter werden gewöhnliche Rattlegram-Textpakete mit bis zu 170
UTF-8-Bytes gesendet. Das Präfix `~RG1` ist für erweiterte Pakete reserviert.
Mit Verschlüsselung allein passen bis zu 103 UTF-8-Bytes in ein Paket.
Mit Kompression hängt die Nutzlast von der Komprimierbarkeit ab. Passt das
Paket nach Verarbeitung nicht in 170 Funkbytes, bricht der Sender mit einer
Fehlermeldung ab. Für erweiterte Pakete brauchen beide Seiten dieses Programm.

Erweiterte Pakete bestehen aus `~RG1<Flags>:` und Base85-Daten. Flag 1 steht
für zlib, Flag 2 für ChaCha20-Poly1305 und Flag 3 für beides. Bei Flag 3 wird
vor der Verschlüsselung komprimiert. Verschlüsselte Base85-Daten enthalten
einen zufälligen 12-Byte-Nonce, den Ciphertext und den 16-Byte-Tag. Der
Paketkopf wird als Associated Data authentifiziert.

## Längere Nachrichten

Mit `--no-length-limit` entfällt die Beschränkung auf ein einzelnes Funkpaket.

```sh
./rattlegram-audio send --no-length-limit --compress "$(cat nachricht.txt)" DL1ABC
```

Der Sender teilt längere Nachrichten in nummerierte Fragmente auf. Der Empfänger
setzt sie automatisch zusammen und gibt die Nachricht erst vollständig aus.
Kompression und Verschlüsselung bleiben unabhängig schaltbar und werden vor
der Aufteilung auf die gesamte Nachricht angewendet. Beide Seiten benötigen
eine Programmversion mit Fragment-Unterstützung.

Jedes Funkpaket bleibt auf 170 Bytes begrenzt. Pro Nachricht verarbeitet das
Programm mit dieser Option bis zu 64 KiB UTF-8-Text. Fehlende Fragmente werden
nicht erneut angefordert. Der Empfänger verwirft unvollständige Übertragungen
nach 30 Sekunden ohne Fortschritt, sobald ein weiteres Fragment eintrifft.
