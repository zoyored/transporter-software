"""Standard basE91 alphabet and binary encoding."""

ALPHABET = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"'
VALUES = {character: index for index, character in enumerate(ALPHABET)}


def encode(data):
    result = bytearray()
    bits = value = 0
    for byte in data:
        value |= byte << bits
        bits += 8
        if bits > 13:
            pair = value & 8191
            used = 13
            if pair <= 88:
                pair = value & 16383
                used = 14
            result.extend((ALPHABET[pair % 91], ALPHABET[pair // 91]))
            value >>= used
            bits -= used
    if bits:
        result.append(ALPHABET[value % 91])
        if bits > 7 or value > 90:
            result.append(ALPHABET[value // 91])
    return bytes(result)


def decode(data):
    result = bytearray()
    bits = value = 0
    first = None
    for character in data:
        digit = VALUES.get(character)
        if digit is None:
            raise ValueError("Invalid basE91 character.")
        if first is None:
            first = digit
            continue
        pair = first + 91 * digit
        value |= pair << bits
        bits += 13 if pair & 8191 > 88 else 14
        while bits >= 8:
            result.append(value & 255)
            value >>= 8
            bits -= 8
        first = None
    if first is not None:
        result.append((value | first << bits) & 255)
    return bytes(result)
