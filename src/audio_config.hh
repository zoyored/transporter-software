#pragma once

#include <charconv>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <utility>
#include <vector>

inline bool parse_int(const char *value, int &result) {
    const char *end = value + std::strlen(value);
    const auto parsed = std::from_chars(value, end, result);
    return parsed.ec == std::errc{} && parsed.ptr == end;
}

struct AudioConfig {
    int rate = 8000;
    int bits = 16;
    int channel = 0;
    int mapping = 4;

    bool read(char **args) {
        return parse_int(args[0], rate) && (rate == 8000 || rate == 48000) &&
               parse_int(args[1], bits) && (bits == 8 || bits == 16 || bits == 24 || bits == 32) &&
               parse_int(args[2], channel) && channel >= 0 && channel <= 4 &&
               parse_int(args[3], mapping) && (mapping == 2 || mapping == 4 || mapping == 8 || mapping == 16);
    }

    int channels() const { return channel == 0 ? 1 : 2; }
};

template <template <int, int> class Codec, class Interface, int Rate, class... Args>
std::unique_ptr<Interface> make_mapping(int mapping, Args &&...args) {
    switch (mapping) {
    case 2: return std::make_unique<Codec<Rate, 2>>(std::forward<Args>(args)...);
    case 4: return std::make_unique<Codec<Rate, 4>>(std::forward<Args>(args)...);
    case 8: return std::make_unique<Codec<Rate, 8>>(std::forward<Args>(args)...);
    case 16: return std::make_unique<Codec<Rate, 16>>(std::forward<Args>(args)...);
    }
    return nullptr;
}

template <template <int, int> class Codec, class Interface, class... Args>
std::unique_ptr<Interface> make_codec(const AudioConfig &audio, Args &&...args) {
    if (audio.rate == 8000)
        return make_mapping<Codec, Interface, 8000>(audio.mapping, std::forward<Args>(args)...);
    return make_mapping<Codec, Interface, 48000>(audio.mapping, std::forward<Args>(args)...);
}

class PcmBuffer {
public:
    PcmBuffer(const AudioConfig &audio, size_t frames)
        : channels(audio.channels()), bytes_per_sample(audio.bits / 8),
          bytes(frames * channels * bytes_per_sample), samples(frames * channels) {}

    size_t read() {
        const size_t frames = std::fread(bytes.data(), channels * bytes_per_sample,
                                         samples.size() / channels, stdin);
        for (size_t i = 0; i < frames * channels; ++i) {
            const size_t end = (i + 1) * bytes_per_sample;
            if (bytes_per_sample == 1) {
                samples[i] = (static_cast<int>(bytes[i]) - 128) * 256;
            } else {
                const int value = (static_cast<int>(bytes[end - 1]) << 8) | bytes[end - 2];
                samples[i] = value >= 32768 ? value - 65536 : value;
            }
        }
        return frames;
    }

    bool write() {
        for (size_t i = 0; i < samples.size(); ++i) {
            const auto value = static_cast<uint16_t>(samples[i]);
            const size_t end = (i + 1) * bytes_per_sample;
            if (bytes_per_sample == 1) {
                bytes[i] = (value >> 8) ^ 0x80;
            } else {
                bytes[end - 1] = value >> 8;
                bytes[end - 2] = value & 0xff;
            }
        }
        return std::fwrite(bytes.data(), 1, bytes.size(), stdout) == bytes.size();
    }

    int16_t *data() { return samples.data(); }

private:
    size_t channels;
    size_t bytes_per_sample;
    std::vector<uint8_t> bytes;
    std::vector<int16_t> samples;
};
