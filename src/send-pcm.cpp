#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string_view>
#include "encoder.hh"
#include "audio_config.hh"

int main(int argc, char **argv) {
    if (argc != 3 && argc != 9) {
        std::fprintf(stderr, "Usage: send-pcm MESSAGE CALLSIGN [RATE BITS CHANNEL MAPPING NOISE_SYMBOLS CARRIER_FREQUENCY]\n");
        return 2;
    }

    AudioConfig audio;
    int noise = 1, carrier = 1500;
    if (argc == 9 && (!audio.read(argv + 3) ||
                     !parse_int(argv[7], noise) || noise < 0 || noise > 32 ||
                     !parse_int(argv[8], carrier) || carrier < 900 || carrier > 3100)) {
        std::fprintf(stderr, "Invalid audio configuration.\n");
        return 2;
    }

    const std::string_view message(argv[1]);
    const std::string_view call(argv[2]);
    if (message.empty() || message.size() > 170) {
        std::fprintf(stderr, "Message must be 1 to 170 bytes long.\n");
        return 2;
    }
    if (call.empty() || call.size() > 9 ||
        call.find_first_not_of("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz") != call.npos) {
        std::fprintf(stderr, "Call sign must contain 1 to 9 ASCII letters or digits.\n");
        return 2;
    }

    std::array<uint8_t, 170> payload{};
    std::memcpy(payload.data(), message.data(), message.size());
    auto encoder = make_codec<Encoder, EncoderInterface>(audio, nullptr);
    encoder->configure(payload.data(), reinterpret_cast<const int8_t *>(argv[2]),
                       carrier, noise, false);

    const size_t symbol_frames = 1440 * audio.rate / 8000;
    PcmBuffer pcm(audio, symbol_frames);
    bool active;
    do {
        active = encoder->produce(pcm.data(), audio.channel);
        if (audio.channel == 3) {
            // Encoder::produce writes mono for mode 3. Duplicate it for the stereo mix.
            for (size_t i = symbol_frames; i-- > 0;)
                pcm.data()[2 * i] = pcm.data()[2 * i + 1] = pcm.data()[i];
        }
        if (!pcm.write()) {
            std::perror("Audio output");
            return 1;
        }
    } while (active);
    if (std::fflush(stdout) == EOF) {
        std::perror("Audio output");
        return 1;
    }
}
