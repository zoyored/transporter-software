#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string_view>
#include "encoder.hh"

int main(int argc, char **argv) {
    if (argc != 3) {
        std::fprintf(stderr, "Aufruf: rattlegram-audio send NACHRICHT RUFZEICHEN\n");
        return 2;
    }

    const std::string_view message(argv[1]);
    const std::string_view call(argv[2]);
    if (message.empty() || message.size() > 170) {
        std::fprintf(stderr, "Die Nachricht muss 1 bis 170 Bytes lang sein.\n");
        return 2;
    }
    if (call.empty() || call.size() > 9 ||
        call.find_first_not_of("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz") != call.npos) {
        std::fprintf(stderr, "Das Rufzeichen braucht 1 bis 9 ASCII-Buchstaben oder Ziffern.\n");
        return 2;
    }

    std::array<uint8_t, 170> payload{};
    std::memcpy(payload.data(), message.data(), message.size());
    auto encoder = std::make_unique<Encoder<8000, 4>>(nullptr);
    encoder->configure(payload.data(), reinterpret_cast<const int8_t *>(argv[2]),
                       1500, 1, false);

    // 1280 Samples pro Symbol plus 160 Samples Schutzintervall bei 8 kHz.
    std::array<int16_t, 1440> samples;
    bool active;
    do {
        active = encoder->produce(samples.data(), 0);
        if (std::fwrite(samples.data(), sizeof(samples[0]), samples.size(), stdout) != samples.size()) {
            std::perror("Audioausgabe");
            return 1;
        }
    } while (active);
    if (std::fflush(stdout) == EOF) {
        std::perror("Audioausgabe");
        return 1;
    }
}
