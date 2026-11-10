#include <array>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string_view>
#include "decoder.hh"

int main(int argc, char **argv) {
    const bool frames = argc == 2 && std::string_view(argv[1]) == "--frames";
    if (argc != 1 && !frames) {
        std::fprintf(stderr, "Aufruf: listen-pcm [--frames]\n");
        return 2;
    }
    auto decoder = std::make_unique<Decoder<8000, 4>>();
    std::array<int16_t, 160> samples; // 20 ms Mono-PCM bei 8 kHz
    for (;;) {
        const auto count = std::fread(samples.data(), sizeof(samples[0]), samples.size(), stdin);
        if (count && decoder->feed(samples.data(), count, 0) &&
            decoder->process() == STATUS_DONE) {
            std::array<uint8_t, 171> payload{};
            if (decoder->fetch(payload.data()) >= 0) {
                const char *message = reinterpret_cast<const char *>(payload.data());
                if (std::fputs(message, stdout) == EOF ||
                    std::fputc(frames ? '\0' : '\n', stdout) == EOF ||
                    std::fflush(stdout) == EOF) {
                    std::perror("Textausgabe");
                    return 1;
                }
            }
        }
        if (count < samples.size()) {
            if (std::ferror(stdin)) {
                std::perror("Audioeingabe");
                return 1;
            }
            return 0;
        }
    }
}
