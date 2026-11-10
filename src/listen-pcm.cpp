#include <array>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string_view>
#include "decoder.hh"

int main(int argc, char **argv) {
    const std::string_view option = argc == 2 ? argv[1] : "";
    const bool metadata = option == "--metadata";
    const bool frames = metadata || option == "--frames";
    if (argc != 1 && !frames) {
        std::fprintf(stderr, "Aufruf: listen-pcm [--frames | --metadata]\n");
        return 2;
    }
    auto decoder = std::make_unique<Decoder<8000, 4>>();
    std::array<int16_t, 160> samples; // 20 ms Mono-PCM bei 8 kHz
    std::array<uint8_t, 10> callsign{};
    for (;;) {
        const auto count = std::fread(samples.data(), sizeof(samples[0]), samples.size(), stdin);
        if (count && decoder->feed(samples.data(), count, 0)) {
            const int status = decoder->process();
            if (metadata && status == STATUS_SYNC) {
                float cfo;
                int32_t mode;
                decoder->staged(&cfo, &mode, callsign.data());
            }
            if (status == STATUS_DONE) {
                std::array<uint8_t, 171> payload{};
                const int corrections = decoder->fetch(payload.data());
                const char *sender = reinterpret_cast<const char *>(callsign.data());
                if (corrections >= 0) {
                    const char *message = reinterpret_cast<const char *>(payload.data());
                    if ((metadata && std::fprintf(stdout, "%s\t%d\t", sender, corrections) < 0) ||
                        std::fputs(message, stdout) == EOF ||
                        std::fputc(frames ? '\0' : '\n', stdout) == EOF ||
                        std::fflush(stdout) == EOF) {
                        std::perror("Textausgabe");
                        return 1;
                    }
                } else if (metadata) {
                    std::fprintf(stderr, "Funkpaket von %s konnte nicht decodiert werden.\n", sender);
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
