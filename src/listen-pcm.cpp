#include <array>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string_view>
#include "decoder.hh"
#include "audio_config.hh"

int main(int argc, char **argv) {
    const std::string_view option = argc > 1 ? argv[1] : "";
    const bool metadata = option == "--metadata";
    const bool frames = metadata || option == "--frames";
    AudioConfig audio;
    if (argc != 1 && (!frames || (argc != 2 && (argc != 6 || !audio.read(argv + 2))))) {
        std::fprintf(stderr, "Usage: listen-pcm [--frames | --metadata [RATE BITS CHANNEL MAPPING]]\n");
        return 2;
    }
    auto decoder = make_codec<Decoder, DecoderInterface>(audio);
    const size_t block_frames = audio.rate / 50; // 20 ms
    PcmBuffer pcm(audio, block_frames);
    std::array<uint8_t, 10> callsign{};
    for (;;) {
        const auto count = pcm.read();
        if (count && decoder->feed(pcm.data(), count, audio.channel)) {
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
                        std::perror("Text output");
                        return 1;
                    }
                } else if (metadata) {
                    std::fprintf(stderr, "Could not decode packet from %s.\n", sender);
                }
            }
        }
        if (count < block_frames) {
            if (std::ferror(stdin)) {
                std::perror("Audio input");
                return 1;
            }
            return 0;
        }
    }
}
