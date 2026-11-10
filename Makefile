CXXFLAGS ?= -O3
HEADERS := $(wildcard src/*.hh)

.PHONY: all clean
all: bin/send-pcm bin/listen-pcm

bin/%: src/%.cpp $(HEADERS)
	mkdir -p bin
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -std=c++17 -march=native $< $(LDFLAGS) -o $@

clean:
	rm -f bin/send-pcm bin/listen-pcm
