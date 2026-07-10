#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace miniqr {
struct QrCode {
    int size = 0;
    std::vector<std::uint8_t> modules;
    bool get(int x, int y) const {
        return x >= 0 && y >= 0 && x < size && y < size && modules[static_cast<size_t>(y) * size + x] != 0;
    }
};

// Local byte-mode QR encoder. Uses QR Model 2, error correction level L.
bool EncodeUtf8(const std::string& text, QrCode& out, std::string& error);
}
