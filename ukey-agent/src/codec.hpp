#pragma once

#include <cctype>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

inline std::string json_escape(const std::string &value) {
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(value.size() + 16);
    for (unsigned char ch : value) {
        switch (ch) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (ch < 0x20) {
                out += "\\u00";
                out += hex[ch >> 4];
                out += hex[ch & 0x0f];
            } else {
                out.push_back(static_cast<char>(ch));
            }
        }
    }
    return out;
}

inline bool json_string(const std::string &json, const std::string &key,
                        std::string &out) {
    const std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return false;
    pos = json.find(':', pos + needle.size());
    if (pos == std::string::npos) return false;
    do { ++pos; } while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos])));
    if (pos >= json.size() || json[pos] != '"') return false;
    ++pos;
    out.clear();
    while (pos < json.size()) {
        unsigned char ch = static_cast<unsigned char>(json[pos++]);
        if (ch == '"') return true;
        if (ch != '\\') {
            if (ch < 0x20) return false;
            out.push_back(static_cast<char>(ch));
            continue;
        }
        if (pos >= json.size()) return false;
        char esc = json[pos++];
        switch (esc) {
        case '"': out.push_back('"'); break;
        case '\\': out.push_back('\\'); break;
        case '/': out.push_back('/'); break;
        case 'b': out.push_back('\b'); break;
        case 'f': out.push_back('\f'); break;
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        default: return false;
        }
    }
    return false;
}

inline std::string base64url_encode(const uint8_t *data, size_t size) {
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    out.reserve((size * 4 + 2) / 3);
    for (size_t i = 0; i < size; i += 3) {
        uint32_t value = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < size) value |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < size) value |= data[i + 2];
        out.push_back(table[(value >> 18) & 63]);
        out.push_back(table[(value >> 12) & 63]);
        if (i + 1 < size) out.push_back(table[(value >> 6) & 63]);
        if (i + 2 < size) out.push_back(table[value & 63]);
    }
    return out;
}

inline std::string base64url_encode(const std::vector<uint8_t> &data) {
    return base64url_encode(data.data(), data.size());
}

inline std::string base64_encode(const uint8_t *data, size_t size) {
    std::string out = base64url_encode(data, size);
    for (char &ch : out) {
        if (ch == '-') ch = '+';
        else if (ch == '_') ch = '/';
    }
    while ((out.size() % 4) != 0) out.push_back('=');
    return out;
}

inline std::vector<uint8_t> base64url_decode(const std::string &text) {
    int reverse[256];
    for (int &item : reverse) item = -1;
    const std::string table =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for (int i = 0; i < 64; ++i) reverse[static_cast<unsigned char>(table[i])] = i;
    reverse[static_cast<unsigned char>('+')] = 62;
    reverse[static_cast<unsigned char>('/')] = 63;

    std::vector<uint8_t> out;
    uint32_t value = 0;
    int bits = -8;
    for (unsigned char ch : text) {
        if (ch == '=') break;
        if (std::isspace(ch)) continue;
        int digit = reverse[ch];
        if (digit < 0) throw std::runtime_error("invalid base64url");
        value = (value << 6) | static_cast<uint32_t>(digit);
        bits += 6;
        if (bits >= 0) {
            out.push_back(static_cast<uint8_t>((value >> bits) & 0xff));
            bits -= 8;
        }
    }
    return out;
}

inline void secure_clear(std::string &value) {
    volatile char *p = value.empty() ? nullptr : &value[0];
    for (size_t i = 0; i < value.size(); ++i) p[i] = 0;
    value.clear();
}
