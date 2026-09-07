#include "fwlint/model.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <sstream>

namespace fwlint {

namespace {

std::string trim(const std::string& text) {
    size_t start = 0;
    while (start < text.size() && std::isspace(static_cast<unsigned char>(text[start]))) {
        ++start;
    }
    size_t end = text.size();
    while (end > start && std::isspace(static_cast<unsigned char>(text[end - 1]))) {
        --end;
    }
    return text.substr(start, end - start);
}

std::string to_lower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(),
                    [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

bool parse_uint(const std::string& text, uint64_t& out) {
    if (text.empty()) return false;
    for (char c : text) {
        if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    }
    errno = 0;
    char* end = nullptr;
    unsigned long long value = std::strtoull(text.c_str(), &end, 10);
    if (errno != 0 || end == text.c_str() || *end != '\0') return false;
    out = value;
    return true;
}

}  // namespace

std::optional<uint32_t> parse_ipv4(const std::string& text) {
    std::stringstream ss(text);
    std::string part;
    std::array<uint32_t, 4> octets{};
    int index = 0;

    while (std::getline(ss, part, '.')) {
        if (index >= 4) return std::nullopt;
        uint64_t value = 0;
        if (!parse_uint(part, value) || value > 255) return std::nullopt;
        octets[index++] = static_cast<uint32_t>(value);
    }
    if (index != 4) return std::nullopt;

    return (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
}

std::string format_ipv4(uint32_t addr) {
    std::ostringstream oss;
    oss << ((addr >> 24) & 0xFF) << '.' << ((addr >> 16) & 0xFF) << '.'
        << ((addr >> 8) & 0xFF) << '.' << (addr & 0xFF);
    return oss.str();
}

std::optional<IntervalSet> parse_cidr_or_any(const std::string& rawText) {
    std::string text = trim(rawText);
    if (to_lower(text) == "any") {
        return full_range(0xFFFFFFFFULL);
    }

    size_t slash = text.find('/');
    if (slash == std::string::npos) {
        auto ip = parse_ipv4(text);
        if (!ip) return std::nullopt;
        return single_value(*ip);
    }

    std::string addrText = text.substr(0, slash);
    std::string prefixText = text.substr(slash + 1);

    auto addr = parse_ipv4(addrText);
    if (!addr) return std::nullopt;

    uint64_t prefixLen = 0;
    if (!parse_uint(prefixText, prefixLen) || prefixLen > 32) return std::nullopt;

    uint32_t maskBits = (prefixLen == 0) ? 0 : (0xFFFFFFFFu << (32 - prefixLen));
    uint32_t network = *addr & maskBits;
    uint32_t hostBits = (prefixLen == 32) ? 0 : (0xFFFFFFFFu >> prefixLen);
    uint32_t broadcast = network | hostBits;

    return IntervalSet{{network, broadcast}};
}

std::optional<IntervalSet> parse_wildcard_address(const std::string& baseText,
                                                    const std::string& wildcardText) {
    auto base = parse_ipv4(baseText);
    auto wildcard = parse_ipv4(wildcardText);
    if (!base || !wildcard) return std::nullopt;

    if (*wildcard == 0) {
        return single_value(*base);
    }

    // A Cisco wildcard is "supported" here only if it is a contiguous
    // trailing run of 1-bits, i.e. wildcard == (2^k - 1) for some k in
    // 1..32. That is exactly the set of wildcards equivalent to a netmask
    // complement (0.0.0.255, 0.0.255.255, ...). Anything else (e.g.
    // 0.0.255.0, a "hole" pattern) is rejected -- see model.h.
    uint32_t w = *wildcard;
    bool contiguousFromLsb = ((w + 1) & w) == 0;  // true iff w = 2^k - 1
    if (!contiguousFromLsb) {
        return std::nullopt;
    }

    uint32_t network = *base & ~w;
    uint32_t broadcast = network | w;
    return IntervalSet{{network, broadcast}};
}

std::optional<IntervalSet> parse_port_spec(const std::string& rawText) {
    std::string text = trim(rawText);
    if (text.empty() || to_lower(text) == "any") {
        return full_range(65535);
    }

    size_t dash = text.find('-');
    if (dash != std::string::npos) {
        uint64_t lo = 0, hi = 0;
        if (!parse_uint(trim(text.substr(0, dash)), lo)) return std::nullopt;
        if (!parse_uint(trim(text.substr(dash + 1)), hi)) return std::nullopt;
        if (lo > 65535 || hi > 65535 || lo > hi) return std::nullopt;
        return IntervalSet{{lo, hi}};
    }

    uint64_t value = 0;
    if (!parse_uint(text, value) || value > 65535) return std::nullopt;
    return single_value(value);
}

std::optional<IntervalSet> parse_protocol_spec(const std::string& rawText) {
    std::string text = to_lower(trim(rawText));
    if (text.empty() || text == "any" || text == "ip") {
        return full_range(255);
    }
    if (text == "tcp") return single_value(6);
    if (text == "udp") return single_value(17);
    if (text == "icmp") return single_value(1);
    if (text == "gre") return single_value(47);
    if (text == "esp") return single_value(50);
    if (text == "ah") return single_value(51);
    if (text == "eigrp") return single_value(88);
    if (text == "ospf") return single_value(89);

    uint64_t value = 0;
    if (parse_uint(text, value) && value <= 255) {
        return single_value(value);
    }
    return std::nullopt;
}

std::string protocol_to_string(uint8_t protocol) {
    switch (protocol) {
        case 1: return "icmp";
        case 6: return "tcp";
        case 17: return "udp";
        case 47: return "gre";
        case 50: return "esp";
        case 51: return "ah";
        case 88: return "eigrp";
        case 89: return "ospf";
        default: return std::to_string(static_cast<int>(protocol));
    }
}

std::string action_to_string(Action action) {
    return action == Action::Allow ? "allow" : "deny";
}

}  // namespace fwlint
