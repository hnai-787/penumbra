#include "fwlint/parser_cisco.h"

#include <algorithm>
#include <cctype>
#include <map>
#include <optional>
#include <sstream>

namespace fwlint {

namespace {

std::string to_lower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(),
                    [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

bool is_all_digits(const std::string& text) {
    if (text.empty()) return false;
    for (char c : text) {
        if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    }
    return true;
}

std::vector<std::string> tokenize(const std::string& line) {
    std::istringstream iss(line);
    std::vector<std::string> tokens;
    std::string tok;
    while (iss >> tok) tokens.push_back(tok);
    return tokens;
}

bool is_port_op(const std::string& tok) {
    return tok == "eq" || tok == "range" || tok == "gt" || tok == "lt" || tok == "neq";
}

std::optional<uint64_t> parse_port_name_or_number(const std::string& tok) {
    static const std::map<std::string, uint64_t> named = {
        {"telnet", 23}, {"www", 80}, {"http", 80}, {"https", 443}, {"ftp", 21},
        {"ssh", 22},    {"smtp", 25}, {"domain", 53}, {"dns", 53},
    };
    auto it = named.find(to_lower(tok));
    if (it != named.end()) return it->second;

    auto parsed = parse_port_spec(tok);
    if (!parsed || parsed->size() != 1 || parsed->front().lo != parsed->front().hi) {
        return std::nullopt;
    }
    return parsed->front().lo;
}

// Returns the port IntervalSet for the clause starting at tokens[idx], and
// advances idx past it. If no port operator is present, returns "any"
// (0..65535) without advancing idx.
std::optional<IntervalSet> parse_port_clause(const std::vector<std::string>& tokens, size_t& idx) {
    if (idx >= tokens.size() || !is_port_op(tokens[idx])) {
        return full_range(65535);
    }
    std::string op = tokens[idx++];

    if (op == "range") {
        if (idx + 1 >= tokens.size()) return std::nullopt;
        auto lo = parse_port_name_or_number(tokens[idx++]);
        auto hi = parse_port_name_or_number(tokens[idx++]);
        if (!lo || !hi || *lo > *hi) return std::nullopt;
        return IntervalSet{{*lo, *hi}};
    }

    if (idx >= tokens.size()) return std::nullopt;
    auto value = parse_port_name_or_number(tokens[idx++]);
    if (!value) return std::nullopt;
    uint64_t v = *value;

    if (op == "eq") return single_value(v);
    if (op == "gt") return (v >= 65535) ? IntervalSet{} : IntervalSet{{v + 1, 65535}};
    if (op == "lt") return (v == 0) ? IntervalSet{} : IntervalSet{{0, v - 1}};
    // neq
    IntervalSet result;
    if (v > 0) result = interval_union(result, IntervalSet{{0, v - 1}});
    if (v < 65535) result = interval_union(result, IntervalSet{{v + 1, 65535}});
    return result;
}

std::optional<IntervalSet> parse_address_clause(const std::vector<std::string>& tokens, size_t& idx) {
    if (idx >= tokens.size()) return std::nullopt;

    if (tokens[idx] == "any") {
        ++idx;
        return full_range(0xFFFFFFFFULL);
    }
    if (tokens[idx] == "host") {
        ++idx;
        if (idx >= tokens.size()) return std::nullopt;
        auto ip = parse_ipv4(tokens[idx++]);
        if (!ip) return std::nullopt;
        return single_value(*ip);
    }
    if (idx + 1 >= tokens.size()) return std::nullopt;
    std::string base = tokens[idx++];
    std::string wildcard = tokens[idx++];
    return parse_wildcard_address(base, wildcard);
}

}  // namespace

ParseResult parse_cisco_acl(const std::string& source, const std::string& fileName) {
    ParseResult result;
    result.policy.format = "cisco-ios";
    result.policy.sourceFile = fileName;

    std::istringstream stream(source);
    std::string rawLine;
    int lineNumber = 0;
    int ordinal = 0;
    std::string currentAclName;

    while (std::getline(stream, rawLine)) {
        ++lineNumber;
        std::string line = rawLine;
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();

        std::vector<std::string> tokens = tokenize(line);
        if (tokens.empty() || tokens[0] == "!") continue;

        if (tokens[0] == "ip" && tokens.size() >= 4 && tokens[1] == "access-list" &&
            tokens[2] == "extended") {
            currentAclName = tokens[3];
            continue;
        }

        size_t idx = 0;
        if (tokens[0] == "access-list") {
            if (tokens.size() < 3) {
                result.errors.push_back({lineNumber, "malformed access-list line: \"" + line + "\""});
                return result;
            }
            idx = 2;  // skip "access-list" <number>
        } else if (tokens[0] == "permit" || tokens[0] == "deny") {
            idx = 0;
        } else if (!currentAclName.empty() && is_all_digits(tokens[0])) {
            idx = 1;  // sequence-numbered line inside a named ACL block
        } else {
            result.errors.push_back(
                {lineNumber, "unsupported or unrecognized ACL syntax: \"" + line + "\""});
            return result;
        }

        if (idx >= tokens.size() || (tokens[idx] != "permit" && tokens[idx] != "deny")) {
            result.errors.push_back(
                {lineNumber, "expected \"permit\" or \"deny\" in: \"" + line + "\""});
            return result;
        }
        Action action = (tokens[idx] == "permit") ? Action::Allow : Action::Deny;
        ++idx;

        if (idx >= tokens.size()) {
            result.errors.push_back({lineNumber, "missing protocol in: \"" + line + "\""});
            return result;
        }
        std::string protocolToken = to_lower(tokens[idx]);
        auto protocolSet = parse_protocol_spec(protocolToken);
        if (!protocolSet) {
            result.errors.push_back({lineNumber, "unsupported protocol \"" + tokens[idx] + "\""});
            return result;
        }
        ++idx;
        bool isPortCapable = (protocolToken == "tcp" || protocolToken == "udp");

        auto srcAddr = parse_address_clause(tokens, idx);
        if (!srcAddr) {
            result.errors.push_back(
                {lineNumber,
                 "malformed or unsupported source address (discontiguous wildcard masks are "
                 "not supported) in: \"" +
                     line + "\""});
            return result;
        }

        IntervalSet srcPort = full_range(65535);
        if (isPortCapable) {
            auto ps = parse_port_clause(tokens, idx);
            if (!ps) {
                result.errors.push_back({lineNumber, "malformed source port clause in: \"" + line + "\""});
                return result;
            }
            srcPort = *ps;
        }

        auto dstAddr = parse_address_clause(tokens, idx);
        if (!dstAddr) {
            result.errors.push_back(
                {lineNumber,
                 "malformed or unsupported destination address (discontiguous wildcard masks "
                 "are not supported) in: \"" +
                     line + "\""});
            return result;
        }

        IntervalSet dstPort = full_range(65535);
        if (isPortCapable) {
            auto ps = parse_port_clause(tokens, idx);
            if (!ps) {
                result.errors.push_back(
                    {lineNumber, "malformed destination port clause in: \"" + line + "\""});
                return result;
            }
            dstPort = *ps;
        }

        bool logging = false;
        if (idx < tokens.size() && tokens[idx] == "log") {
            logging = true;
            ++idx;
        }

        if (idx != tokens.size()) {
            result.errors.push_back(
                {lineNumber,
                 "unsupported trailing syntax (e.g. established/precedence/tos/time-range) in: \"" +
                     line + "\""});
            return result;
        }

        ++ordinal;
        Rule rule;
        rule.id = std::to_string(ordinal);
        rule.ordinal = ordinal;
        rule.source.file = fileName;
        rule.source.line = lineNumber;
        rule.action = action;
        rule.logging = logging;
        rule.box.protocol = *protocolSet;
        rule.box.srcAddr = *srcAddr;
        rule.box.srcPort = srcPort;
        rule.box.dstAddr = *dstAddr;
        rule.box.dstPort = dstPort;
        rule.rawText = line;
        result.policy.rules.push_back(std::move(rule));
    }

    if (result.policy.rules.empty() && result.errors.empty()) {
        result.errors.push_back({0, "no ACL rules found in input"});
        return result;
    }
    if (!result.errors.empty()) {
        return result;
    }

    result.ok = true;
    return result;
}

}  // namespace fwlint
