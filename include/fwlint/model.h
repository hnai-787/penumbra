#ifndef FWLINT_MODEL_H
#define FWLINT_MODEL_H

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "fwlint/box.h"

namespace fwlint {

struct SourceLocation {
    std::string file;
    int line = 0;
};

struct Rule {
    std::string id;      // rule name/number as it appeared in the source
    int ordinal = 0;      // 1-based position in the evaluation order
    SourceLocation source;
    Action action = Action::Deny;
    Box box;
    std::string rawText;
    bool logging = false;  // Cisco `log` keyword / JSON "log": true
};

struct Policy {
    std::string format;       // "cisco-ios" | "canonical-json"
    std::string sourceFile;
    Action defaultAction = Action::Deny;
    std::vector<Rule> rules;
};

struct ParseError {
    int line = 0;
    std::string message;
};

struct ParseResult {
    bool ok = false;
    Policy policy;
    std::vector<ParseError> errors;
};

// --- Field-value parsing helpers shared by both parsers ---

// Parses "10.0.0.0/24", "10.0.0.5" (treated as /32), or "any" (0.0.0.0/0)
// into an address IntervalSet. Returns std::nullopt on malformed input.
std::optional<IntervalSet> parse_cidr_or_any(const std::string& text);

// Parses a Cisco wildcard-mask address expression already split into its
// base address and wildcard mask (e.g. base="10.0.0.0", wildcard="0.0.0.255").
// Only *contiguous* wildcard masks (i.e. ones equivalent to some netmask's
// complement) are supported -- this matches a standard CIDR range exactly.
// A discontiguous wildcard (e.g. "0.0.255.0") returns std::nullopt so the
// caller can fail closed with a clear parse error instead of silently
// mis-analyzing the rule (see README "Design decisions").
std::optional<IntervalSet> parse_wildcard_address(const std::string& base,
                                                    const std::string& wildcard);

// Parses a single dotted-quad into a uint32_t. Returns std::nullopt if the
// text is not a valid IPv4 address.
std::optional<uint32_t> parse_ipv4(const std::string& text);
std::string format_ipv4(uint32_t addr);

// Parses a port specification: "any", "443", or "1000-2000".
std::optional<IntervalSet> parse_port_spec(const std::string& text);

// Parses a protocol name ("tcp", "udp", "icmp", "ip"/"any") or a numeric
// protocol number into a protocol IntervalSet (usually a single value, or
// the full 0..255 range for "ip"/"any").
std::optional<IntervalSet> parse_protocol_spec(const std::string& text);
std::string protocol_to_string(uint8_t protocol);

std::string action_to_string(Action action);

}  // namespace fwlint

#endif
