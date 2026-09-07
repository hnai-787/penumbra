#include "fwlint/parser_json.h"

#include <nlohmann/json.hpp>

namespace fwlint {

using nlohmann::json;

namespace {

// Reads a field that may be a single string or an array of strings,
// unions the parsed IntervalSet of each entry, and reports a parse error
// through `ok` if any entry is malformed or the field has the wrong JSON
// type.
template <typename ParseFn>
bool read_field(const json& ruleJson, const char* fieldName, ParseFn parseOne,
                 IntervalSet& out, std::string& errorMessage) {
    if (!ruleJson.contains(fieldName)) {
        auto def = parseOne("any");
        if (!def) return false;
        out = *def;
        return true;
    }

    const json& field = ruleJson.at(fieldName);
    IntervalSet result;

    auto parseAndUnion = [&](const std::string& text) -> bool {
        auto parsed = parseOne(text);
        if (!parsed) {
            errorMessage = std::string("invalid value \"") + text + "\" for field \"" + fieldName + "\"";
            return false;
        }
        result = interval_union(result, *parsed);
        return true;
    };

    if (field.is_string()) {
        if (!parseAndUnion(field.get<std::string>())) return false;
    } else if (field.is_array()) {
        for (const json& entry : field) {
            if (!entry.is_string()) {
                errorMessage = std::string("field \"") + fieldName + "\" must contain strings";
                return false;
            }
            if (!parseAndUnion(entry.get<std::string>())) return false;
        }
    } else {
        errorMessage = std::string("field \"") + fieldName + "\" must be a string or array of strings";
        return false;
    }

    out = result;
    return true;
}

}  // namespace

ParseResult parse_canonical_json(const std::string& source, const std::string& fileName) {
    ParseResult result;
    result.policy.format = "canonical-json";
    result.policy.sourceFile = fileName;

    json root;
    try {
        root = json::parse(source);
    } catch (const json::parse_error& e) {
        result.errors.push_back({0, std::string("JSON syntax error: ") + e.what()});
        return result;
    }

    if (!root.is_object()) {
        result.errors.push_back({0, "root of canonical JSON policy must be an object"});
        return result;
    }

    if (root.contains("default_action")) {
        std::string action = root.at("default_action").get<std::string>();
        result.policy.defaultAction = (action == "allow") ? Action::Allow : Action::Deny;
    }

    if (!root.contains("rules") || !root.at("rules").is_array()) {
        result.errors.push_back({0, "canonical JSON policy must contain a \"rules\" array"});
        return result;
    }

    int ordinal = 0;
    for (const json& ruleJson : root.at("rules")) {
        ++ordinal;
        if (!ruleJson.is_object()) {
            result.errors.push_back({ordinal, "each rule must be a JSON object"});
            return result;
        }

        Rule rule;
        rule.ordinal = ordinal;
        rule.source.file = fileName;
        rule.source.line = ordinal;  // JSON doesn't preserve line numbers per-element; use position
        rule.id = ruleJson.contains("id") ? ruleJson.at("id").get<std::string>()
                                           : std::to_string(ordinal);

        if (!ruleJson.contains("action")) {
            result.errors.push_back({ordinal, "rule \"" + rule.id + "\" is missing \"action\""});
            return result;
        }
        std::string actionText = ruleJson.at("action").get<std::string>();
        if (actionText == "allow") {
            rule.action = Action::Allow;
        } else if (actionText == "deny") {
            rule.action = Action::Deny;
        } else {
            result.errors.push_back({ordinal, "rule \"" + rule.id + "\" has invalid action \"" + actionText + "\""});
            return result;
        }

        rule.logging = ruleJson.contains("log") && ruleJson.at("log").get<bool>();

        std::string errorMessage;
        bool ok = true;
        ok = ok && read_field(ruleJson, "protocol", parse_protocol_spec, rule.box.protocol, errorMessage);
        ok = ok && read_field(ruleJson, "source", parse_cidr_or_any, rule.box.srcAddr, errorMessage);
        ok = ok && read_field(ruleJson, "source_port", parse_port_spec, rule.box.srcPort, errorMessage);
        ok = ok && read_field(ruleJson, "destination", parse_cidr_or_any, rule.box.dstAddr, errorMessage);
        ok = ok && read_field(ruleJson, "destination_port", parse_port_spec, rule.box.dstPort, errorMessage);

        if (!ok) {
            result.errors.push_back({ordinal, "rule \"" + rule.id + "\": " + errorMessage});
            return result;
        }

        rule.rawText = ruleJson.dump();
        result.policy.rules.push_back(std::move(rule));
    }

    result.ok = true;
    return result;
}

}  // namespace fwlint
