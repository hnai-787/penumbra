#include <nlohmann/json.hpp>
#include <set>

#include "fwlint/report.h"

namespace fwlint {

using nlohmann::json;

namespace {

std::string sarif_level(Severity s) {
    switch (s) {
        case Severity::Critical:
        case Severity::High:
            return "error";
        case Severity::Medium:
            return "warning";
        case Severity::Low:
        case Severity::Info:
            return "note";
    }
    return "note";
}

json rule_descriptor(FindingType type) {
    switch (type) {
        case FindingType::Shadowing:
            return json{{"id", "shadowing"},
                        {"shortDescription", {{"text", "A later rule is unreachable because earlier rule(s) with a conflicting action already match its traffic."}}}};
        case FindingType::Redundancy:
            return json{{"id", "redundancy"},
                        {"shortDescription", {{"text", "A rule (or part of it) is decision-redundant: earlier same-action rule(s) already decide it."}}}};
        case FindingType::Correlation:
            return json{{"id", "correlation"},
                        {"shortDescription", {{"text", "Two rules partially overlap with conflicting actions; order-dependent behavior."}}}};
        case FindingType::Generalization:
            return json{{"id", "generalization"},
                        {"shortDescription", {{"text", "A broader rule follows a narrower, conflicting-action rule (often an intentional exception-then-default)."}}}};
    }
    return json{};
}

}  // namespace

std::string render_sarif(const Policy& policy, const AnalysisResult& result) {
    std::set<std::string> seenRuleTypes;
    json ruleDescriptors = json::array();
    for (const Finding& f : result.findings) {
        std::string typeName = finding_type_name(f.type);
        if (seenRuleTypes.insert(typeName).second) {
            ruleDescriptors.push_back(rule_descriptor(f.type));
        }
    }

    json results = json::array();
    for (const Finding& f : result.findings) {
        json message = f.message;
        json location = {
            {"physicalLocation",
             {{"artifactLocation", {{"uri", policy.sourceFile}}},
              {"region", {{"startLine", std::max(1, f.rule.line)}}}}}};

        results.push_back({
            {"ruleId", finding_type_name(f.type)},
            {"level", sarif_level(f.severity)},
            {"message", {{"text", f.message}}},
            {"locations", json::array({location})},
        });
    }

    json root;
    root["$schema"] =
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
    root["version"] = "2.1.0";
    root["runs"] = json::array({
        {{"tool", {{"driver", {{"name", "fwlint"}, {"version", "1.0.0"}, {"rules", ruleDescriptors}}}}},
         {"results", results}},
    });

    return root.dump(2);
}

}  // namespace fwlint
