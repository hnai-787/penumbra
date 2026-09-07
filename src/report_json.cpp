#include <nlohmann/json.hpp>

#include "fwlint/report.h"

namespace fwlint {

using nlohmann::json;

namespace {

json witness_json(const Packet& w) {
    return json{
        {"protocol", protocol_to_string(w.protocol)},
        {"src_ip", format_ipv4(w.srcAddr)},
        {"src_port", w.srcPort},
        {"dst_ip", format_ipv4(w.dstAddr)},
        {"dst_port", w.dstPort},
    };
}

json rule_ref_json(const FindingRuleRef& r) {
    return json{{"id", r.id}, {"ordinal", r.ordinal}, {"line", r.line}};
}

json finding_json(const Finding& f) {
    json j;
    j["id"] = f.code;
    j["type"] = finding_type_name(f.type);
    j["taxonomy_level"] = f.taxonomyLevel;
    j["severity"] = severity_name(f.severity);
    j["rule"] = rule_ref_json(f.rule);
    j["rule"]["action"] = action_to_string(f.ruleAction);
    j["blockers"] = json::array();
    for (const FindingRuleRef& b : f.blockers) j["blockers"].push_back(rule_ref_json(b));
    j["collective"] = f.collective;
    j["relation"] = f.relation;
    j["message"] = f.message;
    j["recommendation"] = f.recommendation;
    if (f.hasWitness) j["witness"] = witness_json(f.witness);
    return j;
}

}  // namespace

std::string render_json(const Policy& policy, const AnalysisResult& result) {
    json root;
    root["schema_version"] = "1.0";
    root["tool"] = {{"name", "fwlint"}, {"version", "1.0.0"}};
    root["input"] = {{"format", policy.format}, {"file", policy.sourceFile}};
    root["analysis"] = {{"complete", result.complete}, {"rules", result.ruleCount}};
    root["summary"] = {
        {"critical", result.countBySeverity(Severity::Critical)},
        {"high", result.countBySeverity(Severity::High)},
        {"medium", result.countBySeverity(Severity::Medium)},
        {"low", result.countBySeverity(Severity::Low)},
        {"info", result.countBySeverity(Severity::Info)},
    };
    root["findings"] = json::array();
    for (const Finding& f : result.findings) root["findings"].push_back(finding_json(f));

    return root.dump(2);
}

}  // namespace fwlint
