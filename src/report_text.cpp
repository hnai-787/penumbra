#include <algorithm>
#include <sstream>

#include "fwlint/report.h"

namespace fwlint {

namespace {

std::string witness_to_string(const Packet& w) {
    std::ostringstream oss;
    oss << protocol_to_string(w.protocol) << " " << format_ipv4(w.srcAddr) << ":" << w.srcPort
        << " -> " << format_ipv4(w.dstAddr) << ":" << w.dstPort;
    return oss.str();
}

int severity_rank(Severity s) {
    switch (s) {
        case Severity::Critical: return 0;
        case Severity::High: return 1;
        case Severity::Medium: return 2;
        case Severity::Low: return 3;
        case Severity::Info: return 4;
    }
    return 5;
}

std::string severity_upper(Severity s) {
    std::string name = severity_name(s);
    for (char& c : name) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return name;
}

}  // namespace

std::string render_text(const Policy& policy, const AnalysisResult& result) {
    std::ostringstream out;

    out << "Firewall Ruleset Analysis\n";
    out << "=========================\n";
    out << "Input:       " << policy.sourceFile << "\n";
    out << "Format:      " << policy.format << "\n";
    out << "Rules:       " << result.ruleCount << "\n";
    out << "Status:      " << result.findings.size() << " findings\n";
    if (!result.complete) {
        out << "WARNING:     analysis is INCOMPLETE -- see errors above; results may be missing\n";
    }
    out << "CRITICAL  " << result.countBySeverity(Severity::Critical) << "\n";
    out << "HIGH      " << result.countBySeverity(Severity::High) << "\n";
    out << "MEDIUM    " << result.countBySeverity(Severity::Medium) << "\n";
    out << "LOW       " << result.countBySeverity(Severity::Low) << "\n";
    out << "INFO      " << result.countBySeverity(Severity::Info) << "\n";

    std::vector<Finding> sorted = result.findings;
    std::stable_sort(sorted.begin(), sorted.end(), [](const Finding& a, const Finding& b) {
        if (severity_rank(a.severity) != severity_rank(b.severity)) {
            return severity_rank(a.severity) < severity_rank(b.severity);
        }
        return a.rule.ordinal < b.rule.ordinal;
    });

    for (const Finding& f : sorted) {
        out << "\n[" << f.code << "] " << severity_upper(f.severity) << " -- "
            << finding_type_name(f.type) << "\n";
        out << "Rule " << f.rule.id << " (ordinal " << f.rule.ordinal << "), line "
            << f.rule.line << "\n";
        out << "    " << action_to_string(f.ruleAction) << " ... (" << f.relation << " relation)\n";

        if (!f.blockers.empty()) {
            out << (f.collective ? "Blocking rules (combined effect):\n" : "Blocking rule:\n");
            for (const FindingRuleRef& b : f.blockers) {
                out << "    " << b.id << " (line " << b.line << ")\n";
            }
        }

        out << f.message << "\n";

        if (f.hasWitness) {
            out << "Witness:\n";
            out << "    " << witness_to_string(f.witness) << "\n";
        }

        out << "Recommendation:\n";
        out << "    " << f.recommendation << "\n";
    }

    if (result.findings.empty()) {
        out << "\nNo anomalies found.\n";
    }

    return out.str();
}

}  // namespace fwlint
