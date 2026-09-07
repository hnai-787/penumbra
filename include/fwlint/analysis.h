#ifndef FWLINT_ANALYSIS_H
#define FWLINT_ANALYSIS_H

#include <string>
#include <vector>

#include "fwlint/model.h"

namespace fwlint {

enum class FindingType { Shadowing, Redundancy, Correlation, Generalization };
enum class Severity { Critical, High, Medium, Low, Info };

std::string finding_type_name(FindingType type);
std::string severity_name(Severity severity);

struct FindingRuleRef {
    std::string id;
    int ordinal = 0;
    int line = 0;
};

struct Finding {
    std::string code;             // "FWA001", ...
    FindingType type;
    std::string taxonomyLevel;    // "error" | "warning" (Al-Shaer/Hamed classification)
    Severity severity;            // product-level risk, informed by rule actions

    FindingRuleRef rule;
    Action ruleAction = Action::Deny;

    std::vector<FindingRuleRef> blockers;  // earlier rule(s) that cause this finding
    bool collective = false;               // true if no single blocker explains it alone

    std::string relation;   // "subset" | "superset" | "overlap"
    std::string message;
    std::string recommendation;

    bool hasWitness = false;
    Packet witness{};
};

struct AnalysisResult {
    bool complete = true;   // false if analysis had to bail out (see model.h ParseError)
    int ruleCount = 0;
    std::vector<Finding> findings;

    int countBySeverity(Severity s) const;
};

// Runs the four canonical Al-Shaer/Hamed anomaly checks (shadowing,
// redundancy, correlation, generalization) plus whole-policy collective
// shadowing (Hu/Ahn/Kulkarni-style rule-space segmentation: a later rule
// can be fully unreachable because of the *combined* effect of several
// earlier rules, not just one). See README "Design decisions" for the
// algorithm and its citations.
AnalysisResult analyze_policy(const Policy& policy);

}  // namespace fwlint

#endif
