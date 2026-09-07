#ifndef FWLINT_SIMULATE_H
#define FWLINT_SIMULATE_H

#include "fwlint/model.h"

namespace fwlint {

struct SimulationResult {
    Action decision = Action::Deny;
    bool matchedRule = false;
    std::string matchedRuleId;
    int matchedRuleOrdinal = 0;
    int matchedRuleLine = 0;
    int rulesEvaluated = 0;
};

// Evaluates a single concrete packet against the policy using the same
// first-match-wins semantics the parser and analyzer both assume, using
// the exact same compiled Box per rule that analyze_policy() uses -- so
// simulation and analysis can never disagree about what a rule matches.
SimulationResult simulate_packet(const Policy& policy, const Packet& packet);

}  // namespace fwlint

#endif
