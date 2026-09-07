#include "fwlint/simulate.h"

namespace fwlint {

SimulationResult simulate_packet(const Policy& policy, const Packet& packet) {
    SimulationResult result;
    result.decision = policy.defaultAction;

    for (const Rule& rule : policy.rules) {
        ++result.rulesEvaluated;
        if (box_matches(rule.box, packet)) {
            result.decision = rule.action;
            result.matchedRule = true;
            result.matchedRuleId = rule.id;
            result.matchedRuleOrdinal = rule.ordinal;
            result.matchedRuleLine = rule.source.line;
            return result;
        }
    }

    return result;
}

}  // namespace fwlint
