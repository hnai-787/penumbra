#include "fwlint/analysis.h"

#include <cstdio>

namespace fwlint {

std::string finding_type_name(FindingType type) {
    switch (type) {
        case FindingType::Shadowing: return "shadowing";
        case FindingType::Redundancy: return "redundancy";
        case FindingType::Correlation: return "correlation";
        case FindingType::Generalization: return "generalization";
    }
    return "unknown";
}

std::string severity_name(Severity severity) {
    switch (severity) {
        case Severity::Critical: return "critical";
        case Severity::High: return "high";
        case Severity::Medium: return "medium";
        case Severity::Low: return "low";
        case Severity::Info: return "info";
    }
    return "unknown";
}

int AnalysisResult::countBySeverity(Severity s) const {
    int count = 0;
    for (const Finding& f : findings) {
        if (f.severity == s) ++count;
    }
    return count;
}

namespace {

FindingRuleRef ref_of(const Rule& r) {
    return FindingRuleRef{r.id, r.ordinal, r.source.line};
}

// True if some single rule among `candidateOrdinals` fully covers `region`
// on its own -- used to decide whether a finding is genuinely "collective"
// (needs several earlier rules acting together) or just a plain pairwise
// case where one earlier rule happens to be reported alongside others that
// only partially overlap.
bool single_rule_covers(const PacketSet& region, const Policy& policy,
                         const std::vector<int>& candidateOrdinals) {
    for (int ordinal : candidateOrdinals) {
        const Box* box = nullptr;
        for (const Rule& r : policy.rules) {
            if (r.ordinal == ordinal) {
                box = &r.box;
                break;
            }
        }
        if (box && ps_empty(ps_subtract_box(region, *box))) {
            return true;
        }
    }
    return false;
}

std::vector<FindingRuleRef> find_blockers(const PacketSet& deadRegion, const Policy& policy,
                                           size_t upToExclusive, Action matchAction,
                                           std::vector<int>& outOrdinals) {
    std::vector<FindingRuleRef> blockers;
    for (size_t j = 0; j < upToExclusive; ++j) {
        const Rule& earlier = policy.rules[j];
        if (earlier.action != matchAction) continue;
        PacketSet overlap = ps_intersect_set(deadRegion, PacketSet{earlier.box});
        if (!ps_empty(overlap)) {
            blockers.push_back(ref_of(earlier));
            outOrdinals.push_back(earlier.ordinal);
        }
    }
    return blockers;
}

}  // namespace

AnalysisResult analyze_policy(const Policy& policy) {
    AnalysisResult result;
    result.ruleCount = static_cast<int>(policy.rules.size());

    PacketSet covered;         // union of every rule's box seen so far (any action)
    PacketSet effectiveAllow;  // true first-match region decided ALLOW so far
    PacketSet effectiveDeny;   // true first-match region decided DENY so far
    std::vector<bool> ruleIsDead(policy.rules.size(), false);  // fully shadowed/redundant rules

    int findingCounter = 1;
    auto nextCode = [&]() {
        char buf[16];
        std::snprintf(buf, sizeof(buf), "FWA%03d", findingCounter++);
        return std::string(buf);
    };

    for (size_t i = 0; i < policy.rules.size(); ++i) {
        const Rule& rule = policy.rules[i];
        const Box& P = rule.box;

        PacketSet reachable = ps_subtract_set(PacketSet{P}, covered);
        PacketSet& sameSet = (rule.action == Action::Allow) ? effectiveAllow : effectiveDeny;
        PacketSet& oppSet = (rule.action == Action::Allow) ? effectiveDeny : effectiveAllow;

        // Matches the cited algorithm exactly (see README "Design decisions"):
        // shadowing/redundancy are whole-rule properties, checked only when
        // the rule is *entirely* unreachable (`reachable` empty). A rule
        // that is merely partly carved into by an earlier, narrower,
        // conflicting-action rule while remaining otherwise very much
        // alive is the classic "specific exception then general rule"
        // shape -- that's Generalization (Phase B below), not Shadowing.
        // Conflating the two would report the same rule pair twice under
        // contradictory severities.
        if (ps_empty(reachable)) {
            PacketSet oppOverlap = ps_intersect_set(PacketSet{P}, oppSet);
            bool isShadowed = !ps_empty(oppOverlap);

            Finding f;
            f.code = nextCode();
            f.rule = ref_of(rule);
            f.ruleAction = rule.action;
            f.relation = "subset";

            if (isShadowed) {
                f.type = FindingType::Shadowing;
                f.taxonomyLevel = "error";
                f.severity = (rule.action == Action::Deny) ? Severity::Critical : Severity::High;
                std::vector<int> blockerOrdinals;
                f.blockers = find_blockers(PacketSet{P}, policy, i,
                                            rule.action == Action::Allow ? Action::Deny : Action::Allow,
                                            blockerOrdinals);
                f.collective = blockerOrdinals.size() > 1 &&
                                !single_rule_covers(PacketSet{P}, policy, blockerOrdinals);
                f.message =
                    "This rule is completely unreachable: earlier rule(s) already decide all "
                    "traffic it could match, at least some of them with the opposite action.";
                f.recommendation = "Review rule ordering and intended action. Do not reorder automatically.";
                Packet w;
                if (ps_pick_witness(oppOverlap, w)) {
                    f.hasWitness = true;
                    f.witness = w;
                }
            } else {
                f.type = FindingType::Redundancy;
                f.taxonomyLevel = "error";
                f.severity = Severity::Low;
                std::vector<int> blockerOrdinals;
                f.blockers = find_blockers(PacketSet{P}, policy, i, rule.action, blockerOrdinals);
                f.collective = blockerOrdinals.size() > 1;
                f.message =
                    "This rule is fully redundant: earlier same-action rule(s) already decide "
                    "all of its traffic identically.";
                f.recommendation =
                    "Candidate for removal after manual review (differing logging/side effects "
                    "may still justify keeping it).";
                Packet w;
                if (ps_pick_witness(PacketSet{P}, w)) {
                    f.hasWitness = true;
                    f.witness = w;
                }
            }
            result.findings.push_back(f);
        }

        // Phase B: pairwise correlation / generalization against every
        // earlier conflicting-action rule. Skipped entirely when Phase A
        // already found this rule to be fully dead (shadowed or
        // redundant): a rule with no reachable traffic left isn't
        // meaningfully "the broad half of an exception-then-default
        // pattern" or "correlated" with anything -- it's just gone, and
        // Phase A already reported that with full whole-policy (including
        // collective-shadowing) accuracy. Without this guard, a rule that
        // Phase A correctly attributes to *combined* earlier coverage
        // would also get an individually-misleading Generalization/
        // Correlation finding against each single earlier rule that
        // happens to be narrower than it.
        if (ps_empty(reachable)) {
            ruleIsDead[i] = true;
            covered.push_back(P);
            continue;
        }

        for (size_t j = 0; j < i; ++j) {
            const Rule& earlier = policy.rules[j];
            if (earlier.action == rule.action) continue;
            // A rule that is itself fully shadowed/redundant never actually
            // fires for real traffic, so pairing a live rule against it in
            // a Correlation/Generalization finding would be misleading.
            if (ruleIsDead[j]) continue;

            Box overlap = box_intersect(P, earlier.box);
            if (box_empty(overlap)) continue;

            bool piSubsetPj = ps_empty(ps_subtract_box(PacketSet{P}, earlier.box));
            bool pjSubsetPi = ps_empty(ps_subtract_box(PacketSet{earlier.box}, P));

            if (piSubsetPj) {
                continue;  // reported as shadowing above
            }

            Finding f;
            f.code = nextCode();
            f.rule = ref_of(rule);
            f.ruleAction = rule.action;
            f.blockers = {ref_of(earlier)};

            if (pjSubsetPi) {
                f.type = FindingType::Generalization;
                f.taxonomyLevel = "warning";
                f.severity = Severity::Info;
                f.relation = "superset";
                f.message =
                    "This rule is broader than an earlier, more specific rule with a "
                    "conflicting action -- likely an intentional exception-then-default "
                    "pattern, but worth confirming.";
                f.recommendation = "Review as a likely intentional specific-exception pattern.";
            } else {
                f.type = FindingType::Correlation;
                f.taxonomyLevel = "warning";
                f.severity = Severity::Medium;
                f.relation = "overlap";
                f.message =
                    "This rule partially overlaps an earlier rule with a conflicting action; "
                    "the overlapping traffic's decision depends on rule order.";
                f.recommendation = "Manual review required; changing order changes behavior.";
            }
            Packet w;
            if (box_pick_witness(overlap, w)) {
                f.hasWitness = true;
                f.witness = w;
            }
            result.findings.push_back(f);
        }

        for (const Box& b : reachable) sameSet.push_back(b);
        covered.push_back(P);
    }

    return result;
}

}  // namespace fwlint
