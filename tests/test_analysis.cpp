#include <catch2/catch_test_macros.hpp>

#include "fwlint/analysis.h"

using namespace fwlint;

namespace {

Rule make_rule(int ordinal, Action action, const std::string& srcCidr, const std::string& dstCidr,
                const std::string& protocol = "tcp", const std::string& dstPort = "any") {
    Rule r;
    r.ordinal = ordinal;
    r.id = std::to_string(ordinal);
    r.source.line = ordinal;
    r.action = action;
    r.box.protocol = *parse_protocol_spec(protocol);
    r.box.srcAddr = *parse_cidr_or_any(srcCidr);
    r.box.srcPort = full_range(65535);
    r.box.dstAddr = *parse_cidr_or_any(dstCidr);
    r.box.dstPort = *parse_port_spec(dstPort);
    return r;
}

int count(const AnalysisResult& result, FindingType type) {
    int n = 0;
    for (const Finding& f : result.findings) {
        if (f.type == type) ++n;
    }
    return n;
}

}  // namespace

TEST_CASE("no anomalies among disjoint, non-conflicting rules", "[analysis]") {
    Policy policy;
    policy.rules = {
        make_rule(1, Action::Allow, "10.0.0.0/24", "any"),
        make_rule(2, Action::Deny, "10.0.1.0/24", "any"),
    };
    AnalysisResult result = analyze_policy(policy);
    REQUIRE(result.findings.empty());
}

TEST_CASE("direct pairwise shadowing: narrower rule after a broader conflicting one", "[analysis]") {
    Policy policy;
    policy.rules = {
        make_rule(1, Action::Allow, "10.0.0.0/16", "any"),  // broad allow
        make_rule(2, Action::Deny, "10.0.5.0/24", "any"),   // narrower deny, unreachable
    };
    AnalysisResult result = analyze_policy(policy);
    REQUIRE(count(result, FindingType::Shadowing) == 1);
    const Finding& f = result.findings[0];
    REQUIRE(f.rule.ordinal == 2);
    REQUIRE(f.severity == Severity::Critical);  // shadowed DENY is critical
    REQUIRE(f.blockers.size() == 1);
    REQUIRE(f.blockers[0].ordinal == 1);
    REQUIRE_FALSE(f.collective);
    REQUIRE(f.hasWitness);
}

TEST_CASE("collective shadowing: two rules jointly cover a third, neither alone does", "[analysis]") {
    Policy policy;
    policy.rules = {
        make_rule(1, Action::Allow, "10.0.0.0/25", "any", "tcp", "443"),   // left half
        make_rule(2, Action::Allow, "10.0.0.128/25", "any", "tcp", "443"),  // right half
        make_rule(3, Action::Deny, "10.0.0.0/24", "any", "tcp", "443"),    // whole range, unreachable
    };
    AnalysisResult result = analyze_policy(policy);
    REQUIRE(count(result, FindingType::Shadowing) == 1);
    const Finding& f = result.findings[0];
    REQUIRE(f.rule.ordinal == 3);
    REQUIRE(f.collective);
    REQUIRE(f.blockers.size() == 2);
}

TEST_CASE("redundancy: later same-action rule adds nothing new", "[analysis]") {
    Policy policy;
    policy.rules = {
        make_rule(1, Action::Allow, "10.0.0.0/16", "any"),
        make_rule(2, Action::Allow, "10.0.5.0/24", "any"),  // fully covered by rule 1, same action
    };
    AnalysisResult result = analyze_policy(policy);
    REQUIRE(count(result, FindingType::Redundancy) == 1);
    REQUIRE(count(result, FindingType::Shadowing) == 0);
    const Finding& f = result.findings[0];
    REQUIRE(f.rule.ordinal == 2);
    REQUIRE(f.severity == Severity::Low);
}

TEST_CASE("correlation: partial overlap with conflicting actions", "[analysis]") {
    Policy policy;
    Rule r1 = make_rule(1, Action::Allow, "10.0.0.0/24", "any");
    Rule r2 = make_rule(2, Action::Deny, "10.0.0.0/24", "any");
    // Force a genuine partial overlap by shrinking r2's address range so it
    // is neither a subset nor a superset of r1's.
    r2.box.srcAddr = IntervalSet{{*parse_ipv4("10.0.0.128"), *parse_ipv4("10.0.1.128")}};
    policy.rules = {r1, r2};

    AnalysisResult result = analyze_policy(policy);
    REQUIRE(count(result, FindingType::Correlation) == 1);
    const Finding& f = result.findings[0];
    REQUIRE(f.taxonomyLevel == "warning");
}

TEST_CASE("generalization: broader later rule after a specific conflicting exception", "[analysis]") {
    Policy policy;
    policy.rules = {
        make_rule(1, Action::Deny, "10.0.5.0/24", "any"),   // specific exception
        make_rule(2, Action::Allow, "10.0.0.0/16", "any"),  // broad, conflicting, comes after
    };
    AnalysisResult result = analyze_policy(policy);
    REQUIRE(count(result, FindingType::Generalization) == 1);
    const Finding& f = result.findings[0];
    REQUIRE(f.rule.ordinal == 2);
    REQUIRE(f.taxonomyLevel == "warning");
    REQUIRE(f.severity == Severity::Info);
}

TEST_CASE("implicit default deny: a rule with no matching earlier rule reaches default", "[analysis]") {
    Policy policy;
    policy.defaultAction = Action::Deny;
    policy.rules = {
        make_rule(1, Action::Allow, "10.0.0.0/24", "any"),
    };
    AnalysisResult result = analyze_policy(policy);
    REQUIRE(result.findings.empty());  // one rule alone can't be anomalous
    REQUIRE(policy.defaultAction == Action::Deny);
}

TEST_CASE("a fully dead rule is not also reported as generalization against each blocker", "[analysis]") {
    // Regression test: rule 3 is collectively shadowed by rules 1+2 (each
    // individually narrower than rule 3). Before the fix, Phase B's
    // pairwise check independently flagged rule 3 as Generalization
    // against rule 1 AND against rule 2, in addition to Phase A's correct
    // whole-policy Shadowing verdict -- three contradictory findings for
    // one dead rule.
    Policy policy;
    policy.rules = {
        make_rule(1, Action::Allow, "10.0.0.0/25", "any", "tcp", "443"),
        make_rule(2, Action::Allow, "10.0.0.128/25", "any", "tcp", "443"),
        make_rule(3, Action::Deny, "10.0.0.0/24", "any", "tcp", "443"),
    };
    AnalysisResult result = analyze_policy(policy);
    REQUIRE(count(result, FindingType::Shadowing) == 1);
    REQUIRE(count(result, FindingType::Generalization) == 0);
    REQUIRE(count(result, FindingType::Correlation) == 0);
}

TEST_CASE("a later live rule does not correlate against an earlier fully-dead rule", "[analysis]") {
    // Rule 2 is fully shadowed by rule 1 (identical box, opposite action
    // never reached). Rule 3 stays alive overall (its port range extends
    // beyond what rules 1/2 cover) but its port range fully contains
    // rule 2's single port, which would normally read as a Generalization
    // pairing -- except rule 2 never actually fires for any real packet,
    // so that finding would be misleading and must be suppressed.
    Rule r1 = make_rule(1, Action::Allow, "10.0.0.0/24", "any", "tcp", "8080");
    Rule r2 = make_rule(2, Action::Deny, "10.0.0.0/24", "any", "tcp", "8080");  // fully shadowed by r1
    Rule r3 = make_rule(3, Action::Allow, "10.0.0.0/24", "any", "tcp", "8000-8100");
    Policy policy;
    policy.rules = {r1, r2, r3};

    AnalysisResult result = analyze_policy(policy);
    REQUIRE(count(result, FindingType::Shadowing) == 1);
    REQUIRE(result.findings[0].rule.ordinal == 2);
    REQUIRE(count(result, FindingType::Correlation) == 0);
    REQUIRE(count(result, FindingType::Generalization) == 0);
}

TEST_CASE("a rule that is only partly carved into stays alive, not shadowed", "[analysis]") {
    // r2 remains reachable for 10.0.0.128-255 even though r1 preempts its
    // 10.0.0.0-127 half -- this is the Generalization shape (specific
    // exception before a broader conflicting rule), not Shadowing, since
    // r2 is very much still an active rule overall.
    Rule r1 = make_rule(1, Action::Allow, "10.0.0.0/25", "any");  // .0-.127
    Rule r2 = make_rule(2, Action::Deny, "10.0.0.0/24", "any");   // .0-.255, half overlaps r1
    Policy policy;
    policy.rules = {r1, r2};

    AnalysisResult result = analyze_policy(policy);
    REQUIRE(count(result, FindingType::Shadowing) == 0);
    REQUIRE(count(result, FindingType::Redundancy) == 0);
    REQUIRE(count(result, FindingType::Generalization) == 1);
    REQUIRE(result.findings[0].rule.ordinal == 2);
}
