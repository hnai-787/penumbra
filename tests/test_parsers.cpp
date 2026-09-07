#include <catch2/catch_test_macros.hpp>

#include "fwlint/parser_cisco.h"
#include "fwlint/parser_json.h"

using namespace fwlint;

TEST_CASE("canonical JSON: parses a minimal valid policy", "[parser][json]") {
    std::string src = R"({
        "default_action": "deny",
        "rules": [
            { "id": "10", "action": "allow", "protocol": ["tcp"],
              "source": ["10.0.0.0/24"], "destination": ["192.0.2.10/32"],
              "destination_port": ["443"] }
        ]
    })";
    ParseResult result = parse_canonical_json(src, "test.json");
    REQUIRE(result.ok);
    REQUIRE(result.policy.rules.size() == 1);
    REQUIRE(result.policy.rules[0].action == Action::Allow);
    REQUIRE(result.policy.defaultAction == Action::Deny);
}

TEST_CASE("canonical JSON: array-valued fields are unioned", "[parser][json]") {
    std::string src = R"({
        "rules": [
            { "id": "1", "action": "allow", "protocol": ["tcp", "udp"],
              "source": ["any"], "destination": ["any"] }
        ]
    })";
    ParseResult result = parse_canonical_json(src, "test.json");
    REQUIRE(result.ok);
    REQUIRE(interval_contains(result.policy.rules[0].box.protocol, 6));   // tcp
    REQUIRE(interval_contains(result.policy.rules[0].box.protocol, 17));  // udp
    REQUIRE_FALSE(interval_contains(result.policy.rules[0].box.protocol, 1));  // not icmp
}

TEST_CASE("canonical JSON: malformed syntax fails closed", "[parser][json]") {
    ParseResult result = parse_canonical_json("{ not valid json", "test.json");
    REQUIRE_FALSE(result.ok);
    REQUIRE_FALSE(result.errors.empty());
}

TEST_CASE("canonical JSON: invalid CIDR fails closed with a clear error", "[parser][json]") {
    std::string src = R"({"rules": [{"id":"1","action":"allow","source":["999.0.0.0/24"]}]})";
    ParseResult result = parse_canonical_json(src, "test.json");
    REQUIRE_FALSE(result.ok);
    REQUIRE(result.errors[0].message.find("source") != std::string::npos);
}

TEST_CASE("Cisco ACL: parses a numbered access-list", "[parser][cisco]") {
    std::string src =
        "access-list 110 permit tcp 10.0.0.0 0.0.0.255 host 192.0.2.10 eq 443\n"
        "access-list 110 deny tcp any any\n";
    ParseResult result = parse_cisco_acl(src, "test.acl");
    REQUIRE(result.ok);
    REQUIRE(result.policy.rules.size() == 2);
    REQUIRE(result.policy.rules[0].action == Action::Allow);
    REQUIRE(interval_contains(result.policy.rules[0].box.dstPort, 443));
    REQUIRE_FALSE(interval_contains(result.policy.rules[0].box.dstPort, 80));
}

TEST_CASE("Cisco ACL: parses a named extended ACL block with sequence numbers", "[parser][cisco]") {
    std::string src =
        "ip access-list extended EDGE-IN\n"
        " 10 permit tcp 10.0.0.0 0.0.0.255 any eq telnet\n"
        " 20 deny ip any any\n";
    ParseResult result = parse_cisco_acl(src, "test.acl");
    REQUIRE(result.ok);
    REQUIRE(result.policy.rules.size() == 2);
    REQUIRE(interval_contains(result.policy.rules[0].box.dstPort, 23));  // telnet
}

TEST_CASE("Cisco ACL: contiguous wildcard mask is accepted as a CIDR-equivalent range", "[parser][cisco]") {
    std::string src = "access-list 100 permit ip 10.0.0.0 0.0.0.255 any\n";
    ParseResult result = parse_cisco_acl(src, "test.acl");
    REQUIRE(result.ok);
    REQUIRE(interval_contains(result.policy.rules[0].box.srcAddr, *parse_ipv4("10.0.0.128")));
    REQUIRE_FALSE(interval_contains(result.policy.rules[0].box.srcAddr, *parse_ipv4("10.0.1.0")));
}

TEST_CASE("Cisco ACL: discontiguous wildcard mask fails closed rather than being guessed", "[parser][cisco]") {
    std::string src = "access-list 100 permit ip 10.0.0.0 0.0.255.0 any\n";
    ParseResult result = parse_cisco_acl(src, "test.acl");
    REQUIRE_FALSE(result.ok);
    REQUIRE(result.errors[0].message.find("discontiguous") != std::string::npos);
}

TEST_CASE("Cisco ACL: unsupported trailing keyword (established) fails closed", "[parser][cisco]") {
    std::string src = "access-list 100 permit tcp any any established\n";
    ParseResult result = parse_cisco_acl(src, "test.acl");
    REQUIRE_FALSE(result.ok);
}

TEST_CASE("Cisco ACL: port range and gt/lt/neq operators", "[parser][cisco]") {
    std::string src =
        "access-list 100 permit tcp any any range 8000 8999\n"
        "access-list 100 permit tcp any eq 22 any\n"
        "access-list 100 permit tcp any any neq 80\n";
    ParseResult result = parse_cisco_acl(src, "test.acl");
    REQUIRE(result.ok);
    REQUIRE(result.policy.rules.size() == 3);
    REQUIRE(interval_contains(result.policy.rules[0].box.dstPort, 8500));
    REQUIRE_FALSE(interval_contains(result.policy.rules[0].box.dstPort, 7999));
    REQUIRE(interval_contains(result.policy.rules[1].box.srcPort, 22));
    REQUIRE_FALSE(interval_contains(result.policy.rules[2].box.dstPort, 80));
    REQUIRE(interval_contains(result.policy.rules[2].box.dstPort, 81));
}

TEST_CASE("Cisco ACL: comment lines and blank lines are ignored", "[parser][cisco]") {
    std::string src =
        "! this is a comment\n"
        "\n"
        "access-list 100 permit ip any any\n";
    ParseResult result = parse_cisco_acl(src, "test.acl");
    REQUIRE(result.ok);
    REQUIRE(result.policy.rules.size() == 1);
}
