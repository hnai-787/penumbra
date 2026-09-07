#ifndef FIREWALL_H
#define FIREWALL_H

#include <string>
#include <vector>

enum class RuleField {
    SRC,
    DST,
    PRO,
    UNKNOWN
};

enum class Decision {
    ALLOW,
    DENY,
    UNKNOWN
};

struct IPv4Address {
    int octets[4] = {0, 0, 0, 0};
    bool valid = false;
};

struct FirewallRule {
    int ruleNumber = 0;
    RuleField field = RuleField::UNKNOWN;
    std::string value;
    Decision decision = Decision::UNKNOWN;
};

struct NetworkPacket {
    std::string sourceIp;
    std::string destinationIp;
    std::string protocol;
    std::string payload;
};

struct PacketDecision {
    NetworkPacket packet;
    Decision decision = Decision::DENY;
    int matchedRuleNumber = 0;
    std::string reason = "DEFAULT_DENY";
};

class Firewall {
public:
    bool loadRules(const std::string& rulesFilePath);
    bool processPackets(const std::string& packetsFilePath, const std::string& outputFilePath) const;

private:
    std::vector<FirewallRule> rules;

    static std::string trim(const std::string& text);
    static std::string toUpper(std::string text);

    static RuleField parseRuleField(const std::string& text);
    static Decision parseDecision(const std::string& text);
    static std::string decisionToString(Decision decision);

    static bool parsePacketLine(const std::string& line, NetworkPacket& packet);
    static bool parseIPv4(const std::string& ipText, IPv4Address& ip);

    static bool matchExactIp(const std::string& ruleIp, const std::string& packetIp);
    static bool matchIpRange(const std::string& ruleRange, const std::string& packetIp);
    static bool matchesRule(const FirewallRule& rule, const NetworkPacket& packet);

    PacketDecision evaluatePacket(const NetworkPacket& packet) const;
};

#endif
