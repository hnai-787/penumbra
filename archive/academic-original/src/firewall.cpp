#include "firewall.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>
#include <sstream>

std::string Firewall::trim(const std::string& text) {
    size_t start = 0;
    while (start < text.size() && std::isspace(static_cast<unsigned char>(text[start]))) {
        start++;
    }

    size_t end = text.size();
    while (end > start && std::isspace(static_cast<unsigned char>(text[end - 1]))) {
        end--;
    }

    return text.substr(start, end - start);
}

std::string Firewall::toUpper(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return text;
}

RuleField Firewall::parseRuleField(const std::string& text) {
    std::string value = toUpper(trim(text));

    if (value == "SRC") return RuleField::SRC;
    if (value == "DST") return RuleField::DST;
    if (value == "PRO") return RuleField::PRO;

    return RuleField::UNKNOWN;
}

Decision Firewall::parseDecision(const std::string& text) {
    std::string value = toUpper(trim(text));

    if (value == "ALLOW") return Decision::ALLOW;
    if (value == "DENY") return Decision::DENY;

    return Decision::UNKNOWN;
}

std::string Firewall::decisionToString(Decision decision) {
    switch (decision) {
        case Decision::ALLOW:
            return "ALLOW";
        case Decision::DENY:
            return "DENY";
        default:
            return "UNKNOWN";
    }
}

bool Firewall::parseIPv4(const std::string& ipText, IPv4Address& ip) {
    std::stringstream ss(ipText);
    std::string part;
    int index = 0;

    while (std::getline(ss, part, '.')) {
        if (index >= 4 || part.empty()) {
            ip.valid = false;
            return false;
        }

        for (char c : part) {
            if (!std::isdigit(static_cast<unsigned char>(c))) {
                ip.valid = false;
                return false;
            }
        }

        int value = 0;
        for (char c : part) {
            value = (value * 10) + (c - '0');
            if (value > 255) {
                ip.valid = false;
                return false;
            }
        }

        if (value < 0 || value > 255) {
            ip.valid = false;
            return false;
        }

        ip.octets[index++] = value;
    }

    ip.valid = (index == 4);
    return ip.valid;
}

bool Firewall::loadRules(const std::string& rulesFilePath) {
    std::ifstream file(rulesFilePath);
    if (!file.is_open()) {
        return false;
    }

    rules.clear();

    std::string line;
    int lineNumber = 0;

    while (std::getline(file, line)) {
        lineNumber++;
        line = trim(line);

        if (line.empty() || line[0] == '#') {
            continue;
        }

        std::stringstream ss(line);
        FirewallRule rule;
        std::string fieldText;
        std::string decisionText;

        if (!(ss >> rule.ruleNumber >> fieldText >> rule.value >> decisionText)) {
            std::cerr << "Warning: Invalid rule format at line " << lineNumber << ": " << line << "\n";
            continue;
        }

        rule.field = parseRuleField(fieldText);
        rule.decision = parseDecision(decisionText);

        if (rule.ruleNumber <= 0 || rule.field == RuleField::UNKNOWN || rule.decision == Decision::UNKNOWN) {
            std::cerr << "Warning: Invalid rule values at line " << lineNumber << ": " << line << "\n";
            continue;
        }

        rules.push_back(rule);
    }

    return !rules.empty();
}

bool Firewall::parsePacketLine(const std::string& line, NetworkPacket& packet) {
    std::string text = trim(line);

    if (text.empty() || text[0] == '#') {
        return false;
    }

    if (text.front() == '[' && text.back() == ']') {
        text = text.substr(1, text.size() - 2);
    }

    std::stringstream ss(text);
    std::string token;

    while (std::getline(ss, token, ';')) {
        token = trim(token);

        if (token.rfind("SRC:", 0) == 0) {
            packet.sourceIp = trim(token.substr(4));
        } else if (token.rfind("DST:", 0) == 0) {
            packet.destinationIp = trim(token.substr(4));
        } else if (token.rfind("PRO:", 0) == 0) {
            packet.protocol = toUpper(trim(token.substr(4)));
        } else if (!token.empty()) {
            packet.payload = token;
        }
    }

    IPv4Address src;
    IPv4Address dst;

    return parseIPv4(packet.sourceIp, src) &&
           parseIPv4(packet.destinationIp, dst) &&
           !packet.protocol.empty();
}

bool Firewall::matchExactIp(const std::string& ruleIp, const std::string& packetIp) {
    IPv4Address ruleAddress;
    IPv4Address packetAddress;

    if (!parseIPv4(ruleIp, ruleAddress) || !parseIPv4(packetIp, packetAddress)) {
        return false;
    }

    for (int i = 0; i < 4; i++) {
        if (ruleAddress.octets[i] != packetAddress.octets[i]) {
            return false;
        }
    }

    return true;
}

bool Firewall::matchIpRange(const std::string& ruleRange, const std::string& packetIp) {
    size_t dashPosition = ruleRange.find('-');

    if (dashPosition == std::string::npos) {
        return matchExactIp(ruleRange, packetIp);
    }

    std::string startIpText = trim(ruleRange.substr(0, dashPosition));
    std::string endText = trim(ruleRange.substr(dashPosition + 1));

    IPv4Address startIp;
    IPv4Address packetAddress;

    if (!parseIPv4(startIpText, startIp) || !parseIPv4(packetIp, packetAddress)) {
        return false;
    }

    if (endText.empty()) {
        return false;
    }

    int endLastOctet = 0;
    for (char c : endText) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            return false;
        }
        endLastOctet = (endLastOctet * 10) + (c - '0');
        if (endLastOctet > 255) {
            return false;
        }
    }

    if (endLastOctet < 0 || endLastOctet > 255) {
        return false;
    }

    // Simple range format supported:
    // 192.168.1.1-10 means 192.168.1.1 through 192.168.1.10
    for (int i = 0; i < 3; i++) {
        if (packetAddress.octets[i] != startIp.octets[i]) {
            return false;
        }
    }

    if (startIp.octets[3] > endLastOctet) {
        return false;
    }

    return packetAddress.octets[3] >= startIp.octets[3] &&
           packetAddress.octets[3] <= endLastOctet;
}

bool Firewall::matchesRule(const FirewallRule& rule, const NetworkPacket& packet) {
    switch (rule.field) {
        case RuleField::SRC:
            return matchIpRange(rule.value, packet.sourceIp);

        case RuleField::DST:
            return matchIpRange(rule.value, packet.destinationIp);

        case RuleField::PRO:
            return toUpper(rule.value) == toUpper(packet.protocol);

        default:
            return false;
    }
}

PacketDecision Firewall::evaluatePacket(const NetworkPacket& packet) const {
    PacketDecision result;
    result.packet = packet;

    for (const FirewallRule& rule : rules) {
        if (matchesRule(rule, packet)) {
            result.decision = rule.decision;
            result.matchedRuleNumber = rule.ruleNumber;
            result.reason = "MATCHED_RULE_" + std::to_string(rule.ruleNumber);
            return result;
        }
    }

    result.decision = Decision::DENY;
    result.matchedRuleNumber = 0;
    result.reason = "DEFAULT_DENY";
    return result;
}

bool Firewall::processPackets(const std::string& packetsFilePath, const std::string& outputFilePath) const {
    std::ifstream inputFile(packetsFilePath);
    if (!inputFile.is_open()) {
        return false;
    }

    std::ofstream outputFile(outputFilePath);
    if (!outputFile.is_open()) {
        return false;
    }

    outputFile << "SRC,DST,PRO,DECISION,RULE,REASON\n";

    std::string line;
    int lineNumber = 0;

    while (std::getline(inputFile, line)) {
        lineNumber++;

        std::string trimmedLine = trim(line);
        if (trimmedLine.empty() || trimmedLine[0] == '#') {
            continue;
        }

        NetworkPacket packet;

        if (!parsePacketLine(line, packet)) {
            outputFile << "INVALID_PACKET,INVALID_PACKET,INVALID_PACKET,DENY,0,INVALID_FORMAT_LINE_"
                       << lineNumber << "\n";
            continue;
        }

        PacketDecision decision = evaluatePacket(packet);

        outputFile << decision.packet.sourceIp << ","
                   << decision.packet.destinationIp << ","
                   << decision.packet.protocol << ","
                   << decisionToString(decision.decision) << ","
                   << decision.matchedRuleNumber << ","
                   << decision.reason << "\n";
    }

    return true;
}
