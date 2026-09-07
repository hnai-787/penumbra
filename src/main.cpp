#include <fstream>
#include <iostream>
#include <sstream>

#include "fwlint/analysis.h"
#include "fwlint/model.h"
#include "fwlint/parser_cisco.h"
#include "fwlint/parser_json.h"
#include "fwlint/report.h"
#include "fwlint/simulate.h"

namespace {

using namespace fwlint;

constexpr const char* kVersion = "1.0.0";

void print_help() {
    std::cout <<
        "fwlint " << kVersion << " -- firewall ruleset anomaly analyzer\n\n"
        "USAGE:\n"
        "  fwlint analyze <file> [--format cisco|json] [--output text|json|sarif]\n"
        "                        [--sarif <path>] [--fail-on none|low|medium|high|critical]\n"
        "  fwlint simulate <file> [--format cisco|json] --protocol <proto> --src <ip>\n"
        "                         --src-port <port> --dst <ip> --dst-port <port>\n"
        "  fwlint --help | -h\n"
        "  fwlint --version\n\n"
        "EXIT CODES:\n"
        "  0  analysis completed; no finding reached --fail-on threshold\n"
        "  1  analysis completed; a finding reached --fail-on threshold\n"
        "  2  input, parser, or unsupported-syntax error\n";
}

std::string detect_format(const std::string& path, const std::string& explicitFormat) {
    if (!explicitFormat.empty()) return explicitFormat;
    if (path.size() >= 5 && path.compare(path.size() - 5, 5, ".json") == 0) return "json";
    return "cisco";
}

bool read_file(const std::string& path, std::string& out) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return false;
    std::ostringstream ss;
    ss << file.rdbuf();
    out = ss.str();
    return true;
}

ParseResult parse_file(const std::string& path, const std::string& format) {
    std::string source;
    if (!read_file(path, source)) {
        ParseResult result;
        result.errors.push_back({0, "could not open file: " + path});
        return result;
    }
    if (format == "json") {
        return parse_canonical_json(source, path);
    }
    return parse_cisco_acl(source, path);
}

void print_parse_errors(const ParseResult& parsed) {
    std::cerr << "Error: analysis is incomplete -- " << parsed.errors.size()
              << " parse error(s):\n";
    for (const ParseError& e : parsed.errors) {
        std::cerr << "  line " << e.line << ": " << e.message << "\n";
    }
    std::cerr << "No result is reported: an anomaly analyzer must never claim \"clean\" over "
                 "input it did not fully understand.\n";
}

int severity_threshold_rank(const std::string& level) {
    if (level == "critical") return 0;
    if (level == "high") return 1;
    if (level == "medium") return 2;
    if (level == "low") return 3;
    if (level == "none") return 5;
    return 4;  // "info" or unrecognized: never fails the build
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

int cmd_analyze(int argc, char* argv[]) {
    if (argc < 1) {
        std::cerr << "Error: analyze requires a <file> argument\n";
        return 2;
    }
    std::string filePath = argv[0];
    std::string format;
    std::string outputMode = "text";
    std::string sarifPath;
    std::string failOn = "high";

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto nextArg = [&](const char* flag) -> std::string {
            if (i + 1 >= argc) {
                std::cerr << "Error: " << flag << " requires a value\n";
                std::exit(2);
            }
            return argv[++i];
        };
        if (arg == "--format") format = nextArg("--format");
        else if (arg == "--output") outputMode = nextArg("--output");
        else if (arg == "--sarif") sarifPath = nextArg("--sarif");
        else if (arg == "--fail-on") failOn = nextArg("--fail-on");
        else {
            std::cerr << "Error: unrecognized option \"" << arg << "\"\n";
            return 2;
        }
    }

    ParseResult parsed = parse_file(filePath, detect_format(filePath, format));
    if (!parsed.ok) {
        print_parse_errors(parsed);
        return 2;
    }

    AnalysisResult result = analyze_policy(parsed.policy);

    if (outputMode == "json") {
        std::cout << render_json(parsed.policy, result) << "\n";
    } else if (outputMode == "sarif") {
        std::cout << render_sarif(parsed.policy, result) << "\n";
    } else {
        std::cout << render_text(parsed.policy, result) << "\n";
    }

    if (!sarifPath.empty()) {
        std::ofstream out(sarifPath);
        out << render_sarif(parsed.policy, result);
    }

    int threshold = severity_threshold_rank(failOn);
    for (const Finding& f : result.findings) {
        if (severity_rank(f.severity) <= threshold) {
            return 1;
        }
    }
    return 0;
}

int cmd_simulate(int argc, char* argv[]) {
    if (argc < 1) {
        std::cerr << "Error: simulate requires a <file> argument\n";
        return 2;
    }
    std::string filePath = argv[0];
    std::string format, protocolText, srcText, dstText;
    std::string srcPortText = "0", dstPortText = "0";

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto nextArg = [&](const char* flag) -> std::string {
            if (i + 1 >= argc) {
                std::cerr << "Error: " << flag << " requires a value\n";
                std::exit(2);
            }
            return argv[++i];
        };
        if (arg == "--format") format = nextArg("--format");
        else if (arg == "--protocol") protocolText = nextArg("--protocol");
        else if (arg == "--src") srcText = nextArg("--src");
        else if (arg == "--dst") dstText = nextArg("--dst");
        else if (arg == "--src-port") srcPortText = nextArg("--src-port");
        else if (arg == "--dst-port") dstPortText = nextArg("--dst-port");
        else {
            std::cerr << "Error: unrecognized option \"" << arg << "\"\n";
            return 2;
        }
    }

    if (protocolText.empty() || srcText.empty() || dstText.empty()) {
        std::cerr << "Error: simulate requires --protocol, --src, and --dst\n";
        return 2;
    }

    ParseResult parsed = parse_file(filePath, detect_format(filePath, format));
    if (!parsed.ok) {
        print_parse_errors(parsed);
        return 2;
    }

    auto protocolSet = parse_protocol_spec(protocolText);
    auto srcIp = parse_ipv4(srcText);
    auto dstIp = parse_ipv4(dstText);
    auto srcPortSet = parse_port_spec(srcPortText);
    auto dstPortSet = parse_port_spec(dstPortText);
    if (!protocolSet || !srcIp || !dstIp || !srcPortSet || !dstPortSet) {
        std::cerr << "Error: could not parse one or more of --protocol/--src/--dst/--src-port/--dst-port\n";
        return 2;
    }

    Packet packet;
    packet.protocol = static_cast<uint8_t>(interval_pick(*protocolSet));
    packet.srcAddr = *srcIp;
    packet.dstAddr = *dstIp;
    packet.srcPort = static_cast<uint16_t>(interval_pick(*srcPortSet));
    packet.dstPort = static_cast<uint16_t>(interval_pick(*dstPortSet));

    SimulationResult sim = simulate_packet(parsed.policy, packet);

    std::cout << "Decision: " << action_to_string(sim.decision) << "\n";
    if (sim.matchedRule) {
        std::cout << "Matched:  rule " << sim.matchedRuleId << "\n";
        std::cout << "Line:     " << sim.matchedRuleLine << "\n";
    } else {
        std::cout << "Matched:  (none -- default action)\n";
    }
    std::cout << "Rules evaluated: " << sim.rulesEvaluated << "\n";

    return 0;
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_help();
        return 2;
    }

    std::string command = argv[1];
    if (command == "--help" || command == "-h") {
        print_help();
        return 0;
    }
    if (command == "--version") {
        std::cout << "fwlint " << kVersion << "\n";
        return 0;
    }
    if (command == "analyze") {
        return cmd_analyze(argc - 2, argv + 2);
    }
    if (command == "simulate") {
        return cmd_simulate(argc - 2, argv + 2);
    }

    std::cerr << "Error: unrecognized command \"" << command << "\"\n\n";
    print_help();
    return 2;
}
