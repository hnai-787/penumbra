#include <iostream>
#include <string>
#include "firewall.h"

int main(int argc, char* argv[]) {
    std::string rulesPath = "data/rules.txt";
    std::string packetsPath = "data/packets.txt";
    std::string outputPath = "output/result.txt";

    if (argc == 4) {
        rulesPath = argv[1];
        packetsPath = argv[2];
        outputPath = argv[3];
    } else if (argc != 1) {
        std::cerr << "Usage:\n";
        std::cerr << "  firewall\n";
        std::cerr << "  firewall <rules-file> <packets-file> <output-file>\n";
        return 1;
    }

    Firewall firewall;

    if (!firewall.loadRules(rulesPath)) {
        std::cerr << "Error: Could not load rules from " << rulesPath << "\n";
        return 1;
    }

    if (!firewall.processPackets(packetsPath, outputPath)) {
        std::cerr << "Error: Could not process packets from " << packetsPath << "\n";
        return 1;
    }

    std::cout << "Firewall simulation completed successfully.\n";
    std::cout << "Rules file:   " << rulesPath << "\n";
    std::cout << "Packets file: " << packetsPath << "\n";
    std::cout << "Output file:  " << outputPath << "\n";

    return 0;
}
