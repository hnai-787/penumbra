# Firewall Rule Engine (C++)

## Course Information

| Field | Details |
|---|---|
| Course | Programming Fundamentals |
| Semester | Semester 1 — Fall 2023 |
| University | Air University, Islamabad |
| Student | Hussain Ali (232095) |

## Overview

A command-line firewall simulator written in C++. It reads an ordered list
of rules and a set of sample packets, evaluates each packet against the
rules top-down (first match wins, default deny), and writes the decision
for every packet to an output file.

## Problem Statement

Demonstrate how a real packet-filtering firewall makes allow/deny decisions
by implementing the core rule-evaluation logic from scratch — ordered
rules, IP/octet-range matching, protocol matching, and a safe default when
nothing matches.

## Objectives

- Parse a structured rule file into an ordered in-memory rule set.
- Evaluate packets against rules using first-match-wins semantics.
- Default to DENY when no rule matches, and handle malformed input safely.

## Tools and Technologies

- C++ (standard library only — `iostream`, `string`, `vector`)

## Features

- Ordered rule evaluation with first-match-wins semantics.
- Source/destination matching by exact IP or last-octet range.
- Protocol matching (TCP/UDP/etc.) and default-deny fallback.
- Malformed-input detection (reports `INVALID_FORMAT_LINE_<n>`).
- Configurable file paths via command-line arguments.

## Methodology

1. Define the rule and packet file formats.
2. Implement the `Firewall` class (`src/firewall.h`/`.cpp`) to load rules and evaluate packets.
3. Implement `src/main.cpp` to wire input/output files together.
4. Validate against a hand-built sample rule set and packet set.
5. Capture output and screenshots as evidence.

## Repository Structure

```text
firewall-rule-engine-cpp/
  README.md
  PROJECT_NOTES.md
  src/
    main.cpp
    firewall.h
    firewall.cpp
  data/
    rules.txt
    packets.txt
  output/
    result.txt
  screenshots/
  project.yaml
```

## Setup Instructions

```bash
g++ src/main.cpp src/firewall.cpp -o firewall
```

## Usage

```bash
./firewall                                   # uses default data/rules.txt, data/packets.txt, output/result.txt
./firewall <rules_file> <packets_file> <output_file>
```

## How to Review

1. Start with this README.
2. Read `data/rules.txt` (8 rules) and `data/packets.txt` (9 sample packets).
3. Compare against the recorded decisions in `output/result.txt`.
4. Check `screenshots/` for a run of the program.

## Screenshots

See `screenshots/` — 3 screenshots of the program running against the sample rule/packet set.

## Results

Verified against the sample dataset (8 rules, 9 packets), all correctly classified, e.g.:

- `SRC:10.0.0.5 → DST:192.168.1.20 TCP` → **DENY** (matched rule 1)
- `SRC:152.5.23.120 → DST:192.168.255.255 UDP` → **ALLOW** (matched rule 3)
- Malformed packet with an invalid IP octet (`999.1.1.1`) → **DENY**, flagged `INVALID_FORMAT_LINE_12`
- A packet using an unlisted protocol (GRE) that matches no rule → **DEFAULT_DENY**

## Limitations

- In-memory only — no persistence or live packet capture; this is a rule-evaluation demonstration, not a functioning network firewall.
- No IPv6, CIDR, or port-based matching — only exact IP / last-octet ranges.

## Future Enhancements

- CIDR notation support.
- Port-based and stateful rule matching.

## Safety and Privacy

- No real secrets, credentials, or private keys are included.
- No private user data is included.
- All data (rules, packets) is synthetic/hand-authored for the assignment.

## Ethical Notice

This project is intended strictly for academic learning. It simulates
firewall logic against synthetic data only and does not interact with any
real network.
