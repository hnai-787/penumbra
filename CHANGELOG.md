# Changelog

All notable changes to this project are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added

### Changed

### Fixed

## [1.0.0] - 2026-09-08

### Added

- Rebuilt the project as **fwlint**, a firewall ruleset anomaly analyzer,
  on top of the original version packet simulator (preserved unmodified
  under `archive/original/`).
- Exact 5-tuple (protocol/srcIP/srcPort/dstIP/dstPort) packet-space engine
  using axis-aligned box decomposition (`include/fwlint/interval.h`,
  `include/fwlint/box.h`) as an exact, dependency-free alternative to a
  BDD library (no BDD package was available for this build's MinGW-only
  toolchain).
- Whole-policy anomaly engine (`src/analysis.cpp`) implementing the four
  canonical Al-Shaer/Hamed anomaly types (shadowing, redundancy,
  correlation, generalization) plus collective shadowing (a later rule
  made unreachable by the *combination* of several earlier rules).
- Witness-packet generation for every finding.
- Canonical JSON policy parser and a real (bounded-subset, fail-closed)
  Cisco IOS/IOS XE extended ACL parser.
- `fwlint analyze` (text/JSON/SARIF 2.1.0 output, `--fail-on` CI gating)
  and `fwlint simulate` (single-packet evaluation) CLI commands.
- 41 Catch2 unit/regression test cases (125 assertions) covering the
  interval/box algebra, all four anomaly types, collective shadowing, two
  real classification-bug regressions found while building this, and both
  parsers' happy and fail-closed paths.
- CMake + vcpkg build (`build.sh`), statically linked on MinGW (no MinGW
  runtime DLLs required at run time).
- Hand-built example ACL (`examples/cisco/edge-router.acl`) exercising all
  five finding types, plus two synthetic 300-rule benchmarks with real
  measured timing.

### Changed

- `README.md` rewritten to document the new tool while preserving the
  original course info, problem statement, and original results.
