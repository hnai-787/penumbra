# Project Notes

## Source

Migrated from `air-university-cybersecurity-projects/projects/firewall-rule-engine-cpp`
(a separate academic-portfolio repo) into this workspace as an independent
project on 2026-09-07.

## Cleanup decisions

- The compiled `firewall.exe` present in the source folder was **not**
  copied — this workspace's `templates/project/project.gitignore` excludes
  build output, and the source repo's own `PROJECT_STANDARDS.md` already
  flagged it as something that shouldn't have been committed. Rebuild with
  `g++ src/main.cpp src/firewall.cpp -o firewall`.
- No other content changes were made — rules, packets, output, and
  screenshots are copied as-is.

## Assumptions

- `status: completed` in `project.yaml` reflects that this was a finished,
  submitted early version, not that it received a specific grade
  (no grade information exists in the source material).

## Remaining work

- None identified. This project was already in a clean, reviewable state
  in the source repo.

## 2026-09-08: Rebuilt as fwlint (firewall ruleset anomaly analyzer)

### What changed and why

The original assignment (evaluate sample packets against an ordered rule
list) demonstrates real skills but isn't something anyone would use — it's
a toy packet matcher. Following a research pass (grounded in the
Al-Shaer/Hamed firewall-policy-anomaly taxonomy and real commercial tool
documentation from Tufin/AlgoSec/FireMon), the project was rebuilt into
**fwlint**: a static analyzer that audits the *ruleset itself* for
unreachable, redundant, and order-dependent rules — a real, bounded,
differentiated problem, not "yet another packet matcher."

The original program and its data/output were preserved unmodified under
`archive/original/` — nothing about the original submission was
deleted or altered.

### Key engineering decisions and why

- **No BDD library (CUDD/Sylvan).** This build environment has only MinGW
  g++ (no MSVC), and neither BDD library has a vcpkg port or a
  MinGW-friendly build path without significant cross-compilation risk.
  Rather than half-integrate a fragile native dependency, the engine uses
  exact axis-aligned box decomposition instead — a different, also
  peer-reviewed exact technique (Hu/Ahn/Kulkarni 2012's rule-space
  segmentation), not an approximation. Documented in the README's "Design
  decisions" so this reads as a deliberate trade-off, not a corner cut.
- **vcpkg was set up from scratch** (cloned, bootstrapped, and installed
  `nlohmann-json` and `catch2` for the `x64-mingw-static` triplet, with
  `VCPKG_DEFAULT_HOST_TRIPLET` also set to mingw since the default
  x64-windows host triplet needs MSVC for its own helper ports). CMake was
  installed via `winget` since it wasn't present. Ninja was also installed
  but the build ended up using `mingw32-make` (already present) instead.
- **Cisco ACL support is a deliberately bounded subset** (contiguous
  wildcard masks only; no `established`/precedence/tos/time-range/object-
  groups). Anything outside the subset is a hard parse error with a line
  number — the parser never silently ignores syntax it doesn't understand,
  since an anomaly analyzer that says "0 findings" over a policy it
  misunderstood is worse than one that refuses to run.
- **`iptables`/`nftables` support was deliberately deferred**, not
  half-implemented: their chains/jumps/connection-tracking state turn a
  rule list into a control-flow graph, which is a materially harder and
  riskier problem than the stateless 5-tuple model this version handles.

### Bugs found and fixed via the test suite

Two real classification bugs were caught while building the test suite
(not while writing the algorithm — the tests earned their keep):

1. Phase A originally flagged *any* partial pre-emption of a rule's
   traffic by an earlier conflicting rule as Shadowing. This double
   -reported the classic "specific exception before a general default"
   pattern as both Shadowing (critical) and Generalization (info) for the
   same rule pair. Fixed by restricting Shadowing/Redundancy to whole-rule
   unreachability only, matching the cited algorithm precisely.
2. A rule already found fully dead (shadowed/redundant) was still being
   paired against later live rules in the pairwise correlation/
   generalization check, producing findings that referenced a rule with
   zero real-world effect. Fixed by excluding dead rules from that pairing.

Both are now permanent regression tests in `tests/test_analysis.cpp`.

### Verification performed

Everything claimed in the README was actually run: `cmake --build`
succeeded, `fwlint_tests.exe` was run (125/125 assertions passing),
`fwlint analyze`/`simulate` were run against the hand-built example ACL,
the canonical JSON example, and two synthetic 300-rule benchmarks (one
mostly-disjoint, one deliberately pathological/overlapping) with real
measured wall-clock times. No metric, finding count, or timing number in
the README or `project.yaml` was invented.

### Remaining work / honest limitations

See the README's "Limitations" and "Future Enhancements" sections —
notably: no BDD backend, no `iptables`/`nftables`, IPv4 only, no fuzzing
or differential-testing infrastructure, and no CI pipeline has actually
run against this code yet (not pushed to GitHub in this task).
