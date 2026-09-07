#ifndef FWLINT_REPORT_H
#define FWLINT_REPORT_H

#include <string>

#include "fwlint/analysis.h"
#include "fwlint/model.h"

namespace fwlint {

std::string render_text(const Policy& policy, const AnalysisResult& result);
std::string render_json(const Policy& policy, const AnalysisResult& result);
// A minimal, valid SARIF 2.1.0 log (one run, one tool driver, one result
// per finding). Not every optional SARIF property is populated -- see
// README "Design decisions" for what's covered.
std::string render_sarif(const Policy& policy, const AnalysisResult& result);

}  // namespace fwlint

#endif
