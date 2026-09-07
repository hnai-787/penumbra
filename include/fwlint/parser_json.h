#ifndef FWLINT_PARSER_JSON_H
#define FWLINT_PARSER_JSON_H

#include <string>

#include "fwlint/model.h"

namespace fwlint {

// Parses fwlint's canonical policy format:
//
// {
//   "default_action": "deny",
//   "rules": [
//     { "id": "10", "action": "allow", "protocol": ["tcp"],
//       "source": ["10.0.0.0/24"], "source_port": ["any"],
//       "destination": ["192.0.2.10/32"], "destination_port": ["443"] }
//   ]
// }
//
// Every rule field accepts either a single string or an array of strings
// (values within one field are OR'd together; fields are AND'd, matching
// how a single rule/box is a conjunction of per-field sets).
ParseResult parse_canonical_json(const std::string& source, const std::string& fileName);

}  // namespace fwlint

#endif
