#ifndef FWLINT_PARSER_CISCO_H
#define FWLINT_PARSER_CISCO_H

#include <string>

#include "fwlint/model.h"

namespace fwlint {

// Parses a deliberately bounded subset of Cisco IOS/IOS XE extended IPv4
// ACL syntax:
//
//   access-list <100-199|2000-2699> <permit|deny> <protocol> <src> [src-port] <dst> [dst-port] [log]
//   ip access-list extended <name>
//    [seq] <permit|deny> <protocol> <src> [src-port] <dst> [dst-port] [log]
//
// where <src>/<dst> is "any", "host A.B.C.D", or "A.B.C.D W.X.Y.Z"
// (address + contiguous wildcard mask only), and the optional port clause
// is "eq|neq|gt|lt <port>" or "range <port> <port>" (numeric or a small
// set of well-known names: telnet, www, http, https, ftp, ssh, smtp,
// domain/dns).
//
// Anything outside this subset (discontiguous wildcard masks, "established",
// precedence/tos/time-range/reflexive keywords, object-groups, IPv6, etc.)
// is a hard parse error rather than a silently-ignored token: an anomaly
// analyzer must never report "0 findings" when it actually means "I didn't
// understand part of this policy". See README "Design decisions".
ParseResult parse_cisco_acl(const std::string& source, const std::string& fileName);

}  // namespace fwlint

#endif
