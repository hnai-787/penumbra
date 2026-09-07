#ifndef FWLINT_BOX_H
#define FWLINT_BOX_H

#include <cstdint>
#include <vector>

#include "fwlint/interval.h"

namespace fwlint {

enum class Action { Allow, Deny };

// A Box is an axis-aligned hyperrectangle in the 5-dimensional packet space
// (protocol x srcAddr x srcPort x dstAddr x dstPort). Every individual rule
// compiles to exactly one Box: each field of a rule is itself a set of
// allowed values (e.g. protocol in {tcp, udp}), and the rule as a whole is
// the conjunction ("AND") of those per-field sets, which is precisely what
// a Box represents.
//
// This plays the same role in this project that a Binary Decision Diagram
// (BDD) plays in tools like FIREMAN or Batfish: an exact, symbolic
// representation of "the set of all packets matching X", without ever
// enumerating packets. We use box decomposition instead of a BDD library
// because no BDD package (e.g. CUDD) is available in this build
// environment without a package manager; box decomposition is slower on
// pathological inputs but produces exactly the same set-theoretic answer
// for the rule-set sizes this project targets (tens to low hundreds of
// rules). See README.md "Design decisions" for the full rationale.
struct Box {
    IntervalSet protocol;  // 0..255
    IntervalSet srcAddr;   // 0..2^32-1
    IntervalSet srcPort;   // 0..65535
    IntervalSet dstAddr;   // 0..2^32-1
    IntervalSet dstPort;   // 0..65535
};

struct Packet {
    uint8_t protocol = 0;
    uint32_t srcAddr = 0;
    uint16_t srcPort = 0;
    uint32_t dstAddr = 0;
    uint16_t dstPort = 0;
};

bool box_empty(const Box& b);
bool box_matches(const Box& b, const Packet& p);
Box box_intersect(const Box& a, const Box& b);

// Returns a \ b as a list of pairwise-disjoint, individually non-empty
// boxes whose union is exactly a \ b. Uses the standard axis-slicing
// decomposition: for each dimension in turn, split off the part of the
// current remainder that lies entirely outside b in that dimension (which
// is therefore guaranteed disjoint from b), then shrink the remainder to
// the intersection in that dimension and continue to the next. After all
// dimensions are processed the remainder equals a ∩ b exactly, which is
// correctly excluded from the result.
std::vector<Box> box_subtract(const Box& a, const Box& b);

// Picks one concrete packet inside a non-empty box. Returns false if b is
// empty.
bool box_pick_witness(const Box& b, Packet& out);

// A PacketSet is a union of boxes (not required to be pre-merged/disjoint;
// every operation below is correct regardless of overlap between the
// boxes it's given, though `ps_empty` and callers assume no box in the
// vector is itself empty).
using PacketSet = std::vector<Box>;

bool ps_empty(const PacketSet& s);
PacketSet ps_subtract_box(const PacketSet& s, const Box& b);
// s \ (union of other) -- applies subtraction sequentially, which is
// set-theoretically equivalent to subtracting the union in one step.
PacketSet ps_subtract_set(const PacketSet& s, const PacketSet& other);
PacketSet ps_intersect_set(const PacketSet& s, const PacketSet& other);
bool ps_pick_witness(const PacketSet& s, Packet& out);

}  // namespace fwlint

#endif
