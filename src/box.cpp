#include "fwlint/box.h"

namespace fwlint {

bool box_empty(const Box& b) {
    return interval_empty(b.protocol) || interval_empty(b.srcAddr) ||
           interval_empty(b.srcPort) || interval_empty(b.dstAddr) ||
           interval_empty(b.dstPort);
}

bool box_matches(const Box& b, const Packet& p) {
    return interval_contains(b.protocol, p.protocol) &&
           interval_contains(b.srcAddr, p.srcAddr) &&
           interval_contains(b.srcPort, p.srcPort) &&
           interval_contains(b.dstAddr, p.dstAddr) &&
           interval_contains(b.dstPort, p.dstPort);
}

Box box_intersect(const Box& a, const Box& b) {
    Box out;
    out.protocol = interval_intersect(a.protocol, b.protocol);
    out.srcAddr = interval_intersect(a.srcAddr, b.srcAddr);
    out.srcPort = interval_intersect(a.srcPort, b.srcPort);
    out.dstAddr = interval_intersect(a.dstAddr, b.dstAddr);
    out.dstPort = interval_intersect(a.dstPort, b.dstPort);
    return out;
}

namespace {

// Pointer-to-member lets us iterate the five dimensions with one function
// instead of five nearly-identical hand copies.
using Field = IntervalSet Box::*;
constexpr Field kFields[5] = {&Box::protocol, &Box::srcAddr, &Box::srcPort,
                               &Box::dstAddr, &Box::dstPort};

}  // namespace

std::vector<Box> box_subtract(const Box& a, const Box& b) {
    if (box_empty(a)) {
        return {};
    }

    Box overlap = box_intersect(a, b);
    if (box_empty(overlap)) {
        return {a};  // a and b share no packets at all; nothing to remove
    }

    std::vector<Box> result;
    Box remaining = a;

    for (Field field : kFields) {
        const IntervalSet& remDim = remaining.*field;
        const IntervalSet& bDim = b.*field;

        IntervalSet outside = interval_subtract(remDim, bDim);
        IntervalSet inside = interval_intersect(remDim, bDim);

        if (!interval_empty(outside)) {
            Box piece = remaining;
            piece.*field = outside;
            result.push_back(std::move(piece));
        }

        remaining.*field = std::move(inside);
    }

    // `remaining` now equals a ∩ b exactly, which is intentionally excluded.
    return result;
}

bool box_pick_witness(const Box& b, Packet& out) {
    if (box_empty(b)) {
        return false;
    }
    out.protocol = static_cast<uint8_t>(interval_pick(b.protocol));
    out.srcAddr = static_cast<uint32_t>(interval_pick(b.srcAddr));
    out.srcPort = static_cast<uint16_t>(interval_pick(b.srcPort));
    out.dstAddr = static_cast<uint32_t>(interval_pick(b.dstAddr));
    out.dstPort = static_cast<uint16_t>(interval_pick(b.dstPort));
    return true;
}

bool ps_empty(const PacketSet& s) {
    for (const Box& b : s) {
        if (!box_empty(b)) {
            return false;
        }
    }
    return true;
}

PacketSet ps_subtract_box(const PacketSet& s, const Box& b) {
    PacketSet result;
    for (const Box& box : s) {
        std::vector<Box> pieces = box_subtract(box, b);
        for (Box& piece : pieces) {
            if (!box_empty(piece)) {
                result.push_back(std::move(piece));
            }
        }
    }
    return result;
}

PacketSet ps_subtract_set(const PacketSet& s, const PacketSet& other) {
    PacketSet result = s;
    for (const Box& b : other) {
        result = ps_subtract_box(result, b);
        if (result.empty()) {
            break;
        }
    }
    return result;
}

PacketSet ps_intersect_set(const PacketSet& s, const PacketSet& other) {
    PacketSet result;
    for (const Box& a : s) {
        for (const Box& b : other) {
            Box i = box_intersect(a, b);
            if (!box_empty(i)) {
                result.push_back(std::move(i));
            }
        }
    }
    return result;
}

bool ps_pick_witness(const PacketSet& s, Packet& out) {
    for (const Box& b : s) {
        if (box_pick_witness(b, out)) {
            return true;
        }
    }
    return false;
}

}  // namespace fwlint
