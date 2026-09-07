#include <catch2/catch_test_macros.hpp>

#include "fwlint/box.h"
#include "fwlint/model.h"

using namespace fwlint;

namespace {

// Builds a box for "tcp, src=srcCidr, any src port, dst=dstCidr, dst port dstPort".
Box make_box(const std::string& srcCidr, const std::string& dstCidr, uint16_t dstPort) {
    Box b;
    b.protocol = single_value(6);  // tcp
    b.srcAddr = *parse_cidr_or_any(srcCidr);
    b.srcPort = full_range(65535);
    b.dstAddr = *parse_cidr_or_any(dstCidr);
    b.dstPort = single_value(dstPort);
    return b;
}

Packet make_packet(const std::string& src, const std::string& dst, uint16_t dstPort) {
    Packet p;
    p.protocol = 6;
    p.srcAddr = *parse_ipv4(src);
    p.srcPort = 12345;
    p.dstAddr = *parse_ipv4(dst);
    p.dstPort = dstPort;
    return p;
}

}  // namespace

TEST_CASE("box_matches basic containment", "[box]") {
    Box b = make_box("10.0.0.0/24", "192.0.2.10/32", 443);
    REQUIRE(box_matches(b, make_packet("10.0.0.5", "192.0.2.10", 443)));
    REQUIRE_FALSE(box_matches(b, make_packet("10.0.1.5", "192.0.2.10", 443)));  // outside /24
    REQUIRE_FALSE(box_matches(b, make_packet("10.0.0.5", "192.0.2.10", 80)));   // wrong port
}

TEST_CASE("box_intersect: exact match yields the same box", "[box]") {
    Box a = make_box("10.0.0.0/24", "any", 443);
    Box b = make_box("10.0.0.0/24", "any", 443);
    Box i = box_intersect(a, b);
    REQUIRE_FALSE(box_empty(i));
    REQUIRE(i.srcAddr == a.srcAddr);
}

TEST_CASE("box_intersect: disjoint boxes produce an empty box", "[box]") {
    Box a = make_box("10.0.0.0/24", "any", 443);
    Box b = make_box("10.0.1.0/24", "any", 443);
    REQUIRE(box_empty(box_intersect(a, b)));
}

TEST_CASE("box_intersect: subset/superset relation", "[box]") {
    Box broad = make_box("10.0.0.0/16", "any", 443);
    Box narrow = make_box("10.0.5.0/24", "any", 443);
    Box i = box_intersect(broad, narrow);
    REQUIRE(i.srcAddr == narrow.srcAddr);  // narrow ⊆ broad, so intersection == narrow
}

TEST_CASE("box_intersect: partial overlap", "[box]") {
    Box a = make_box("10.0.0.0/24", "any", 443);  // .0 - .255
    Box b;
    b.protocol = single_value(6);
    b.srcAddr = IntervalSet{{*parse_ipv4("10.0.0.128"), *parse_ipv4("10.0.1.128")}};
    b.srcPort = full_range(65535);
    b.dstAddr = full_range(0xFFFFFFFFULL);
    b.dstPort = single_value(443);

    Box i = box_intersect(a, b);
    REQUIRE_FALSE(box_empty(i));
    // Overlap should be exactly 10.0.0.128 - 10.0.0.255
    REQUIRE(i.srcAddr.size() == 1);
    REQUIRE(i.srcAddr[0].lo == *parse_ipv4("10.0.0.128"));
    REQUIRE(i.srcAddr[0].hi == *parse_ipv4("10.0.0.255"));
}

TEST_CASE("box_subtract: a fully inside b yields nothing", "[box]") {
    Box a = make_box("10.0.5.0/24", "any", 443);
    Box b = make_box("10.0.0.0/16", "any", 443);
    std::vector<Box> pieces = box_subtract(a, b);
    REQUIRE(pieces.empty());
}

TEST_CASE("box_subtract: disjoint boxes yield a itself", "[box]") {
    Box a = make_box("10.0.0.0/24", "any", 443);
    Box b = make_box("10.0.1.0/24", "any", 443);
    std::vector<Box> pieces = box_subtract(a, b);
    REQUIRE(pieces.size() == 1);
    REQUIRE(pieces[0].srcAddr == a.srcAddr);
}

TEST_CASE("box_subtract: partial overlap splits correctly and union equals a\\b", "[box]") {
    // a: ports 0-100, b: ports 50-200. Only the address dimension differs.
    Box a = make_box("10.0.0.0/24", "any", 443);
    a.dstPort = IntervalSet{{0, 100}};
    Box b = make_box("10.0.0.0/24", "any", 443);
    b.dstPort = IntervalSet{{50, 200}};

    std::vector<Box> pieces = box_subtract(a, b);
    REQUIRE_FALSE(pieces.empty());

    // Verify every value in a\b (ports 0-49) is covered by exactly the pieces,
    // and nothing in b's ports (50-200) leaks through.
    for (const Box& piece : pieces) {
        REQUIRE_FALSE(box_empty(piece));
        for (const Interval& iv : piece.dstPort) {
            REQUIRE(iv.hi < 50);
        }
    }

    Packet stillThere = make_packet("10.0.0.1", "10.0.0.1", 0);
    stillThere.dstPort = 20;
    bool matchedSomePiece = false;
    for (const Box& piece : pieces) matchedSomePiece = matchedSomePiece || box_matches(piece, stillThere);
    REQUIRE(matchedSomePiece);

    Packet removed = stillThere;
    removed.dstPort = 75;  // in b's range, must NOT appear in a\b
    for (const Box& piece : pieces) REQUIRE_FALSE(box_matches(piece, removed));
}

TEST_CASE("PacketSet subtract across a union of boxes (collective coverage)", "[box]") {
    // R1 covers the left half of a port range, R2 the right half; together
    // they should fully cover a third box spanning the whole range.
    Box r1 = make_box("10.0.0.0/24", "any", 443);
    r1.dstPort = IntervalSet{{0, 100}};
    Box r2 = make_box("10.0.0.0/24", "any", 443);
    r2.dstPort = IntervalSet{{101, 200}};
    Box r3 = make_box("10.0.0.0/24", "any", 443);
    r3.dstPort = IntervalSet{{0, 200}};

    PacketSet covered = {r1, r2};
    PacketSet effective = ps_subtract_set(PacketSet{r3}, covered);
    REQUIRE(ps_empty(effective));  // fully covered collectively, though neither r1 nor r2 alone covers r3
    REQUIRE_FALSE(ps_empty(ps_subtract_box(PacketSet{r3}, r1)));  // r1 alone does NOT cover r3
    REQUIRE_FALSE(ps_empty(ps_subtract_box(PacketSet{r3}, r2)));  // nor does r2 alone
}

TEST_CASE("box_pick_witness returns a packet the box actually matches", "[box]") {
    Box b = make_box("10.0.0.0/24", "192.0.2.10/32", 443);
    Packet w;
    REQUIRE(box_pick_witness(b, w));
    REQUIRE(box_matches(b, w));
}

TEST_CASE("box_pick_witness fails on an empty box", "[box]") {
    Box empty = make_box("10.0.0.0/24", "any", 443);
    empty.srcAddr = {};  // force empty
    Packet w;
    REQUIRE_FALSE(box_pick_witness(empty, w));
}
