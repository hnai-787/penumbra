#include <catch2/catch_test_macros.hpp>

#include "fwlint/interval.h"

using namespace fwlint;

TEST_CASE("interval_union merges overlapping and adjacent ranges", "[interval]") {
    IntervalSet a = {{0, 10}};
    IntervalSet b = {{5, 15}};
    IntervalSet result = interval_union(a, b);
    REQUIRE(result.size() == 1);
    REQUIRE(result[0].lo == 0);
    REQUIRE(result[0].hi == 15);

    IntervalSet c = {{0, 10}};
    IntervalSet d = {{11, 20}};  // adjacent, should merge
    result = interval_union(c, d);
    REQUIRE(result.size() == 1);
    REQUIRE(result[0].hi == 20);

    IntervalSet e = {{0, 10}};
    IntervalSet f = {{12, 20}};  // gap of one value, should NOT merge
    result = interval_union(e, f);
    REQUIRE(result.size() == 2);
}

TEST_CASE("interval_intersect finds overlap", "[interval]") {
    IntervalSet a = {{0, 10}, {20, 30}};
    IntervalSet b = {{5, 25}};
    IntervalSet result = interval_intersect(a, b);
    REQUIRE(result.size() == 2);
    REQUIRE(result[0].lo == 5);
    REQUIRE(result[0].hi == 10);
    REQUIRE(result[1].lo == 20);
    REQUIRE(result[1].hi == 25);
}

TEST_CASE("interval_intersect of disjoint sets is empty", "[interval]") {
    IntervalSet a = {{0, 10}};
    IntervalSet b = {{20, 30}};
    REQUIRE(interval_empty(interval_intersect(a, b)));
}

TEST_CASE("interval_subtract removes a middle chunk", "[interval]") {
    IntervalSet a = {{0, 100}};
    IntervalSet b = {{40, 60}};
    IntervalSet result = interval_subtract(a, b);
    REQUIRE(result.size() == 2);
    REQUIRE(result[0].lo == 0);
    REQUIRE(result[0].hi == 39);
    REQUIRE(result[1].lo == 61);
    REQUIRE(result[1].hi == 100);
}

TEST_CASE("interval_subtract of a superset yields empty", "[interval]") {
    IntervalSet a = {{10, 20}};
    IntervalSet b = {{0, 100}};
    REQUIRE(interval_empty(interval_subtract(a, b)));
}

TEST_CASE("interval_subtract of disjoint sets returns the original", "[interval]") {
    IntervalSet a = {{0, 10}};
    IntervalSet b = {{20, 30}};
    IntervalSet result = interval_subtract(a, b);
    REQUIRE(result == a);
}

TEST_CASE("interval_subset_of", "[interval]") {
    REQUIRE(interval_subset_of({{5, 10}}, {{0, 100}}));
    REQUIRE_FALSE(interval_subset_of({{5, 200}}, {{0, 100}}));
    REQUIRE(interval_subset_of({{0, 100}}, {{0, 100}}));  // equal sets are subsets
}

TEST_CASE("interval_contains", "[interval]") {
    IntervalSet a = {{0, 10}, {20, 30}};
    REQUIRE(interval_contains(a, 5));
    REQUIRE(interval_contains(a, 25));
    REQUIRE_FALSE(interval_contains(a, 15));
    REQUIRE_FALSE(interval_contains(a, 31));
}

TEST_CASE("full_range and single_value", "[interval]") {
    REQUIRE(interval_contains(full_range(65535), 0));
    REQUIRE(interval_contains(full_range(65535), 65535));
    IntervalSet single = single_value(443);
    REQUIRE(interval_contains(single, 443));
    REQUIRE_FALSE(interval_contains(single, 444));
}
