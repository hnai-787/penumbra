#ifndef FWLINT_INTERVAL_H
#define FWLINT_INTERVAL_H

#include <cstdint>
#include <vector>

namespace fwlint {

// A closed integer interval [lo, hi]. Used as the building block for every
// field dimension (protocol, addresses, ports) in the packet-space algebra.
struct Interval {
    uint64_t lo;
    uint64_t hi;

    friend bool operator==(const Interval& a, const Interval& b) {
        return a.lo == b.lo && a.hi == b.hi;
    }
};

// A normalized IntervalSet is sorted by `lo` with no overlapping or
// touching intervals (adjacent intervals are merged). All functions below
// both expect and produce normalized sets.
using IntervalSet = std::vector<Interval>;

IntervalSet normalize(IntervalSet set);

IntervalSet interval_union(const IntervalSet& a, const IntervalSet& b);
IntervalSet interval_intersect(const IntervalSet& a, const IntervalSet& b);
// a \ b
IntervalSet interval_subtract(const IntervalSet& a, const IntervalSet& b);

bool interval_empty(const IntervalSet& a);
bool interval_contains(const IntervalSet& a, uint64_t value);
// true if every value in `a` is also in `b`
bool interval_subset_of(const IntervalSet& a, const IntervalSet& b);

// Picks the smallest value contained in the set. `a` must be non-empty.
uint64_t interval_pick(const IntervalSet& a);

IntervalSet full_range(uint64_t maxValueInclusive);
IntervalSet single_value(uint64_t value);

}  // namespace fwlint

#endif
