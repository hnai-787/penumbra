#include "fwlint/interval.h"

#include <algorithm>

namespace fwlint {

IntervalSet normalize(IntervalSet set) {
    std::sort(set.begin(), set.end(), [](const Interval& a, const Interval& b) {
        return a.lo < b.lo;
    });

    IntervalSet result;
    for (const Interval& iv : set) {
        if (iv.lo > iv.hi) {
            continue;
        }
        if (!result.empty() && iv.lo <= result.back().hi + 1) {
            result.back().hi = std::max(result.back().hi, iv.hi);
        } else {
            result.push_back(iv);
        }
    }
    return result;
}

IntervalSet interval_union(const IntervalSet& a, const IntervalSet& b) {
    IntervalSet combined = a;
    combined.insert(combined.end(), b.begin(), b.end());
    return normalize(std::move(combined));
}

IntervalSet interval_intersect(const IntervalSet& a, const IntervalSet& b) {
    IntervalSet result;
    size_t i = 0, j = 0;
    while (i < a.size() && j < b.size()) {
        uint64_t lo = std::max(a[i].lo, b[j].lo);
        uint64_t hi = std::min(a[i].hi, b[j].hi);
        if (lo <= hi) {
            result.push_back({lo, hi});
        }
        if (a[i].hi < b[j].hi) {
            ++i;
        } else {
            ++j;
        }
    }
    return result;  // already sorted and disjoint by construction
}

// Note: every dimension we use this on is bounded well below UINT64_MAX
// (protocol <= 255, ports <= 65535, IPv4 addresses <= 2^32-1), so `hi + 1`
// below never overflows in practice.
IntervalSet interval_subtract(const IntervalSet& a, const IntervalSet& b) {
    IntervalSet result;
    size_t startJ = 0;
    for (const Interval& iv : a) {
        uint64_t cursor = iv.lo;

        size_t k = startJ;
        while (k < b.size() && b[k].hi < cursor) {
            ++k;
        }
        startJ = k;

        while (k < b.size() && b[k].lo <= iv.hi && cursor <= iv.hi) {
            if (b[k].lo > cursor) {
                result.push_back({cursor, b[k].lo - 1});
            }
            if (b[k].hi >= cursor) {
                cursor = b[k].hi + 1;
            }
            ++k;
        }

        if (cursor <= iv.hi) {
            result.push_back({cursor, iv.hi});
        }
    }
    return normalize(std::move(result));
}

bool interval_empty(const IntervalSet& a) {
    return a.empty();
}

bool interval_contains(const IntervalSet& a, uint64_t value) {
    // Binary search for the first interval whose hi >= value.
    size_t lo = 0, hi = a.size();
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (a[mid].hi < value) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo < a.size() && a[lo].lo <= value && value <= a[lo].hi;
}

bool interval_subset_of(const IntervalSet& a, const IntervalSet& b) {
    return interval_empty(interval_subtract(a, b));
}

uint64_t interval_pick(const IntervalSet& a) {
    return a.front().lo;
}

IntervalSet full_range(uint64_t maxValueInclusive) {
    return IntervalSet{{0, maxValueInclusive}};
}

IntervalSet single_value(uint64_t value) {
    return IntervalSet{{value, value}};
}

}  // namespace fwlint
