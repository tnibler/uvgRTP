#pragma once

#include <array>
#include <cstdint>
#include <functional>

// there is not reason to believe this is a particularly good way to hash 2 64
// bit values into one, but for use with std::unordered_set it will do.
namespace std {
template <> struct hash<array<uint64_t, 2>> {
  typedef array<uint64_t, 2> argument_type;
  typedef size_t result_type;

  result_type operator()(const argument_type &a) const {
    hash<uint64_t> hasher;
    result_type h = hasher(a[0]);
    h ^= 31 * hasher(a[1]);
    return h;
  }
};
} // namespace std
