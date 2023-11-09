#include <stddef.h>

namespace fuzzer {

struct ParseTreeMetrics {
    size_t parse_tree_depth;
    size_t parse_tree_size;
    size_t unique_field_count;
    float parsed_input_ratio;
};

bool IsDissectionInteresting();
ParseTreeMetrics GetDissectionMetrics();

} // namespace fuzzer