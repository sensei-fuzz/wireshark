#include "tracer.h"

#include <iostream>
#include <iomanip>

namespace fuzzer {

Tracer::Tracer() {}

ParseTreeInfo
Tracer::ExtractParseTreeInfo(const epan_dissect_t *edt) {
    ParseTreeInfo info;
    FieldByteCoverage parsed_bytes;

    /* record fields into the local depth map */
    TreeTraversal<proto_node, DepthMap>::TraverseTreeBreadthFirst(
        edt->tree, RecordField, GetSubFields, &info.depth_map);

    /* aggregate field info */
    for (auto &level : info.depth_map) {
        for (auto &pair : level) {
            auto &field_id = pair.first;
            auto &field = pair.second;
            auto &agg =
                (*(info.field_map.try_emplace(field_id).first)).second;
            agg.count += field.count;
            agg.max_length = std::max(agg.max_length, field.max_length);
            agg.bytes += field.bytes;
        }
    }

    for (auto &field : info.field_map)
        parsed_bytes += field.second.bytes;

    size_t input_length = tvb_captured_length(edt->tvb);
    if (input_length > 0)
        info.parsed_ratio = parsed_bytes.size() / (float)input_length;

    return info;
}

NodeChildren<NodeIterator<proto_node>>
Tracer::GetSubFields(proto_node *node) {
    return NodeChildren<NodeIterator<proto_node>>(node->first_child);
}

bool
Tracer::RecordField(proto_node *node, size_t depth, DepthMap *map) {
    auto finfo = node->finfo;
    if (finfo) {
        auto hfinfo = finfo->hfinfo;
        if (strcmp(hfinfo->abbrev, "data") != 0 && /* data is unparsed bytes */
                strstr(hfinfo->abbrev, "_ws.") != hfinfo->abbrev) {
            FieldId id = hfinfo->id;
            size_t len = finfo->length;

            --depth; /* depth 0 has no finfo, it seems */
            FieldMap &level = [&]() -> FieldMap& {
                if (depth < map->size())
                    return (*map)[depth];
                else if (depth == map->size()) {
                    return map->emplace_back();
                } else
                    throw;
            }();
            auto &record = (*(level.try_emplace(id).first)).second;
            record.count += 1;
            record.max_length = std::max(record.max_length, len);
            auto finterval = FieldInterval(
                finfo->start, finfo->start + finfo->length - 1);
            record.bytes += finterval;
        }
    }

    return false;
}

void
Tracer::RecordSingleDissection(const epan_dissect_t *edt) {
    last_dissection_info = ExtractParseTreeInfo(edt);
    UpdateGlobalInfo(last_dissection_info);

#if 0
    auto metrics = GetDissectionMetrics();
    std::cout << "Dissection info:"
              << " depth: " << metrics.parse_tree_depth
              << " size: " << metrics.parse_tree_size
              << " unique: " << metrics.unique_field_count
              << std::fixed
              << " ratio: " << metrics.parsed_input_ratio
              << std::endl;
#endif
}

void
Tracer::UpdateGlobalInfo(const ParseTreeInfo &local_info)
{
    /* TODO
     * Walk the local and global depth maps and record changes in:
     *   - total depth
     *   - new fields at each depth
     *   - field count increases
     *   - field length increases
     */
    StorageReasons reasons;

    /* First, we check if the total depth is already better */
    if (local_info.depth_map.size() > global_info.depth_map.size())
        reasons.push_back(NewParseDepthReason {
            .old_depth = global_info.depth_map.size(),
            .new_depth = local_info.depth_map.size()
        });

    /* Second, we check if, at each depth, whether a new field is found*/
    for (size_t depth = 0; auto &local_level : local_info.depth_map) {
        FieldMap &global_level = [&]() -> FieldMap& {
            if (depth < global_info.depth_map.size())
                return global_info.depth_map[depth];
            else if (depth == global_info.depth_map.size()) {
                return global_info.depth_map.emplace_back();
            } else
                throw;
        }();
        for (auto &pair : local_level) {
            auto &field_id = pair.first;
            auto &local_field _U_ = pair.second;
            auto result = global_level.try_emplace(field_id);
            if (result.second) /* is_new_field */
                reasons.push_back(NewFieldAtDepthReason {
                    .field = field_id,
                    .depth = depth
                });
        }
        ++depth;
    }

    /* Third, we check if the aggregate results are higher */
    for (auto &pair : local_info.field_map) {
        auto &field_id = pair.first;
        auto &local_field = pair.second;
        auto &global_field =
            (*(global_info.field_map.try_emplace(field_id).first)).second;
        if (local_field.count > global_field.count) {
            reasons.push_back(HigherFieldCountReason {
                .field = field_id,
                .old_count = global_field.count,
                .new_count = local_field.count,
            });
            global_field.count = local_field.count;
        }
        if (local_field.max_length > global_field.max_length) {
            reasons.push_back(HigherFieldLengthReason {
                .field = field_id,
                .old_length = global_field.max_length,
                .new_length = local_field.max_length,
            });
            global_field.max_length = local_field.max_length;
        }
    }

    if (local_info.parsed_ratio > global_info.parsed_ratio) {
        reasons.push_back(HigherInputByteCoverageReason {
            .old_ratio = global_info.parsed_ratio,
            .new_ratio = local_info.parsed_ratio,
        });
    }

    /* Update the reasons for retrieval by libFuzzer */
    last_dissection_reasons = reasons;
}

template <typename T, typename U>
void
TreeTraversal<T,U>::TraverseTreeBreadthFirst
(T *root, ProcessNode process, GetChildren children, U *data) {
    typedef struct {
        T *node;
        size_t depth;
    } item;
    std::deque<item> queue = {{.node = root, .depth = 0}};
    for (; !queue.empty(); queue.pop_front()) {
        item &current = queue.front();
        for (T *child : children(current.node)) {
            queue.push_back(std::move(
                item {.node = child, .depth = current.depth + 1}));
        }
        if (process(current.node, current.depth, data))
            break;
    }
}

/****************************
 * Fuzzer interface functions
 ****************************/

bool
IsDissectionInteresting() {
    return FuzzTracer.GetLastDissectionReasons().size() > 0;
}

const StorageReasons &
GetStorageReasons() {
    return FuzzTracer.GetLastDissectionReasons();
}

ParseTreeMetrics
GetDissectionMetrics() {
    auto &dissection_info = FuzzTracer.GetLastDissectionInfo();
    ParseTreeMetrics metrics {
        .parse_tree_depth = dissection_info.depth_map.size(),
        .unique_field_count = dissection_info.field_map.size(),
        .parsed_input_ratio = dissection_info.parsed_ratio
    };
    if (metrics.parse_tree_depth)
        --metrics.parse_tree_depth;

    /* sum the number of fields from each level */
    for (auto &level : dissection_info.depth_map) {
        for (auto &pair : level) {
            auto &field = pair.second;
            metrics.parse_tree_size += field.count;
        }
    }

    return metrics;
}

template class TreeTraversal<proto_node, fuzzer::Tracer>;
Tracer FuzzTracer;
} // namespace fuzzer
