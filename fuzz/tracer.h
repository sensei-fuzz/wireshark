#ifndef __TRACER_H__
#define __TRACER_H__

#include "hooks.h"
#include "fuzz_interface.h"
#include <stddef.h>
#include <iterator>
#include <vector>
#include <deque>
#include <unordered_map>
#include <type_traits>
#include <variant>
#include <boost/icl/interval_set.hpp>
#include <boost/icl/interval_map.hpp>

namespace fuzzer {

template <typename T>
class NodeIterator;

template <class U, typename = void>
class NodeChildren;

template <template <typename> class U, typename T>
class NodeChildren<U<T>, std::enable_if_t<std::is_base_of_v<NodeIterator<T>, U<T>>>>
{
public:
    NodeChildren(T* node) : m_node(node) {}
    NodeIterator<T> begin() const { return U<T>(m_node); }
    NodeIterator<T> end() const { return U<T>(nullptr); }

private:
    T* m_node;
};

template <typename T, typename U>
class TreeTraversal {
public:
    typedef bool (*ProcessNode)(T *node, size_t depth, U *data);
    typedef NodeChildren<NodeIterator<T>> (*GetChildren)(T *node);

    static void TraverseTreeBreadthFirst(
        T *root, ProcessNode process, GetChildren children, U *data);
};

template <>
class NodeIterator<proto_node> {
public:
    using iterator_category = std::forward_iterator_tag;
    using value_type = proto_node;
    using difference_type = std::ptrdiff_t;
    using pointer = value_type*;
    using reference = value_type&;

    NodeIterator(pointer ptr) : m_ptr(ptr) {}
    pointer operator*() const { return m_ptr; }

    NodeIterator& operator++() {
        if (m_ptr) m_ptr = m_ptr->next;
        return *this;
    }

    bool operator==(const NodeIterator& other) const {
        return m_ptr == other.m_ptr;
    }

    bool operator!=(const NodeIterator& other) const {
        return m_ptr != other.m_ptr;
    }

private:
    pointer m_ptr;
};

auto FieldInterval = [](size_t lower, size_t upper){
    return boost::icl::interval<size_t>::closed(lower, upper);
};
using FieldByteCoverage = boost::icl::interval_set<size_t>;
using FieldId = int;
struct FieldInfo {
    size_t count;
    size_t max_length;
    FieldByteCoverage bytes;
};

/* Storage reasons */
struct NewParseDepthReason {
    size_t old_depth;
    size_t new_depth;
};
struct NewFieldAtDepthReason {
    FieldId field;
    size_t depth;
};
struct HigherFieldCountReason {
    FieldId field;
    size_t old_count;
    size_t new_count;
};
struct HigherFieldLengthReason {
    FieldId field;
    size_t old_length;
    size_t new_length;
};
struct HigherInputByteCoverageReason {
    float old_ratio;
    float new_ratio;
};

using StorageReason = std::variant<
    struct NewParseDepthReason,
    struct NewFieldAtDepthReason,
    struct HigherFieldCountReason,
    struct HigherFieldLengthReason,
    struct HigherInputByteCoverageReason
>;
using StorageReasons = std::deque<StorageReason>;

using FieldMap = std::unordered_map<FieldId, FieldInfo>;
using DepthMap = std::vector<FieldMap>;
struct ParseTreeInfo {
    DepthMap depth_map;
    FieldMap field_map;
    float parsed_ratio = 0.0;
};

class Tracer {
public:
    Tracer();
    void RecordSingleDissection(const epan_dissect_t *edt);
    const StorageReasons & GetLastDissectionReasons() const
        { return last_dissection_reasons; }
    const ParseTreeInfo & GetLastDissectionInfo() const
        { return last_dissection_info; }

private:
    static ParseTreeInfo ExtractParseTreeInfo(const epan_dissect_t *edt);
    static bool RecordField(proto_node *node, size_t depth, DepthMap *map);
    static NodeChildren<NodeIterator<proto_node>> GetSubFields(proto_node *node);

    void UpdateGlobalInfo(const ParseTreeInfo &local_info);

    ParseTreeInfo global_info;
    ParseTreeInfo last_dissection_info;
    StorageReasons last_dissection_reasons;
};

extern Tracer FuzzTracer;
} // namespace fuzzer

#endif