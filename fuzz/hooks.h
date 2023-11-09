#ifndef __HOOKS_H__
#define __HOOKS_H__

#include "epan/epan.h"
#include "epan/epan_dissect.h"
#include "epan/column-info.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef ENABLE_FUZZER
#define WRAPPED(fn) wrapped_##fn
#define WRAPPER(fn) fn
#else
#define WRAPPED(fn) fn
#define WRAPPER(fn) unused_##fn
#endif

#define HOOK(tag, fn) fn##_##tag##_hook
#define EXPAND(...) __VA_ARGS__
#define HOOK_PROTO(tag, rettype, fn, args) \
    void HOOK(tag, fn)(EXPAND args, rettype retval)
#define HOOK_PROTO_VOID(tag, fn, args) \
    void HOOK(tag, fn)(EXPAND args)

#define DECLARE_HOOKS(rettype, fn, args) \
    HOOK_PROTO(prologue, rettype, fn, args); \
    HOOK_PROTO(epilogue, rettype, fn, args);
#define DECLARE_HOOKS_VOID(fn, args) \
    HOOK_PROTO_VOID(prologue, fn, args); \
    HOOK_PROTO_VOID(epilogue, fn, args);

DECLARE_HOOKS_VOID(epan_dissect_run,
    (epan_dissect_t *edt, int file_type_subtype, wtap_rec *rec, tvbuff_t *tvb,
    frame_data *fd, column_info *cinfo))

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif