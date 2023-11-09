#include "hooks.h"
#include "tracer.h"
#include "ws_attributes.h"

extern "C" {

HOOK_PROTO_VOID(prologue,
epan_dissect_run,
    (epan_dissect_t *edt _U_, int file_type_subtype _U_, wtap_rec *rec _U_, tvbuff_t *tvb _U_,
    frame_data *fd _U_, column_info *cinfo _U_))
{
} /* HOOK prologue */

HOOK_PROTO_VOID(epilogue,
epan_dissect_run,
    (epan_dissect_t *edt, int file_type_subtype _U_, wtap_rec *rec _U_, tvbuff_t *tvb _U_,
    frame_data *fd _U_, column_info *cinfo _U_))
{
    fuzzer::FuzzTracer.RecordSingleDissection(edt);
} /* HOOK epilogue */

} /* extern "C" */