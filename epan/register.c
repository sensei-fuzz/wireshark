/* register.c
 * Definitions for protocol registration
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "register-int.h"
#include "ws_attributes.h"

#include <glib.h>

#include <epan/exceptions.h>

#include "epan/dissectors/dissectors.h"

void
register_all_protocols(register_cb cb, gpointer cb_data)
{
    const char *cb_name;
    volatile gboolean called_back = FALSE;

    for (gulong i = 0; i < dissector_reg_proto_count; i++) {
        cb_name = dissector_reg_proto[i].cb_name;
        dissector_reg_proto[i].cb_func();
        if (cb && cb_name) {
            cb(RA_REGISTER, cb_name, cb_data);
            called_back = TRUE;
        }
    }
    if (cb && !called_back) {
        cb(RA_REGISTER, "finished", cb_data);
    }
}

void
register_all_protocol_handoffs(register_cb cb, gpointer cb_data)
{
    const char *cb_name;
    gboolean called_back = FALSE;

    for (gulong i = 0; i < dissector_reg_handoff_count; i++) {
        cb_name = dissector_reg_handoff[i].cb_name;
        dissector_reg_handoff[i].cb_func();
        if (cb && cb_name) {
            cb(RA_HANDOFF, cb_name, cb_data);
            called_back = TRUE;
        }
    }
    if (cb && !called_back) {
        cb(RA_HANDOFF, "finished", cb_data);
    }
}

gulong register_count(void)
{
    return dissector_reg_proto_count + dissector_reg_handoff_count;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
