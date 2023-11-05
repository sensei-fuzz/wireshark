/* dependump.c
 * Shows the dependencies among protocol dissectors.
 */

#include <config.h>
#define WS_LOG_DOMAIN  LOG_DOMAIN_MAIN

#include <stdlib.h>
#include <stdio.h>
#include <locale.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

#include <ws_exit_codes.h>

#include <epan/epan.h>
#include <epan/timestamp.h>
#include <epan/prefs.h>
#include <epan/register.h>
#include <epan/proto.h>
#include <epan/packet.h>

#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif
#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#include <wsutil/report_message.h>
#include <wsutil/wslog.h>
#include <wsutil/ws_getopt.h>

#include <wiretap/wtap.h>

#include "ui/util.h"
#include "wsutil/cmdarg_err.h"
#include "ui/failure_message.h"
#include "wsutil/version_info.h"

typedef struct {
    const char *parser_name;
    protocol_t *proto;
    GList *dissector_tables;
    GList *heur_tables;
} tracked_protocol_t;

typedef struct {
    const char *table_name;
    dissector_table_t tbl;
} tracked_dissector_table_t;

typedef struct {
    const char *table_name;
    heur_dissector_list_t tbl;
} tracked_heur_table_t;

typedef struct {
    GHashTable *parsers;
    GHashTable *protocols;
    GHashTable *visited;
} dependencies_t;

static int opt_verbose = 0;
#define DEPENDUMP_LOG_NONE     0
#define DEPENDUMP_LOG_NOISY    1
static int opt_log_level = DEPENDUMP_LOG_NONE;

static void
dependump_tracked_protocol_free(tracked_protocol_t *tp)
{
    g_list_free_full(tp->dissector_tables, g_free);
    g_list_free_full(tp->heur_tables, g_free);
    g_free(tp);
}

/*
 * Report an error in command-line arguments.
 */
static void
dependump_cmdarg_err(const char *fmt, va_list ap)
{
    fprintf(stderr, "dependump: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
}

/*
 * Report additional information for an error in command-line arguments.
 */
static void
dependump_cmdarg_err_cont(const char *fmt, va_list ap)
{
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
}

WS_NORETURN static void
print_usage(int status)
{
    FILE *fp = stdout;
    fprintf(fp, "\n");
    fprintf(fp, "Usage: dependump [OPTIONS] -- PROTOCOL\n");
    fprintf(fp, "Options:\n");
    fprintf(fp, "  -V, --verbose       enable verbose mode\n");
    fprintf(fp, "  -d, --debug         enable compiler debug logs\n");
    fprintf(fp, "  -h, --help          display this help and exit\n");
    fprintf(fp, "  -v, --version       print version\n");
    fprintf(fp, "\n");
    ws_log_print_usage(fp);
    exit(status);
}

static void
register_callback(register_action_e action, const char *name, gpointer client_data)
{
    dependencies_t *dep = (dependencies_t *)client_data;
    void *cookie;
    switch (action) {
    case RA_REGISTER:
        name = name + strlen("proto_register_");
        // printf("RA_REGISTER: %s\n", name);
        for (int id = proto_get_first_protocol(&cookie); \
                id != -1; \
                id = proto_get_next_protocol(&cookie)) {
            protocol_t *proto = find_protocol_by_id(id);
            const char *protocol = proto_get_protocol_filter_name(id);
            if (!protocol || \
                    g_hash_table_contains(dep->visited, protocol))
                continue;
            g_hash_table_add(dep->visited, protocol);

            tracked_protocol_t *tp = g_new0(tracked_protocol_t, 1);
            tp->parser_name = name;
            tp->proto = proto;

            g_hash_table_insert(dep->protocols, protocol, tp);
            GList *list = g_hash_table_lookup(dep->parsers, name);
            list = g_list_append(list, tp);
            g_hash_table_insert(dep->parsers, name, list);
        }
        break;
    case RA_HANDOFF:
        name = name + strlen("proto_reg_handoff_");
        // printf("RA_HANDOFF: %s\n", name);
        break;
    default:
        break;
    }
}

static void
print_protocols(gpointer key, gpointer value, gpointer user_data _U_)
{
    const char *parser_name = (const char *)key;
    GList *list = value;
    printf("%s: ", parser_name);
    for (GList *i = list; i != NULL; i = i->next) {
        tracked_protocol_t *tp = i->data;
        int id = proto_get_id(tp->proto);
        const char *protocol = proto_get_protocol_filter_name(id);
        printf("%s ", protocol);
    }
    puts("");
}

#if 0
static void
print_deps_for_protocol_func(gpointer data, gpointer user_data)
{
    const char *pn = (const char *) data;
    int id = proto_get_id_by_short_name(pn);
    void **args = user_data;
    const char *parent = (const char *) args[0];
    dependencies_t *dep = (dependencies_t *)args[1];
    const char *dependant = proto_get_protocol_filter_name(id);
    if (dependant && strcmp("(none)", dependant)) {
        const char *parent_parser = g_hash_table_lookup(dep->protocols, parent);
        const char *dep_parser = g_hash_table_lookup(dep->protocols, dependant);
        printf("\t%s->%s\n", parent_parser, dep_parser);
    }
}

static void
print_deps_for_protocol(gpointer data, gpointer user_data)
{
    tracked_protocol_t *tp = data;
    protocol_t *proto = tp->proto;
    int id = proto_get_id(proto);
    const char *protocol = proto_get_protocol_filter_name(id);

    if (proto_is_pino(proto))
        return;

    const char *pn = proto_get_protocol_short_name(proto);
    depend_dissector_list_t dependants = find_depend_dissector_list(pn);
    if (dependants) {
        GList **plist = (GList **) dependants;
        gpointer args[] = {protocol, user_data};
        g_list_foreach(*plist, print_deps_for_protocol_func, &args);
    }
}
#endif

static void
print_deps_from_dtbl_entry(const gchar *table_name, ftenum_t selector_type,
    gpointer key, gpointer value, gpointer user_data)
{
    struct dtbl_entry {
        dissector_handle_t initial;
        dissector_handle_t current;
    } *dtbl_entry = value;
    dissector_handle_t handle = dtbl_entry->current;
    void **args = user_data;
    const char *parent_parser = args[0];
    dependencies_t *dep = args[1];

    int id = dissector_handle_get_protocol_index(handle);
    const char *protocol = proto_get_protocol_filter_name(id);
    if (!protocol) {
        const char *desc = dissector_handle_get_description(handle);
        fprintf(stderr, "Failed to find protocol for dissector with description: %s\n", desc);
        return;
    }
    tracked_protocol_t *tp = g_hash_table_lookup(dep->protocols, protocol);
    if (!tp) {
        fprintf(stderr, "Failed to find tracked protocol for dissector protocol: %s\n", protocol);
        return;
    }
    const char *dep_parser = tp->parser_name;
    printf("\t\t%s->%s\n", parent_parser, dep_parser);

}

static void
print_deps_from_heur_dtbl_entry(const gchar *table_name,
    struct heur_dtbl_entry *dtbl_entry, gpointer user_data)
{
    heur_dissector_t handle = dtbl_entry->dissector;
    void **args = user_data;
    const char *parent_parser = args[0];
    dependencies_t *dep = args[1];

    int id = proto_get_id(dtbl_entry->protocol);
    const char *protocol = proto_get_protocol_filter_name(id);
    if (!protocol) {
        fprintf(stderr, "Failed to find protocol for heur dissector: %s\n", dtbl_entry->short_name);
        return;
    }
    tracked_protocol_t *tp = g_hash_table_lookup(dep->protocols, protocol);
    if (!tp) {
        fprintf(stderr, "Failed to find tracked protocol for heur dissector protocol: %s\n", protocol);
        return;
    }
    const char *dep_parser = tp->parser_name;
    printf("\t\t%s->%s\n", parent_parser, dep_parser);

}

static void
print_deps_from_dissector_table(gpointer data, gpointer user_data)
{
    tracked_dissector_table_t *tt = data;
    printf("\t%s:\n", tt->table_name);
    dissector_table_foreach(tt->table_name, print_deps_from_dtbl_entry, user_data);
}

static void
print_deps_from_heur_table(gpointer data, gpointer user_data)
{
    tracked_heur_table_t *tt = data;
    printf("\t%s[heur]:\n", tt->table_name);
    heur_dissector_table_foreach(tt->table_name, print_deps_from_heur_dtbl_entry, user_data);
}

static void
print_deps_for_protocol(gpointer data, gpointer user_data)
{
    tracked_protocol_t *tp = data;
    protocol_t *proto = tp->proto;

    // PINOs should not have dependants anyway; but they may depend on something
    if (proto_is_pino(proto)) {
        struct {
            const char *name;
            const char *short_name;
            const char *filter_name;
            GPtrArray  *fields;
            int         proto_id;
            gboolean    is_enabled;
            gboolean    enabled_by_default;
            gboolean    can_toggle;
            int         parent_proto_id;
            GList      *heur_list;
        } *pino = proto;
        tp->proto = find_protocol_by_id(pino->parent_proto_id);
    }

    gpointer args[] = {tp->parser_name, user_data};
    g_list_foreach(tp->dissector_tables, print_deps_from_dissector_table, &args);
    g_list_foreach(tp->heur_tables, print_deps_from_heur_table, &args);
}

static void
print_deps(gpointer key, gpointer value, gpointer user_data)
{
    const char *parser_name = (const char *)key;
    GList *protocols = value;
    printf("parser-%s:\n", parser_name);
    g_list_foreach(protocols, print_deps_for_protocol, user_data);
}

static void
record_dissector_tables_func(const gchar *table_name, const gchar *ui_name,
    gpointer user_data)
{
    struct dissector_table {
        GHashTable  *hash_table;
        GSList      *dissector_handles;
        const char  *ui_name;
        ftenum_t    type;
        int     param;
        protocol_t  *protocol;
        GHashFunc   hash_func;
        gboolean    supports_decode_as;
    } *sub_dissectors = find_dissector_table(table_name);

    dependencies_t *dep = user_data;
    protocol_t *proto = sub_dissectors->protocol;
    if (!proto) {
        fprintf(stderr, "Failed to find protocol for table: %s\n", table_name);
        return;

    }
    int id = proto_get_id(proto);
    const char *protocol = proto_get_protocol_filter_name(id);
    tracked_protocol_t *tp = g_hash_table_lookup(dep->protocols, protocol);
    if (!tp) {
        fprintf(stderr, "Failed to find tracked protocol for table: %s\n", table_name);
        return;
    }
    tracked_dissector_table_t *tt = g_new0(tracked_dissector_table_t, 1);
    tt->table_name = table_name;
    tt->tbl = sub_dissectors;
    tp->dissector_tables = g_list_append(tp->dissector_tables, tt);
}

static void
record_heur_tables_func(const char *table_name,
    struct heur_dissector_list *table, gpointer user_data)
{
    struct {
        protocol_t  *protocol;
        GSList      *dissectors;
    } *sub_dissectors = table;

    dependencies_t *dep = user_data;
    protocol_t *proto = sub_dissectors->protocol;
    if (!proto) {
        fprintf(stderr, "Failed to find protocol for heur table: %s\n", table_name);
        return;
    }

    int id = proto_get_id(proto);
    const char *protocol = proto_get_protocol_filter_name(id);
    tracked_protocol_t *tp = g_hash_table_lookup(dep->protocols, protocol);
    if (!tp) {
        fprintf(stderr, "Failed to find tracked protocol for heur table: %s\n", table_name);
        return;
    }
    tracked_heur_table_t *tt = g_new0(tracked_heur_table_t, 1);
    tt->table_name = table_name;
    tt->tbl = sub_dissectors;
    tp->heur_tables = g_list_append(tp->heur_tables, tt);
}

static gboolean
track_dependencies(void)
{
    dependencies_t dep;
    dep.visited = g_hash_table_new(g_str_hash, g_str_equal);
    dep.parsers = g_hash_table_new(g_str_hash, g_str_equal);
    dep.protocols = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
        dependump_tracked_protocol_free);
    if (!dep.visited)
        return FALSE;
    if (!epan_init(register_callback, &dep, FALSE))
        return FALSE;
    dissector_all_tables_foreach_table(
        record_dissector_tables_func, &dep, NULL);
    dissector_all_heur_tables_foreach_table(
        record_heur_tables_func, &dep, NULL);

    // g_hash_table_foreach(dep.parsers, print_protocols, NULL);

    g_hash_table_foreach(dep.parsers, print_deps, &dep);

    g_hash_table_destroy(dep.protocols);
    g_hash_table_destroy(dep.parsers);
    g_hash_table_destroy(dep.visited);
    return TRUE;
}

int
main(int argc, char **argv)
{
    char        *configuration_init_error;
    char        *proto_name = NULL;
    int          exit_status = EXIT_FAILURE;

    /*
     * Set the C-language locale to the native environment and set the
     * code page to UTF-8 on Windows.
     */
#ifdef _WIN32
    setlocale(LC_ALL, ".UTF-8");
#else
    setlocale(LC_ALL, "");
#endif

    cmdarg_err_init(dependump_cmdarg_err, dependump_cmdarg_err_cont);

    /* Initialize log handler early for startup. */
    ws_log_init("dependump", vcmdarg_err);

    /* Early logging command-line initialization. */
    ws_log_parse_args(&argc, argv, vcmdarg_err, 1);

    ws_noisy("Finished log init and parsing command line log arguments");

    ws_init_version_info("DepenDump", NULL, NULL);

    const char *optstring = "hvdV";
    static struct ws_option long_options[] = {
        { "help",     ws_no_argument,   0,  'h' },
        { "version",  ws_no_argument,   0,  'v' },
        { "debug",    ws_no_argument,   0,  'd' },
        { "verbose",  ws_no_argument,   0,  'V' },
        { NULL,       0,                0,  0   }
    };
    int opt;

    for (;;) {
        opt = ws_getopt_long(argc, argv, optstring, long_options, NULL);
        if (opt == -1)
            break;

        switch (opt) {
            case 'V':
                opt_verbose = 1;
                break;
            case 'd':
                opt_log_level = DEPENDUMP_LOG_NOISY;
                break;
            case 'v':
                show_help_header(NULL);
                exit(EXIT_SUCCESS);
                break;
            case 'h':
                show_help_header(NULL);
                print_usage(EXIT_SUCCESS);
                break;
            case '?':
                print_usage(EXIT_FAILURE);
            default:
                ws_assert_not_reached();
        }
    }

    /* Check for protocol name on command line */
    if (argv[ws_optind] == NULL) {
        printf("Error: Missing argument.\n");
        print_usage(EXIT_FAILURE);
    }

    if (opt_log_level == DEPENDUMP_LOG_NOISY) {
        ws_log_set_noisy_filter(LOG_DOMAIN_DFILTER);
    }

    /*
     * Get credential information for later use.
     */
    init_process_policies();

    /*
     * Attempt to get the pathname of the directory containing the
     * executable file.
     */
    configuration_init_error = configuration_init(argv[0], NULL);
    if (configuration_init_error != NULL) {
        fprintf(stderr, "Error: Can't get pathname of directory containing "
                        "the dependump program: %s.\n",
            configuration_init_error);
        g_free(configuration_init_error);
    }

    static const struct report_message_routines dependump_report_routines = {
        failure_message,
        failure_message,
        open_failure_message,
        read_failure_message,
        write_failure_message,
        cfile_open_failure_message,
        cfile_dump_open_failure_message,
        cfile_read_failure_message,
        cfile_write_failure_message,
        cfile_close_failure_message
    };

    init_report_message("dependump", &dependump_report_routines);

    timestamp_set_type(TS_RELATIVE);
    timestamp_set_seconds_type(TS_SECONDS_DEFAULT);

    /*
     * Libwiretap must be initialized before libwireshark is, so that
     * dissection-time handlers for file-type-dependent blocks can
     * register using the file type/subtype value for the file type.
     */
    wtap_init(TRUE);

    /* Register all dissectors */
    if (!track_dependencies())
        goto out;

    /* Load libwireshark settings from the current profile. */
    epan_load_settings();

    /* notify all registered modules that have had any of their preferences
       changed either from one of the preferences file or from the command
       line that its preferences have changed. */
    prefs_apply_all();

    /* This is useful to prevent confusion with option parsing.
     * Skips printing options and argv[0]. */
    if (opt_verbose) {
        for (int i = ws_optind; i < argc; i++) {
            fprintf(stderr, "argv[%d]: %s\n", i, argv[i]);
        }
        fprintf(stderr, "\n");
    }

    /* Get protocol name */
    proto_name = get_args_as_string(argc, argv, ws_optind);

    printf("Protocol:\n %s\n\n", proto_name);


    /* If logging is enabled add an empty line. */
    if (opt_log_level > DEPENDUMP_LOG_NONE) {
        printf("\n");
    }

    exit_status = 0;

out:
    epan_cleanup();
    g_free(proto_name);
    exit(exit_status);
}
