# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

set(fuzzshark_LIBS
	ui
	wiretap
	epan
	wsutil
)
if(OSS_FUZZ)
	if("$ENV{LIB_FUZZING_ENGINE}" STREQUAL "")
		message(FATAL_ERROR "LIB_FUZZING_ENGINE is not set!")
	endif()
	list(APPEND fuzzshark_LIBS $ENV{LIB_FUZZING_ENGINE})
endif()
set(fuzzshark_FILES
	fuzzshark.c
)
set(FUZZ_LINK_FLAGS "${WS_LINK_FLAGS}")
if(ENABLE_FUZZER)
	set(FUZZ_LINK_FLAGS "${FUZZ_LINK_FLAGS} -fsanitize=fuzzer")
endif()
if(OSS_FUZZ)
	# libFuzzingEngine.a is not position independent, so cannot use -pie.
	set(FUZZ_LINK_FLAGS "${FUZZ_LINK_FLAGS} -no-pie")
endif()

# Targets that are build via all-fuzzers:
# - fuzzshark: a non-specific fuzz target, configurable through env vars (requires BUILD_fuzzshark)
# - fuzzshark_<target>: fuzz target for a specific dissector target.
# - fuzzshark_<table>-<target>: fuzz target for a specific dissector via a dissector table.
add_custom_target(all-fuzzers)

function(fuzzshark_set_common_options fuzzer_name)
	# Sanitizers require a C++ runtime, so use a C++ linker.
	set_target_properties(${fuzzer_name} PROPERTIES
		FOLDER "Fuzzers"
		LINK_FLAGS "${FUZZ_LINK_FLAGS}"
		LINKER_LANGUAGE "CXX"
	)
	target_link_libraries(${fuzzer_name} ${fuzzshark_LIBS})
	add_dependencies(all-fuzzers ${fuzzer_name})
endfunction()

if(BUILD_fuzzshark)
	if(NOT (ENABLE_FUZZER OR OSS_FUZZ))
		# libFuzzer includes a main routine that enables fuzzing. If
		# support for fuzzing was not enabled, add a small standalone
		# target that can be used to test-compile fuzzshark.c.
		list(APPEND fuzzshark_FILES StandaloneFuzzTargetMain.c)
	endif()
	add_executable(fuzzshark ${fuzzshark_FILES})
	fuzzshark_set_common_options(fuzzshark)
endif()

# Create a new dissector fuzzer target.
# If <dissector_table> is empty, <name> will be called directly.
# If <dissector_table> is non-empty, a dissector with filter name <name> will be
# looked up in dissector table <dissector_table>.
function(generate_fuzzer dissector_table name)
	if(NOT (ENABLE_FUZZER OR OSS_FUZZ))
		return()
	endif()

	if(dissector_table STREQUAL "")
		set(fuzzer_name fuzzshark_${name})
	else()
		# "ip.proto" and "udp" -> "ip_proto-udp"
		set(fuzzer_name fuzzshark_${dissector_table}-${name})
		string(REPLACE "." "_" fuzzer_name ${fuzzer_name})
	endif()

	add_executable(${fuzzer_name} EXCLUDE_FROM_ALL ${fuzzshark_FILES})
	fuzzshark_set_common_options(${fuzzer_name})
	target_compile_definitions(${fuzzer_name} PRIVATE
		FUZZ_DISSECTOR_TARGET="${name}"
	)
	if(NOT dissector_table STREQUAL "")
		target_compile_definitions(${fuzzer_name} PRIVATE
			FUZZ_DISSECTOR_TABLE="${dissector_table}")
	endif()
endfunction()

# Add fuzzer targets for every dissector in list FUZZ_<table-var>_DISSECTORS,
# where <table-var> changes a <table> such as "ip.proto" into "IP_PROTO".
function(add_table_fuzzers table)
	string(REPLACE "." "_" table_var ${table})
	string(TOUPPER "${table_var}" table_var)
	foreach(dissector IN LISTS FUZZ_${table_var}_DISSECTORS)
		generate_fuzzer(${table} ${dissector})
	endforeach()
endfunction()

foreach(dissector IN LISTS FUZZ_DISSECTORS)
	generate_fuzzer("" ${dissector})
endforeach()

foreach(table IN LISTS FUZZ_TABLES)
	add_table_fuzzers(${table})
endforeach()

#
# Editor modelines  -  https://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 8
# tab-width: 8
# indent-tabs-mode: t
# End:
#
# vi: set shiftwidth=8 tabstop=8 noexpandtab:
# :indentSize=8:tabSize=8:noTabs=false:
#
