#!/bin/bash

run/dependump 1 2>/dev/null | sort | uniq | awk 'BEGIN {print "digraph G {"} /\S*?->\S*?/ { print gensub(/(\S*?)->(\S*?)/, "\"\\1\"->\"\\2\";", "g", $1)} END {print "}"}'
