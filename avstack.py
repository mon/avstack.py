#!/usr/bin/env python3
# avstack.py: AVR stack checker
# Copyright (C) 2013 Daniel Beer <dlbeer@gmail.com>
# Python port Will Toohey 2021 <will@mon.im>
#
# Permission to use, copy, modify, and/or distribute this software for
# any purpose with or without fee is hereby granted, provided that the
# above copyright notice and this permission notice appear in all
# copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
# AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
# DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
# PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
# TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.
#
# Usage
# -----
#
# This script requires that you compile your code with -fstack-usage.
# This results in GCC generating a .su file for each .o file. Once you
# have these, do:
#
#    ./avstack.py <object files>
#
# This will disassemble .o files to construct a call graph, and read
# frame size information from .su. The call graph is traced to find, for
# each function:
#
#    - Call height: the maximum call height of any callee, plus 1
#      (defined to be 1 for any function which has no callees).
#
#    - Inherited frame: the maximum *inherited* frame of any callee, plus
#      the GCC-calculated frame size of the function in question.
#
# Using these two pieces of information, we calculate a cost (estimated
# peak stack usage) for calling the function. Functions are then listed
# on stdout in decreasing order of cost.
#
# Functions which are recursive are marked with an 'R' to the left of
# them. Their cost is calculated for a single level of recursion.
#
# The peak stack usage of your entire program can usually be estimated
# as the stack cost of "main", plus the maximum stack cost of any
# interrupt handler which might execute.

#
# If you want to manually add edges that are not automatically detected due to
# the use of function pointers, make a second dummy function containing calls to
# the real functions. Prefix its name with `__stack_check_dummy__` and it will
# be picked up.
#
# For example, if you have a function:
#   int test(void) {
#      return some_function_pointer();
#   }
#
# ... and you know that some_function_pointer always points to real_func,
# create the dummy function:
#   void __stack_check_dummy__test(void) {
#       real_func();
#   }
#
# This function will be optimised out by the compiler as it is never called,
# but will exist in the intermediate .o file and thus be picked up by avstack.

import sys
import subprocess
import re
import os

def calculate_stack(object_file_paths, objdump='arm-none-eabi-objdump',
        call_cost=4, log_ambiguous=True, function_whitelist=None):
    # First, we need to read all object and corresponding .su files. We're
    # gathering a mapping of functions to callees and functions to frame
    # sizes. We're just parsing at this stage -- callee name resolution
    # comes later.

    frame_size = {}     # "func@file" -> size
    call_graph = {}     # "func@file" -> {callees}
    addresses  = {}     # "addr@file" -> "func@file"

    global_name = {}    # "func" -> "func@file"
    ambiguous   = set() # "func" -> 1

    for objfile in object_file_paths:
        # Disassemble this object file to obtain a callees. Sources in the
        # call graph are named "func@file". Targets in the call graph are
        # named either "offset@file" or "funcname". We also keep a list of
        # the addresses and names of each function we encounter.
        ran = subprocess.run([objdump, '-dr', objfile], capture_output=True, check=True)

        for line in ran.stdout.decode().split('\n'):
            line = line.strip()

            match = re.search(r'^([0-9a-fA-F]+) <(.*)>:', line)
            if match:
                a, name = match.groups()

                is_dummy = False
                if name.startswith('__stack_check_dummy__'):
                    is_dummy = True
                    name = name[len('__stack_check_dummy__'):]

                source = f"{name}@{objfile}"

                if function_whitelist is None or name in function_whitelist:
                    if source not in call_graph:
                        call_graph[source] = set()
                    if name in global_name and not is_dummy:
                        ambiguous.add(name)
                    global_name[name] = source

                    if not is_dummy:
                        a = a.lstrip('0')
                        addresses[f"{a}@{objfile}"] = source

            match = re.search(r': R_[A-Za-z0-9_]+_CALL[ \t]+(.*)', line)
            if match:
                t = match.group(1)

                if t == ".text":
                    t = f"@{objfile}"
                else:
                    match = re.search(r'^\.text\+0x(.*)$', t)
                    if match:
                        t = f"{match.group(1)}@{objfile}"

                if function_whitelist is None or name in function_whitelist:
                    call_graph[source].add(t)

        # Extract frame sizes from the corresponding .su file.
        base, ext = os.path.splitext(objfile)
        if ext == '.o':
            sufile = f"{base}.su"

            with open(sufile, 'r') as f:
                for line in f.readlines():
                    match = re.search(r'^.*:([^\t ]+)[ \t]+([0-9]+)', line)
                    if match:
                        name, size = match.groups()
                        size = int(size)
                        frame_size[f"{name}@{objfile}"] = size + call_cost

    # In this step, we enumerate each list of callees in the call graph and
    # try to resolve the symbols. We omit ones we can't resolve, but keep a
    # set of them anyway.

    unresolved = set()

    for _from, callees in call_graph.items():
        resolved = set()

        for t in callees:
            if t in addresses:
                resolved.add(addresses[t])
            elif t in global_name:
                resolved.add(global_name[t])
                if t in ambiguous and log_ambiguous:
                    print(f"Ambiguous resolution: {t}", file=sys.stderr)
            elif t in call_graph:
                resolved.add(t)
            else:
                unresolved.add(t)

        call_graph[_from] = resolved

    # Create fake edges and nodes to account for dynamic behaviour.
    call_graph["INTERRUPT"] = set()

    for t in call_graph.keys():
        if t.startswith('__vector_'):
            call_graph["INTERRUPT"].add(t)

    # Trace the call graph and calculate, for each function:
    #
    #    - inherited frames: maximum inherited frame of callees, plus own
    #      frame size.
    #    - height: maximum height of callees, plus one.
    #    - recursion: is the function called recursively (including indirect
    #      recursion)?

    has_caller = set()
    visited = {}
    total_cost = {}
    call_depth = {}

    def trace(f):
        if f in visited:
            if visited[f] == '?':
                visited[f] = 'R'
            return

        visited[f] = "?"

        max_depth = 0
        max_frame = 0

        for t in call_graph[f]:
            has_caller.add(t)
            trace(t)

            _is = total_cost[t]
            d = call_depth[t]

            max_frame = max(_is, max_frame)
            max_depth = max(d, max_depth)

        call_depth[f] = max_depth + 1
        total_cost[f] = max_frame + frame_size.get(f, 0)

        if visited[f] == "?":
            visited[f] = " "

    for key in call_graph.keys():
        trace(key)

    return (total_cost, frame_size, call_depth, visited, has_caller,
        global_name, ambiguous, unresolved)

def pretty_print_results(total_cost, frame_size, call_depth, visited, has_caller,
        global_name, ambiguous, unresolved):
    # Now, print results in a nice table.
    print("  %-30s %8s %8s %8s" % (
        "Func", "Cost", "Frame", "Height"))
    print("------------------------------------------------------------------------")

    max_iv = 0
    main = 0

    sorted_funcs = sorted(visited.keys(), key=lambda x: total_cost[x], reverse=True)
    for func in sorted_funcs:
        name = func

        match = re.search(r'^(.*)@(.*)$', func)
        if match:
            name = match.group(1)

        tag = visited[func]
        cost = total_cost[func]

        if name in ambiguous:
            name = func
        tag = ' ' if func in has_caller else '>'

        if func.startswith('__vector_'):
            max_iv = max(cost, max_iv)
        elif func.startswith('main@'):
            main = cost

        print("%s %-30s %8d %8d %8d" % (tag, name, cost,
            frame_size.get(func, 0), call_depth[func]))

    print("")

    main_cost = total_cost.get(global_name.get("main"), 0)
    iv_cost = total_cost["INTERRUPT"]

    print("Peak execution estimate (main + worst-case IV):")
    print("  main = %d, worst IV = %d, total = %d\n" % (
        main_cost,
        iv_cost,
        main_cost + iv_cost))

    print("The following functions were not resolved:")
    for f in unresolved:
        print(f"  {f}")


if __name__ == '__main__':
    pretty_print_results(*calculate_stack(sys.argv[1:]))

