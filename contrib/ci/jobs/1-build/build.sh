#!/bin/bash
set -exuo pipefail

# The smoke build: exactly what a user typing the three commands from
# README/INSTALL gets.  No asserts, no sanitizers, default everything.
# If this breaks, nothing else in the pipeline is worth running.
#
# "configure" prints a "Configuration Summary:" block at the end; it is
# the quickest way to see in the CI log which optional features (HTTPS,
# digest algorithms, libcurl tests) were actually compiled in.

./bootstrap
./configure
make -j"$(nproc)"
