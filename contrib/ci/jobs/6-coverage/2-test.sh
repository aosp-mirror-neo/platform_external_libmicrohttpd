#!/bin/bash
set -exuo pipefail

# A failing test still produces useful coverage data, so this step does
# not abort the job; the coverage report is the deliverable here and
# job 2-test is the one that gates on test results.
make -j"$(nproc)" check || echo "WARNING: 'make check' failed; the coverage report below is still generated, but it describes a failing run."
