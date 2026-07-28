#!/bin/bash
set -exuo pipefail

# Sweep a moderate range of zzuf seeds.  A single seed proves almost
# nothing; a huge range takes correspondingly long, so the recommended
# pattern from src/testzzuf/README is a moderate range per job with
# different jobs given different ranges.  ZZUF_SEED_START takes
# precedence over ZZUF_SEED.
#
# On failure both runner scripts print a block containing the failing
# seed and a copy-pasteable replay command; grep the job log for
# "FUZZING TEST FAILED".

ZZUF_START="${MHD_CI_ZZUF_SEED_START:-0}"
ZZUF_STOP="${MHD_CI_ZZUF_SEED_STOP:-64}"

make -C src/testzzuf check \
     ZZUF_SEED_START="${ZZUF_START}" \
     ZZUF_SEED_STOP="${ZZUF_STOP}"
