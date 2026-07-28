#!/bin/bash -eu
#
# Package src/fuzz/corpus/ into the $OUT/<fuzzer>_seed_corpus.zip files that
# OSS-Fuzz/ClusterFuzz picks up automatically.
#
# This file is in the public domain.
#
# Usage:  make_seed_corpus.sh [SRCDIR] [OUTDIR]
#
#   SRCDIR   top of the libmicrohttpd source tree   (default: derived from $0)
#   OUTDIR   where the zips are written             (default: $OUT, else ./out)
#
# Corpus layout in src/fuzz/corpus/:
#
#   fuzz_<harness>-NN.bin     per-harness seeds; the file name prefix is the
#                             harness the seed belongs to.  Inputs are NOT
#                             interchangeable between harnesses: byte 0 of
#                             every harness input selects a different thing.
#   known-findings/K*.bin     byte-exact reproducers for the findings in
#                             src/fuzz/README section 6.  All of them are
#                             fuzz_request inputs, so they go into that
#                             harness' seed corpus, where OSS-Fuzz will keep
#                             re-running them forever - i.e. they become
#                             permanent regression tests.  Reproducers of
#                             findings that are still open are skipped; see
#                             the loop below.
#   README                    documentation, not an input; excluded.
#
# The corpus itself is regenerated from the harnesses' built-in seeds with
#   make -C src/fuzz refresh-corpus
# (which runs "./fuzz_<name> --write-corpus=corpus" for every harness).
# known-findings/ is hand-maintained and is never touched by that.

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
SRCDIR="${1:-$(cd "${SELF_DIR}/../.." && pwd)}"
OUTDIR="${2:-${OUT:-$(pwd)/out}}"

CORPUS="${SRCDIR}/src/fuzz/corpus"
FINDINGS="${CORPUS}/known-findings"
PATCHES="${SRCDIR}/patches"

FUZZERS="fuzz_request fuzz_str fuzz_auth_header fuzz_postprocessor"

if [ ! -d "${CORPUS}" ]; then
  echo "ERROR: no corpus directory at ${CORPUS}" >&2
  exit 1
fi

mkdir -p "${OUTDIR}"

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/mhd-seed-corpus.XXXXXX")"
trap 'rm -rf "${STAGE}"' EXIT

for fuzzer in ${FUZZERS}; do
  dir="${STAGE}/${fuzzer}"
  mkdir -p "${dir}"

  n=0
  for f in "${CORPUS}/${fuzzer}"-*.bin; do
    [ -f "${f}" ] || continue
    cp "${f}" "${dir}/$(basename "${f}")"
    n=$((n + 1))
  done

  # The K* reproducers are fuzz_request inputs.
  #
  # Only the ones whose defect is already fixed are shipped.  While a
  # finding is open its proposed fix is kept as an unapplied diff in
  # patches/$ID.diff, and its reproducer crashes the target by
  # construction; shipping it would make every ClusterFuzz run start by
  # rediscovering a bug that is already written down, and bury the
  # findings that are actually new.  Committing the fix deletes the diff,
  # and that alone promotes the reproducer to a permanent regression seed
  # here, with no further edit.
  #
  # patches/ therefore does not exist while nothing is open, which is the
  # normal state; the test below simply never fires then.
  if [ "${fuzzer}" = "fuzz_request" ] && [ -d "${FINDINGS}" ]; then
    for f in "${FINDINGS}"/*.bin; do
      [ -f "${f}" ] || continue
      id="$(basename "${f}" | sed -n 's/^\(K[0-9]*\).*/\1/p')"
      if [ -n "${id}" ] && [ -f "${PATCHES}/${id}.diff" ]; then
        echo "  skipping ${fuzzer} seed $(basename "${f}"): ${id} is open" \
             "(${PATCHES}/${id}.diff)"
        continue
      fi
      cp "${f}" "${dir}/known-finding-$(basename "${f}")"
      n=$((n + 1))
    done
  fi

  if [ "${n}" -eq 0 ]; then
    echo "ERROR: no seeds found for ${fuzzer} in ${CORPUS}" >&2
    exit 1
  fi

  zip_path="${OUTDIR}/${fuzzer}_seed_corpus.zip"
  rm -f "${zip_path}"
  # -j: flat archive, which is what ClusterFuzz expects.
  # -X: no extra file attributes, so the zip stays reproducible.
  zip -q -j -X "${zip_path}" "${dir}"/* || {
    echo "ERROR: failed to create ${zip_path}" >&2
    exit 1
  }
  echo "  ${zip_path}: ${n} seed(s)"
done
