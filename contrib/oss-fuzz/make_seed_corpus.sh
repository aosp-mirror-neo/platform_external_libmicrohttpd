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
#                             src/fuzz/README section 6.  Each goes into the
#                             seed corpus of the harness that found it, where
#                             OSS-Fuzz keeps re-running it forever - i.e. it
#                             becomes a permanent regression test.  The owning
#                             harness is named in the file, "K<n>-<harness>-
#                             <what>.bin"; a name without one means
#                             fuzz_request, which is what the reproducers
#                             predating the convention are.  Reproducers of
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
DISTILLED="${CORPUS}/distilled"
PATCHES="${SRCDIR}/patches"

FUZZERS="fuzz_request fuzz_options fuzz_eventloop fuzz_str fuzz_memorypool fuzz_auth_header fuzz_postprocessor"

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
  #
  # A reproducer belongs to the harness named in its file name,
  # "K<n>-<harness>-<what>.bin"; the older ones predate that convention
  # and are all fuzz_request inputs, so a name without a harness means
  # fuzz_request.
  if [ -d "${FINDINGS}" ]; then
    for f in "${FINDINGS}"/*.bin; do
      [ -f "${f}" ] || continue
      owner="$(basename "${f}" | sed -n 's/^K[0-9]*-\(fuzz_[a-z_]*\)-.*/\1/p')"
      [ -n "${owner}" ] || owner="fuzz_request"
      [ "${owner}" = "${fuzzer}" ] || continue
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

  # distilled/ is the edge-minimal residue of a fuzzing campaign, named
  # "<harness>-dNNN.bin" and therefore routed by prefix like the seeds
  # above.  It is by far the largest part of the seed corpus and the
  # reason a fresh ClusterFuzz run starts near the coverage the last
  # campaign reached instead of climbing back to it.
  if [ -d "${DISTILLED}" ]; then
    for f in "${DISTILLED}/${fuzzer}"-*.bin; do
      [ -f "${f}" ] || continue
      cp "${f}" "${dir}/distilled-$(basename "${f}")"
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
