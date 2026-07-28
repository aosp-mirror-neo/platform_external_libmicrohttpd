#!/bin/bash
set -exuo pipefail

# Produce an HTML coverage report into a local artifacts directory.
#
# Unlike the GNU Taler jobs this deliberately does *not* upload anywhere:
# there is no rsync target for libmicrohttpd, and a CI job that silently
# depends on a private host is a job that breaks for everyone else.  The
# report is left in the working tree; wire it up to whatever artifact
# store the runner has.

ARTIFACT_DIR="${MHD_CI_ARTIFACT_DIR:-contrib/ci/artifacts/coverage/${CI_COMMIT_REF:-local}}"

mkdir -p "${ARTIFACT_DIR}"

# lcov 2.x turns a lot of things that used to be warnings into errors and
# needs them switched off explicitly; lcov 1.x does not know some of
# those keywords at all.  Try the strict-lcov invocation first and fall
# back to the plain one, so the job works on either.
lcov_try()
{
	lcov "$@" --ignore-errors mismatch,negative,source,empty,unused \
	  || lcov "$@"
}

lcov_try --capture \
         --directory . \
         --output-file "${ARTIFACT_DIR}/coverage.info"

# Only MHD's own sources are interesting; drop system headers and the
# test programs themselves.
lcov_try --remove "${ARTIFACT_DIR}/coverage.info" \
         '/usr/*' \
         "${PWD}/src/testcurl/*" \
         "${PWD}/src/testzzuf/*" \
         "${PWD}/src/fuzz/*" \
         "${PWD}/src/examples/*" \
         --output-file "${ARTIFACT_DIR}/coverage-lib.info" \
  || cp "${ARTIFACT_DIR}/coverage.info" "${ARTIFACT_DIR}/coverage-lib.info"

genhtml "${ARTIFACT_DIR}/coverage-lib.info" \
        --output-directory "${ARTIFACT_DIR}/html" \
        --title "GNU libmicrohttpd ${CI_COMMIT_REF:-local}" \
        --legend \
        --ignore-errors source,empty \
  || genhtml "${ARTIFACT_DIR}/coverage-lib.info" \
             --output-directory "${ARTIFACT_DIR}/html" \
             --title "GNU libmicrohttpd ${CI_COMMIT_REF:-local}" \
             --legend

echo "===================================================================="
echo "== coverage report written to:"
echo "==   ${PWD}/${ARTIFACT_DIR}/html/index.html"
echo "== raw tracefiles:"
echo "==   ${PWD}/${ARTIFACT_DIR}/coverage.info      (everything)"
echo "==   ${PWD}/${ARTIFACT_DIR}/coverage-lib.info  (library only)"
echo "===================================================================="
lcov_try --summary "${ARTIFACT_DIR}/coverage-lib.info" || true
