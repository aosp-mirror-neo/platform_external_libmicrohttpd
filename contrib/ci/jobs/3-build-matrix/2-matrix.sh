#!/bin/bash
#
# The build-configuration matrix of TESTING.md, proposal P3.
#
# Why this job exists, concretely:
#
#   MAX_DIGEST in src/microhttpd/digestauth.c is the size of the largest
#   digest the build supports.  It is 16 in an MD5-only build and 32 when
#   SHA-256 or SHA-512/256 are compiled in.  The out-of-bounds stack
#   write fixed in commit 5a73c1ae wrote up to 64 bytes into a
#   MAX_DIGEST-sized array, so *the very same request overflows by a
#   different amount - or not at all - depending purely on the configure
#   flags*.  A CI that only ever builds the default configuration cannot
#   see that, and cannot tell whether a fix holds in every shipped build.
#   Distributions do ship reduced builds, so the reduced builds have to
#   be tested.
#
#   The same argument applies to --enable-asserts (mhd_assert() is
#   compiled out of a normal build, so every invariant the library
#   documents is unchecked there), to the sanitizers (they are the only
#   oracle that turns a silent memory-safety defect into a test failure)
#   and to -m32 (pointer and size_t width change the arithmetic in the
#   read-buffer shift-back path of 29eaa56b).
#
# The sweep is
#
#   {asserts on, asserts off}
#     x {sanitizers on, sanitizers off}
#     x {all digests, MD5 only, SHA-256 only, SHA-512/256 only,
#        --disable-dauth, --disable-bauth}
#     x {native 64-bit, 32-bit via -m32}
#
# = 48 combinations, each a clean out-of-tree build plus a full
# "make check".  This is a nightly job; the every-push subset is job
# 2-test.
#
# Combinations that the environment cannot support (no 32-bit toolchain,
# no sanitizer runtime, no 32-bit sanitizer runtime) are reported as SKIP
# with the reason, never as a failure - a missing i386 libasan is a
# property of the runner, not a defect in MHD.
#
# Knobs:
#   MHD_CI_MATRIX_FILTER   only run combinations whose tag matches this
#                          extended regular expression
#   MHD_CI_MATRIX_JOBS     -j level for each build (default: nproc)
#   MHD_CI_MATRIX_KEEP     set to 1 to keep the build trees for triage
#
# No "set -e": a failing combination must be recorded and the sweep must
# continue.  No "set -x" either (job.sh switches it on): with 48 builds
# the trace drowns the summary, and every step prints its own banner.
set +x
set -uo pipefail

srcdir="$(pwd)"
probe_dir="$(mktemp -d)"
trap 'rm -rf "${probe_dir}"' EXIT

jobs="${MHD_CI_MATRIX_JOBS:-$(nproc)}"
filter="${MHD_CI_MATRIX_FILTER:-.}"
keep="${MHD_CI_MATRIX_KEEP:-0}"

# ---------------------------------------------------------------------
# Environment probes
# ---------------------------------------------------------------------

# Compile *and run* a trivial program.  Running it matters: a machine can
# have a working 32-bit compiler and 32-bit headers while being unable to
# execute i386 binaries at all (missing loader, restricted container,
# CONFIG_IA32_EMULATION off).  Probing with a compile alone would then
# turn every 32-bit combination into a wall of bogus SIGSEGV failures
# instead of one honest SKIP.
probe_cc()
{
	printf 'int main(void){return 0;}\n' > "${probe_dir}/probe.c"
	# shellcheck disable=SC2086
	${CC:-gcc} "$@" -o "${probe_dir}/probe" "${probe_dir}/probe.c" \
		> "${probe_dir}/probe.log" 2>&1 || return 1
	"${probe_dir}/probe" >> "${probe_dir}/probe.log" 2>&1
}

have_m32=no
have_san=no
have_m32_san=no
have_m32_curl=no
have_m32_gnutls=no

probe_cc -m32                            && have_m32=yes
probe_cc -fsanitize=address,undefined    && have_san=yes
if [ "${have_m32}" = "yes" ]; then
	probe_cc -m32 -fsanitize=address,undefined && have_m32_san=yes
	probe_cc -m32 -lcurl                       && have_m32_curl=yes
	probe_cc -m32 -lgnutls                     && have_m32_gnutls=yes
fi

echo "== environment probes =============================================="
echo "  gcc -m32 .............................. ${have_m32}"
echo "  gcc -fsanitize=address,undefined ...... ${have_san}"
echo "  gcc -m32 -fsanitize=address,undefined . ${have_m32_san}"
echo "  32-bit libcurl ........................ ${have_m32_curl}"
echo "  32-bit gnutls ......................... ${have_m32_gnutls}"
echo "===================================================================="

# ---------------------------------------------------------------------
# The axes.  Every option spelling below is the one configure.ac really
# defines; --enable-md5 and --enable-sha256 take a TYPE argument
# (yes/no/builtin/tlslib) while --enable-sha512-256 is a plain
# enable/disable switch, and --enable-sanitizers takes a comma separated
# list.
# ---------------------------------------------------------------------

# tag                 configure arguments
digest_tags=(all md5 sha256 sha512-256 nodauth nobauth)
digest_args_all=""
digest_args_md5="--enable-md5=builtin --enable-sha256=no --disable-sha512-256"
digest_args_sha256="--enable-md5=no --enable-sha256=builtin --disable-sha512-256"
digest_args_sha512_256="--enable-md5=no --enable-sha256=no --enable-sha512-256"
digest_args_nodauth="--disable-dauth"
digest_args_nobauth="--disable-bauth"

digest_args()
{
	case "$1" in
		all)         echo "${digest_args_all}" ;;
		md5)         echo "${digest_args_md5}" ;;
		sha256)      echo "${digest_args_sha256}" ;;
		sha512-256)  echo "${digest_args_sha512_256}" ;;
		nodauth)     echo "${digest_args_nodauth}" ;;
		nobauth)     echo "${digest_args_nobauth}" ;;
	esac
}

results=()
failures=0

record()
{
	results+=("$(printf '%-34s %-5s %s' "$1" "$2" "${3:-}")")
}

run_combination()
{
	local tag="$1" bits="$2" asserts="$3" san="$4" digest="$5"
	local builddir="${srcdir}/build-${tag}"
	local -a args=()

	if ! printf '%s' "${tag}" | grep -Eq -- "${filter}"; then
		return 0
	fi

	# --- skip decisions -------------------------------------------
	if [ "${bits}" = "32" ] && [ "${have_m32}" != "yes" ]; then
		record "${tag}" SKIP "no 32-bit toolchain (gcc -m32 fails)"
		return 0
	fi
	if [ "${san}" = "on" ] && [ "${bits}" = "64" ] && [ "${have_san}" != "yes" ]; then
		record "${tag}" SKIP "no sanitizer runtime for this compiler"
		return 0
	fi
	if [ "${san}" = "on" ] && [ "${bits}" = "32" ] && [ "${have_m32_san}" != "yes" ]; then
		record "${tag}" SKIP "no 32-bit sanitizer runtime (i386 libasan)"
		return 0
	fi

	# --- configure arguments --------------------------------------
	if [ "${asserts}" = "on" ]; then
		args+=(--enable-asserts)
	else
		args+=(--disable-asserts)
	fi
	if [ "${san}" = "on" ]; then
		# shellcheck disable=SC2054  # one argument, the comma is part of it
		args+=(--enable-sanitizers=address,undefined)
	fi
	# Word splitting is intended here: digest_args() returns a
	# whitespace separated list of configure arguments.
	# shellcheck disable=SC2207
	args+=($(digest_args "${digest}"))

	if [ "${bits}" = "32" ]; then
		args+=(CC="${CC:-gcc} -m32")
		args+=(--build=x86_64-pc-linux-gnu --host=i686-pc-linux-gnu)
		# The 32-bit development libraries of libcurl and GnuTLS are
		# usually not installed next to a 64-bit toolchain; turn the
		# corresponding parts of the suite off explicitly rather than
		# letting configure fail a link test and print a warning.
		[ "${have_m32_curl}" = "yes" ]   || args+=(--disable-curl)
		[ "${have_m32_gnutls}" = "yes" ] || args+=(--disable-https)
		# src/examples/json_echo links against libjansson, which is
		# not part of MHD's own dependency set and is essentially
		# never installed for i386 next to an amd64 toolchain.  The
		# examples are not built by "make check", so dropping them
		# costs no coverage and keeps the 32-bit leg buildable.
		args+=(--disable-examples)
	fi

	# --- clean out-of-tree build ----------------------------------
	rm -rf "${builddir}"
	mkdir -p "${builddir}"

	echo "===================================================================="
	echo "== ${tag}"
	echo "==   ../configure ${args[*]}"
	echo "===================================================================="

	if ! ( cd "${builddir}" && ../configure "${args[@]}" ); then
		record "${tag}" FAIL "configure failed"
		failures=$((failures + 1))
		return 0
	fi
	if ! ( cd "${builddir}" && make -j"${jobs}" ); then
		record "${tag}" FAIL "build failed"
		failures=$((failures + 1))
		return 0
	fi
	if ! ( cd "${builddir}" && make -j"${jobs}" check ); then
		record "${tag}" FAIL "make check failed"
		failures=$((failures + 1))
		echo "## test logs for ${tag}:"
		find "${builddir}" -name 'test-suite.log' -print -exec cat {} \; || true
		return 0
	fi

	record "${tag}" PASS ""
	[ "${keep}" = "1" ] || rm -rf "${builddir}"
	return 0
}

for bits in 64 32; do
	for asserts in on off; do
		for san in on off; do
			for digest in "${digest_tags[@]}"; do
				run_combination \
					"${bits}bit-asserts-${asserts}-san-${san}-${digest}" \
					"${bits}" "${asserts}" "${san}" "${digest}"
			done
		done
	done
done

# ---------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------
echo
echo "===================================================================="
echo "== build-configuration matrix summary"
echo "===================================================================="
printf '%-34s %-5s %s\n' "COMBINATION" "STATE" "NOTE"
for line in "${results[@]}"; do
	echo "${line}"
done
echo "===================================================================="
echo "== ${failures} failing combination(s)"
echo "===================================================================="

if [ "${failures}" -ne 0 ]; then
	exit 1
fi
exit 0
