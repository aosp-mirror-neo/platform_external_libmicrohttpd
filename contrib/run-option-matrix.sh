#!/bin/sh
# This file is in the public domain.
#
# Re-run already built libmicrohttpd test binaries across the daemon option
# matrix defined in src/microhttpd/mhd_opt_matrix.c.
#
# See --help below for the full documentation.

set -u

me=`basename "$0"`

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

# The binaries that honour the matrix (they read the MHD_TEST_* environment
# variables), plus a few libcurl based ones that at least get re-run in every
# threading/polling mode of the daemon they start themselves.
default_tests="src/microhttpd/test_option_matrix
src/microhttpd/test_rq_shift_back
src/microhttpd/test_chunked_ext
src/microhttpd/test_dauth_malformed
src/microhttpd/test_raw_requests
src/testcurl/test_get
src/testcurl/test_post
src/testcurl/test_put_chunked
src/testcurl/test_process_headers"

profiles_arg=""
jobs=1
builddir=""
timeout_sec=600
verbose=0
list_only=0

usage ()
{
  cat <<EOF
Usage: $me [OPTION]... [TEST-BINARY]...

Re-runs libmicrohttpd test binaries across the daemon option matrix.  The
matrix is defined once, in src/microhttpd/mhd_opt_matrix.c, and is selected
per run through the environment, so nothing has to be recompiled:

  MHD_TEST_PROFILE           the profile, by name or by index
  MHD_TEST_MEM_LIMIT         override MHD_OPTION_CONNECTION_MEMORY_LIMIT
  MHD_TEST_DISCIPLINE        override MHD_OPTION_CLIENT_DISCIPLINE_LVL
  MHD_TEST_STRICT_FOR_CLIENT override the same knob via the deprecated
                             MHD_OPTION_STRICT_FOR_CLIENT
  MHD_TEST_THREADING         external | internal | per-connection | pool
  MHD_TEST_POLL              select | poll | epoll

This script only sets MHD_TEST_PROFILE; the other variables stay available
for a manual run.

Options:
  --profiles=LIST   comma separated profile names or indices to visit
                    (default: every profile of the matrix)
  --jobs=N          run up to N test processes in parallel (default: 1)
  --builddir=DIR    the root of the built tree (default: the directory this
                    script is called from, or the parent of contrib/)
  --timeout=SEC     kill a single run after SEC seconds (default: $timeout_sec)
  --list-profiles   print the profiles of the matrix and exit
  --verbose         echo the output of every run
  --help            print this help and exit

Arguments:
  TEST-BINARY...    the binaries to run, relative to the build directory or
                    absolute.  The default set is:
EOF
  echo "$default_tests" | sed 's/^/                      /'
  cat <<EOF

                    Only the src/microhttpd binaries listed above read the
                    MHD_TEST_* variables; the src/testcurl ones ignore them
                    and are simply re-run, which is still useful as a
                    stability check but does not vary the configuration.

Exit status:
  0   every run passed (or was skipped)
  1   at least one run failed
  2   usage error or nothing could be run

A run that exits with 77 is reported as SKIP and does not fail the script;
99 is reported as ERROR and does fail it.
EOF
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

tests=""
while [ $# -gt 0 ] ; do
  case "$1" in
    --help | -h)
      usage ; exit 0 ;;
    --profiles=*)
      profiles_arg=`expr "x$1" : 'x--profiles=\(.*\)'` ;;
    --jobs=*)
      jobs=`expr "x$1" : 'x--jobs=\(.*\)'` ;;
    -j)
      shift ; jobs="${1:-1}" ;;
    --builddir=*)
      builddir=`expr "x$1" : 'x--builddir=\(.*\)'` ;;
    --timeout=*)
      timeout_sec=`expr "x$1" : 'x--timeout=\(.*\)'` ;;
    --list-profiles)
      list_only=1 ;;
    --verbose | -v)
      verbose=1 ;;
    -*)
      echo "$me: unknown option '$1'; try '$me --help'." >&2 ; exit 2 ;;
    *)
      tests="$tests
$1" ;;
  esac
  shift
done

case "$jobs" in
  '' | *[!0-9]*) echo "$me: --jobs needs a number." >&2 ; exit 2 ;;
esac
[ "$jobs" -ge 1 ] || jobs=1
case "$timeout_sec" in
  '' | *[!0-9]*) echo "$me: --timeout needs a number." >&2 ; exit 2 ;;
esac

# ---------------------------------------------------------------------------
# Locate the built tree
# ---------------------------------------------------------------------------

if [ -z "$builddir" ] ; then
  if [ -x "src/microhttpd/test_option_matrix" ] ; then
    builddir="."
  else
    d=`dirname "$0"`/..
    if [ -x "$d/src/microhttpd/test_option_matrix" ] ; then
      builddir="$d"
    else
      builddir="."
    fi
  fi
fi
if [ ! -d "$builddir" ] ; then
  echo "$me: '$builddir' is not a directory." >&2
  exit 2
fi

matrix_bin="$builddir/src/microhttpd/test_option_matrix"

# ---------------------------------------------------------------------------
# The list of profiles
# ---------------------------------------------------------------------------

# The matrix is defined in exactly one place: ask the test binary for it.
# The fallback list is only used when the binary has not been built yet, so
# that --list-profiles still says something useful.
fallback_profiles="default
mem-64
mem-128
mem-256
mem-512
mem-1024
mem-2048
mem-3072
mem-4096
strict-1
strict-2
strict-3
lax-1
lax-2
lax-3
legacy-strict
legacy-lax"

if [ -x "$matrix_bin" ] ; then
  all_profiles=`"$matrix_bin" --list-profiles 2>/dev/null` || all_profiles=""
fi
if [ -z "${all_profiles:-}" ] ; then
  all_profiles="$fallback_profiles"
fi

if [ -n "$profiles_arg" ] ; then
  profiles=`echo "$profiles_arg" | tr ',' '\n' | sed '/^$/d'`
else
  profiles="$all_profiles"
fi

if [ "$list_only" -eq 1 ] ; then
  echo "$all_profiles"
  exit 0
fi

if [ -z "$tests" ] ; then
  tests="$default_tests"
fi

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

workdir=`mktemp -d "${TMPDIR:-/tmp}/mhd-option-matrix.XXXXXX"` || {
  echo "$me: cannot create a temporary directory." >&2 ; exit 2 ; }
trap 'rm -rf "$workdir"' 0
trap 'rm -rf "$workdir" ; exit 130' 1 2 3 15

timeout_cmd=""
if command -v timeout >/dev/null 2>&1 ; then
  timeout_cmd="timeout -k 5 $timeout_sec"
fi

# Run one (profile, binary) pair and record the outcome.
# $1 profile, $2 binary, $3 result file
run_one ()
{
  _prof="$1"
  _bin="$2"
  _out="$3"
  _path="$_bin"
  case "$_path" in
    /*) ;;
    *) _path="$builddir/$_bin" ;;
  esac
  if [ ! -x "$_path" ] ; then
    echo "MISSING $_prof $_bin" > "$_out"
    return 0
  fi
  MHD_TEST_PROFILE="$_prof" ; export MHD_TEST_PROFILE
  # shellcheck disable=SC2086
  $timeout_cmd "$_path" > "$_out.log" 2>&1
  _rc=$?
  case "$_rc" in
    0)  echo "PASS $_prof $_bin" > "$_out" ;;
    77) echo "SKIP $_prof $_bin" > "$_out" ;;
    99) echo "ERROR $_prof $_bin (exit 99)" > "$_out" ;;
    124 | 137)
        echo "TIMEOUT $_prof $_bin (after ${timeout_sec}s)" > "$_out" ;;
    *)  echo "FAIL $_prof $_bin (exit $_rc)" > "$_out" ;;
  esac
  return 0
}

n=0
running=0
for prof in $profiles ; do
  for t in $tests ; do
    n=`expr $n + 1`
    res="$workdir/r$n"
    echo "$prof" > "$res.prof"
    echo "$t" > "$res.bin"
    if [ "$jobs" -gt 1 ] ; then
      run_one "$prof" "$t" "$res" &
      running=`expr $running + 1`
      if [ "$running" -ge "$jobs" ] ; then
        wait
        running=0
      fi
    else
      run_one "$prof" "$t" "$res"
      if [ "$verbose" -eq 1 ] ; then
        cat "$res" 2>/dev/null
      fi
    fi
  done
done
wait

if [ "$n" -eq 0 ] ; then
  echo "$me: nothing to run." >&2
  exit 2
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

total=0
n_pass=0
n_skip=0
n_fail=0
n_missing=0

echo ""
echo "=========================================================================="
echo " option matrix summary"
echo "=========================================================================="

i=0
for prof in $profiles ; do
  line=""
  bad=0
  base=$i
  for t in $tests ; do
    i=`expr $i + 1`
    res="$workdir/r$i"
    if [ -f "$res" ] ; then
      status=`cut -d' ' -f1 < "$res"`
    else
      status="ERROR"
    fi
    total=`expr $total + 1`
    case "$status" in
      PASS)    n_pass=`expr $n_pass + 1` ;;
      SKIP)    n_skip=`expr $n_skip + 1` ;;
      MISSING) n_missing=`expr $n_missing + 1` ;;
      *)       n_fail=`expr $n_fail + 1` ; bad=1 ;;
    esac
    line="$line $status"
  done
  printf '%-16s%s\n' "$prof" "$line"
  if [ "$bad" -ne 0 ] || [ "$verbose" -eq 1 ] ; then
    j=$base
    for t in $tests ; do
      j=`expr $j + 1`
      res="$workdir/r$j"
      [ -f "$res" ] || continue
      status=`cut -d' ' -f1 < "$res"`
      case "$status" in
        PASS | SKIP | MISSING) continue ;;
      esac
      echo "  --- $t: `cat "$res"`"
      if [ -f "$res.log" ] ; then
        sed 's/^/      /' < "$res.log" | tail -n 25
      fi
    done
  fi
done

echo "--------------------------------------------------------------------------"
echo "binaries, in the order of the columns above:"
for t in $tests ; do
  echo "  $t"
done
echo "--------------------------------------------------------------------------"
echo "total $total, pass $n_pass, skip $n_skip, fail $n_fail, missing $n_missing"
if [ "$n_fail" -ne 0 ] ; then
  echo "RESULT: FAILED"
  exit 1
fi
echo "RESULT: OK"
exit 0
