#!/bin/sh
#
# Run one fuzzing test with zzuf intercepting the network input of the
# test process itself.
#
# Recognised environment variables:
#   ZZUF             the zzuf command (set by configure)
#   ZZUF_SEED        the single seed to use (default "0")
#   ZZUF_SEED_START  the first seed of a seed range (overrides ZZUF_SEED)
#   ZZUF_SEED_STOP   the last seed of a seed range
#   ZZUF_FLAGS       additional flags for zzuf
#   SOCAT            the socat command (set by configure)
#   SOCAT_FLAGS      additional flags for socat
#
# This script is POSIX shell only, do not use any bashism.

mhd_listen_ip='127.0.0.1'
max_runtime_sec='1800'

if test "x${ZZUF}" = "xno" ; then
  echo "zzuf command missing" 1>&2
  exit 77
fi

if command -v "${ZZUF}" > /dev/null 2>&1 ; then : ; else
  echo "zzuf command missing" 1>&2
  exit 77
fi

# Build the "--seed" parameter for zzuf.
# A seed range makes zzuf start one child per seed, which is what CI uses
# to sweep a large number of seeds.
zzuf_seed_param=''
if test -n "${ZZUF_SEED_START}" ; then
  if test -n "${ZZUF_SEED_STOP}" ; then
    zzuf_seed_param="--seed=${ZZUF_SEED_START}:${ZZUF_SEED_STOP}"
    seed_descr="range ${ZZUF_SEED_START}:${ZZUF_SEED_STOP}"
  else
    zzuf_seed_param="--seed=${ZZUF_SEED_START}"
    seed_descr="${ZZUF_SEED_START}"
  fi
elif test -n "${ZZUF_SEED}" ; then
  zzuf_seed_param="--seed=${ZZUF_SEED}"
  seed_descr="${ZZUF_SEED}"
else
  seed_descr="(zzuf default)"
fi

test_log=''

cleanup_log ()
{
  if test -n "${test_log}" ; then
    rm -f "${test_log}"
    test_log=''
  fi
}

# Print a loud, easy to grep report about a failing run, including the
# seed(s) that produced the failure.
# $1: the exit code of zzuf
report_failure ()
{
  failed_seeds=''
  if test -n "${test_log}" && test -r "${test_log}" ; then
    # zzuf prints one line per child, e.g.
    #   zzuf[s=17,r=0.012345]: signal 6 (SIGABRT)
    failed_seeds=`grep -E '^zzuf\[s=[0-9]+' "${test_log}" 2> /dev/null | \
      grep -E 'signal|exit|crash|abort|too (slow|much|many)' 2> /dev/null | \
      sed -e 's/^zzuf\[s=//' -e 's/[^0-9].*$//' | \
      sort -n -u | tr '\n' ' '`
  fi
  echo '' 1>&2
  echo '###############################################################' 1>&2
  echo '## FUZZING TEST FAILED' 1>&2
  echo "## test        : ${test_descr}" 1>&2
  echo "## exit code   : $1" 1>&2
  echo "## seed(s) used: ${seed_descr}" 1>&2
  if test -n "${failed_seeds}" ; then
    echo "## FAILING SEED(S): ${failed_seeds}" 1>&2
    echo '## Replay a single failing seed with:' 1>&2
    for one_seed in ${failed_seeds} ; do
      echo "##   make ZZUF_SEED=${one_seed} TESTS=${test_name} check" 1>&2
    done
  else
    echo '## No failing seed could be extracted from the zzuf output.' 1>&2
    echo '## Replay the whole run with:' 1>&2
    if test -n "${ZZUF_SEED_START}" ; then
      echo "##   make ZZUF_SEED_START=${ZZUF_SEED_START} \
ZZUF_SEED_STOP=${ZZUF_SEED_STOP} TESTS=${test_name} check" 1>&2
    else
      echo "##   make ZZUF_SEED=${ZZUF_SEED} TESTS=${test_name} check" 1>&2
    fi
  fi
  echo '###############################################################' 1>&2
  echo '' 1>&2
}

run_with_socat ()
{
  echo "Trying to run the test with socat..."
  script_dir=""
  if command -v dirname > /dev/null 2>&1 ; then
    test_dir=`dirname /`
    if test "x${test_dir}" = "x/" ; then
      if dirname "$1" > /dev/null 2>&1 ; then
        script_dir=`dirname "$1"`
        if test -n "${script_dir}" ; then
          # Assume script is not in the root dir
          script_dir="${script_dir}/"
        else
          script_dir="./"
        fi
      fi
    fi
  fi
  if test -z "${script_dir}" ; then
    if echo "$1" | sed 's|[^/]*$||' > /dev/null 2>&1 ; then
      script_dir=`echo "$1" | sed 's|[^/]*$||'`
        if test -z "${script_dir}" ; then
          script_dir="./"
        fi
    fi
  fi
  if test -z "${script_dir}" ; then
    echo "Cannot determine script location, will try current directory." 1>&2
    script_dir="./"
  fi
  cleanup_log
  $SHELL "${script_dir}zzuf_socat_test_runner.sh" "$@"
  exit $?
}

test_descr="$*"
test_name=`echo "$1" | sed 's|^.*/||'`
trap 'cleanup_log' EXIT

# zzuf cannot pass-through the return value of checked program
# so try the direct dry-run first to get possible 77 or 99 codes
echo "## Dry-run of the $* ..."
if "$@" --dry-run ; then
  echo "# Dry-run succeeded."
else
  res_code=$?
  echo "Dry-run failed with exit code $res_code." 1>&2
  if test $res_code -ne 99; then
    run_with_socat "$@"
  fi
  echo "$* will not be run with zzuf." 1>&2
  exit $res_code
fi

# fuzz the input only for IP ${mhd_listen_ip}. libcurl and the raw client
# use another IP in these tests, therefore the input of the clients is not
# fuzzed.
zzuf_all_params="--ratio=0.001:0.4 --autoinc --verbose --signal \
 --max-usertime=${max_runtime_sec} --check-exit --network \
 --allow=${mhd_listen_ip} --exclude=."

if test -n "${zzuf_seed_param}" ; then
  zzuf_all_params="${zzuf_all_params} ${zzuf_seed_param}"
fi

if test -n "${ZZUF_FLAGS}" ; then
  zzuf_all_params="${zzuf_all_params} ${ZZUF_FLAGS}"
fi

# Uncomment the next line to see more data in logs
#zzuf_all_params="${zzuf_all_params} -dd"

echo "## Dry-run of the $* with zzuf..."
if "$ZZUF" ${zzuf_all_params} "$@" --dry-run ; then
  echo "# Dry-run with zzuf succeeded."
else
  res_code=$?
  echo "$* cannot be run with zzuf directly." 1>&2
  run_with_socat "$@"
  exit $res_code
fi

echo "## Real test of $* with zzuf (seed: ${seed_descr})..."
if command -v tee > /dev/null 2>&1 ; then
  test_log="${TMPDIR:-/tmp}/mhd_zzuf_$$.log"
  rc_file="${test_log}.rc"
  { "$ZZUF" ${zzuf_all_params} "$@" ; echo $? > "${rc_file}" ; } 2>&1 | \
    tee "${test_log}"
  if test -r "${rc_file}" ; then
    res_code=`cat "${rc_file}"`
  else
    res_code=1
  fi
  rm -f "${rc_file}"
else
  # No 'tee': run without capturing, the failing seed has to be taken
  # from the test log by hand.
  "$ZZUF" ${zzuf_all_params} "$@"
  res_code=$?
fi

if test "x${res_code}" != "x0" ; then
  report_failure "${res_code}"
fi
cleanup_log
exit ${res_code}
