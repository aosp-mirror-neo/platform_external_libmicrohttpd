#!/bin/sh
#
# Run one fuzzing test with zzuf fuzzing a socat relay that sits between
# the test clients and MHD.  This mode is mandatory when MHD is built with
# sanitizers (zzuf and the sanitizers cannot both intercept the standard
# library calls) or when MHD uses accept4().
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

if set -m ; then : ; else
  echo "The shell $SHELL does not support background jobs, the test cannot run." 1>&2
  exit 77
fi

socat_listen_ip='127.0.0.121'
socat_listen_port='10121'
mhd_listen_port='4010'
max_runtime_sec='1800'

if test "x${ZZUF}" = "xno" ; then
  echo "zzuf command missing" 1>&2
  exit 77
fi

if command -v "${ZZUF}" > /dev/null 2>&1 ; then : ; else
  echo "zzuf command missing" 1>&2
  exit 77
fi

if test "x${SOCAT}" = "xno" ; then
  echo "socat command missing" 1>&2
  exit 77
fi

if command -v "${SOCAT}" > /dev/null 2>&1 ; then : ; else
  echo "socat command missing" 1>&2
  exit 77
fi

# Build the "--seed" parameter for zzuf.
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

test_descr="$*"
test_name=`echo "$1" | sed 's|^.*/||'`

# Print a loud, easy to grep report about a failing run.
# In this mode zzuf fuzzes socat, while the test program (and MHD) runs
# outside of zzuf, so the exit code below is the exit code (or the signal)
# of the *server side* and the seed is the one this run was started with.
# $1: the exit code of the test program
report_failure ()
{
  echo '' 1>&2
  echo '###############################################################' 1>&2
  echo '## FUZZING TEST FAILED (server side)' 1>&2
  echo "## test        : ${test_descr}" 1>&2
  echo "## exit code   : $1" 1>&2
  if test "$1" -gt 128 2> /dev/null ; then
    echo "##               (killed by signal `expr $1 - 128`)" 1>&2
  fi
  echo "## FAILING SEED: ${seed_descr}" 1>&2
  echo '## Replay with:' 1>&2
  if test -n "${ZZUF_SEED_START}" ; then
    echo "##   make ZZUF_SEED_START=${ZZUF_SEED_START} \
ZZUF_SEED_STOP=${ZZUF_SEED_STOP} TESTS=${test_name} check" 1>&2
  else
    echo "##   make ZZUF_SEED=${ZZUF_SEED} TESTS=${test_name} check" 1>&2
  fi
  echo '###############################################################' 1>&2
  echo '' 1>&2
}

socat_test_params="-ls -lu \
  -T0.1 -4 \
  TCP-LISTEN:${socat_listen_port},bind=${socat_listen_ip},reuseaddr,linger=2,linger2=1,accept-timeout=0.1 \
  TCP:127.0.0.1:${mhd_listen_port},reuseaddr"

echo "## Trying to run socat to test ports availability..."
if "${SOCAT}" ${socat_test_params} ; then
  echo "Success."
else
  echo "socat test run failed" 1>&2
  exit 77
fi

# fuzz the input only for IP ${socat_listen_ip}. libcurl and the raw client
# use another IP in these tests, therefore the input of the clients is not
# fuzzed.
zzuf_all_params="--ratio=0.001:0.4 --autoinc --verbose --signal \
 --max-usertime=${max_runtime_sec} --check-exit --network --allow=${socat_listen_ip} --exclude=."

if test -n "${zzuf_seed_param}" ; then
  zzuf_all_params="${zzuf_all_params} ${zzuf_seed_param}"
fi

if test -n "${ZZUF_FLAGS}" ; then
  zzuf_all_params="${zzuf_all_params} ${ZZUF_FLAGS}"
fi

# Uncomment the next line to see more zzuf data in logs
#zzuf_all_params="${zzuf_all_params} -dd"

socat_options="-ls -lu \
  -T3 -4"
socat_addr1="TCP-LISTEN:${socat_listen_port},bind=${socat_listen_ip},reuseaddr,nodelay,linger=2,linger2=1,accept-timeout=${max_runtime_sec},fork"
socat_addr2="TCP:127.0.0.1:${mhd_listen_port},reuseaddr,connect-timeout=3,nodelay,linger=2,linger2=1"

if test -n "${SOCAT_FLAGS}" ; then
  socat_options="${socat_options} ${SOCAT_FLAGS}"
fi

# Uncomment the next line to see more socat data in logs
#socat_options="${socat_options} -dd -D"

# Uncomment the next line to see all traffic in logs
#socat_options="${socat_options} -v"

stop_zzuf_socat ()
{
  trap - EXIT
  if test -n "$zzuf_pid" ; then
    echo "The test has been interrupted." 1>&2
    test "x$zzuf_pid" = "xstarting" && zzuf_pid=$!
    # Finish zzuf + socat
    kill -TERM ${zzuf_pid} -${zzuf_pid}
    # Finish the test
    kill -INT %2 2> /dev/null || kill -INT %1 2> /dev/null
    exit 99
  fi
}

echo "## Starting zzuf with socat to reflect fuzzed traffic (seed: ${seed_descr})..."
trap 'stop_zzuf_socat' EXIT
zzuf_pid="starting"
"${ZZUF}" ${zzuf_all_params} "${SOCAT}" ${socat_options} ${socat_addr1} ${socat_addr2} &
if test $? -eq 0 ; then
  zzuf_pid=$!
  echo "zzuf with socat has been started."
else
  zzuf_pid=''
  echo "Failed to start zzuf with socat" 1>&2
  exit 99
fi

echo "## Starting real test of $* with traffic fuzzed by zzuf with socat..."
"$@" --with-socat
test_result=$?
trap - EXIT
echo "$* has exited with the return code $test_result"
if kill -s 0 -- $$ 2> /dev/null ; then
  if kill -s 0 -- ${zzuf_pid} -${zzuf_pid} 2> /dev/null ; then : ; else
    echo "No running zzuf with socat is detected after the test." 1>&2
    echo "Looks like zzuf ended prematurely, at least part of the testing has not been performed." 1>&2
    if test "x${test_result}" = "x0" ; then
      test_result=99
    else
      echo "The test itself has already failed with the code ${test_result}," 1>&2
      echo "this code is kept as the result of this run." 1>&2
    fi
  fi
fi
kill -TERM ${zzuf_pid} -${zzuf_pid} 2> /dev/null
zzuf_pid=''
if test "x${test_result}" != "x0" && test "x${test_result}" != "x77" ; then
  report_failure "${test_result}"
fi
exit $test_result
