#!/bin/bash
set -exuo pipefail

check_command()
{
	make -j"$(nproc)" check
}

print_logs()
{
	set +e
	echo "###############################################################"
	echo "## make check FAILED - dumping the logs of every failing test"
	echo "###############################################################"
	# Automake writes one .log per test plus a per-directory
	# test-suite.log; the per-test logs carry the actual diagnostics.
	find . -name 'test-suite.log' -print -exec cat {} \;
	find . -name '*.log' -path '*/src/*' -newer config.status -print0 |
	while IFS= read -r -d '' logfile; do
		case "${logfile}" in
			*/config.log) continue ;;
		esac
		# Only the logs of tests that did not pass: automake writes a
		# matching .trs with ":test-result: PASS" for successful ones.
		trs="${logfile%.log}.trs"
		if [ -f "${trs}" ] && grep -q ':test-result: PASS' "${trs}"; then
			continue
		fi
		echo "--------------------------------------------------------"
		echo "## ${logfile}"
		echo "--------------------------------------------------------"
		cat "${logfile}"
	done
	set -e
}

if ! check_command ; then
	print_logs
	exit 1
fi
