#!/bin/sh
set -ex
# This file is in the public domain.
# Determines the current version of our code.
# Shared between various jobs.

BRANCH=$(git name-rev --name-only HEAD)
if [ -z "${BRANCH}" ]; then
	exit 1
else
        # "Unshallow" our checkout, but only our current branch, and exclude the submodules.
	git fetch --no-recurse-submodules --tags --depth=1000 origin "${BRANCH}"
	RECENT_VERSION_TAG=$(git describe --tags --match 'v*.*.*' --exclude '*-dev*' --always --abbrev=0 HEAD || exit 1)
	commits="$(git rev-list ${RECENT_VERSION_TAG}..HEAD --count)"
	if [ "${commits}" = "0" ]; then
		git describe --tag HEAD | sed -r 's/^v//' || exit 1
	else
		echo $(echo ${RECENT_VERSION_TAG} | sed -r 's/^v//')-${commits}-$(git rev-parse --short=8 HEAD)
	fi
fi
