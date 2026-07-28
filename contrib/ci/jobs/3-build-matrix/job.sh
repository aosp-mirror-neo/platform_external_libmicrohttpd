#!/bin/bash
set -exuo pipefail

job_dir=$(dirname "${BASH_SOURCE[0]}")

. "${job_dir}"/1-bootstrap.sh
. "${job_dir}"/2-matrix.sh
