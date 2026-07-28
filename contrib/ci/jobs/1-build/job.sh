#!/bin/bash
set -exuo pipefail

job_dir=$(dirname "${BASH_SOURCE[0]}")

. "${job_dir}"/build.sh
