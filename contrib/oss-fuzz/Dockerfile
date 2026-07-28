# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
#
# OSS-Fuzz Dockerfile for GNU libmicrohttpd.
#
# This file becomes projects/libmicrohttpd/Dockerfile in the google/oss-fuzz
# repository; the Apache-2.0 header above is the one OSS-Fuzz requires for
# files living in that repository.

FROM gcr.io/oss-fuzz-base/base-builder

# libmicrohttpd is an autotools project and the git checkout ships no
# 'configure', so the autotools themselves are build dependencies.
# No other dependency is needed: build.sh configures with --disable-https,
# --disable-curl and --disable-doc, which removes GnuTLS, libcurl and
# texinfo from the picture (see build.sh for the reasoning).
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        autoconf \
        automake \
        libtool \
        make \
        pkg-config \
        zip && \
    rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://git.gnunet.org/libmicrohttpd.git libmicrohttpd

WORKDIR $SRC/libmicrohttpd

COPY build.sh $SRC/
