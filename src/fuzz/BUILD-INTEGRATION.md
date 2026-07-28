# Build integration for `src/fuzz/`

> **Status: applied.**  The three changes described below are already
> present in this tree — `configure.ac` carries the `--enable-fuzzing`
> option and the `ENABLE_FUZZING` conditional, `AC_CONFIG_FILES` lists
> `src/fuzz/Makefile`, and `src/Makefile.am` adds `fuzz` to `SUBDIRS`
> under that conditional.  Only §1.3 (the optional configuration-summary
> line) is *not* applied.  The sections below are kept as the record of
> what was changed and as the recipe for porting `src/fuzz/` to another
> branch.
>
> For running these same harnesses on OSS-Fuzz — a different build path
> that does **not** go through `src/fuzz/Makefile.am` — see
> `../../contrib/oss-fuzz/` and §6 at the end of this file.

`src/fuzz/Makefile.am` is complete.  Three files outside `src/fuzz/`
have to be touched.  The snippets below are the *exact* text that was
added; nothing else changes.

The harnesses are guarded by a new automake conditional
`ENABLE_FUZZING` (`--enable-fuzzing`, default **no**), because they are
only meaningful in a build with sanitizers and assertions, and because
they need a static archive of the library (they call functions that are
hidden in the shared object).

---

## 1. `configure.ac`

### 1.1 The `--enable-fuzzing` option and the conditional

Add this next to the other feature checks — a good spot is right after
the `AM_CONDITIONAL([RUN_ZZUF_TESTS], ...)` /
`AM_CONDITIONAL([FORCE_USE_ZZUF_SOCAT], ...)` pair (around line 5833 in
the v1.0.7 tree):

```m4
# Fuzzing harnesses (src/fuzz)
AC_MSG_CHECKING([[whether to build the fuzzing harnesses]])
AC_ARG_ENABLE([[fuzzing]],
  [AS_HELP_STRING([[--enable-fuzzing]],
    [build the in-process fuzzing harnesses in src/fuzz and run them ]
    [as part of "make check"; requires a static build of the library ]
    [and is only really useful together with --enable-asserts and ]
    [--enable-sanitizers=address,undefined [no]])],
  [], [enable_fuzzing="no"])
AS_VAR_IF([enable_fuzzing], ["yes"],
  [
    AS_VAR_IF([enable_static], ["no"],
      [AC_MSG_RESULT([[no]])
       AC_MSG_ERROR([[--enable-fuzzing requires --enable-static]])],
      [AC_MSG_RESULT([[yes]])])
  ],
  [enable_fuzzing="no"
   AC_MSG_RESULT([[no]])])
AM_CONDITIONAL([ENABLE_FUZZING], [[test "x$enable_fuzzing" = "xyes"]])
```

### 1.2 Register the new `Makefile`

In the final `AC_CONFIG_FILES([...])` list (around line 5931 of the
v1.0.7 tree) add `src/fuzz/Makefile`, i.e. change

```
src/microhttpd/Makefile
...
src/testzzuf/Makefile])
```

to

```
src/microhttpd/Makefile
...
src/testzzuf/Makefile
src/fuzz/Makefile])
```

### 1.3 (optional, NOT applied) mention it in the configuration summary

If you want the harness state to show up in the final summary, add a
line next to the other `AC_MSG_NOTICE` entries:

```m4
AC_MSG_NOTICE([[  Fuzzing harnesses:  ${enable_fuzzing}]])
```

---

## 2. `src/Makefile.am`

Add the conditional `SUBDIRS` entry.  The current file reads

```make
SUBDIRS = include microhttpd .

if RUN_LIBCURL_TESTS
SUBDIRS += testcurl
if RUN_ZZUF_TESTS
SUBDIRS += testzzuf
endif
endif
```

Add immediately after that block:

```make
if ENABLE_FUZZING
SUBDIRS += fuzz
endif
```

Automake derives `DIST_SUBDIRS` from all branches of `SUBDIRS`
automatically, so `make dist` keeps working and ships `src/fuzz/`
regardless of the conditional.

---

## 3. `Makefile.am` (top level) — nothing to do

`src/fuzz/` is reached through `src/Makefile.am`; the top-level file
needs no change.

---

## 4. Regenerate and build

```sh
autoreconf -fi          # or ./bootstrap
./configure --enable-fuzzing \
            --enable-static \
            --enable-asserts \
            --enable-sanitizers=address,undefined \
            --disable-doc --disable-examples
make
make -C src/fuzz check
```

A full fuzzing session:

```sh
make -C src/fuzz check \
     MHD_FUZZ_ITERATIONS=5000000 \
     MHD_FUZZ_SEED=$RANDOM
```

Replay the checked-in corpus (what CI should do after a fix):

```sh
make -C src/fuzz check-corpus
```

---

## 5. Notes / caveats

* **`--enable-static` is mandatory.**  `fuzz_str` and
  `fuzz_auth_header` call `MHD_hex_to_bin()`, `MHD_str_quote()`,
  `MHD_pool_create()`, `MHD_get_rq_dauth_params_()` etc., which are
  built with `$(HIDDEN_VISIBILITY_CFLAGS)` and are therefore not
  exported from `libmicrohttpd.so`.  The `-static` in the per-program
  `_LDFLAGS` makes libtool pick `.libs/libmicrohttpd.a`.

* `fuzz_auth_header` is only built when `HAVE_ANYAUTH` is true (Basic or
  Digest authentication enabled).  Inside the harness the individual
  code paths are additionally guarded by `DAUTH_SUPPORT` /
  `BAUTH_SUPPORT`, and `fuzz_str` guards `MHD_str_unquote()`,
  `MHD_str_quote()` and `MHD_base64_to_bin_n()` the same way, so a
  `--disable-dauth --disable-bauth` build still compiles.

* `fuzz_postprocessor` needs `--enable-postprocessor` (the default); if
  you build with `--disable-postprocessor`, additionally guard it with
  the existing `HAVE_POSTPROCESSOR` conditional:

  ```make
  if HAVE_POSTPROCESSOR
  check_PROGRAMS += fuzz_postprocessor
  endif
  ```

  (it is currently listed unconditionally, matching the default build).

* The harnesses include internal headers (`internal.h`,
  `memorypool.h`, `gen_auth.h`, `mhd_str.h`), hence the
  `-I$(top_srcdir)/src/microhttpd` in `AM_CPPFLAGS`.  `MHD_config.h` is
  found through automake's default `-I$(top_builddir)`.

* `make check` in `src/fuzz` runs the full discipline / memory-limit
  range (`MHD_FUZZ_MIN_DISCIPLINE=-3`, `MHD_FUZZ_MIN_MEM_LIMIT=0`) with
  50000 iterations per harness, roughly 3 seconds in total under
  ASAN+UBSAN.  The findings K1-K6 of `README` section 6 are all fixed on
  master, so the full range is clean; their reproducers stay in
  `corpus/known-findings/` as regressions.  K7 is open, and its
  reproducer lives there too — `check-corpus` does not recurse into that
  directory, which is what keeps `make check` green while it is.

---

## 6. The OSS-Fuzz build path (does not use this Makefile.am)

`contrib/oss-fuzz/` builds the *same four harness sources* for
libFuzzer/AFL++/honggfuzz without going through `src/fuzz/Makefile.am`
at all.  It configures the library out of tree, then compiles each
harness by hand with `-DFUZZ_NO_MAIN` and links it against
`$LIB_FUZZING_ENGINE`:

```sh
$CC $CFLAGS -DFUZZ_NO_MAIN \
    -I$BUILD -I$SRCDIR -I$SRCDIR/src/include \
    -I$SRCDIR/src/microhttpd -I$SRCDIR/src/fuzz \
    -c $SRCDIR/src/fuzz/fuzz_request.c -o $WORK/fuzz_request.o
$CXX $CXXFLAGS $WORK/fuzz_request.o -o $OUT/fuzz_request \
    $LIB_FUZZING_ENGINE $BUILD/src/microhttpd/.libs/libmicrohttpd.a -lpthread
```

Two consequences for anyone editing `src/fuzz/`:

* **`LLVMFuzzerTestOneInput()` must stay unconditional.**  Only
  `main()` may be `#ifndef FUZZ_NO_MAIN`; a harness whose fuzz target is
  itself conditional silently produces an empty OSS-Fuzz binary.
* **Anything the fuzz target needs must not live inside the
  `#ifndef FUZZ_NO_MAIN` block of `fuzz_common.h`.**  The PRNG, the crash
  bookkeeping, `fuzz_report_finding()` and `fuzz_ignore_sigpipe()` are
  outside it; the generator loop, the mutator, the corpus walker and
  `main()` are inside.

  This is easy to get wrong and the failure is silent, so it is worth
  spelling out how it already bit us once.  `signal (SIGPIPE, SIG_IGN)`
  used to sit in `fuzz_install_handlers()`, i.e. inside the block.  Under
  the built-in driver everything looked perfect; under `-DFUZZ_NO_MAIN`
  the call vanished, and since `fuzz_request` writes into a socketpair
  whose peer MHD closes on any input that terminates the connection
  early, the process took a SIGPIPE and died after a few dozen
  executions.  libFuzzer does not intercept SIGPIPE (there is no
  `-handle_sigpipe`; see `-help=1`), so there was no stack trace, no
  artifact and no crash report -- the target just stopped, which reads
  exactly like a clean run that found nothing.  It is now
  `fuzz_ignore_sigpipe()`, called from both the driver and
  `LLVMFuzzerTestOneInput()`.

  The lesson generalises: a bug in this split cannot be caught by
  `make -C src/fuzz check`, because that path always defines `main()`.
  After touching `fuzz_common.h`, build the OSS-Fuzz way as well and
  confirm the target still runs -- `contrib/oss-fuzz/build.sh` works
  standalone on any machine with clang and `libclang-rt-dev`:

  ```sh
  git clone --shared . /tmp/mhd-fuzz-src        # build.sh needs a tree
                                                # with no in-tree config.status
  WORK=/tmp/mhd-fuzz-work OUT=/tmp/mhd-fuzz-out \
    MHD_SRC=/tmp/mhd-fuzz-src /tmp/mhd-fuzz-src/contrib/oss-fuzz/build.sh
  /tmp/mhd-fuzz-out/fuzz_request /tmp/mhd-fuzz-out/../corpus -max_total_time=60
  echo "exit=$?"        # anything but 0 here is a bug in the harness,
                        # not a finding
  ```

`contrib/oss-fuzz/` also relies on two things this directory provides:
`make -C src/fuzz refresh-corpus` (to regenerate `corpus/`) and the
`corpus/known-findings/` reproducers, which it packages into
`fuzz_request_seed_corpus.zip` so that K1–K6 become permanent
regressions.  It is deliberately **not** part of `contrib/ci/jobs/`.
