# VS 2026 18.6 + clang-cl + ASan use-after-poison repro attempt

Standalone repro attempt for a Firefox CI failure: `AddressSanitizer:
use-after-poison` (shadow byte `f7`, "Poisoned by user") inside
`base::win::SecurityDescriptor::WriteToHandle` when called from
`sandbox::HardenTokenIntegrityLevelPolicy` on Windows ASan builds using VS 2026
18.6.0 (MSVC 14.51.36231) + clang-cl 20.

## Status

**Likely identified.** MSVC STL 14.51 added `__asan_poison_memory_region`
calls to `<optional>` itself (see `__msvc_sanitizer_annotate_container.hpp`
and the `_Asan_optional_should_annotate` checks in `<optional>` lines
123/133/163/185). When an `optional<T>` is disengaged, the inner `_Value`
storage is poisoned. Chromium's `SecurityDescriptor` contains four
`optional<>` members; in `HardenTokenIntegrityLevelPolicy` only one
(`sacl_`) is engaged, so the other three storages stay poisoned.
`SetSecurityDescriptor` then appears to speculatively load through the
disengaged optionals when inlined by clang-cl at -O2, hitting the `f7`
shadow.

The fix should be `-D_DISABLE_OPTIONAL_ANNOTATION` (in addition to the
existing `_DISABLE_VECTOR_ANNOTATION` and `_DISABLE_STRING_ANNOTATION`).
This repro currently doesn't reproduce the crash standalone - investigating
what makes Firefox CI hit the speculative-load path while the standalone
doesn't.

## What's been ruled out

Confirmed in Firefox CI that **none** of the following individually
fixes the crash, even though each is correctly applied to the failing TU:

- `-D_DISABLE_VECTOR_ANNOTATION`
- `-D_DISABLE_STRING_ANNOTATION`
- `-fno-sanitize-address-use-after-scope`
- `-mllvm -asan-stack=0`
- `-U_MSVC_STL_HARDENING`
- No-op'ing absl's `ABSL_ANNOTATE_CONTIGUOUS_CONTAINER`

## Goal

A standalone C++ program that reproduces the same `f7` use-after-poison crash,
so we can:

1. Confirm the bug exists outside Firefox's build environment.
2. Use a debugger to find the actual call site of
   `__asan_poison_memory_region`.
3. Reduce to the smallest pattern that triggers it.
4. File upstream with Microsoft (separate from
   [microsoft/STL#6276](https://github.com/microsoft/STL/issues/6276), which
   doesn't appear to be the same bug).

## Build

Requires:

- A VS 2026 18.6 x64 developer command prompt active (so MSVC 14.51 headers
  and runtime libs are reachable).
- A `clang-cl` matching Firefox CI (Mozilla's prebuilt clang-20). `build.bat`
  looks for it in this order:
  1. `%CLANG_CL%` env var
  2. `clang-cl` on `PATH`
  3. `%USERPROFILE%\.mozbuild\clang\bin\clang-cl.exe` (the standard location
     that Firefox's `mach bootstrap` installs to)

Then:

```
build.bat
```

This produces `min_repro.exe` with ASan enabled. The compile flags in
`build.bat` mirror what Firefox CI passes to `security_descriptor.cc`.

## Run

```
min_repro.exe
```

If the bug reproduces standalone, expected output is an ASan
`use-after-poison` report. If the bug doesn't reproduce yet, the program will
print four pointer values and exit 0 - meaning the minimal mirror of
`SecurityDescriptor` isn't sufficient to trigger the poison, and we need to
add more of the real Chromium code (next steps below).

## Debug

If we get a crash, recommended workflow:

```
set ASAN_OPTIONS=halt_on_error=1:abort_on_error=1:disable_coredump=0:windows_hook_rtl_allocators=true
windbg min_repro.exe
```

In windbg: `bm clang_rt.asan_*!__asan_poison_memory_region` then `g`. Each
breakpoint hit is a candidate for the source of the leftover poison. The one
that hits the address that later triggers the crash is the culprit.

## Iteration plan

1. Compile and run min_repro.cc as-is. **If it crashes**, great - we have a
   1-file standalone repro. Proceed to debug.
2. If it doesn't crash, the minimal storage mirror isn't enough. Add real
   `FromHandle()` work (open the current process token, populate the
   `optional<>` members from real Windows APIs).
3. If still no crash, swap `std::optional` for `absl::optional` (more
   faithful to the Firefox tree).
4. If still no crash, copy in the actual Chromium source for `Sid`,
   `AccessControlList`, and `SecurityDescriptor` rather than re-implementing.

Each step should be a separate commit so we can bisect later.
