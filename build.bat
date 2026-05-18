@echo off
REM Build min_repro.cc with the same flags Firefox CI uses for security_descriptor.cc.
REM Assumes clang-cl is on PATH and a "VS 2026 18.6 x64" developer environment is active
REM (or that ASan / MSVC headers are otherwise reachable).

setlocal
set "OUT_EXE=min_repro.exe"

REM Flags that match Firefox's Windows ASan build for security/sandbox/chromium:
REM   -fms-compatibility-version=19.51    target MSVC 14.51 (VS 2026 18.6)
REM   -std:c++20
REM   -fsanitize=address                  enable ASan
REM   -mllvm -asan-stack=0                CI has this; harmless to keep
REM   -D_MSVC_STL_HARDENING=1             CI default (set by stl_hardening_flags)
REM   -D_DISABLE_VECTOR_ANNOTATION        WIP workaround flag from CI
REM   -D_DISABLE_STRING_ANNOTATION        WIP workaround flag from CI
REM   -D_HAS_EXCEPTIONS=0                 CI default
REM   -GR-                                no RTTI (matches CI)
REM   -O2 -Oy-                            CI optimization profile
REM   -Z7                                 debug info
clang-cl ^
    -fms-compatibility-version=19.51 ^
    -std:c++20 ^
    -fsanitize=address ^
    -mllvm -asan-stack=0 ^
    -D_MSVC_STL_HARDENING=1 ^
    -D_DISABLE_VECTOR_ANNOTATION ^
    -D_DISABLE_STRING_ANNOTATION ^
    -D_HAS_EXCEPTIONS=0 ^
    -GR- ^
    -O2 -Oy- ^
    -Z7 ^
    min_repro.cc ^
    /Fe:%OUT_EXE% ^
    /link Advapi32.lib

if errorlevel 1 (
    echo BUILD FAILED
    exit /b 1
)

echo Built %OUT_EXE%
