@echo off
REM Build min_repro.cc with the same flags Firefox CI uses for security_descriptor.cc.
REM Requires a "VS 2026 18.6 x64" developer environment to be active (so MSVC
REM headers and the runtime libs are reachable).
REM
REM clang-cl is found in this order:
REM   1. CLANG_CL env var, if set
REM   2. clang-cl on PATH
REM   3. %USERPROFILE%\.mozbuild\clang\bin (the standard Mozilla bootstrap location)

setlocal
set "OUT_EXE=min_repro.exe"

if defined CLANG_CL (
    set "CLANG_CL_EXE=%CLANG_CL%"
    goto :have_clang
)

where clang-cl >nul 2>nul
if not errorlevel 1 (
    set "CLANG_CL_EXE=clang-cl"
    goto :have_clang
)

if exist "%USERPROFILE%\.mozbuild\clang\bin\clang-cl.exe" (
    set "CLANG_CL_EXE=%USERPROFILE%\.mozbuild\clang\bin\clang-cl.exe"
    goto :have_clang
)

echo Could not find clang-cl. Set CLANG_CL, add it to PATH, or install
echo Mozilla's bootstrap clang to %%USERPROFILE%%\.mozbuild\clang\bin.
exit /b 1

:have_clang
echo Using clang-cl: %CLANG_CL_EXE%

REM Flags that match Firefox's Windows ASan build for security/sandbox/chromium:
REM   -fms-compatibility-version=19.51    target MSVC 14.51 (VS 2026 18.6)
REM   -std:c++20
REM   -fsanitize=address                  enable ASan (MSVC STL auto-defines
REM                                       _INSERT_OPTIONAL_ANNOTATION on
REM                                       clang-cl + ASan, links stl_asan.lib)
REM   -mllvm -asan-stack=0                CI has this; harmless to keep
REM   -D_MSVC_STL_HARDENING=1             CI default (set by stl_hardening_flags)
REM   -D_HAS_EXCEPTIONS=0                 CI default
REM   -GR-                                no RTTI (matches CI)
REM   -O2 -Oy-                            CI optimization profile
REM   -Z7                                 debug info
REM
REM Note: deliberately NOT passing -D_DISABLE_OPTIONAL_ANNOTATION here; that's
REM the workaround Firefox uses in CI. We want the bug to manifest, not be
REM suppressed.
"%CLANG_CL_EXE%" ^
    -fms-compatibility-version=19.51 ^
    -std:c++20 ^
    -fsanitize=address ^
    -mllvm -asan-stack=0 ^
    -D_MSVC_STL_HARDENING=1 ^
    -D_HAS_EXCEPTIONS=0 ^
    -GR- ^
    -MD ^
    -O2 -Oy- ^
    -Z7 ^
    min_repro.cc ^
    /Fe:%OUT_EXE% ^
    /link Advapi32.lib Kernel32.lib

if errorlevel 1 (
    echo BUILD FAILED
    exit /b 1
)

REM Copy the matching ASan runtime DLL next to the .exe. Without this, Windows
REM picks up whichever clang_rt.asan_dynamic-x86_64.dll happens to be first on
REM PATH (e.g. the one from MSVC's AddressSanitizer component), which will be
REM ABI-incompatible with the binary we just linked.
set "ASAN_DLL_NAME=clang_rt.asan_dynamic-x86_64.dll"
set "ASAN_DLL_SRC="
for /f "delims=" %%I in ('dir /s /b "%~dp0..\..\.mozbuild\clang\%ASAN_DLL_NAME%" 2^>nul') do (
    set "ASAN_DLL_SRC=%%I"
)
if not defined ASAN_DLL_SRC (
    for /f "delims=" %%I in ('dir /s /b "%USERPROFILE%\.mozbuild\clang\%ASAN_DLL_NAME%" 2^>nul') do (
        set "ASAN_DLL_SRC=%%I"
    )
)
if defined ASAN_DLL_SRC (
    echo Copying %ASAN_DLL_SRC%
    copy /y "%ASAN_DLL_SRC%" "%~dp0%ASAN_DLL_NAME%" >nul
) else (
    echo WARNING: could not find %ASAN_DLL_NAME% to colocate with %OUT_EXE%.
    echo The exe will likely pick up a mismatched ASan runtime at launch.
)

echo Built %OUT_EXE%
