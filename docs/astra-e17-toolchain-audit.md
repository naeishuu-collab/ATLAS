# E17 Toolchain Audit (measured, offline)

- OS: Windows 10.0.26200.0. Python 3.11.9 (venv). rustc/cargo 1.99.0.
- PATH: no `cl/clang/gcc/cc/link` (E16 finding confirmed for PATH scope).
- Standard locations: `C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools`
  with `VC\Tools\MSVC\14.51.36231`, `vcvars64.bat` present;
  `C:\Program Files (x86)\Windows Kits\10` with SDK `10.0.26100.0`
  (bin/Include/Lib). No download needed.
- Effective toolchain: MSVC `19.51.36256` for x64 (from `cl` banner) +
  Windows SDK 10.0.26100.0. No LLVM/MinGW present. No new packages installed.
