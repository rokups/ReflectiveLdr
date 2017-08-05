ReflectiveLdr
=============

This is a position-independent windows DLL/EXE loader based on original
[ReflectiveDLLInjection](https://github.com/stephenfewer/ReflectiveDLLInjection) project.

# Features

* Position-independent even after converting to c++.
* Heavily cleaned up code.
* Provides easy way to export reflective loader, just use `EXPORT_REFLECTIVE_LOADER` macro.
* Allows reflective modules to import api from another reflective modules.
* Provides means of specifying alternative procedures to be used when imports are missing (for example when OS does not
implement then, like `GetTickCount64()` on XP).
* C++ exception support on x64.
* MSVC and MingW support.
