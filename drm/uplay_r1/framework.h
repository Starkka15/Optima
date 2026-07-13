#pragma once

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>

// --- MinGW compatibility shims for MSVC-only helpers used by the vendored
// Mini_Uplay source (Rat431/Mini_Uplay_API_Emu). ---
#include <cstdio>
#include <cstdint>
#ifndef sprintf_s
#define sprintf_s(buf, size, ...) snprintf((buf), (size), __VA_ARGS__)
#endif
