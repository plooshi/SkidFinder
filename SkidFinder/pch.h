// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

// add headers that you want to pre-compile here
#include "framework.h"
#include <thread>
#include <string>
#include <sstream>
#include <format>
#include <vector>
#include <stdexcept>
#include <type_traits>
#include <intrin.h>
#include <Windows.h>
#include <source_location>
#include <DbgHelp.h>
#include <algorithm>
#include <functional>
#include <iostream>
#include <array>
#include <map>
#pragma comment(lib, "Dbghelp.lib")
#include "memcury.h"
using namespace std;
typedef uint64_t uint64;
typedef uint32_t uint32;
typedef uint16_t uint16;
typedef uint8_t uint8;
typedef int64_t int64;
typedef int32_t int32;
typedef int16_t int16;
typedef int8_t int8;

#endif //PCH_H