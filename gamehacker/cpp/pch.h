#ifndef PCH_H
#define PCH_H

#include "vmmdll.h"
#include "framework.h"
#include <cstdio>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <unordered_map>
#include <algorithm>

#define DEBUG_INFO
#ifdef DEBUG_INFO
#define LOG(fmt, ...) std::printf(fmt, ##__VA_ARGS__)
#define LOGW(fmt, ...) std::wprintf(fmt, ##__VA_ARGS__)
#else
#define LOG
#define LOGW
#endif

#define THROW_EXCEPTION
#ifdef THROW_EXCEPTION
#define THROW(fmt, ...) throw std::runtime_error(fmt, ##__VA_ARGS__)
#endif

#endif