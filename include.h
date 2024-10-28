#pragma once
#include "globals.hh"
#include <d3d9.h>
#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "imgui/imgui_impl_dx9.h"
#include "imgui/imgui_impl_win32.h"
#include <string>
#include <array>
#include "prefetch_parser.hh"
#include <chrono>
#include <Windows.h>
#include <iomanip>
#include <sstream>
#include <unordered_set>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <algorithm>
#include <comdef.h>
#include <Wbemidl.h>
#include <vector>
#include <yara.h>
#include <filesystem>
#include <system_error>
#include <thread>
#include <ntsecapi.h>
#include <ntstatus.h>

#pragma comment(lib, "secur32.lib")
#pragma comment(lib,"d3d9.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

struct PrefetchFileInfo {
    std::string filename;
    long long executed_time;
    std::array<time_t, 8> last_eight_execution_times;
    std::string readable_time;
    std::vector<std::wstring> related_filenames;
    bool is_signed;
    bool is_present = true;
    std::vector<std::string> matched_rules;
    std::wstring proper_path;
    bool signature_checked = false;
    bool isInInstance;
};

struct LogonSessionInfo {
    FILETIME logonTime;
    DWORD sessionId;
    bool isInteractive;
};

std::string ConvertExecutedTime(long long executed_time);
std::wstring GetDriveLetterFromVolumePath(const std::wstring& volumePath);
bool IsFileSignatureValid(const std::wstring& filePath);
std::wstring StringToWString(const std::string& str);
std::string WStringToString(const std::wstring& wstr);
std::vector<PrefetchFileInfo> GetPrefetchFileInfos();
std::string GetFileTimeString(const FILETIME& fileTime);
std::string getOwnPath();
std::wstring ToUpperCase(const std::wstring& str);

struct GenericRule {
    std::string name;
    std::string rule;
};

extern std::vector<GenericRule> genericRules;

void addGenericRule(const std::string& name, const std::string& rule);

void initializeGenericRules();

bool scan_with_yara(const std::string& path, std::vector<std::string>& matched_rules);
