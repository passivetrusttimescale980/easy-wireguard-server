#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WINVER
#define WINVER 0x0601
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windowsx.h>
#include <winhttp.h>
#include <iphlpapi.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <shellapi.h>
#include <winsvc.h>
#include <shlwapi.h>
#include <commdlg.h>
#include <dwmapi.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <cwctype>
#include <cstring>
#include <fstream>
#include <mutex>
#include <regex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "wireguard_api_min.h"
#include "windivert_api_min.h"
#include "mini_qr.hpp"
#include "x25519_fallback.hpp"
#include "resource.h"
#include "version_auto.h"

// Windows RPC headers may define `small` as a preprocessor macro.
// Undefine it defensively so ordinary C++ identifiers are not rewritten.
#ifdef small
#undef small
#endif

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "dwmapi.lib")

// Older Windows SDK headers used with a Win7 target do not always expose
// this algorithm identifier, even though BCryptOpenAlgorithmProvider accepts
// the documented string value at runtime. Keep compilation independent of the
// SDK header version.
#ifndef BCRYPT_ECDH_ALGORITHM
#define BCRYPT_ECDH_ALGORITHM L"ECDH"
#endif
#ifndef BCRYPT_ECC_CURVE_25519
#define BCRYPT_ECC_CURVE_25519 L"curve25519"
#endif
#ifndef BCRYPT_ECC_CURVE_NAME
#define BCRYPT_ECC_CURVE_NAME L"ECCCurveName"
#endif
#ifndef LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR
#define LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR 0x00000100
#endif
#ifndef LOAD_LIBRARY_SEARCH_SYSTEM32
#define LOAD_LIBRARY_SEARCH_SYSTEM32 0x00000800
#endif

namespace {

constexpr wchar_t kAppName[] = L"EasyWG Server";
constexpr wchar_t kMainClass[] = L"EasyWG_Server_MainWindow";
constexpr wchar_t kModalClass[] = L"EasyWG_Server_ModalWindow";
constexpr wchar_t kQrClass[] = L"EasyWG_Server_QrWindow";
constexpr wchar_t kAdapterName[] = L"EasyWG";
constexpr wchar_t kTunnelType[] = L"EasyWG";
constexpr wchar_t kLegacyServiceName[] = L"WireGuardTunnel$EasyWG_Server_Win7";
constexpr wchar_t kSingleInstanceMutexName[] = L"Local\\EasyWG_Server_UI_6D5B8B5A_9C75_4F7A_A8E6_6A31B88DA146";
constexpr wchar_t kLegacyTunnelUrl[] =
    L"https://github.com/Terence0816/easy-wg-portable/releases/download/core-v1/tunnel-win7.dll";
constexpr wchar_t kLegacyWintunUrl[] = L"https://www.wintun.net/builds/wintun-0.13.zip";
constexpr UINT WM_APP_DLL_READY = WM_APP + 10;
constexpr UINT WM_APP_LOG_UPDATED = WM_APP + 11;
constexpr UINT WM_APP_WD_READY = WM_APP + 12;
constexpr UINT WM_APP_PUBLIC_IP_READY = WM_APP + 13;
constexpr UINT WM_APP_TRAY = WM_APP + 14;
constexpr UINT WM_APP_AUTOSTART_SERVER = WM_APP + 15;
constexpr UINT_PTR TIMER_STATS = 100;
constexpr int SERVER_TRANSITION_IDLE = 0;
constexpr int SERVER_TRANSITION_STARTING = 1;
constexpr int SERVER_TRANSITION_STOPPING = 2;

constexpr UINT IDM_TRAY_SHOW = 4101;
constexpr UINT IDM_TRAY_TOGGLE = 4102;
constexpr UINT IDM_TRAY_EXIT = 4103;
constexpr UINT IDM_PEER_EDIT = 4201;
constexpr UINT IDM_PEER_EXPORT = 4202;
constexpr UINT IDM_PEER_QR = 4203;
constexpr UINT IDM_PEER_REMOVE = 4204;
constexpr UINT IDC_ADD_NAME = 4301;
constexpr UINT IDC_ADD_OCTET = 4302;
constexpr UINT IDC_ADD_CREATE = 4303;
constexpr UINT IDC_ADD_SAVE_QR = 4304;
constexpr UINT IDC_ADD_SAVE_CONFIG = 4305;
constexpr UINT IDC_ADD_FULL_TUNNEL = 4306;
constexpr UINT IDC_DASH_SCROLL = 4310;
constexpr UINT IDC_USERS_SCROLL = 4311;

struct RectI { int x, y, w, h; };

bool PtIn(const RectI& r, int x, int y) {
    return x >= r.x && y >= r.y && x < r.x + r.w && y < r.y + r.h;
}

std::wstring Trim(std::wstring s) {
    const wchar_t* ws = L" \t\r\n";
    size_t a = s.find_first_not_of(ws);
    size_t b = s.find_last_not_of(ws);
    if (a == std::wstring::npos) return L"";
    return s.substr(a, b - a + 1);
}

std::wstring GetExePath() {
    std::vector<wchar_t> buf(32768);
    DWORD n = GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
    return n ? std::wstring(buf.data(), n) : L"EasyWG_Server.exe";
}

std::wstring GetExeDir() {
    std::wstring p = GetExePath();
    size_t pos = p.find_last_of(L"\\/");
    return pos == std::wstring::npos ? L"." : p.substr(0, pos);
}

std::wstring JoinPath(const std::wstring& a, const std::wstring& b) {
    if (a.empty()) return b;
    if (a.back() == L'\\' || a.back() == L'/') return a + b;
    return a + L"\\" + b;
}

std::wstring IniPath() { return JoinPath(GetExeDir(), L"EasyWG_Server.ini"); }
std::wstring DllPath() { return JoinPath(GetExeDir(), L"wireguard.dll"); }
std::wstring LegacyTunnelPath() { return JoinPath(GetExeDir(), L"tunnel-win7.dll"); }
std::wstring WintunDllPath() { return JoinPath(GetExeDir(), L"wintun.dll"); }
std::wstring WinDivertDllPath() { return JoinPath(GetExeDir(), L"WinDivert.dll"); }
std::wstring WinDivertSysPath() { return JoinPath(GetExeDir(), L"WinDivert64.sys"); }

bool IsWindows7OrEarlier();

std::wstring WinDivertVariantTag() {
    wchar_t buf[64]{};
    GetPrivateProfileStringW(L"Runtime", L"WinDivertVariant", L"",
                             buf, static_cast<DWORD>(_countof(buf)), IniPath().c_str());
    return Trim(buf);
}

bool SetWinDivertVariantTag(const std::wstring& tag) {
    return WritePrivateProfileStringW(L"Runtime", L"WinDivertVariant",
                                      tag.c_str(), IniPath().c_str()) != FALSE;
}

bool FileExistsNonEmpty(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data)) return false;
    if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) return false;
    ULARGE_INTEGER size{};
    size.HighPart = data.nFileSizeHigh;
    size.LowPart = data.nFileSizeLow;
    return size.QuadPart > 0;
}

bool WinDivertRuntimeReady() {
    const bool filesReady = FileExistsNonEmpty(WinDivertDllPath()) &&
                            FileExistsNonEmpty(WinDivertSysPath());
    if (!filesReady) return false;
    if (!IsWindows7OrEarlier()) return true;

    // Fix5: Windows 7 deliberately pins the tested 2.2.0-C package.
    // Do not treat A/B or a legacy folder runtime as ready; those variants
    // triggered the delayed Win7 PCA warning on the user's test system.
    const std::wstring tag = WinDivertVariantTag();
    return _wcsicmp(tag.c_str(), L"2.2.0-C") == 0;
}

bool IsWindows7OrEarlier() {
    using RtlGetVersionProc = LONG (WINAPI*)(PRTL_OSVERSIONINFOW);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;
    auto proc = reinterpret_cast<RtlGetVersionProc>(GetProcAddress(ntdll, "RtlGetVersion"));
    if (!proc) return false;
    RTL_OSVERSIONINFOW v{};
    v.dwOSVersionInfoSize = sizeof(v);
    if (proc(&v) != 0) return false;
    return v.dwMajorVersion < 6 || (v.dwMajorVersion == 6 && v.dwMinorVersion <= 1);
}

bool LegacyCoreRuntimeReady() {
    return FileExistsNonEmpty(LegacyTunnelPath()) &&
           FileExistsNonEmpty(WintunDllPath());
}

bool CoreRuntimeReady() {
    return IsWindows7OrEarlier() ? LegacyCoreRuntimeReady()
                                 : FileExistsNonEmpty(DllPath());
}

HMODULE LoadLibraryFromAppDirCompat(const std::wstring& fullPath) {
    // LOAD_LIBRARY_SEARCH_* flags require KB2533623 on Windows 7. Try the
    // hardened path first, then fall back to SetDllDirectory + LoadLibrary.
    HMODULE mod = LoadLibraryExW(fullPath.c_str(), nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (mod) return mod;

    const std::wstring dir = GetExeDir();
    SetDllDirectoryW(dir.c_str());
    mod = LoadLibraryW(fullPath.c_str());
    SetDllDirectoryW(nullptr);
    return mod;
}

bool RunHidden(const std::wstring& cmdLine, DWORD timeoutMs, DWORD* exitCode = nullptr);
bool WriteTempPowerShellScript(const std::string& body, std::wstring& path, std::wstring& err);

bool RemoveLegacyStartupRunValue() {
    HKEY key = nullptr;
    LONG rc = RegOpenKeyExW(HKEY_CURRENT_USER,
                            L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                            0, KEY_SET_VALUE, &key);
    if (rc == ERROR_FILE_NOT_FOUND) return true;
    if (rc != ERROR_SUCCESS) return false;
    rc = RegDeleteValueW(key, L"EasyWG Server");
    RegCloseKey(key);
    return rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND;
}

bool ApplyStartupRegistration(bool enable, std::wstring& err) {
    // v0.4.7+: use Task Scheduler instead of HKCU\\Run.  EasyWG requires
    // administrator privileges for WireGuardNT/WinDivert, so the startup task
    // is registered with "Run with highest privileges".  Also remove the old
    // HKCU Run value left by earlier builds.
    RemoveLegacyStartupRunValue();

    constexpr wchar_t kTaskName[] = L"EasyWG Server AutoStart";
    if (!enable) {
        DWORD ec = 0;
        std::wstring del = L"schtasks.exe /Delete /TN \"" + std::wstring(kTaskName) + L"\" /F";
        // Deleting a missing task is harmless; startup is disabled either way.
        RunHidden(del, 15000, &ec);
        return true;
    }

    std::wstring exe = GetExePath();
    std::wstring cmd = L"schtasks.exe /Create /TN \"" + std::wstring(kTaskName) +
                       L"\" /SC ONLOGON /RL HIGHEST /IT /TR \"\\\"" + exe +
                       L"\\\"\" /F";
    DWORD ec = 0;
    if (!RunHidden(cmd, 30000, &ec)) {
        err = L"Cannot create elevated Windows startup task (schtasks exit " + std::to_wstring(ec) + L")";
        return false;
    }
    return true;
}


// Packet-level diagnostic file tracing was removed after the NAT/Host Alias
// path was validated.  Keep call sites compiled out so packet hot paths do not
// build trace strings or touch disk.  Basic operational messages still use
// AddLog() and remain visible on the Logs page.
#define PacketTrace(...) ((void)0)
#define ResetPacketTrace(...) ((void)0)

std::wstring WinError(DWORD e = GetLastError()) {
    wchar_t* msg = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, e, 0, reinterpret_cast<wchar_t*>(&msg), 0, nullptr);
    std::wstring out = msg ? Trim(msg) : L"未知錯誤";
    LocalFree(msg);
    std::wstringstream ss;
    ss << out << L" (" << e << L")";
    return ss.str();
}

std::wstring FormatBytes(uint64_t n) {
    const wchar_t* u[] = {L"B", L"KB", L"MB", L"GB", L"TB"};
    double v = static_cast<double>(n);
    int i = 0;
    while (v >= 1024.0 && i < 4) { v /= 1024.0; ++i; }
    wchar_t b[64];
    if (i == 0) swprintf_s(b, L"%llu %s", static_cast<unsigned long long>(n), u[i]);
    else swprintf_s(b, L"%.2f %s", v, u[i]);
    return b;
}

std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (!n) return L"";
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}

// Decode redirected child-process output robustly. Windows PowerShell 5.1 can
// emit UTF-8, UTF-16LE, OEM code-page, or ANSI bytes depending on how a script
// writes to stdout/stderr. Treating all of them as UTF-8 caused mojibake in the
// NAT error dialog on Traditional Chinese Windows.
std::wstring DecodeProcessOutput(const std::string& bytes) {
    if (bytes.empty()) return L"";

    const auto u8 = reinterpret_cast<const unsigned char*>(bytes.data());
    const size_t n = bytes.size();

    auto decodeUtf16 = [&](bool bigEndian, size_t start) {
        std::wstring out;
        out.reserve((n - start) / 2);
        for (size_t i = start; i + 1 < n; i += 2) {
            uint16_t v = bigEndian
                ? static_cast<uint16_t>((static_cast<uint16_t>(u8[i]) << 8) | u8[i + 1])
                : static_cast<uint16_t>(u8[i] | (static_cast<uint16_t>(u8[i + 1]) << 8));
            out.push_back(static_cast<wchar_t>(v));
        }
        return out;
    };

    // BOM-based UTF-16 detection.
    if (n >= 2 && u8[0] == 0xFF && u8[1] == 0xFE) return decodeUtf16(false, 2);
    if (n >= 2 && u8[0] == 0xFE && u8[1] == 0xFF) return decodeUtf16(true, 2);

    // Heuristic UTF-16 detection for redirected PowerShell output without BOM.
    if (n >= 4) {
        size_t oddNul = 0, evenNul = 0, pairs = n / 2;
        for (size_t i = 0; i + 1 < n; i += 2) {
            if (u8[i] == 0) ++evenNul;
            if (u8[i + 1] == 0) ++oddNul;
        }
        if (pairs && oddNul * 4 >= pairs) return decodeUtf16(false, 0);
        if (pairs && evenNul * 4 >= pairs) return decodeUtf16(true, 0);
    }

    size_t start = (n >= 3 && u8[0] == 0xEF && u8[1] == 0xBB && u8[2] == 0xBF) ? 3 : 0;
    const char* data = bytes.data() + start;
    int len = static_cast<int>(n - start);

    // Strict UTF-8 first. MB_ERR_INVALID_CHARS prevents invalid OEM/ANSI bytes
    // from being silently converted into replacement characters.
    int chars = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, data, len, nullptr, 0);
    if (chars > 0) {
        std::wstring out(chars, L'\0');
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, data, len, out.data(), chars);
        return out;
    }

    // Console tools on zh-TW Windows commonly use the OEM code page (CP950 in
    // many environments), while other APIs use ACP. Try both before giving up.
    for (UINT cp : {CP_OEMCP, CP_ACP}) {
        chars = MultiByteToWideChar(cp, 0, data, len, nullptr, 0);
        if (chars > 0) {
            std::wstring out(chars, L'\0');
            MultiByteToWideChar(cp, 0, data, len, out.data(), chars);
            return out;
        }
    }
    return L"";
}

std::wstring GetIni(const wchar_t* section, const wchar_t* key, const wchar_t* def = L"") {
    std::vector<wchar_t> b(8192);
    GetPrivateProfileStringW(section, key, def, b.data(), static_cast<DWORD>(b.size()), IniPath().c_str());
    return b.data();
}

void SetIni(const wchar_t* section, const wchar_t* key, const std::wstring& value) {
    WritePrivateProfileStringW(section, key, value.c_str(), IniPath().c_str());
}

void DeleteIniKey(const wchar_t* section, const wchar_t* key) {
    WritePrivateProfileStringW(section, key, nullptr, IniPath().c_str());
}

std::wstring Base64Encode(const BYTE* data, DWORD len) {
    DWORD chars = 0;
    if (!CryptBinaryToStringW(data, len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &chars)) return L"";
    std::wstring out(chars, L'\0');
    if (!CryptBinaryToStringW(data, len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, out.data(), &chars)) return L"";
    if (!out.empty() && out.back() == L'\0') out.pop_back();
    return out;
}

bool Base64Decode(const std::wstring& text, BYTE* out, DWORD expected) {
    DWORD bytes = expected;
    return CryptStringToBinaryW(text.c_str(), 0, CRYPT_STRING_BASE64, out, &bytes, nullptr, nullptr) && bytes == expected;
}

bool GenerateKeyPair(BYTE publicKey[32], BYTE privateKey[32]) {
    // Windows 10+ path: use CNG named curve25519 when available. Skip the
    // named-curve probe entirely on Win7, where this capability is absent.
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    NTSTATUS st = static_cast<NTSTATUS>(-1);
    if (!IsWindows7OrEarlier()) {
        st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDH_ALGORITHM, nullptr, 0);
    }
    if (st >= 0) {
        st = BCryptSetProperty(alg, BCRYPT_ECC_CURVE_NAME,
                               reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_ECC_CURVE_25519)),
                               static_cast<ULONG>((wcslen(BCRYPT_ECC_CURVE_25519) + 1) * sizeof(wchar_t)), 0);
    }
    if (st >= 0) st = BCryptGenerateKeyPair(alg, &key, 255, 0);
    if (st >= 0) st = BCryptFinalizeKeyPair(key, 0);

    struct ExportBlob {
        BCRYPT_ECCKEY_BLOB Header;
        BYTE Public[32];
        BYTE Unused[32];
        BYTE Private[32];
    } blob{};
    ULONG written = 0;
    if (st >= 0) {
        st = BCryptExportKey(key, nullptr, BCRYPT_ECCPRIVATE_BLOB,
                             reinterpret_cast<PUCHAR>(&blob), sizeof(blob), &written, 0);
    }
    const bool cngOk = st >= 0 && written >= sizeof(blob);
    if (cngOk) {
        memcpy(publicKey, blob.Public, 32);
        memcpy(privateKey, blob.Private, 32);
    }
    SecureZeroMemory(&blob, sizeof(blob));
    if (key) BCryptDestroyKey(key);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    if (cngOk) return true;

    // Windows 7 fallback: BCryptGenRandom exists, but CNG named curve25519
    // does not. Generate a random WireGuard private key and derive the public
    // key with the bundled compact X25519 implementation.
    if (BCryptGenRandom(nullptr, privateKey, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        return false;
    return easywg_x25519::public_from_private(publicKey, privateKey);
}

bool RandomKey(BYTE key[32]) {
    return BCryptGenRandom(nullptr, key, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0;
}

struct PeerInfo {
    std::wstring name;
    std::wstring ip;
    std::array<BYTE, 32> publicKey{};
    std::array<BYTE, 32> privateKey{};
    std::array<BYTE, 32> presharedKey{};
    uint64_t rx = 0;
    uint64_t tx = 0;
    uint64_t lastHandshake = 0;
    // true: route all IPv4 traffic through EasyWG; false: only VPN/LAN /24 networks.
    bool fullTunnel = false;
};

struct ServerSettings {
    std::wstring address = L"10.66.66.1";
    int prefix = 24;
    int port = 51820;
    std::wstring endpoint;
    std::wstring clientAllowedIPs = L"10.66.66.0/24";
    std::wstring dns;
    // v0.4 product defaults are fixed: /24 + NAT. Hidden from Settings UI.
    std::wstring lanAccessMode = L"nat";
    std::wstring lanSubnet = L"192.168.11.0/24";
    std::wstring language = L"zh-TW";
    std::wstring theme = L"system"; // system / light / dark
    bool closeToTray = true;
    bool startWithWindows = false;
    bool autoStartServer = false;
    std::array<BYTE, 32> publicKey{};
    std::array<BYTE, 32> privateKey{};
};

std::mutex gDataMutex;
ServerSettings gSettings;
std::vector<PeerInfo> gPeers;
std::vector<std::wstring> gLogs;
std::atomic<bool> gEnglish{false};
bool gFirstRun = false;
bool gNeedInitialEndpointDetect = false;
std::wstring gCurrentPublicIp;
std::mutex gPublicIpMutex;

NOTIFYICONDATAW gTrayData{};
bool gTrayAdded = false;
bool gExitRequested = false;
HANDLE gSingleInstanceMutex = nullptr;
HICON gAppIcon = nullptr;
HICON gAppIconSmall = nullptr;
int gAutoStartRetry = 0;

void UpdateTrayIconTip();
bool AllowedIpListContains(const std::wstring& list, const std::wstring& wanted);

std::wstring T(const wchar_t* zh, const wchar_t* en) { return gEnglish.load() ? en : zh; }

void AddLog(const std::wstring& s) {
    SYSTEMTIME st{};
    GetLocalTime(&st);
    wchar_t t[32];
    swprintf_s(t, L"%02u:%02u:%02u", st.wHour, st.wMinute, st.wSecond);
    std::lock_guard<std::mutex> lock(gDataMutex);
    gLogs.push_back(std::wstring(t) + L"  " + s);
    if (gLogs.size() > 500) gLogs.erase(gLogs.begin(), gLogs.begin() + 100);
}

void SaveConfig() {
    std::lock_guard<std::mutex> lock(gDataMutex);
    SetIni(L"Server", L"Address", gSettings.address);
    SetIni(L"Server", L"Prefix", std::to_wstring(gSettings.prefix));
    SetIni(L"Server", L"ListenPort", std::to_wstring(gSettings.port));
    SetIni(L"Server", L"Endpoint", gSettings.endpoint);
    SetIni(L"Server", L"ClientAllowedIPs", gSettings.clientAllowedIPs);
    SetIni(L"Server", L"DNS", gSettings.dns);
    SetIni(L"Server", L"LanAccessMode", gSettings.lanAccessMode);
    SetIni(L"Server", L"LanSubnet", gSettings.lanSubnet);
    SetIni(L"Server", L"Language", gSettings.language);
    SetIni(L"Server", L"Theme", gSettings.theme);
    SetIni(L"Server", L"CloseToTray", gSettings.closeToTray ? L"1" : L"0");
    SetIni(L"Server", L"StartWithWindows", gSettings.startWithWindows ? L"1" : L"0");
    SetIni(L"Server", L"AutoStartServer", gSettings.autoStartServer ? L"1" : L"0");
    // Provider-specific DDNS integration remains removed. Clean old v0.4.0 keys
    // during upgrade so DuckDNS tokens/domains are not left behind in the INI.
    DeleteIniKey(L"Server", L"DuckDnsDomain");
    DeleteIniKey(L"Server", L"DuckDnsToken");
    SetIni(L"Server", L"ConfigVersion", EASYWG_VERSION_STR_W);
    SetIni(L"Server", L"PrivateKey", Base64Encode(gSettings.privateKey.data(), 32));
    SetIni(L"Server", L"PublicKey", Base64Encode(gSettings.publicKey.data(), 32));
    SetIni(L"Peers", L"Count", std::to_wstring(gPeers.size()));
    for (size_t i = 0; i < gPeers.size(); ++i) {
        std::wstring sec = L"Peer" + std::to_wstring(i);
        SetIni(sec.c_str(), L"Name", gPeers[i].name);
        SetIni(sec.c_str(), L"IP", gPeers[i].ip);
        SetIni(sec.c_str(), L"PublicKey", Base64Encode(gPeers[i].publicKey.data(), 32));
        SetIni(sec.c_str(), L"PrivateKey", Base64Encode(gPeers[i].privateKey.data(), 32));
        SetIni(sec.c_str(), L"PresharedKey", Base64Encode(gPeers[i].presharedKey.data(), 32));
        SetIni(sec.c_str(), L"FullTunnel", gPeers[i].fullTunnel ? L"1" : L"0");
    }
}

void LoadConfig() {
    std::lock_guard<std::mutex> lock(gDataMutex);
    gSettings.address = GetIni(L"Server", L"Address", L"10.66.66.1");
    gSettings.prefix = _wtoi(GetIni(L"Server", L"Prefix", L"24").c_str());
    gSettings.port = _wtoi(GetIni(L"Server", L"ListenPort", L"51820").c_str());
    gSettings.endpoint = GetIni(L"Server", L"Endpoint", L"");
    gSettings.clientAllowedIPs = GetIni(L"Server", L"ClientAllowedIPs", L"10.66.66.0/24");
    gSettings.dns = GetIni(L"Server", L"DNS", L"");
    std::wstring cfgVer = GetIni(L"Server", L"ConfigVersion", L"");
    gSettings.lanAccessMode = GetIni(L"Server", L"LanAccessMode", L"nat");
    // v0.3.2 keeps NAT as the product default so ordinary home routers
    // only need UDP port forwarding.  Old v0.2.x configs did not carry a
    // ConfigVersion and were saved as route by default; migrate those defaults.
    if (cfgVer.empty() && gSettings.lanAccessMode == L"route") gSettings.lanAccessMode = L"nat";
    gSettings.lanSubnet = GetIni(L"Server", L"LanSubnet", L"192.168.11.0/24");
    // v0.4: Prefix and LAN mode are fixed product defaults and no longer user-facing.
    gSettings.prefix = 24;
    gSettings.lanAccessMode = L"nat";
    std::wstring defaultLang = PRIMARYLANGID(GetUserDefaultUILanguage()) == LANG_CHINESE ? L"zh-TW" : L"en";
    gSettings.language = GetIni(L"Server", L"Language", defaultLang.c_str());
    if (gSettings.language != L"en") gSettings.language = L"zh-TW";
    gSettings.theme = GetIni(L"Server", L"Theme", L"system");
    if (gSettings.theme != L"light" && gSettings.theme != L"dark") gSettings.theme = L"system";
    gSettings.closeToTray = GetIni(L"Server", L"CloseToTray", L"1") != L"0";
    gSettings.startWithWindows = GetIni(L"Server", L"StartWithWindows", L"0") == L"1";
    gSettings.autoStartServer = GetIni(L"Server", L"AutoStartServer", L"0") == L"1";
    gEnglish = (gSettings.language == L"en");

    std::wstring priv = GetIni(L"Server", L"PrivateKey", L"");
    std::wstring pub = GetIni(L"Server", L"PublicKey", L"");
    if (!Base64Decode(priv, gSettings.privateKey.data(), 32) ||
        !Base64Decode(pub, gSettings.publicKey.data(), 32)) {
        GenerateKeyPair(gSettings.publicKey.data(), gSettings.privateKey.data());
    }

    gPeers.clear();
    int count = _wtoi(GetIni(L"Peers", L"Count", L"0").c_str());
    count = std::clamp(count, 0, 1000);
    for (int i = 0; i < count; ++i) {
        std::wstring sec = L"Peer" + std::to_wstring(i);
        PeerInfo p;
        p.name = GetIni(sec.c_str(), L"Name", (L"User " + std::to_wstring(i + 1)).c_str());
        p.ip = GetIni(sec.c_str(), L"IP", L"");
        if (!Base64Decode(GetIni(sec.c_str(), L"PublicKey", L""), p.publicKey.data(), 32)) continue;
        Base64Decode(GetIni(sec.c_str(), L"PrivateKey", L""), p.privateKey.data(), 32);
        Base64Decode(GetIni(sec.c_str(), L"PresharedKey", L""), p.presharedKey.data(), 32);
        // Existing INI files did not have FullTunnel. Preserve their old global
        // AllowedIPs behavior during the first load, then SaveConfig writes it per user.
        const wchar_t* legacyMode = AllowedIpListContains(gSettings.clientAllowedIPs, L"0.0.0.0/0") ? L"1" : L"0";
        p.fullTunnel = GetIni(sec.c_str(), L"FullTunnel", legacyMode) == L"1";
        gPeers.push_back(p);
    }
}

std::wstring NextPeerIp() {
    // Initial version intentionally targets the common 10.x.x.0/24-style server setup.
    std::lock_guard<std::mutex> lock(gDataMutex);
    IN_ADDR srv{};
    if (InetPtonW(AF_INET, gSettings.address.c_str(), &srv) != 1) return L"10.66.66.2";
    uint32_t host = ntohl(srv.S_un.S_addr);
    uint32_t base = host & 0xFFFFFF00u;
    for (uint32_t n = 2; n <= 254; ++n) {
        IN_ADDR a{}; a.S_un.S_addr = htonl(base | n);
        wchar_t b[64]{}; InetNtopW(AF_INET, &a, b, 64);
        bool used = false;
        for (const auto& p : gPeers) if (p.ip == b) { used = true; break; }
        if (!used && gSettings.address != b) return b;
    }
    return L"10.66.66.2";
}

bool ParseIpv4Cidr(const std::wstring& cidr, IN_ADDR& address, int& prefix) {
    size_t slash = cidr.find(L'/');
    std::wstring ip = slash == std::wstring::npos ? cidr : cidr.substr(0, slash);
    prefix = slash == std::wstring::npos ? 32 : _wtoi(cidr.substr(slash + 1).c_str());
    return prefix >= 0 && prefix <= 32 && InetPtonW(AF_INET, Trim(ip).c_str(), &address) == 1;
}

std::wstring Ipv4NetworkCidr(const std::wstring& ip, int prefix) {
    IN_ADDR a{};
    if (prefix < 0 || prefix > 32 || InetPtonW(AF_INET, ip.c_str(), &a) != 1) return L"";
    uint32_t host = ntohl(a.S_un.S_addr);
    uint32_t mask = prefix == 0 ? 0u : (0xFFFFFFFFu << (32 - prefix));
    IN_ADDR net{}; net.S_un.S_addr = htonl(host & mask);
    wchar_t buf[64]{};
    if (!InetNtopW(AF_INET, &net, buf, _countof(buf))) return L"";
    return std::wstring(buf) + L"/" + std::to_wstring(prefix);
}

std::wstring EffectiveClientAllowedIPs(const ServerSettings& s) {
    std::wstring out = Trim(s.clientAllowedIPs);
    if (s.lanAccessMode != L"off" && !Trim(s.lanSubnet).empty()) {
        std::wstring lowOut = out, lowLan = Trim(s.lanSubnet);
        std::transform(lowOut.begin(), lowOut.end(), lowOut.begin(), [](wchar_t c){ return static_cast<wchar_t>(towlower(c)); });
        std::transform(lowLan.begin(), lowLan.end(), lowLan.begin(), [](wchar_t c){ return static_cast<wchar_t>(towlower(c)); });
        if (lowOut.find(lowLan) == std::wstring::npos) {
            if (!out.empty()) out += L", ";
            out += Trim(s.lanSubnet);
        }
    }
    return out.empty() ? Ipv4NetworkCidr(s.address, s.prefix) : out;
}

bool AllowedIpListContains(const std::wstring& list, const std::wstring& wanted) {
    size_t start = 0;
    while (start <= list.size()) {
        const size_t comma = list.find(L',', start);
        const std::wstring token = Trim(list.substr(
            start, comma == std::wstring::npos ? std::wstring::npos : comma - start));
        if (_wcsicmp(token.c_str(), wanted.c_str()) == 0) return true;
        if (comma == std::wstring::npos) break;
        start = comma + 1;
    }
    return false;
}

void AppendUniqueCidr(std::vector<std::wstring>& cidrs, const std::wstring& cidr) {
    if (cidr.empty()) return;
    for (const auto& old : cidrs) {
        if (_wcsicmp(old.c_str(), cidr.c_str()) == 0) return;
    }
    cidrs.push_back(cidr);
}

std::wstring NormalizeIpv4Network24(const std::wstring& value) {
    IN_ADDR address{};
    int prefix = 0;
    if (!ParseIpv4Cidr(value, address, prefix)) return L"";
    wchar_t ip[64]{};
    if (!InetNtopW(AF_INET, &address, ip, _countof(ip))) return L"";
    return Ipv4NetworkCidr(ip, 24);
}

std::wstring JoinCidrs(const std::vector<std::wstring>& cidrs) {
    std::wstring out;
    for (const auto& cidr : cidrs) {
        if (!out.empty()) out += L", ";
        out += cidr;
    }
    return out;
}

std::wstring PeerClientAllowedIPs(const ServerSettings& st, const PeerInfo& peer) {
    if (peer.fullTunnel) return L"0.0.0.0/0";

    // Private-network-only profiles keep normal Internet traffic on the client.
    // The public edition has one local LAN plus the EasyWG VPN subnet, both /24.
    std::vector<std::wstring> cidrs;
    AppendUniqueCidr(cidrs, NormalizeIpv4Network24(st.lanSubnet));
    AppendUniqueCidr(cidrs, Ipv4NetworkCidr(st.address, 24));
    if (cidrs.empty()) AppendUniqueCidr(cidrs, L"10.66.66.0/24");
    return JoinCidrs(cidrs);
}

bool IsElevated() {
    BOOL elevated = FALSE;
    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION te{}; DWORD cb = 0;
        if (GetTokenInformation(token, TokenElevation, &te, sizeof(te), &cb)) elevated = te.TokenIsElevated;
        CloseHandle(token);
    }
    return elevated == TRUE;
}

bool RelaunchElevated() {
    std::wstring exe = GetExePath();
    HINSTANCE h = ShellExecuteW(nullptr, L"runas", exe.c_str(), nullptr, GetExeDir().c_str(), SW_SHOWNORMAL);
    return reinterpret_cast<INT_PTR>(h) > 32;
}

// ---------------- HTTP / WireGuard DLL bootstrap ----------------

bool HttpGet(const std::wstring& url, std::vector<BYTE>& out, std::wstring& err) {
    URL_COMPONENTS uc{}; uc.dwStructSize = sizeof(uc);
    wchar_t host[256]{}; wchar_t path[4096]{}; wchar_t extra[4096]{};
    uc.lpszHostName = host; uc.dwHostNameLength = _countof(host);
    uc.lpszUrlPath = path; uc.dwUrlPathLength = _countof(path);
    uc.lpszExtraInfo = extra; uc.dwExtraInfoLength = _countof(extra);
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &uc)) { err = L"網址解析失敗: " + WinError(); return false; }

    std::wstring userAgent = L"EasyWG-Server/" + std::wstring(EASYWG_VERSION_STR_W);
    constexpr DWORD kWinHttpAutomaticProxy = 4; // WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY
    DWORD accessType = IsWindows7OrEarlier() ? WINHTTP_ACCESS_TYPE_DEFAULT_PROXY
                                               : kWinHttpAutomaticProxy;
    HINTERNET ses = WinHttpOpen(userAgent.c_str(), accessType,
                                WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!ses) { err = L"WinHTTP 初始化失敗: " + WinError(); return false; }
    WinHttpSetTimeouts(ses, 10000, 10000, 15000, 30000);
#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 0x00000800
#endif
    if (IsWindows7OrEarlier()) {
        DWORD secureProtocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
        WinHttpSetOption(ses, WINHTTP_OPTION_SECURE_PROTOCOLS,
                         &secureProtocols, sizeof(secureProtocols));
    }
    HINTERNET con = WinHttpConnect(ses, std::wstring(host, uc.dwHostNameLength).c_str(), uc.nPort, 0);
    if (!con) { err = L"連線失敗: " + WinError(); WinHttpCloseHandle(ses); return false; }
    DWORD flags = uc.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0;
    std::wstring objectPath(path, uc.dwUrlPathLength);
    if (uc.dwExtraInfoLength) objectPath.append(extra, uc.dwExtraInfoLength);
    HINTERNET req = WinHttpOpenRequest(con, L"GET", objectPath.c_str(),
                                       nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!req) { err = L"建立 HTTP 要求失敗: " + WinError(); WinHttpCloseHandle(con); WinHttpCloseHandle(ses); return false; }
    bool ok = WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, nullptr, 0, 0, 0) && WinHttpReceiveResponse(req, nullptr);
    if (!ok) err = L"下載失敗: " + WinError();
    if (ok) {
        DWORD status = 0, cb = sizeof(status);
        WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &cb, WINHTTP_NO_HEADER_INDEX);
        if (status < 200 || status >= 300) { ok = false; err = L"伺服器回應 HTTP " + std::to_wstring(status); }
    }
    while (ok) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(req, &avail)) { ok = false; err = L"讀取下載大小失敗: " + WinError(); break; }
        if (!avail) break;
        size_t old = out.size(); out.resize(old + avail);
        DWORD read = 0;
        if (!WinHttpReadData(req, out.data() + old, avail, &read)) { ok = false; err = L"下載資料失敗: " + WinError(); break; }
        out.resize(old + read);
    }
    WinHttpCloseHandle(req); WinHttpCloseHandle(con); WinHttpCloseHandle(ses);
    return ok;
}

bool DetectPublicIpv4(std::wstring& ip, std::wstring& err) {
    std::vector<BYTE> body;
    if (!HttpGet(L"https://api.ipify.org", body, err)) return false;
    std::string raw(reinterpret_cast<const char*>(body.data()), body.size());
    ip = Trim(Utf8ToWide(raw));
    IN_ADDR a{};
    if (InetPtonW(AF_INET, ip.c_str(), &a) != 1) { err = L"Invalid public IPv4 response"; ip.clear(); return false; }
    return true;
}

bool DetectPrimaryLan(std::wstring& ip, std::wstring& cidr) {
    SOCKADDR_IN dst{}; dst.sin_family = AF_INET; InetPtonW(AF_INET, L"1.1.1.1", &dst.sin_addr);
    DWORD best = 0;
    if (GetBestInterfaceEx(reinterpret_cast<SOCKADDR*>(&dst), &best) != NO_ERROR) return false;
    ULONG bytes = 0;
    GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &bytes);
    if (!bytes) return false;
    std::vector<BYTE> buf(bytes);
    auto* aa = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, aa, &bytes) != NO_ERROR) return false;
    for (auto* a = aa; a; a = a->Next) {
        if (a->IfIndex != best || a->OperStatus != IfOperStatusUp) continue;
        for (auto* u = a->FirstUnicastAddress; u; u = u->Next) {
            auto* sa = reinterpret_cast<SOCKADDR_IN*>(u->Address.lpSockaddr);
            if (!sa || sa->sin_family != AF_INET) continue;
            wchar_t b[64]{}; if (!InetNtopW(AF_INET, &sa->sin_addr, b, _countof(b))) continue;
            ip = b; cidr = Ipv4NetworkCidr(ip, static_cast<int>(u->OnLinkPrefixLength));
            return !cidr.empty();
        }
    }
    return false;
}


std::vector<int> ParseVersionNums(const std::wstring& s) {
    std::vector<int> v; int cur = -1;
    for (wchar_t c : s) {
        if (c >= L'0' && c <= L'9') { if (cur < 0) cur = 0; cur = cur * 10 + (c - L'0'); }
        else if (cur >= 0) { v.push_back(cur); cur = -1; }
    }
    if (cur >= 0) v.push_back(cur);
    return v;
}

bool VersionLess(const std::wstring& a, const std::wstring& b) {
    auto va = ParseVersionNums(a), vb = ParseVersionNums(b);
    size_t n = (std::max)(va.size(), vb.size());
    va.resize(n); vb.resize(n);
    return va < vb;
}

bool WriteBytes(const std::wstring& path, const std::vector<BYTE>& data) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    bool ok = data.empty() || (WriteFile(h, data.data(), static_cast<DWORD>(data.size()), &written, nullptr) && written == data.size());
    CloseHandle(h);
    return ok;
}

std::wstring ReadUtf8FileSmall(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return L"";
    LARGE_INTEGER li{};
    if (!GetFileSizeEx(h, &li) || li.QuadPart <= 0 || li.QuadPart > 65536) {
        CloseHandle(h);
        return L"";
    }
    std::vector<char> bytes(static_cast<size_t>(li.QuadPart));
    DWORD got = 0;
    const BOOL ok = ReadFile(h, bytes.data(), static_cast<DWORD>(bytes.size()), &got, nullptr);
    CloseHandle(h);
    if (!ok || got == 0) return L"";
    bytes.resize(got);
    return Trim(Utf8ToWide(std::string(bytes.begin(), bytes.end())));
}

bool RunHidden(const std::wstring& cmdLine, DWORD timeoutMs, DWORD* exitCode) {
    STARTUPINFOW si{}; si.cb = sizeof(si); si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> buf(cmdLine.begin(), cmdLine.end()); buf.push_back(0);
    if (!CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) return false;
    DWORD wait = WaitForSingleObject(pi.hProcess, timeoutMs);
    DWORD ec = 1;
    if (wait == WAIT_OBJECT_0) GetExitCodeProcess(pi.hProcess, &ec);
    else TerminateProcess(pi.hProcess, 2);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    if (exitCode) *exitCode = ec;
    return wait == WAIT_OBJECT_0 && ec == 0;
}

bool RunHiddenCapture(const std::wstring& cmdLine, DWORD timeoutMs, std::wstring& output, DWORD* exitCode = nullptr) {
    output.clear();
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE readPipe = nullptr, writePipe = nullptr;
    if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) return false;
    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = writePipe;
    si.hStdError = writePipe;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> buf(cmdLine.begin(), cmdLine.end());
    buf.push_back(0);

    BOOL created = CreateProcessW(nullptr, buf.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                                  nullptr, nullptr, &si, &pi);
    CloseHandle(writePipe);
    if (!created) {
        CloseHandle(readPipe);
        return false;
    }

    std::string bytes;
    DWORD start = GetTickCount();
    for (;;) {
        DWORD avail = 0;
        if (PeekNamedPipe(readPipe, nullptr, 0, nullptr, &avail, nullptr) && avail > 0) {
            char chunk[4096];
            DWORD got = 0;
            DWORD want = (std::min)(avail, static_cast<DWORD>(sizeof(chunk)));
            if (ReadFile(readPipe, chunk, want, &got, nullptr) && got > 0) bytes.append(chunk, got);
        }

        DWORD wait = WaitForSingleObject(pi.hProcess, 50);
        if (wait == WAIT_OBJECT_0) break;
        if (GetTickCount() - start >= timeoutMs) {
            TerminateProcess(pi.hProcess, 2);
            break;
        }
    }

    for (;;) {
        char chunk[4096];
        DWORD got = 0;
        if (!ReadFile(readPipe, chunk, sizeof(chunk), &got, nullptr) || got == 0) break;
        bytes.append(chunk, got);
    }

    DWORD ec = 1;
    GetExitCodeProcess(pi.hProcess, &ec);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(readPipe);

    if (exitCode) *exitCode = ec;
    if (!bytes.empty()) output = Trim(DecodeProcessOutput(bytes));
    return ec == 0;
}

bool FindDllRecursive(const std::wstring& root, const std::wstring& archTag, std::wstring& found) {
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(JoinPath(root, L"*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return false;
    std::vector<std::wstring> candidates;
    do {
        if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) continue;
        std::wstring p = JoinPath(root, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            std::wstring nested;
            if (FindDllRecursive(p, archTag, nested)) candidates.push_back(nested);
        } else if (_wcsicmp(fd.cFileName, L"wireguard.dll") == 0) {
            candidates.push_back(p);
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    for (const auto& c : candidates) {
        std::wstring low = c;
        std::transform(low.begin(), low.end(), low.begin(), [](wchar_t ch) { return static_cast<wchar_t>(towlower(ch)); });
        if (low.find(archTag) != std::wstring::npos) { found = c; return true; }
    }
    if (!candidates.empty()) { found = candidates.front(); return true; }
    return false;
}


bool FindNamedFileRecursive(const std::wstring& root, const std::wstring& fileName,
                            const std::wstring& preferTag, std::wstring& found) {
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(JoinPath(root, L"*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return false;
    std::vector<std::wstring> candidates;
    do {
        if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) continue;
        std::wstring path = JoinPath(root, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            std::wstring nested;
            if (FindNamedFileRecursive(path, fileName, preferTag, nested)) candidates.push_back(nested);
        } else if (_wcsicmp(fd.cFileName, fileName.c_str()) == 0) {
            candidates.push_back(path);
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);

    if (!preferTag.empty()) {
        for (const auto& c : candidates) {
            std::wstring low = c, tag = preferTag;
            std::transform(low.begin(), low.end(), low.begin(), [](wchar_t ch){ return static_cast<wchar_t>(towlower(ch)); });
            std::transform(tag.begin(), tag.end(), tag.begin(), [](wchar_t ch){ return static_cast<wchar_t>(towlower(ch)); });
            if (low.find(tag) != std::wstring::npos) { found = c; return true; }
        }
        return false;
    }
    if (!candidates.empty()) { found = candidates.front(); return true; }
    return false;
}

bool NormalizeServiceImagePath(std::wstring path, std::wstring& normalized) {
    path = Trim(path);
    if (path.size() >= 2 && path.front() == L'"' && path.back() == L'"')
        path = path.substr(1, path.size() - 2);
    if (path.rfind(L"\\??\\", 0) == 0) path.erase(0, 4);
    std::replace(path.begin(), path.end(), L'/', L'\\');

    wchar_t full[32768]{};
    DWORD n = GetFullPathNameW(path.c_str(), static_cast<DWORD>(_countof(full)), full, nullptr);
    if (!n || n >= _countof(full)) return false;
    normalized.assign(full, n);
    while (normalized.size() > 3 && normalized.back() == L'\\') normalized.pop_back();
    return true;
}

bool PrepareWin7WinDivertRuntimeSwap(std::wstring& err) {
    if (!IsWindows7OrEarlier()) return true;

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        DWORD e = GetLastError();
        if (e == ERROR_ACCESS_DENIED) {
            err = L"切換 Win7 WinDivert 簽章版本需要系統管理員權限。";
            return false;
        }
        // No SCM access is not fatal if there is no service to migrate; however
        // EasyWG normally runs elevated, so keep the error explicit.
        err = L"OpenSCManager 失敗: " + WinError(e);
        return false;
    }

    SC_HANDLE svc = OpenServiceW(scm, L"WinDivert",
        SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP | DELETE);
    if (!svc) {
        DWORD e = GetLastError();
        CloseServiceHandle(scm);
        if (e == ERROR_SERVICE_DOES_NOT_EXIST) return true;
        err = L"開啟既有 WinDivert 服務失敗: " + WinError(e);
        return false;
    }

    DWORD needed = 0;
    QueryServiceConfigW(svc, nullptr, 0, &needed);
    std::vector<BYTE> cfgBuf(needed ? needed : 4096);
    auto* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(cfgBuf.data());
    if (!QueryServiceConfigW(svc, cfg, static_cast<DWORD>(cfgBuf.size()), &needed)) {
        DWORD e = GetLastError();
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        err = L"讀取既有 WinDivert 服務路徑失敗: " + WinError(e);
        return false;
    }

    std::wstring servicePath, ownPath;
    const bool servicePathOk = cfg->lpBinaryPathName &&
                               NormalizeServiceImagePath(cfg->lpBinaryPathName, servicePath);
    const bool ownPathOk = NormalizeServiceImagePath(WinDivertSysPath(), ownPath);
    if (!servicePathOk || !ownPathOk || _wcsicmp(servicePath.c_str(), ownPath.c_str()) != 0) {
        const std::wstring shown = servicePathOk ? servicePath : L"(unknown)";
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        err = L"系統已有其他位置的 WinDivert 服務，為避免影響其他程式，EasyWG 不會自動移除。\n\n"
              L"目前服務路徑: " + shown + L"\nEasyWG 路徑: " + ownPath;
        return false;
    }

    SERVICE_STATUS_PROCESS sp{};
    DWORD cb = 0;
    if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                             reinterpret_cast<LPBYTE>(&sp), sizeof(sp), &cb) &&
        sp.dwCurrentState != SERVICE_STOPPED) {
        SERVICE_STATUS st{};
        if (!ControlService(svc, SERVICE_CONTROL_STOP, &st)) {
            DWORD e = GetLastError();
            if (e != ERROR_SERVICE_NOT_ACTIVE) {
                CloseServiceHandle(svc);
                CloseServiceHandle(scm);
                err = L"停止舊 WinDivert 服務失敗: " + WinError(e) +
                      L"。請先關閉其他使用 WinDivert 的程式後再試。";
                return false;
            }
        }

        const ULONGLONG started = GetTickCount64();
        while (GetTickCount64() - started < 10000) {
            ZeroMemory(&sp, sizeof(sp));
            if (!QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                                      reinterpret_cast<LPBYTE>(&sp), sizeof(sp), &cb)) break;
            if (sp.dwCurrentState == SERVICE_STOPPED) break;
            Sleep(200);
        }
        if (sp.dwCurrentState != SERVICE_STOPPED) {
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            err = L"舊 WinDivert 服務仍在執行，無法安全切換簽章版本。請重新開機後再啟動 EasyWG。";
            return false;
        }
    }

    if (!DeleteService(svc)) {
        DWORD e = GetLastError();
        if (e != ERROR_SERVICE_MARKED_FOR_DELETE && e != ERROR_SERVICE_DOES_NOT_EXIST) {
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            err = L"移除舊 WinDivert 服務註冊失敗: " + WinError(e);
            return false;
        }
    }
    CloseServiceHandle(svc);

    // Wait briefly for the service object to disappear so the alternate driver
    // is recreated cleanly by the new WinDivert.dll on first WinDivertOpen().
    const ULONGLONG started = GetTickCount64();
    while (GetTickCount64() - started < 10000) {
        SC_HANDLE probe = OpenServiceW(scm, L"WinDivert", SERVICE_QUERY_STATUS);
        if (!probe) {
            if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) break;
        } else {
            CloseServiceHandle(probe);
        }
        Sleep(200);
    }
    CloseServiceHandle(scm);
    return true;
}

bool DownloadOfficialWinDivertRuntime(std::wstring& err) {
    struct PackageCandidate {
        const wchar_t* variant;
        const wchar_t* url;
    };

    // Fix5: Win7 uses only official WinDivert 2.2.0-C. This exact variant
    // was verified on the user's Win7 SP1 system without the delayed PCA
    // unsigned-driver warning. Do not silently fall back to A/B on Win7.
    const PackageCandidate win7Candidates[] = {
        { L"2.2.0-C", L"https://github.com/basil00/WinDivert/releases/download/v2.2.0/WinDivert-2.2.0-C.zip" },
        { L"2.2.0-C", L"https://reqrypt.org/download/WinDivert-2.2.0-C.zip" }
    };
    const PackageCandidate modernCandidates[] = {
        { L"2.2.2-A", L"https://reqrypt.org/download/WinDivert-2.2.2-A.zip" },
        { L"2.2.2-A", L"https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip" }
    };

    const bool win7 = IsWindows7OrEarlier();
    const PackageCandidate* candidates = win7 ? win7Candidates : modernCandidates;
    const size_t candidateCount = win7 ? _countof(win7Candidates) : _countof(modernCandidates);

    std::vector<BYTE> zip;
    std::wstring lastErr;
    std::wstring selectedVariant;
    bool downloaded = false;
    for (size_t i = 0; i < candidateCount; ++i) {
        zip.clear();
        std::wstring oneErr;
        if (HttpGet(candidates[i].url, zip, oneErr) &&
            zip.size() >= 4 && zip[0] == 'P' && zip[1] == 'K') {
            downloaded = true;
            selectedVariant = candidates[i].variant;
            break;
        }
        if (oneErr.empty()) oneErr = L"下載內容不是有效 ZIP";
        lastErr = oneErr;
    }
    if (!downloaded) {
        err = win7 ? L"下載官方 WinDivert 2.2.0-C 失敗: " + lastErr
                   : L"下載官方 WinDivert 2.2.2-A 失敗: " + lastErr;
        return false;
    }

    wchar_t tempBase[MAX_PATH]{}; GetTempPathW(MAX_PATH, tempBase);
    wchar_t tempName[MAX_PATH]{}; GetTempFileNameW(tempBase, L"EWD", 0, tempName);
    DeleteFileW(tempName);
    std::wstring work = tempName;
    CreateDirectoryW(work.c_str(), nullptr);
    std::wstring zipPath = JoinPath(work, L"windivert.zip");
    std::wstring outDir = JoinPath(work, L"out");
    CreateDirectoryW(outDir.c_str(), nullptr);
    if (!WriteBytes(zipPath, zip)) { err = L"無法寫入 WinDivert 暫存 ZIP"; return false; }

    DWORD ec = 1;
    std::wstring cmd = L"tar.exe -xf \"" + zipPath + L"\" -C \"" + outDir + L"\"";
    bool extracted = RunHidden(cmd, 120000, &ec);
    if (!extracted) {
        cmd = L"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"Expand-Archive -LiteralPath '" +
              zipPath + L"' -DestinationPath '" + outDir + L"' -Force\"";
        extracted = RunHidden(cmd, 120000, &ec);
    }
    if (!extracted && win7) {
        const std::string shellScript = R"PS1(param([string]$ZipPath,[string]$OutputDir)
$ErrorActionPreference='Stop'
$shell=New-Object -ComObject Shell.Application
$zipNs=$shell.NameSpace($ZipPath); $destNs=$shell.NameSpace($OutputDir)
if($null -eq $zipNs -or $null -eq $destNs){throw 'Windows ZIP shell namespace unavailable.'}
$destNs.CopyHere($zipNs.Items(),20)
for($i=0;$i -lt 400;$i++){
  $dll=Get-ChildItem -Path $OutputDir -Recurse -Filter 'WinDivert.dll' -ErrorAction SilentlyContinue | Where-Object {-not $_.PSIsContainer} | Select-Object -First 1
  $sys=Get-ChildItem -Path $OutputDir -Recurse -Filter 'WinDivert64.sys' -ErrorAction SilentlyContinue | Where-Object {-not $_.PSIsContainer} | Select-Object -First 1
  if($dll -and $sys){exit 0}
  Start-Sleep -Milliseconds 100
}
throw 'WinDivert files were not extracted in time.'
)PS1";
        std::wstring scriptPath, scriptErr;
        if (WriteTempPowerShellScript(shellScript, scriptPath, scriptErr)) {
            cmd = L"powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"" + scriptPath +
                  L"\" -ZipPath \"" + zipPath + L"\" -OutputDir \"" + outDir + L"\"";
            extracted = RunHidden(cmd, 120000, &ec);
            DeleteFileW(scriptPath.c_str());
        }
    }
    if (!extracted) { err = L"無法解壓 WinDivert 套件（tar/Expand-Archive/Win7 Shell 均失敗）"; return false; }

    std::wstring dllSrc, sysSrc;
    if (!FindNamedFileRecursive(outDir, L"WinDivert.dll", L"\\x64\\", dllSrc) &&
        !FindNamedFileRecursive(outDir, L"WinDivert.dll", L"x64", dllSrc)) {
        err = L"WinDivert ZIP 內找不到 x64 WinDivert.dll"; return false;
    }
    if (!FindNamedFileRecursive(outDir, L"WinDivert64.sys", L"", sysSrc)) {
        err = L"WinDivert ZIP 內找不到 WinDivert64.sys"; return false;
    }

    if (win7) {
        // Existing Fix1/Fix2/Fix3 folders contain 2.2.2-A. Stop/delete only the
        // WinDivert service whose image path is exactly EasyWG's own SYS file.
        // This avoids touching another application's WinDivert installation.
        std::wstring swapErr;
        if (!PrepareWin7WinDivertRuntimeSwap(swapErr)) {
            err = L"Win7 WinDivert 簽章版本切換失敗: " + swapErr;
            return false;
        }
        SetWinDivertVariantTag(L"");
    }

    if (!CopyFileW(dllSrc.c_str(), WinDivertDllPath().c_str(), FALSE)) {
        DWORD e = GetLastError();
        err = L"複製 WinDivert.dll 失敗: " + WinError(e);
        if (win7 && (e == ERROR_SHARING_VIOLATION || e == ERROR_ACCESS_DENIED))
            err += L"。請重新開機後直接啟動 EasyWG 再試。";
        return false;
    }
    if (!CopyFileW(sysSrc.c_str(), WinDivertSysPath().c_str(), FALSE)) {
        DWORD e = GetLastError();
        err = L"複製 WinDivert64.sys 失敗: " + WinError(e);
        if (win7 && (e == ERROR_SHARING_VIOLATION || e == ERROR_ACCESS_DENIED))
            err += L"。請重新開機後直接啟動 EasyWG 再試。";
        return false;
    }

    if (!SetWinDivertVariantTag(selectedVariant)) {
        err = L"Runtime 已複製，但無法在 EasyWG_Server.ini 記錄 WinDivertVariant=" + selectedVariant;
        return false;
    }
    AddLog(L"WinDivert 官方 Runtime 已安裝: " + selectedVariant +
           (win7 ? L"（Windows 7 實測 2.2.0-C）" : L""));
    return true;
}

bool DownloadOfficialWireGuardDll(std::wstring& err) {
    const std::wstring indexUrl = L"https://download.wireguard.com/wireguard-nt/";
    std::vector<BYTE> idx;
    if (!HttpGet(indexUrl, idx, err)) return false;
    std::string html(reinterpret_cast<const char*>(idx.data()), idx.size());
    std::wstring whtml = Utf8ToWide(html);
    std::wregex re(LR"(wireguard-nt-([0-9][0-9A-Za-z._-]*)\.zip)", std::regex::icase);
    std::wstring bestFile, bestVer;
    for (std::wsregex_iterator it(whtml.begin(), whtml.end(), re), end; it != end; ++it) {
        std::wstring file = (*it)[0].str();
        std::wstring ver = (*it)[1].str();
        if (bestFile.empty() || VersionLess(bestVer, ver)) { bestFile = file; bestVer = ver; }
    }
    if (bestFile.empty()) { err = L"官方下載頁中找不到 wireguard-nt ZIP 檔"; return false; }
    AddLog(L"找到官方 WireGuardNT 套件: " + bestFile);

    std::vector<BYTE> zip;
    if (!HttpGet(indexUrl + bestFile, zip, err)) return false;

    wchar_t tempBase[MAX_PATH]{}; GetTempPathW(MAX_PATH, tempBase);
    wchar_t tempName[MAX_PATH]{}; GetTempFileNameW(tempBase, L"EWG", 0, tempName);
    DeleteFileW(tempName);
    std::wstring work = tempName;
    CreateDirectoryW(work.c_str(), nullptr);
    std::wstring zipPath = JoinPath(work, L"wireguard-nt.zip");
    std::wstring outDir = JoinPath(work, L"out");
    CreateDirectoryW(outDir.c_str(), nullptr);
    if (!WriteBytes(zipPath, zip)) { err = L"無法寫入暫存 ZIP"; return false; }

    // Windows 10/11 include bsdtar. PowerShell is the fallback.
    DWORD ec = 1;
    std::wstring cmd = L"tar.exe -xf \"" + zipPath + L"\" -C \"" + outDir + L"\"";
    bool extracted = RunHidden(cmd, 120000, &ec);
    if (!extracted) {
        cmd = L"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"Expand-Archive -LiteralPath '" +
              zipPath + L"' -DestinationPath '" + outDir + L"' -Force\"";
        extracted = RunHidden(cmd, 120000, &ec);
    }
    if (!extracted) { err = L"無法解壓 WireGuardNT 套件（tar/PowerShell 均失敗）"; return false; }

#if defined(_M_X64)
    const std::wstring arch = L"amd64";
#elif defined(_M_IX86)
    const std::wstring arch = L"x86";
#elif defined(_M_ARM64)
    const std::wstring arch = L"arm64";
#else
    const std::wstring arch = L"amd64";
#endif

    std::wstring src;
    if (!FindDllRecursive(outDir, arch, src)) { err = L"ZIP 內找不到對應架構的 wireguard.dll"; return false; }
    if (!CopyFileW(src.c_str(), DllPath().c_str(), FALSE)) { err = L"複製 wireguard.dll 失敗: " + WinError(); return false; }
    AddLog(L"wireguard.dll 已從官方下載並安裝: " + bestVer);
    return true;
}

// ---------------- WireGuardNT dynamic binding ----------------

struct WgApi {
    HMODULE dll = nullptr;
    WIREGUARD_CREATE_ADAPTER_FUNC* CreateAdapter = nullptr;
    WIREGUARD_OPEN_ADAPTER_FUNC* OpenAdapter = nullptr;
    WIREGUARD_CLOSE_ADAPTER_FUNC* CloseAdapter = nullptr;
    WIREGUARD_GET_ADAPTER_LUID_FUNC* GetAdapterLuid = nullptr;
    WIREGUARD_GET_RUNNING_DRIVER_VERSION_FUNC* GetRunningDriverVersion = nullptr;
    WIREGUARD_SET_LOGGER_FUNC* SetLogger = nullptr;
    WIREGUARD_SET_ADAPTER_LOGGING_FUNC* SetAdapterLogging = nullptr;
    WIREGUARD_GET_ADAPTER_STATE_FUNC* GetAdapterState = nullptr;
    WIREGUARD_SET_ADAPTER_STATE_FUNC* SetAdapterState = nullptr;
    WIREGUARD_GET_CONFIGURATION_FUNC* GetConfiguration = nullptr;
    WIREGUARD_SET_CONFIGURATION_FUNC* SetConfiguration = nullptr;

    void Unload() {
        if (dll) FreeLibrary(dll);
        *this = {};
    }

    bool Load(std::wstring& err) {
        if (dll) return true;
        dll = LoadLibraryFromAppDirCompat(DllPath());
        if (!dll) { err = L"載入 wireguard.dll 失敗: " + WinError(); return false; }
#define WGGET(member, name) member = reinterpret_cast<decltype(member)>(GetProcAddress(dll, name)); if (!member) { err = L"wireguard.dll 缺少 API: " + Utf8ToWide(name); Unload(); return false; }
        WGGET(CreateAdapter, "WireGuardCreateAdapter");
        WGGET(OpenAdapter, "WireGuardOpenAdapter");
        WGGET(CloseAdapter, "WireGuardCloseAdapter");
        WGGET(GetAdapterLuid, "WireGuardGetAdapterLUID");
        WGGET(GetRunningDriverVersion, "WireGuardGetRunningDriverVersion");
        WGGET(SetLogger, "WireGuardSetLogger");
        WGGET(SetAdapterLogging, "WireGuardSetAdapterLogging");
        WGGET(GetAdapterState, "WireGuardGetAdapterState");
        WGGET(SetAdapterState, "WireGuardSetAdapterState");
        WGGET(GetConfiguration, "WireGuardGetConfiguration");
        WGGET(SetConfiguration, "WireGuardSetConfiguration");
#undef WGGET
        return true;
    }
};

WgApi gWg;
WIREGUARD_ADAPTER_HANDLE gAdapter = nullptr;
std::atomic<bool> gRunning{false};
std::atomic<bool> gLegacyWin7Mode{false};
std::atomic<int> gServerTransition{SERVER_TRANSITION_IDLE};
std::atomic<bool> gDllDownloading{false};
std::atomic<bool> gWinDivertDownloading{false};
std::atomic<bool> gLegacyStatsAvailable{false};
std::atomic<int> gLegacyStatsFailureCount{0};
std::wstring gLegacyUapiPipePath;
std::chrono::steady_clock::time_point gStartedAt;

void CALLBACK WgLogger(WIREGUARD_LOGGER_LEVEL level, DWORD64, LPCWSTR msg) {
    std::wstring p = level == WIREGUARD_LOG_ERR ? L"[ERR] " : level == WIREGUARD_LOG_WARN ? L"[WARN] " : L"[INFO] ";
    AddLog(p + (msg ? msg : L""));
}

bool BuildWgConfig(std::vector<BYTE>& buf, std::wstring& err) {
    ServerSettings s;
    std::vector<PeerInfo> peers;
    {
        std::lock_guard<std::mutex> lock(gDataMutex);
        s = gSettings; peers = gPeers;
    }
    size_t bytes = sizeof(WIREGUARD_INTERFACE);
    bytes += peers.size() * (sizeof(WIREGUARD_PEER) + sizeof(WIREGUARD_ALLOWED_IP));
    buf.assign(bytes, 0);
    BYTE* cur = buf.data();
    auto* iface = reinterpret_cast<WIREGUARD_INTERFACE*>(cur);
    iface->Flags = static_cast<WIREGUARD_INTERFACE_FLAG>(WIREGUARD_INTERFACE_HAS_PRIVATE_KEY |
                     WIREGUARD_INTERFACE_HAS_LISTEN_PORT | WIREGUARD_INTERFACE_REPLACE_PEERS);
    iface->ListenPort = static_cast<WORD>(s.port);
    memcpy(iface->PrivateKey, s.privateKey.data(), 32);
    iface->PeersCount = static_cast<DWORD>(peers.size());
    cur += sizeof(WIREGUARD_INTERFACE);

    for (const auto& p : peers) {
        auto* peer = reinterpret_cast<WIREGUARD_PEER*>(cur);
        peer->Flags = static_cast<WIREGUARD_PEER_FLAG>(WIREGUARD_PEER_HAS_PUBLIC_KEY |
                       WIREGUARD_PEER_HAS_PRESHARED_KEY | WIREGUARD_PEER_REPLACE_ALLOWED_IPS);
        memcpy(peer->PublicKey, p.publicKey.data(), 32);
        memcpy(peer->PresharedKey, p.presharedKey.data(), 32);
        peer->AllowedIPsCount = 1;
        cur += sizeof(WIREGUARD_PEER);

        auto* aip = reinterpret_cast<WIREGUARD_ALLOWED_IP*>(cur);
        aip->AddressFamily = AF_INET;
        aip->Cidr = 32;
        if (InetPtonW(AF_INET, p.ip.c_str(), &aip->Address.V4) != 1) {
            err = L"Peer IP 無效: " + p.ip; return false;
        }
        cur += sizeof(WIREGUARD_ALLOWED_IP);
    }
    return true;
}

bool AssignAdapterIp(NET_LUID luid, std::wstring& err) {
    ServerSettings s;
    { std::lock_guard<std::mutex> lock(gDataMutex); s = gSettings; }
    MIB_UNICASTIPADDRESS_ROW row{};
    InitializeUnicastIpAddressEntry(&row);
    row.InterfaceLuid = luid;
    row.Address.Ipv4.sin_family = AF_INET;
    if (InetPtonW(AF_INET, s.address.c_str(), &row.Address.Ipv4.sin_addr) != 1) { err = L"Server VPN IP 無效"; return false; }
    row.OnLinkPrefixLength = static_cast<UINT8>(s.prefix);
    row.DadState = IpDadStatePreferred;
    DWORD rc = CreateUnicastIpAddressEntry(&row);
    if (rc != NO_ERROR && rc != ERROR_OBJECT_ALREADY_EXISTS) { err = L"設定 WG 介面 IP 失敗: " + WinError(rc); return false; }

    MIB_IPINTERFACE_ROW ifr{};
    InitializeIpInterfaceEntry(&ifr);
    ifr.InterfaceLuid = luid; ifr.Family = AF_INET;
    rc = GetIpInterfaceEntry(&ifr);
    if (rc == NO_ERROR) {
        ifr.UseAutomaticMetric = FALSE;
        ifr.Metric = 5;
        ifr.NlMtu = 1420;
        SetIpInterfaceEntry(&ifr);
    }
    return true;
}

void AddFirewallRule(int port) {
    std::wstring cmd = L"netsh.exe advfirewall firewall delete rule name=\"EasyWG Server\" >nul 2>nul & "
                       L"netsh.exe advfirewall firewall add rule name=\"EasyWG Server\" dir=in action=allow protocol=UDP localport=" +
                       std::to_wstring(port) + L" profile=any >nul";
    RunHidden(L"cmd.exe /c " + cmd, 30000);
}

struct ForwardingBackup {
    NET_LUID luid{};
    BOOLEAN oldValue = FALSE;
};
std::vector<ForwardingBackup> gForwardingBackup;
bool gNatCreated = false;

bool SetForwardingViaPowerShell(NET_LUID luid, bool enabled, std::wstring& err) {
    NET_IFINDEX index = 0;
    DWORD rc = ConvertInterfaceLuidToIndex(&luid, &index);
    if (rc != NO_ERROR || index == 0) {
        err = L"無法取得介面索引: " + WinError(rc);
        return false;
    }
    std::wstring cmd =
        L"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \""
        L"Set-NetIPInterface -AddressFamily IPv4 -InterfaceIndex " + std::to_wstring(index) +
        L" -Forwarding " + (enabled ? std::wstring(L"Enabled") : std::wstring(L"Disabled")) +
        L" -ErrorAction Stop\"";
    DWORD ec = 1;
    if (!RunHidden(cmd, 30000, &ec)) {
        err = L"PowerShell 設定介面 Forwarding 失敗（InterfaceIndex=" + std::to_wstring(index) +
              L", ExitCode=" + std::to_wstring(ec) + L"）";
        return false;
    }
    return true;
}


bool SetForwardingViaNetsh(NET_LUID luid, bool enabled, std::wstring& err) {
    NET_IFINDEX index = 0;
    DWORD rc = ConvertInterfaceLuidToIndex(&luid, &index);
    if (rc != NO_ERROR || index == 0) {
        err = L"無法取得介面索引: " + WinError(rc);
        return false;
    }
    std::wstring cmd = L"cmd.exe /c netsh interface ipv4 set interface " + std::to_wstring(index) +
                       L" forwarding=" + (enabled ? std::wstring(L"enabled") : std::wstring(L"disabled")) +
                       L" >nul";
    DWORD ec = 1;
    if (!RunHidden(cmd, 30000, &ec)) {
        err = L"netsh 設定介面 Forwarding 失敗（InterfaceIndex=" + std::to_wstring(index) +
              L", ExitCode=" + std::to_wstring(ec) + L"）";
        return false;
    }
    return true;
}

bool SetInterfaceForwarding(NET_LUID luid, bool enabled, bool rememberOld, std::wstring& err) {
    MIB_IPINTERFACE_ROW row{};
    InitializeIpInterfaceEntry(&row);
    row.InterfaceLuid = luid;
    row.Family = AF_INET;
    DWORD rc = GetIpInterfaceEntry(&row);
    if (rc != NO_ERROR) { err = L"讀取介面 Forwarding 失敗: " + WinError(rc); return false; }
    if (rememberOld) {
        bool known = false;
        for (const auto& x : gForwardingBackup) if (x.luid.Value == luid.Value) { known = true; break; }
        if (!known) gForwardingBackup.push_back({luid, row.ForwardingEnabled});
    }
    row.ForwardingEnabled = enabled ? TRUE : FALSE;
    rc = SetIpInterfaceEntry(&row);
    if (rc == NO_ERROR) return true;

    // Some Windows builds/drivers reject ForwardingEnabled through SetIpInterfaceEntry.
    // Fall back to the built-in NetTCPIP PowerShell cmdlet instead of pretending
    // that no LAN adapter exists.
    std::wstring apiErr = WinError(rc);
    std::wstring psErr;
    if (SetForwardingViaPowerShell(luid, enabled, psErr)) return true;
    std::wstring netshErr;
    if (SetForwardingViaNetsh(luid, enabled, netshErr)) return true;
    err = L"設定介面 Forwarding 失敗。IP Helper: " + apiErr + L"；PowerShell: " + psErr + L"；netsh: " + netshErr;
    return false;
}


bool ParseIpv4Cidr(const std::wstring& cidr, ULONG& networkHostOrder, int& prefix) {
    size_t slash = cidr.find(L'/');
    std::wstring ipText = slash == std::wstring::npos ? cidr : cidr.substr(0, slash);
    prefix = slash == std::wstring::npos ? 32 : _wtoi(cidr.substr(slash + 1).c_str());
    if (prefix < 0 || prefix > 32) return false;
    IN_ADDR a{};
    if (InetPtonW(AF_INET, Trim(ipText).c_str(), &a) != 1) return false;
    ULONG ip = ntohl(a.S_un.S_addr);
    ULONG mask = prefix == 0 ? 0u : (0xFFFFFFFFu << (32 - prefix));
    networkHostOrder = ip & mask;
    return true;
}

bool Ipv4InCidr(const SOCKADDR_IN* sa, ULONG networkHostOrder, int prefix) {
    if (!sa || sa->sin_family != AF_INET) return false;
    ULONG ip = ntohl(sa->sin_addr.S_un.S_addr);
    ULONG mask = prefix == 0 ? 0u : (0xFFFFFFFFu << (32 - prefix));
    return (ip & mask) == networkHostOrder;
}

std::wstring SockaddrIpv4Text(const SOCKADDR_IN* sa) {
    if (!sa) return L"";
    wchar_t buf[INET_ADDRSTRLEN]{};
    return InetNtopW(AF_INET, const_cast<IN_ADDR*>(&sa->sin_addr), buf, _countof(buf)) ? buf : L"";
}

std::wstring FindLocalIpv4InCidr(const std::wstring& cidr) {
    ULONG network = 0;
    int prefix = 0;
    if (!ParseIpv4Cidr(cidr, network, prefix)) return L"";

    ULONG size = 0;
    const ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    DWORD rc = GetAdaptersAddresses(AF_INET, flags, nullptr, nullptr, &size);
    if (rc != ERROR_BUFFER_OVERFLOW || size == 0) return L"";

    std::vector<BYTE> buf(size);
    auto* first = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
    rc = GetAdaptersAddresses(AF_INET, flags, nullptr, first, &size);
    if (rc != NO_ERROR) return L"";

    for (int pass = 0; pass < 2; ++pass) {
        for (auto* aa = first; aa; aa = aa->Next) {
            if (aa->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
            if (pass == 0 && aa->OperStatus != IfOperStatusUp) continue;
            for (auto* ua = aa->FirstUnicastAddress; ua; ua = ua->Next) {
                if (!ua->Address.lpSockaddr || ua->Address.lpSockaddr->sa_family != AF_INET) continue;
                auto* sa = reinterpret_cast<SOCKADDR_IN*>(ua->Address.lpSockaddr);
                if (Ipv4InCidr(sa, network, prefix)) return SockaddrIpv4Text(sa);
            }
        }
    }
    return L"";
}

bool EnableForwardingForLan(NET_LUID wgLuid, std::wstring& err) {
    gForwardingBackup.clear();
    std::wstring wgErr;
    if (!SetInterfaceForwarding(wgLuid, true, true, wgErr)) {
        err = L"無法啟用 WireGuard 介面的 IPv4 Forwarding：" + wgErr;
        return false;
    }

    // Do not change WeakHostReceive/WeakHostSend. Local access to this
    // machine's LAN address is handled inside EasyWG by Host Alias NAT.
    AddLog(L"本機 LAN IP 存取: Host Alias NAT（不修改 WeakHostReceive / WeakHostSend）");

    ServerSettings s;
    { std::lock_guard<std::mutex> lock(gDataMutex); s = gSettings; }

    ULONG lanNetwork = 0;
    int lanPrefix = 0;
    const bool haveLanCidr = ParseIpv4Cidr(s.lanSubnet, lanNetwork, lanPrefix);

    ULONG size = 0;
    const ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    DWORD rc = GetAdaptersAddresses(AF_INET, flags, nullptr, nullptr, &size);
    if (rc != ERROR_BUFFER_OVERFLOW || size == 0) {
        err = L"列舉 Windows IPv4 網卡失敗: " + WinError(rc);
        return false;
    }
    std::vector<BYTE> buf(size);
    auto* first = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
    rc = GetAdaptersAddresses(AF_INET, flags, nullptr, first, &size);
    if (rc != NO_ERROR) {
        err = L"讀取 Windows IPv4 網卡失敗: " + WinError(rc);
        return false;
    }

    std::vector<ULONGLONG> attempted;
    std::wstring lastErr;
    bool anyLan = false;

    auto alreadyAttempted = [&](const NET_LUID& luid) {
        return std::find(attempted.begin(), attempted.end(), luid.Value) != attempted.end();
    };

    auto tryAdapter = [&](PIP_ADAPTER_ADDRESSES aa, const std::wstring& reason) {
        if (!aa || aa->Luid.Value == wgLuid.Value || alreadyAttempted(aa->Luid)) return false;
        if (aa->IfType == IF_TYPE_SOFTWARE_LOOPBACK) return false;
        attempted.push_back(aa->Luid.Value);
        std::wstring localErr;
        if (SetInterfaceForwarding(aa->Luid, true, true, localErr)) {
            std::wstring name = aa->FriendlyName ? aa->FriendlyName : L"未命名網卡";
            AddLog(L"已啟用 LAN Forwarding: " + name + L"（" + reason + L"）");
            return true;
        }
        std::wstring name = aa->FriendlyName ? aa->FriendlyName : L"未命名網卡";
        lastErr = name + L": " + localErr;
        AddLog(L"LAN Forwarding 失敗: " + lastErr);
        return false;
    };

    // Pass 1: prefer the adapter that actually owns an IPv4 address inside LanSubnet.
    if (haveLanCidr) {
        for (auto* aa = first; aa; aa = aa->Next) {
            for (auto* ua = aa->FirstUnicastAddress; ua; ua = ua->Next) {
                if (!ua->Address.lpSockaddr || ua->Address.lpSockaddr->sa_family != AF_INET) continue;
                auto* sa = reinterpret_cast<SOCKADDR_IN*>(ua->Address.lpSockaddr);
                if (!Ipv4InCidr(sa, lanNetwork, lanPrefix)) continue;
                std::wstring ip = SockaddrIpv4Text(sa);
                if (tryAdapter(aa, L"符合 LAN 網段 " + s.lanSubnet + (ip.empty() ? L"" : L", IP " + ip))) {
                    anyLan = true;
                }
                break;
            }
        }
    }

    // Pass 2: fallback to any active non-loopback adapter with a usable IPv4 address.
    if (!anyLan) {
        AddLog(L"未找到符合 LAN 網段的可用介面，改用活躍 IPv4 網卡 fallback");
        for (auto* aa = first; aa; aa = aa->Next) {
            if (aa->OperStatus != IfOperStatusUp) continue;
            bool hasUsableIpv4 = false;
            for (auto* ua = aa->FirstUnicastAddress; ua; ua = ua->Next) {
                if (!ua->Address.lpSockaddr || ua->Address.lpSockaddr->sa_family != AF_INET) continue;
                auto* sa = reinterpret_cast<SOCKADDR_IN*>(ua->Address.lpSockaddr);
                ULONG ip = ntohl(sa->sin_addr.S_un.S_addr);
                if ((ip >> 24) == 127) continue;
                if ((ip & 0xFFFF0000u) == 0xA9FE0000u) continue; // 169.254/16
                hasUsableIpv4 = true;
                break;
            }
            if (!hasUsableIpv4) continue;
            if (tryAdapter(aa, L"活躍 IPv4 fallback")) anyLan = true;
        }
    }

    if (!anyLan) {
        err = L"找得到 Windows 網卡，但無法啟用 LAN IPv4 Forwarding。";
        if (!lastErr.empty()) err += L"\n最後錯誤：" + lastErr;
        err += L"\n請確認設定中的 LAN 網段是否正確（目前：" + s.lanSubnet + L"）。";
        return false;
    }
    AddLog(L"已啟用 Windows IPv4 路由轉送（WireGuard + LAN）");
    return true;
}

void RestoreForwarding() {
    for (const auto& x : gForwardingBackup) {
        std::wstring ignored;
        SetInterfaceForwarding(x.luid, x.oldValue != FALSE, false, ignored);
    }
    gForwardingBackup.clear();
}

// ---------------- EasyWG native user-mode NAT backend ----------------
//
// This backend intentionally does NOT use New-NetNat/Hyper-V/WinNAT.  EasyWG
// owns the NAT/PAT state table and translates forwarded IPv4 packets itself.
// WinDivert is used only as the packet interception/re-injection transport.

std::wstring WinDivertOpenErrorText(DWORD code) {
    std::wstring out = WinError(code);
    if (code == ERROR_ACCESS_DENIED) out += L"；請確認以系統管理員身分執行";
    else if (code == 1275) out += L"；WinDivert 驅動可能被 Windows 安全性或防毒阻擋";
    else if (code == 1753) out += L"；Base Filtering Engine (BFE) 服務可能未啟動";
    else if (code == 654) out += L"；系統可能殘留不相容版本的 WinDivert 驅動";
    return out;
}

struct WdApi {
    HMODULE dll = nullptr;
    WINDIVERT_OPEN_FUNC* Open = nullptr;
    WINDIVERT_RECV_FUNC* Recv = nullptr;
    WINDIVERT_SEND_FUNC* Send = nullptr;
    WINDIVERT_SHUTDOWN_FUNC* Shutdown = nullptr;
    WINDIVERT_CLOSE_FUNC* Close = nullptr;
    WINDIVERT_SET_PARAM_FUNC* SetParam = nullptr;
    WINDIVERT_HELPER_CALC_CHECKSUMS_FUNC* CalcChecksums = nullptr;

    void Unload() {
        if (dll) FreeLibrary(dll);
        *this = {};
    }

    bool Load(std::wstring& err) {
        if (dll) return true;
        dll = LoadLibraryFromAppDirCompat(WinDivertDllPath());
        if (!dll) { err = L"載入 WinDivert.dll 失敗: " + WinError(); return false; }
#define WDGET(member, name) member = reinterpret_cast<decltype(member)>(GetProcAddress(dll, name)); \
        if (!member) { err = L"WinDivert.dll 缺少 API: " + Utf8ToWide(name); Unload(); return false; }
        WDGET(Open, "WinDivertOpen");
        WDGET(Recv, "WinDivertRecv");
        WDGET(Send, "WinDivertSend");
        WDGET(Shutdown, "WinDivertShutdown");
        WDGET(Close, "WinDivertClose");
        WDGET(SetParam, "WinDivertSetParam");
        WDGET(CalcChecksums, "WinDivertHelperCalcChecksums");
#undef WDGET
        return true;
    }
};

struct ParsedIpv4Packet {
    WINDIVERT_IPHDR* ip = nullptr;
    WINDIVERT_TCPHDR* tcp = nullptr;
    WINDIVERT_UDPHDR* udp = nullptr;
    WINDIVERT_ICMPHDR* icmp = nullptr;
    UINT ipHeaderLen = 0;
    UINT fragOffset = 0;
    bool moreFragments = false;
};

bool ParseIpv4Packet(BYTE* packet, UINT packetLen, ParsedIpv4Packet& out) {
    out = {};
    if (!packet || packetLen < sizeof(WINDIVERT_IPHDR)) return false;
    auto* ip = reinterpret_cast<WINDIVERT_IPHDR*>(packet);
    if (ip->Version != 4 || ip->HdrLength < 5) return false;
    UINT ihl = static_cast<UINT>(ip->HdrLength) * 4u;
    if (ihl > packetLen) return false;
    out.ip = ip;
    out.ipHeaderLen = ihl;
    UINT16 frag = ntohs(ip->FragOff0);
    out.fragOffset = frag & 0x1FFFu;
    out.moreFragments = (frag & 0x2000u) != 0;
    if (out.fragOffset != 0) return true;

    BYTE* l4 = packet + ihl;
    UINT l4Len = packetLen - ihl;
    if (ip->Protocol == IPPROTO_TCP && l4Len >= sizeof(WINDIVERT_TCPHDR))
        out.tcp = reinterpret_cast<WINDIVERT_TCPHDR*>(l4);
    else if (ip->Protocol == IPPROTO_UDP && l4Len >= sizeof(WINDIVERT_UDPHDR))
        out.udp = reinterpret_cast<WINDIVERT_UDPHDR*>(l4);
    else if (ip->Protocol == IPPROTO_ICMP && l4Len >= sizeof(WINDIVERT_ICMPHDR))
        out.icmp = reinterpret_cast<WINDIVERT_ICMPHDR*>(l4);
    return true;
}


std::wstring Ipv4NetworkOrderToText(UINT32 networkOrder) {
    IN_ADDR a{};
    a.S_un.S_addr = networkOrder;
    wchar_t buf[INET_ADDRSTRLEN]{};
    if (!InetNtopW(AF_INET, &a, buf, _countof(buf))) return L"?";
    return buf;
}

std::wstring TraceProtocolName(BYTE proto) {
    if (proto == IPPROTO_TCP) return L"TCP";
    if (proto == IPPROTO_UDP) return L"UDP";
    if (proto == IPPROTO_ICMP) return L"ICMP";
    return L"P" + std::to_wstring(proto);
}

UINT16 TraceIcmpIdentifier(const WINDIVERT_ICMPHDR* icmp) {
    if (!icmp) return 0;
    const BYTE* p = reinterpret_cast<const BYTE*>(&icmp->Body);
    UINT16 n = 0; memcpy(&n, p, sizeof(n)); return ntohs(n);
}

UINT16 TraceIcmpSequence(const WINDIVERT_ICMPHDR* icmp) {
    if (!icmp) return 0;
    const BYTE* p = reinterpret_cast<const BYTE*>(&icmp->Body) + sizeof(UINT16);
    UINT16 n = 0; memcpy(&n, p, sizeof(n)); return ntohs(n);
}

std::wstring PacketSummary(const ParsedIpv4Packet& p) {
    if (!p.ip) return L"<no IPv4 header>";
    std::wstringstream ss;
    ss << TraceProtocolName(p.ip->Protocol) << L" "
       << Ipv4NetworkOrderToText(p.ip->SrcAddr);
    if (p.tcp) ss << L":" << ntohs(p.tcp->SrcPort);
    else if (p.udp) ss << L":" << ntohs(p.udp->SrcPort);
    ss << L" -> " << Ipv4NetworkOrderToText(p.ip->DstAddr);
    if (p.tcp) ss << L":" << ntohs(p.tcp->DstPort);
    else if (p.udp) ss << L":" << ntohs(p.udp->DstPort);
    if (p.icmp) {
        ss << L" type=" << static_cast<unsigned>(p.icmp->Type)
           << L" code=" << static_cast<unsigned>(p.icmp->Code)
           << L" id=" << TraceIcmpIdentifier(p.icmp)
           << L" seq=" << TraceIcmpSequence(p.icmp);
    }
    if (p.fragOffset || p.moreFragments)
        ss << L" fragOff=" << p.fragOffset << L" more=" << (p.moreFragments ? 1 : 0);
    return ss.str();
}

std::wstring WinDivertAddressSummary(const WINDIVERT_ADDRESS& a) {
    std::wstringstream ss;
    ss << L"WD{layer=" << static_cast<unsigned long long>(a.Layer)
       << L",event=" << static_cast<unsigned long long>(a.Event)
       << L",out=" << static_cast<unsigned long long>(a.Outbound)
       << L",loop=" << static_cast<unsigned long long>(a.Loopback)
       << L",imp=" << static_cast<unsigned long long>(a.Impostor)
       << L",sniff=" << static_cast<unsigned long long>(a.Sniffed)
       << L",if=" << a.Network.IfIdx
       << L",sub=" << a.Network.SubIfIdx << L"}";
    return ss.str();
}

#define TracePacketEvent(...) ((void)0)

bool ParseCidrHostRange(const std::wstring& cidr, UINT32& networkHost, UINT32& maskHost) {
    IN_ADDR a{}; int prefix = 0;
    if (!ParseIpv4Cidr(cidr, a, prefix)) return false;
    maskHost = prefix == 0 ? 0u : (0xFFFFFFFFu << (32 - prefix));
    networkHost = ntohl(a.S_un.S_addr) & maskHost;
    return true;
}

bool IpNetworkOrderInRange(UINT32 ipNetworkOrder, UINT32 networkHost, UINT32 maskHost) {
    return (ntohl(ipNetworkOrder) & maskHost) == networkHost;
}

std::wstring Ipv4HostOrderToText(UINT32 hostOrder) {
    IN_ADDR a{}; a.S_un.S_addr = htonl(hostOrder);
    wchar_t buf[INET_ADDRSTRLEN]{};
    if (!InetNtopW(AF_INET, &a, buf, _countof(buf))) return L"";
    return buf;
}

class NativeNatEngine {
public:
    bool Start(const ServerSettings& s, NET_IFINDEX wgIfIndex, std::wstring& err) {
        if (running_) return true;
        if (wgIfIndex == 0) {
            err = L"無法取得 EasyWG WireGuard 介面索引，Host Alias NAT 無法安全注入本機封包";
            return false;
        }
        wgIfIndex_ = wgIfIndex;
        ResetPacketTrace(EASYWG_VERSION_DISPLAY_W);
        PacketTrace(L"[START] wgIfIndex=" + std::to_wstring(wgIfIndex_) +
                    L" vpnHost=" + s.address + L"/" + std::to_wstring(s.prefix) +
                    L" lanCidr=" + s.lanSubnet + L" mode=" + s.lanAccessMode);
        if (!WinDivertRuntimeReady()) {
            err = L"NAT 模式需要 WinDivert Runtime。程式會自動從 WinDivert 官方下載。\n\n"
                  L"請等待下載完成後再啟動服務。";
            return false;
        }
        if (!api_.Load(err)) return false;

        vpnCidr_ = Ipv4NetworkCidr(s.address, s.prefix);
        if (vpnCidr_.empty() || !ParseCidrHostRange(vpnCidr_, vpnNetworkHost_, vpnMaskHost_)) {
            err = L"VPN 網段無效，無法啟動 EasyWG Native NAT";
            api_.Unload();
            return false;
        }
        if (!ParseCidrHostRange(s.lanSubnet, lanNetworkHost_, lanMaskHost_)) {
            err = L"LAN 網段格式錯誤，無法啟動 EasyWG Native NAT：" + s.lanSubnet;
            api_.Unload();
            return false;
        }
        lanCidr_ = s.lanSubnet;
        lanHostIpText_ = FindLocalIpv4InCidr(s.lanSubnet);
        if (lanHostIpText_.empty()) {
            err = L"找不到位於 " + s.lanSubnet + L" 的本機 LAN IPv4 位址。\n\n"
                  L"請確認 LAN 網段與這台 EasyWG 主機實體網卡 IP 一致。";
            api_.Unload();
            return false;
        }
        IN_ADDR lanHost{};
        if (InetPtonW(AF_INET, lanHostIpText_.c_str(), &lanHost) != 1) {
            err = L"EasyWG 主機 LAN IP 解析失敗";
            api_.Unload();
            return false;
        }
        lanHostIpN_ = lanHost.S_un.S_addr;

        IN_ADDR vpnHost{};
        if (InetPtonW(AF_INET, s.address.c_str(), &vpnHost) != 1) {
            err = L"EasyWG VPN 主機 IP 解析失敗";
            api_.Unload();
            return false;
        }
        vpnHostIpN_ = vpnHost.S_un.S_addr;
        PacketTrace(L"[CONFIG] vpnCidr=" + vpnCidr_ + L" vpnHost=" + s.address +
                    L" lanCidr=" + lanCidr_ + L" lanHost=" + lanHostIpText_ +
                    L" wgIfIndex=" + std::to_wstring(wgIfIndex_));

        // Capture every forwarded IPv4 packet that leaves the WireGuard subnet,
        // not only packets whose destination is inside the configured LAN.  A
        // full-tunnel client sends public Internet destinations through WG, so
        // those packets must receive the same PAT/SNAT as ordinary LAN access.
        // Traffic to the EasyWG host's own LAN address remains owned by the
        // separate Host Alias NAT path.
        UINT32 vpnEndHost = vpnNetworkHost_ | ~vpnMaskHost_;
        std::string forwardFilter =
            "ip and !impostor and ip.SrcAddr >= " + WideToUtf8(Ipv4HostOrderToText(vpnNetworkHost_)) +
            " and ip.SrcAddr <= " + WideToUtf8(Ipv4HostOrderToText(vpnEndHost)) +
            " and (ip.DstAddr < " + WideToUtf8(Ipv4HostOrderToText(vpnNetworkHost_)) +
            " or ip.DstAddr > " + WideToUtf8(Ipv4HostOrderToText(vpnEndHost)) + ")" +
            " and ip.DstAddr != " + WideToUtf8(lanHostIpText_) +
            " and (tcp or udp or icmp)";
        PacketTrace(L"[FILTER] FORWARD=" + Utf8ToWide(forwardFilter));
        PacketTrace(L"[FILTER] FORWARD covers LAN + Internet and excludes lanHost=" +
                    lanHostIpText_ + L"; Host Alias owns this destination");
        forward_ = api_.Open(forwardFilter.c_str(), WINDIVERT_LAYER_NETWORK_FORWARD, 100, 0);
        if (forward_ == INVALID_HANDLE_VALUE) {
            forward_ = nullptr;
            err = L"開啟 WinDivert Forward Layer 失敗: " + WinDivertOpenErrorText(GetLastError());
            api_.Unload();
            return false;
        }
        // Replies are addressed to this Windows host after SNAT. Capture them
        // on the normal inbound network path, reverse the NAT mapping, then
        // reinject them inbound so Windows routes them to the WireGuard subnet.
        // The source can be either a LAN host or any public Internet address;
        // restricting this filter to the LAN CIDR breaks full-tunnel Internet
        // return traffic. TranslateInbound still validates every packet against
        // the NAT state table before changing it.
        // Exclude the VPN source subnet so requests sent directly to this
        // server's own LAN IP continue to the separate Host Alias handle rather
        // than being captured as possible PAT replies.
        std::string inboundFilter =
            "inbound and ip and !impostor" +
            std::string(" and (ip.SrcAddr < ") + WideToUtf8(Ipv4HostOrderToText(vpnNetworkHost_)) +
            " or ip.SrcAddr > " + WideToUtf8(Ipv4HostOrderToText(vpnEndHost)) + ")" +
            " and ip.DstAddr == " + WideToUtf8(lanHostIpText_) +
            " and (tcp or udp or icmp)";
        PacketTrace(L"[FILTER] INBOUND_REPLY=" + Utf8ToWide(inboundFilter));
        inbound_ = api_.Open(inboundFilter.c_str(), WINDIVERT_LAYER_NETWORK, 100, 0);
        if (inbound_ == INVALID_HANDLE_VALUE) {
            inbound_ = nullptr;
            err = L"開啟 WinDivert Inbound Layer 失敗: " + WinDivertOpenErrorText(GetLastError());
            api_.Close(forward_); forward_ = nullptr;
            api_.Unload();
            return false;
        }

        // Host Alias NAT handles traffic to this machine's own LAN address
        // without changing Windows Weak Host settings. Requests such as
        // 10.66.66.2 -> 192.168.1.200 are rewritten to 10.66.66.1 before
        // reaching the local TCP/IP stack. Matching replies are rewritten
        // from 10.66.66.1 back to 192.168.1.200.
        // Do not classify Host Alias traffic by WinDivert's inbound/outbound
        // flag.  Local/loopback-related traffic can be reported as outbound-only.
        // Match by IP tuple instead, then classify request/reply from addresses.
        std::string aliasFilter =
            "ip and !impostor and ("
            "(ip.SrcAddr >= " + WideToUtf8(Ipv4HostOrderToText(vpnNetworkHost_)) +
            " and ip.SrcAddr <= " + WideToUtf8(Ipv4HostOrderToText(vpnEndHost)) +
            " and ip.DstAddr == " + WideToUtf8(lanHostIpText_) +
            " and (tcp or udp or icmp))"
            " or "
            "(ip.SrcAddr == " + WideToUtf8(s.address) +
            " and ip.DstAddr >= " + WideToUtf8(Ipv4HostOrderToText(vpnNetworkHost_)) +
            " and ip.DstAddr <= " + WideToUtf8(Ipv4HostOrderToText(vpnEndHost)) +
            " and (tcp or udp or icmp))"
            ")";
        PacketTrace(L"[FILTER] HOST_ALIAS=" + Utf8ToWide(aliasFilter));
        alias_ = api_.Open(aliasFilter.c_str(), WINDIVERT_LAYER_NETWORK, 200, 0);
        if (alias_ == INVALID_HANDLE_VALUE) {
            alias_ = nullptr;
            err = L"開啟 WinDivert Host Alias Layer 失敗: " + WinDivertOpenErrorText(GetLastError());
            api_.Close(inbound_); inbound_ = nullptr;
            api_.Close(forward_); forward_ = nullptr;
            api_.Unload();
            return false;
        }



        api_.SetParam(forward_, WINDIVERT_PARAM_QUEUE_LENGTH, 8192);
        api_.SetParam(forward_, WINDIVERT_PARAM_QUEUE_SIZE, 16ull * 1024ull * 1024ull);
        api_.SetParam(inbound_, WINDIVERT_PARAM_QUEUE_LENGTH, 8192);
        api_.SetParam(inbound_, WINDIVERT_PARAM_QUEUE_SIZE, 16ull * 1024ull * 1024ull);
        api_.SetParam(alias_, WINDIVERT_PARAM_QUEUE_LENGTH, 4096);
        api_.SetParam(alias_, WINDIVERT_PARAM_QUEUE_SIZE, 8ull * 1024ull * 1024ull);

        {
            std::lock_guard<std::mutex> lock(mapMutex_);
            entries_.clear();
            aliasEntries_.clear();
            nextPort_ = 20000;
        }
        running_ = true;
        forwardThread_ = std::thread([this]{ ForwardLoop(); });
        inboundThread_ = std::thread([this]{ InboundLoop(); });
        aliasThread_ = std::thread([this]{ AliasLoop(); });
        PacketTrace(L"[START] NAT threads running; begin ping tests now");
        DeleteFileW(JoinPath(GetExeDir(), L"EasyWG_NAT_Error.txt").c_str());
        AddLog(L"EasyWG Native NAT 已啟動: " + vpnCidr_ + L" -> " + lanHostIpText_ +
               L" -> LAN / Internet（" + lanCidr_ + L"）");
        AddLog(L"Host Alias NAT 已啟動: " + lanHostIpText_ + L" <-> " + s.address +
               L"（固定 WG inbound/outbound 注入，不修改 WeakHost）");
        AddLog(L"NAT Backend: EasyWG PAT + Host Alias + WinDivert（不使用 Hyper-V / New-NetNat）");
        return true;
    }

    void Stop() {
        if (!running_.exchange(false)) {
            CloseHandles();
            api_.Unload();
            return;
        }
        if (forward_ && api_.Shutdown) api_.Shutdown(forward_, WINDIVERT_SHUTDOWN_BOTH);
        if (inbound_ && api_.Shutdown) api_.Shutdown(inbound_, WINDIVERT_SHUTDOWN_BOTH);
        if (alias_ && api_.Shutdown) api_.Shutdown(alias_, WINDIVERT_SHUTDOWN_BOTH);
        if (forwardThread_.joinable()) forwardThread_.join();
        if (inboundThread_.joinable()) inboundThread_.join();
        if (aliasThread_.joinable()) aliasThread_.join();
        CloseHandles();
        {
            std::lock_guard<std::mutex> lock(mapMutex_);
            entries_.clear();
            aliasEntries_.clear();
        }
        api_.Unload();
        PacketTrace(L"[STOP] Native NAT stopped cleanly");
        AddLog(L"EasyWG Native NAT 已停止");
    }

    bool IsRunning() const { return running_.load(); }

private:
    struct NatEntry {
        BYTE proto = 0;
        UINT32 clientIpN = 0;
        UINT16 clientPortH = 0;
        UINT32 remoteIpN = 0;
        UINT16 remotePortH = 0;
        UINT16 natPortH = 0;
        std::chrono::steady_clock::time_point lastSeen{};
    };

    struct AliasEntry {
        BYTE proto = 0;
        UINT32 clientIpN = 0;
        UINT16 clientPortH = 0;   // TCP/UDP source port or ICMP identifier
        UINT16 serverPortH = 0;   // TCP/UDP destination port; 0 for ICMP
        std::chrono::steady_clock::time_point lastSeen{};
    };

    WdApi api_;
    HANDLE forward_ = nullptr;
    HANDLE inbound_ = nullptr;
    HANDLE alias_ = nullptr;
    std::thread forwardThread_;
    std::thread inboundThread_;
    std::thread aliasThread_;
    std::atomic<bool> running_{false};
    std::mutex mapMutex_;
    std::vector<NatEntry> entries_;
    std::vector<AliasEntry> aliasEntries_;
    UINT16 nextPort_ = 20000;
    UINT32 vpnNetworkHost_ = 0, vpnMaskHost_ = 0;
    UINT32 lanNetworkHost_ = 0, lanMaskHost_ = 0;
    UINT32 lanHostIpN_ = 0;
    UINT32 vpnHostIpN_ = 0;
    NET_IFINDEX wgIfIndex_ = 0;
    std::wstring vpnCidr_, lanCidr_, lanHostIpText_;
    std::atomic<ULONGLONG> lastErrorLogTick_{0};

    void CloseHandles() {
        if (forward_ && api_.Close) { api_.Close(forward_); forward_ = nullptr; }
        if (inbound_ && api_.Close) { api_.Close(inbound_); inbound_ = nullptr; }
        if (alias_ && api_.Close) { api_.Close(alias_); alias_ = nullptr; }
    }

    void LogPacketErrorThrottled(const std::wstring& text) {
        ULONGLONG now = GetTickCount64();
        ULONGLONG old = lastErrorLogTick_.load();
        if (now - old >= 5000 && lastErrorLogTick_.compare_exchange_strong(old, now)) AddLog(text);
    }

    void CleanupLocked(std::chrono::steady_clock::time_point now) {
        entries_.erase(std::remove_if(entries_.begin(), entries_.end(), [&](const NatEntry& e){
            auto age = now - e.lastSeen;
            if (e.proto == IPPROTO_TCP) return age > std::chrono::minutes(30);
            if (e.proto == IPPROTO_UDP) return age > std::chrono::minutes(3);
            return age > std::chrono::minutes(1);
        }), entries_.end());
        aliasEntries_.erase(std::remove_if(aliasEntries_.begin(), aliasEntries_.end(), [&](const AliasEntry& e){
            auto age = now - e.lastSeen;
            if (e.proto == IPPROTO_TCP) return age > std::chrono::minutes(30);
            if (e.proto == IPPROTO_UDP) return age > std::chrono::minutes(3);
            return age > std::chrono::minutes(1);
        }), aliasEntries_.end());
    }

    UINT16 AllocatePortLocked(BYTE proto) {
        for (int tries = 0; tries < 21000; ++tries) {
            UINT16 candidate = nextPort_++;
            if (nextPort_ > 39999) nextPort_ = 20000;
            bool used = false;
            for (const auto& e : entries_) {
                if (e.proto == proto && e.natPortH == candidate) { used = true; break; }
            }
            if (!used) return candidate;
        }
        return 0;
    }

    bool GetOrCreateOutbound(BYTE proto, UINT32 clientIpN, UINT16 clientPortH,
                             UINT32 remoteIpN, UINT16 remotePortH, NatEntry& out) {
        std::lock_guard<std::mutex> lock(mapMutex_);
        auto now = std::chrono::steady_clock::now();
        CleanupLocked(now);
        for (auto& e : entries_) {
            if (e.proto == proto && e.clientIpN == clientIpN && e.clientPortH == clientPortH &&
                e.remoteIpN == remoteIpN && e.remotePortH == remotePortH) {
                e.lastSeen = now; out = e; return true;
            }
        }
        UINT16 natPort = AllocatePortLocked(proto);
        if (!natPort) return false;
        NatEntry e{};
        e.proto = proto; e.clientIpN = clientIpN; e.clientPortH = clientPortH;
        e.remoteIpN = remoteIpN; e.remotePortH = remotePortH;
        e.natPortH = natPort; e.lastSeen = now;
        entries_.push_back(e); out = e;
        return true;
    }

    bool LookupInbound(BYTE proto, UINT16 natPortH, UINT32 remoteIpN,
                       UINT16 remotePortH, NatEntry& out) {
        std::lock_guard<std::mutex> lock(mapMutex_);
        auto now = std::chrono::steady_clock::now();
        CleanupLocked(now);
        for (auto& e : entries_) {
            if (e.proto == proto && e.natPortH == natPortH && e.remoteIpN == remoteIpN &&
                e.remotePortH == remotePortH) {
                e.lastSeen = now; out = e; return true;
            }
        }
        return false;
    }

    bool RememberAlias(BYTE proto, UINT32 clientIpN, UINT16 clientPortH,
                       UINT16 serverPortH) {
        std::lock_guard<std::mutex> lock(mapMutex_);
        auto now = std::chrono::steady_clock::now();
        CleanupLocked(now);
        for (auto& e : aliasEntries_) {
            if (e.proto == proto && e.clientIpN == clientIpN &&
                e.clientPortH == clientPortH && e.serverPortH == serverPortH) {
                e.lastSeen = now;
                return true;
            }
        }
        AliasEntry e{};
        e.proto = proto;
        e.clientIpN = clientIpN;
        e.clientPortH = clientPortH;
        e.serverPortH = serverPortH;
        e.lastSeen = now;
        aliasEntries_.push_back(e);
        PacketTrace(L"[ALIAS_STATE] remember proto=" + TraceProtocolName(proto) +
                    L" client=" + Ipv4NetworkOrderToText(clientIpN) + L":" + std::to_wstring(clientPortH) +
                    L" serverPort=" + std::to_wstring(serverPortH) +
                    L" entries=" + std::to_wstring(aliasEntries_.size()));
        return true;
    }

    bool LookupAliasReply(BYTE proto, UINT32 clientIpN, UINT16 clientPortH,
                          UINT16 serverPortH) {
        std::lock_guard<std::mutex> lock(mapMutex_);
        auto now = std::chrono::steady_clock::now();
        CleanupLocked(now);
        for (auto& e : aliasEntries_) {
            if (e.proto == proto && e.clientIpN == clientIpN &&
                e.clientPortH == clientPortH && e.serverPortH == serverPortH) {
                e.lastSeen = now;
                PacketTrace(L"[ALIAS_STATE] reply HIT proto=" + TraceProtocolName(proto) +
                            L" client=" + Ipv4NetworkOrderToText(clientIpN) + L":" + std::to_wstring(clientPortH) +
                            L" serverPort=" + std::to_wstring(serverPortH));
                return true;
            }
        }
        PacketTrace(L"[ALIAS_STATE] reply MISS proto=" + TraceProtocolName(proto) +
                    L" client=" + Ipv4NetworkOrderToText(clientIpN) + L":" + std::to_wstring(clientPortH) +
                    L" serverPort=" + std::to_wstring(serverPortH) +
                    L" entries=" + std::to_wstring(aliasEntries_.size()));
        return false;
    }

    static UINT16 IcmpIdentifierHost(WINDIVERT_ICMPHDR* icmp) {
        const BYTE* p = reinterpret_cast<const BYTE*>(&icmp->Body);
        UINT16 n = 0; memcpy(&n, p, sizeof(n)); return ntohs(n);
    }

    static void SetIcmpIdentifierHost(WINDIVERT_ICMPHDR* icmp, UINT16 idH) {
        UINT16 n = htons(idH);
        BYTE* p = reinterpret_cast<BYTE*>(&icmp->Body);
        memcpy(p, &n, sizeof(n));
    }

    static UINT16 IcmpSequenceHost(WINDIVERT_ICMPHDR* icmp) {
        const BYTE* p = reinterpret_cast<const BYTE*>(&icmp->Body) + sizeof(UINT16);
        UINT16 n = 0; memcpy(&n, p, sizeof(n)); return ntohs(n);
    }

    bool TranslateAliasInbound(ParsedIpv4Packet& p) {
        if (!p.ip || !IpNetworkOrderInRange(p.ip->SrcAddr, vpnNetworkHost_, vpnMaskHost_) ||
            p.ip->DstAddr != lanHostIpN_) return false;
        if (p.fragOffset != 0 || p.moreFragments) return false;

        if (p.tcp) {
            RememberAlias(IPPROTO_TCP, p.ip->SrcAddr, ntohs(p.tcp->SrcPort), ntohs(p.tcp->DstPort));
            p.ip->DstAddr = vpnHostIpN_;
            return true;
        }
        if (p.udp) {
            RememberAlias(IPPROTO_UDP, p.ip->SrcAddr, ntohs(p.udp->SrcPort), ntohs(p.udp->DstPort));
            p.ip->DstAddr = vpnHostIpN_;
            return true;
        }
        if (p.icmp && p.icmp->Type == 8) {
            RememberAlias(IPPROTO_ICMP, p.ip->SrcAddr, IcmpIdentifierHost(p.icmp), IcmpSequenceHost(p.icmp));
            p.ip->DstAddr = vpnHostIpN_;
            return true;
        }
        return false;
    }

    bool TranslateAliasOutbound(ParsedIpv4Packet& p) {
        if (!p.ip || p.ip->SrcAddr != vpnHostIpN_ ||
            !IpNetworkOrderInRange(p.ip->DstAddr, vpnNetworkHost_, vpnMaskHost_)) return false;
        if (p.fragOffset != 0 || p.moreFragments) return false;

        if (p.tcp) {
            if (!LookupAliasReply(IPPROTO_TCP, p.ip->DstAddr, ntohs(p.tcp->DstPort),
                                  ntohs(p.tcp->SrcPort))) return false;
            p.ip->SrcAddr = lanHostIpN_;
            return true;
        }
        if (p.udp) {
            if (!LookupAliasReply(IPPROTO_UDP, p.ip->DstAddr, ntohs(p.udp->DstPort),
                                  ntohs(p.udp->SrcPort))) return false;
            p.ip->SrcAddr = lanHostIpN_;
            return true;
        }
        if (p.icmp && p.icmp->Type == 0) {
            if (!LookupAliasReply(IPPROTO_ICMP, p.ip->DstAddr, IcmpIdentifierHost(p.icmp),
                                  IcmpSequenceHost(p.icmp))) return false;
            p.ip->SrcAddr = lanHostIpN_;
            return true;
        }
        return false;
    }

    bool TranslateOutbound(ParsedIpv4Packet& p) {
        if (!p.ip || !IpNetworkOrderInRange(p.ip->SrcAddr, vpnNetworkHost_, vpnMaskHost_) ||
            IpNetworkOrderInRange(p.ip->DstAddr, vpnNetworkHost_, vpnMaskHost_)) return false;

        // The generic PAT path now covers both configured LAN destinations and
        // public Internet destinations. Client-side AllowedIPs decides whether
        // a peer sends only private networks or uses the full 0.0.0.0/0 tunnel.

        // The EasyWG host's own LAN IP must never be handled by the generic
        // forward SNAT path.  It is reserved for Host Alias NAT instead.
        // Without this guard, 10.66.66.x -> lanHost becomes lanHost -> lanHost.
        if (p.ip->DstAddr == lanHostIpN_) {
            PacketTrace(L"[FORWARD_GUARD] skip lanHost destination " + lanHostIpText_ +
                        L"; reserved for Host Alias NAT");
            return false;
        }

        // Fragmented transport datagrams need incremental checksum handling.
        // v0.3.2 deliberately leaves those packets untouched instead of
        // corrupting them. TCP through WireGuard normally follows interface MTU
        // and is not fragmented; ordinary SMB/RDP/HTTP and ping are supported.
        if (p.fragOffset != 0 || p.moreFragments) return false;

        NatEntry e{};
        if (p.tcp) {
            if (!GetOrCreateOutbound(IPPROTO_TCP, p.ip->SrcAddr, ntohs(p.tcp->SrcPort),
                                     p.ip->DstAddr, ntohs(p.tcp->DstPort), e)) return false;
            p.ip->SrcAddr = lanHostIpN_;
            p.tcp->SrcPort = htons(e.natPortH);
            return true;
        }
        if (p.udp) {
            if (!GetOrCreateOutbound(IPPROTO_UDP, p.ip->SrcAddr, ntohs(p.udp->SrcPort),
                                     p.ip->DstAddr, ntohs(p.udp->DstPort), e)) return false;
            p.ip->SrcAddr = lanHostIpN_;
            p.udp->SrcPort = htons(e.natPortH);
            return true;
        }
        if (p.icmp && p.icmp->Type == 8) { // Echo request
            UINT16 id = IcmpIdentifierHost(p.icmp);
            if (!GetOrCreateOutbound(IPPROTO_ICMP, p.ip->SrcAddr, id, p.ip->DstAddr, 0, e)) return false;
            p.ip->SrcAddr = lanHostIpN_;
            SetIcmpIdentifierHost(p.icmp, e.natPortH);
            return true;
        }
        return false;
    }

    bool TranslateInbound(ParsedIpv4Packet& p) {
        if (!p.ip || p.ip->DstAddr != lanHostIpN_) return false;
        if (p.fragOffset != 0 || p.moreFragments) return false;

        NatEntry e{};
        if (p.tcp) {
            if (!LookupInbound(IPPROTO_TCP, ntohs(p.tcp->DstPort), p.ip->SrcAddr,
                               ntohs(p.tcp->SrcPort), e)) return false;
            p.ip->DstAddr = e.clientIpN;
            p.tcp->DstPort = htons(e.clientPortH);
            return true;
        }
        if (p.udp) {
            if (!LookupInbound(IPPROTO_UDP, ntohs(p.udp->DstPort), p.ip->SrcAddr,
                               ntohs(p.udp->SrcPort), e)) return false;
            p.ip->DstAddr = e.clientIpN;
            p.udp->DstPort = htons(e.clientPortH);
            return true;
        }
        if (p.icmp && p.icmp->Type == 0) { // Echo reply
            UINT16 natId = IcmpIdentifierHost(p.icmp);
            if (!LookupInbound(IPPROTO_ICMP, natId, p.ip->SrcAddr, 0, e)) return false;
            p.ip->DstAddr = e.clientIpN;
            SetIcmpIdentifierHost(p.icmp, e.clientPortH);
            return true;
        }
        return false;
    }

    void ForwardLoop() {
        std::vector<BYTE> packet(65535);
        while (running_) {
            UINT packetLen = 0;
            WINDIVERT_ADDRESS addr{};
            if (!api_.Recv(forward_, packet.data(), static_cast<UINT>(packet.size()), &packetLen, &addr)) {
                if (!running_) break;
                LogPacketErrorThrottled(L"Native NAT Forward Recv 失敗: " + WinError());
                continue;
            }
            ParsedIpv4Packet parsed{};
            bool parsedOk = ParseIpv4Packet(packet.data(), packetLen, parsed);
            if (parsedOk) TracePacketEvent(L"FORWARD_CAPTURE", parsed, addr, L"len=" + std::to_wstring(packetLen));
            else PacketTrace(L"[FORWARD_CAPTURE] parse failed len=" + std::to_wstring(packetLen) + L" | " + WinDivertAddressSummary(addr));
            bool changed = parsedOk && TranslateOutbound(parsed);
            PacketTrace(L"[FORWARD_DECISION] changed=" + std::to_wstring(changed ? 1 : 0));
            if (changed) {
                TracePacketEvent(L"FORWARD_AFTER_SNAT", parsed, addr);
                api_.CalcChecksums(packet.data(), packetLen, &addr, 0);
            }
            UINT sent = 0;
            BOOL ok = api_.Send(forward_, packet.data(), packetLen, &sent, &addr);
            PacketTrace(L"[FORWARD_SEND] ok=" + std::to_wstring(ok ? 1 : 0) +
                        L" sent=" + std::to_wstring(sent) + (ok ? L"" : L" err=" + WinError()));
            if (!ok && running_) LogPacketErrorThrottled(L"Native NAT Forward Send 失敗: " + WinError());
        }
    }

    void InboundLoop() {
        std::vector<BYTE> packet(65535);
        while (running_) {
            UINT packetLen = 0;
            WINDIVERT_ADDRESS addr{};
            if (!api_.Recv(inbound_, packet.data(), static_cast<UINT>(packet.size()), &packetLen, &addr)) {
                if (!running_) break;
                LogPacketErrorThrottled(L"Native NAT Inbound Recv 失敗: " + WinError());
                continue;
            }
            ParsedIpv4Packet parsed{};
            bool parsedOk = ParseIpv4Packet(packet.data(), packetLen, parsed);
            if (parsedOk) TracePacketEvent(L"INBOUND_CAPTURE", parsed, addr, L"len=" + std::to_wstring(packetLen));
            bool changed = parsedOk && TranslateInbound(parsed);
            PacketTrace(L"[INBOUND_DECISION] changed=" + std::to_wstring(changed ? 1 : 0));
            if (changed) {
                TracePacketEvent(L"INBOUND_AFTER_DNAT", parsed, addr);
                api_.CalcChecksums(packet.data(), packetLen, &addr, 0);
            }
            UINT sent = 0;
            BOOL ok = api_.Send(inbound_, packet.data(), packetLen, &sent, &addr);
            PacketTrace(L"[INBOUND_SEND] ok=" + std::to_wstring(ok ? 1 : 0) +
                        L" sent=" + std::to_wstring(sent) + (ok ? L"" : L" err=" + WinError()));
            if (!ok && running_) LogPacketErrorThrottled(L"Native NAT Inbound Send 失敗: " + WinError());
        }
    }


    void AliasLoop() {
        std::vector<BYTE> packet(65535);
        while (running_) {
            UINT packetLen = 0;
            WINDIVERT_ADDRESS addr{};
            if (!api_.Recv(alias_, packet.data(), static_cast<UINT>(packet.size()), &packetLen, &addr)) {
                if (!running_) break;
                LogPacketErrorThrottled(L"Host Alias NAT Recv 失敗: " + WinError());
                continue;
            }
            ParsedIpv4Packet parsed{};
            bool changed = false;
            bool parsedOk = ParseIpv4Packet(packet.data(), packetLen, parsed);
            if (parsedOk) TracePacketEvent(L"ALIAS_CAPTURE", parsed, addr, L"len=" + std::to_wstring(packetLen));
            else PacketTrace(L"[ALIAS_CAPTURE] parse failed len=" + std::to_wstring(packetLen) + L" | " + WinDivertAddressSummary(addr));
            if (parsedOk && parsed.ip) {
                // Classify by the packet tuple, not by addr.Outbound.  This is
                // important for traffic involving another local address on the
                // same Windows host, which may appear as outbound/loopback.
                const bool aliasRequest =
                    IpNetworkOrderInRange(parsed.ip->SrcAddr, vpnNetworkHost_, vpnMaskHost_) &&
                    parsed.ip->DstAddr == lanHostIpN_;
                const bool aliasReply =
                    parsed.ip->SrcAddr == vpnHostIpN_ &&
                    IpNetworkOrderInRange(parsed.ip->DstAddr, vpnNetworkHost_, vpnMaskHost_);
                PacketTrace(L"[ALIAS_CLASSIFY] request=" + std::to_wstring(aliasRequest ? 1 : 0) +
                            L" reply=" + std::to_wstring(aliasReply ? 1 : 0) +
                            L" originalOut=" + std::to_wstring(addr.Outbound ? 1 : 0) +
                            L" originalIf=" + std::to_wstring(addr.Network.IfIdx));

                if (aliasRequest) {
                    changed = TranslateAliasInbound(parsed);
                    if (changed) {
                        TracePacketEvent(L"ALIAS_AFTER_REQUEST_DNAT", parsed, addr,
                                         L"forcing inbound via WG if=" + std::to_wstring(wgIfIndex_));
                        // WinDivert injects according to Address.Outbound, NOT
                        // according to the rewritten IP addresses. Force the
                        // DNATed packet into the inbound path of the WG adapter
                        // so Windows sees the same arrival path as a direct
                        // 10.66.66.x -> 10.66.66.1 packet.
                        addr.Outbound = 0;
                        addr.Loopback = 0;
                        addr.Network.IfIdx = wgIfIndex_;
                        addr.Network.SubIfIdx = 0;
                    }
                } else if (aliasReply) {
                    changed = TranslateAliasOutbound(parsed);
                    if (changed) {
                        TracePacketEvent(L"ALIAS_AFTER_REPLY_SNAT", parsed, addr, L"forcing outbound");
                        // After restoring the alias source (192.168.x.x), the
                        // reply must leave toward the WG client. Outbound is
                        // authoritative for NETWORK-layer injection.
                        addr.Outbound = 1;
                        addr.Loopback = 0;
                    }
                }
            }
            PacketTrace(L"[ALIAS_DECISION] changed=" + std::to_wstring(changed ? 1 : 0));
            if (changed) {
                api_.CalcChecksums(packet.data(), packetLen, &addr, 0);
                TracePacketEvent(L"ALIAS_BEFORE_SEND", parsed, addr);
            }
            UINT sent = 0;
            BOOL ok = api_.Send(alias_, packet.data(), packetLen, &sent, &addr);
            PacketTrace(L"[ALIAS_SEND] ok=" + std::to_wstring(ok ? 1 : 0) +
                        L" sent=" + std::to_wstring(sent) + (ok ? L"" : L" err=" + WinError()));
            if (!ok && running_) LogPacketErrorThrottled(L"Host Alias NAT Send 失敗: " + WinError());
        }
    }
};

NativeNatEngine gNativeNat;

bool ConfigureNativeNat(const ServerSettings& s, NET_LUID wgLuid, std::wstring& err) {
    NET_IFINDEX wgIfIndex = 0;
    DWORD rc = ConvertInterfaceLuidToIndex(&wgLuid, &wgIfIndex);
    if (rc != NO_ERROR || wgIfIndex == 0) {
        err = L"無法取得 EasyWG WireGuard 介面索引: " + WinError(rc);
        return false;
    }
    return gNativeNat.Start(s, wgIfIndex, err);
}

void RemoveNativeNat() {
    gNativeNat.Stop();
}

bool ConfigureLanAccess(NET_LUID wgLuid, std::wstring& err) {
    ServerSettings s;
    { std::lock_guard<std::mutex> lock(gDataMutex); s = gSettings; }
    if (s.lanAccessMode == L"off") { AddLog(L"LAN 存取模式: off"); return true; }
    if (!EnableForwardingForLan(wgLuid, err)) { RestoreForwarding(); return false; }
    // v0.4 product path is fixed to Native NAT. Route mode is no longer user-facing.
    if (!ConfigureNativeNat(s, wgLuid, err)) { RestoreForwarding(); return false; }
    AddLog(T(L"LAN 存取: EasyWG Native NAT + Host Alias NAT",
             L"LAN access: EasyWG Native NAT + Host Alias NAT"));
    return true;
}

void CleanupLanAccess() {
    RemoveNativeNat();
    RestoreForwarding();
}

std::wstring LegacyProgramDataDir() {
    wchar_t b[32768]{};
    DWORD n = GetEnvironmentVariableW(L"ProgramData", b, _countof(b));
    if (!n || n >= _countof(b)) return L"";
    return JoinPath(b, L"EasyWG");
}

std::wstring LegacyConfigPath() {
    const std::wstring base = LegacyProgramDataDir();
    return base.empty() ? L"" : JoinPath(JoinPath(base, L"Runtime"), L"EasyWG_Server_Win7.conf");
}

bool EnsureDirectoryTreeWin7(const std::wstring& path, std::wstring& err) {
    // Avoid SHCreateDirectoryExW here. Besides requiring an extra Shell header,
    // keeping directory creation on basic Win32 APIs makes the Win7 build less
    // sensitive to SDK/header variations.
    if (path.empty()) {
        err = L"建立目錄失敗: 路徑為空";
        return false;
    }

    auto isDirectory = [](const std::wstring& p) -> bool {
        DWORD attrs = GetFileAttributesW(p.c_str());
        return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
    };

    std::wstring target = path;
    // Remove trailing separators, but preserve roots such as C:\\ and \\server\share.
    while (target.size() > 3 && (target.back() == L'\\' || target.back() == L'/'))
        target.pop_back();

    if (isDirectory(target)) return true;

    if (CreateDirectoryW(target.c_str(), nullptr)) return true;
    DWORD rc = GetLastError();
    if (rc == ERROR_ALREADY_EXISTS && isDirectory(target)) return true;

    if (rc == ERROR_PATH_NOT_FOUND) {
        const size_t pos = target.find_last_of(L"\\/");
        if (pos != std::wstring::npos) {
            std::wstring parent = target.substr(0, pos);
            // For drive paths, keep the root slash (C:\\) instead of recursing to C:.
            if (parent.size() == 2 && parent[1] == L':') parent.push_back(L'\\');
            if (!parent.empty() && parent != target) {
                if (!EnsureDirectoryTreeWin7(parent, err)) return false;
                if (CreateDirectoryW(target.c_str(), nullptr)) return true;
                rc = GetLastError();
                if (rc == ERROR_ALREADY_EXISTS && isDirectory(target)) return true;
            }
        }
    }

    err = L"建立目錄失敗: " + target + L" - " + WinError(rc);
    return false;
}

bool WriteUtf8File(const std::wstring& path, const std::wstring& text, std::wstring& err) {
    const std::string bytes = WideToUtf8(text);
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) { err = L"建立檔案失敗: " + path + L" - " + WinError(); return false; }
    DWORD written = 0;
    BOOL ok = bytes.empty() || WriteFile(h, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr);
    CloseHandle(h);
    if (!ok || written != bytes.size()) { err = L"寫入檔案失敗: " + path; return false; }
    return true;
}

std::wstring BuildLegacyServerConfigText() {
    ServerSettings st;
    std::vector<PeerInfo> peers;
    {
        std::lock_guard<std::mutex> lk(gDataMutex);
        st = gSettings;
        peers = gPeers;
    }
    std::wstringstream ss;
    ss << L"[Interface]\r\n"
       << L"PrivateKey = " << Base64Encode(st.privateKey.data(), 32) << L"\r\n"
       << L"Address = " << st.address << L"/" << st.prefix << L"\r\n"
       << L"ListenPort = " << st.port << L"\r\n";
    for (const auto& p : peers) {
        ss << L"\r\n[Peer]\r\n"
           << L"PublicKey = " << Base64Encode(p.publicKey.data(), 32) << L"\r\n"
           << L"PresharedKey = " << Base64Encode(p.presharedKey.data(), 32) << L"\r\n"
           << L"AllowedIPs = " << p.ip << L"/32\r\n";
    }
    return ss.str();
}

bool PrepareLegacyServerConfig(std::wstring& configPath, std::wstring& err) {
    const std::wstring base = LegacyProgramDataDir();
    if (base.empty()) { err = L"無法取得 ProgramData 路徑"; return false; }
    const std::wstring runtime = JoinPath(base, L"Runtime");
    if (!EnsureDirectoryTreeWin7(runtime, err)) return false;
    configPath = LegacyConfigPath();
    return WriteUtf8File(configPath, BuildLegacyServerConfigText(), err);
}

std::wstring LegacyServiceLogPath() {
    const std::wstring base = LegacyProgramDataDir();
    return base.empty() ? L"" : JoinPath(base, L"win7-server-service.log");
}

void AppendLegacyServiceLog(const std::wstring& message) {
    const std::wstring base = LegacyProgramDataDir();
    if (base.empty()) return;
    std::wstring ignored;
    if (!EnsureDirectoryTreeWin7(base, ignored)) return;

    SYSTEMTIME st{};
    GetLocalTime(&st);
    wchar_t stamp[64]{};
    swprintf_s(stamp, L"[%04u-%02u-%02u %02u:%02u:%02u] ",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    const std::string line = WideToUtf8(std::wstring(stamp) + message + L"\r\n");
    if (line.empty()) return;

    const std::wstring path = LegacyServiceLogPath();
    HANDLE h = CreateFileW(path.c_str(), FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    WriteFile(h, line.data(), static_cast<DWORD>(line.size()), &written, nullptr);
    CloseHandle(h);
}

bool WaitServiceState(SC_HANDLE service, DWORD desired, DWORD timeoutMs, DWORD& lastState) {
    const ULONGLONG start = GetTickCount64();
    SERVICE_STATUS_PROCESS sp{};
    DWORD needed = 0;
    while (GetTickCount64() - start < timeoutMs) {
        if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                                  reinterpret_cast<LPBYTE>(&sp), sizeof(sp), &needed)) return false;
        lastState = sp.dwCurrentState;
        if (lastState == desired) return true;
        if (desired == SERVICE_RUNNING && lastState == SERVICE_STOPPED) return false;
        Sleep(200);
    }
    return false;
}

bool WaitLegacyServiceDeleted(SC_HANDLE scm, DWORD timeoutMs) {
    const ULONGLONG start = GetTickCount64();
    while (GetTickCount64() - start < timeoutMs) {
        SC_HANDLE probe = OpenServiceW(scm, kLegacyServiceName, SERVICE_QUERY_STATUS);
        if (!probe) {
            if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) return true;
        } else {
            CloseServiceHandle(probe);
        }
        Sleep(200);
    }
    return false;
}

void StopLegacyTunnelService() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return;
    SC_HANDLE svc = OpenServiceW(scm, kLegacyServiceName,
                                 SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (svc) {
        SERVICE_STATUS st{};
        ControlService(svc, SERVICE_CONTROL_STOP, &st);
        DWORD last = SERVICE_STOP_PENDING;
        WaitServiceState(svc, SERVICE_STOPPED, 10000, last);
        DeleteService(svc);
        CloseServiceHandle(svc);
        WaitLegacyServiceDeleted(scm, 10000);
    }
    CloseServiceHandle(scm);
}

bool StartLegacyTunnelService(const std::wstring& configPath, std::wstring& err) {
    StopLegacyTunnelService();

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr,
                                   SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (!scm) { err = L"OpenSCManager 失敗: " + WinError(); return false; }

    const std::wstring cmd = L"\"" + GetExePath() + L"\" /legacy-service \"" + configPath +
                             L"\" " + std::to_wstring(GetCurrentProcessId());
    const wchar_t dependencies[] = L"Nsi\0TcpIp\0";
    SC_HANDLE svc = CreateServiceW(
        scm, kLegacyServiceName, L"EasyWG Server Windows 7 Legacy Tunnel",
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL, cmd.c_str(), nullptr, nullptr, dependencies, nullptr, nullptr);
    DWORD createError = svc ? ERROR_SUCCESS : GetLastError();
    if (!svc && createError == ERROR_SERVICE_MARKED_FOR_DELETE) {
        WaitLegacyServiceDeleted(scm, 10000);
        svc = CreateServiceW(
            scm, kLegacyServiceName, L"EasyWG Server Windows 7 Legacy Tunnel",
            SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL, cmd.c_str(), nullptr, nullptr, dependencies, nullptr, nullptr);
        createError = svc ? ERROR_SUCCESS : GetLastError();
    }
    if (!svc) {
        DWORD e = createError;
        CloseServiceHandle(scm);
        err = L"建立 Win7 Legacy Tunnel 服務失敗: " + WinError(e);
        return false;
    }

    SERVICE_SID_INFO sid{};
    sid.dwServiceSidType = SERVICE_SID_TYPE_UNRESTRICTED;
    if (!ChangeServiceConfig2W(svc, SERVICE_CONFIG_SERVICE_SID_INFO, &sid)) {
        DWORD e = GetLastError();
        DeleteService(svc);
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        err = L"設定 Win7 Legacy Tunnel 服務 SID 失敗: " + WinError(e);
        return false;
    }

    if (!StartServiceW(svc, 0, nullptr)) {
        DWORD e = GetLastError();
        DeleteService(svc);
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        err = L"啟動 Win7 Legacy Tunnel 服務失敗: " + WinError(e);
        return false;
    }

    DWORD last = SERVICE_START_PENDING;
    if (!WaitServiceState(svc, SERVICE_RUNNING, 20000, last)) {
        SERVICE_STATUS_PROCESS sp{}; DWORD needed = 0;
        QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                             reinterpret_cast<LPBYTE>(&sp), sizeof(sp), &needed);
        SERVICE_STATUS st{}; ControlService(svc, SERVICE_CONTROL_STOP, &st);
        DeleteService(svc);
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        err = L"Win7 Legacy Tunnel 未進入 Running 狀態。最後狀態=" +
              std::to_wstring(last) + L"，Win32Exit=" + std::to_wstring(sp.dwWin32ExitCode) +
              L"，ServiceExit=" + std::to_wstring(sp.dwServiceSpecificExitCode) +
              L"。診斷日誌: " + LegacyServiceLogPath();
        return false;
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return true;
}

void MarkLegacyServiceDeleteThenStop() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return;
    SC_HANDLE svc = OpenServiceW(scm, kLegacyServiceName,
                                 SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (svc) {
        DeleteService(svc);
        SERVICE_STATUS st{};
        ControlService(svc, SERVICE_CONTROL_STOP, &st);
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
}

void WatchLegacyParentAndCleanup(DWORD parentPid) {
    if (!parentPid) return;
    HANDLE parent = OpenProcess(SYNCHRONIZE, FALSE, parentPid);
    if (!parent) {
        AppendLegacyServiceLog(L"Parent watcher could not open PID " + std::to_wstring(parentPid) +
                               L". Error=" + std::to_wstring(GetLastError()));
        return;
    }
    WaitForSingleObject(parent, INFINITE);
    CloseHandle(parent);
    AppendLegacyServiceLog(L"EasyWG parent process exited; stopping and deleting legacy service.");
    MarkLegacyServiceDeleteThenStop();
}

int RunLegacyTunnelServiceMode(const std::wstring& configPath, DWORD parentPid) {
    AppendLegacyServiceLog(L"Legacy service process started. Config=" + configPath +
                           L", ParentPID=" + std::to_wstring(parentPid));
    if (parentPid) {
        std::thread watcher(WatchLegacyParentAndCleanup, parentPid);
        watcher.detach();
    }
    SetCurrentDirectoryW(GetExeDir().c_str());
    SetDllDirectoryW(GetExeDir().c_str());
    HMODULE tunnel = LoadLibraryW(LegacyTunnelPath().c_str());
    const DWORD loadError = tunnel ? ERROR_SUCCESS : GetLastError();
    SetDllDirectoryW(nullptr);
    if (!tunnel) {
        AppendLegacyServiceLog(L"LoadLibrary(tunnel-win7.dll) failed. Error=" +
                               std::to_wstring(loadError));
        return static_cast<int>(loadError ? loadError : 11);
    }

    using ForceLegacyProc = void(__cdecl*)(BOOL);
    using TunnelServiceProc = BOOL(__cdecl*)(LPCWSTR);
    auto forceLegacy = reinterpret_cast<ForceLegacyProc>(
        GetProcAddress(tunnel, "WireGuardForceLegacyImplementation"));
    auto tunnelService = reinterpret_cast<TunnelServiceProc>(
        GetProcAddress(tunnel, "WireGuardTunnelService"));
    if (!forceLegacy || !tunnelService) {
        AppendLegacyServiceLog(L"Required legacy tunnel export missing. ForceLegacy=" +
                               std::to_wstring(forceLegacy ? 1 : 0) + L", TunnelService=" +
                               std::to_wstring(tunnelService ? 1 : 0));
        FreeLibrary(tunnel);
        return 12;
    }

    AppendLegacyServiceLog(L"Calling WireGuardForceLegacyImplementation(TRUE).");
    forceLegacy(TRUE);
    AppendLegacyServiceLog(L"Calling WireGuardTunnelService().");
    const BOOL ok = tunnelService(configPath.c_str());
    AppendLegacyServiceLog(std::wstring(L"WireGuardTunnelService returned ") +
                           (ok ? L"TRUE" : L"FALSE"));
    FreeLibrary(tunnel);
    return ok ? 0 : 13;
}

bool FindAdapterLuidByIpv4(const std::wstring& ipText, NET_LUID& luid) {
    IN_ADDR target{};
    if (InetPtonW(AF_INET, ipText.c_str(), &target) != 1) return false;
    ULONG size = 0;
    DWORD rc = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &size);
    if (rc != ERROR_BUFFER_OVERFLOW || !size) return false;
    std::vector<BYTE> buf(size);
    auto* first = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
    rc = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, first, &size);
    if (rc != NO_ERROR) return false;
    for (auto* aa = first; aa; aa = aa->Next) {
        for (auto* ua = aa->FirstUnicastAddress; ua; ua = ua->Next) {
            if (!ua->Address.lpSockaddr || ua->Address.lpSockaddr->sa_family != AF_INET) continue;
            auto* sa = reinterpret_cast<SOCKADDR_IN*>(ua->Address.lpSockaddr);
            if (sa->sin_addr.S_un.S_addr == target.S_un.S_addr) { luid = aa->Luid; return true; }
        }
    }
    return false;
}

bool WaitForLegacyAdapterLuid(const std::wstring& ipText, NET_LUID& luid, DWORD timeoutMs) {
    const ULONGLONG start = GetTickCount64();
    while (GetTickCount64() - start < timeoutMs) {
        if (FindAdapterLuidByIpv4(ipText, luid)) return true;
        Sleep(200);
    }
    return false;
}

bool WriteTempPowerShellScript(const std::string& body, std::wstring& path, std::wstring& err) {
    wchar_t tempDir[MAX_PATH]{};
    if (!GetTempPathW(_countof(tempDir), tempDir)) { err = L"GetTempPath 失敗: " + WinError(); return false; }
    wchar_t tempFile[MAX_PATH]{};
    if (!GetTempFileNameW(tempDir, L"EW7", 0, tempFile)) { err = L"GetTempFileName 失敗: " + WinError(); return false; }
    path = std::wstring(tempFile) + L".ps1";
    MoveFileExW(tempFile, path.c_str(), MOVEFILE_REPLACE_EXISTING);
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) { err = L"建立暫存 PowerShell 腳本失敗: " + WinError(); return false; }
    DWORD wr = 0; BOOL ok = body.empty() || WriteFile(h, body.data(), static_cast<DWORD>(body.size()), &wr, nullptr);
    CloseHandle(h);
    if (!ok || wr != body.size()) { DeleteFileW(path.c_str()); err = L"寫入暫存 PowerShell 腳本失敗"; return false; }
    return true;
}

bool DownloadLegacyWintun(std::wstring& err) {
    std::vector<BYTE> zip;
    std::wstring downloadErr;
    if (!HttpGet(kLegacyWintunUrl, zip, downloadErr)) {
        err = L"下載官方 Wintun 0.13 ZIP 失敗: " + downloadErr;
        return false;
    }
    if (zip.size() < 4 || zip[0] != 'P' || zip[1] != 'K') {
        err = L"Wintun 下載內容不是有效 ZIP（可能被代理伺服器或網頁攔截）";
        return false;
    }

    wchar_t tempDir[MAX_PATH]{};
    if (!GetTempPathW(_countof(tempDir), tempDir)) {
        err = L"取得暫存目錄失敗: " + WinError();
        return false;
    }

    // Shell.Application on Windows 7 recognizes ZIP archives by the .zip
    // extension.  The previous code wrote ZIP bytes to GetTempFileName's
    // default .tmp file, causing NameSpace($ZipPath) to fail on Win7.
    wchar_t tempBase[MAX_PATH]{};
    if (!GetTempFileNameW(tempDir, L"EWW", 0, tempBase)) {
        err = L"建立 Wintun 暫存檔失敗: " + WinError();
        return false;
    }
    DeleteFileW(tempBase);
    const std::wstring zipPath = std::wstring(tempBase) + L".zip";
    if (!WriteBytes(zipPath, zip)) {
        DeleteFileW(zipPath.c_str());
        err = L"寫入 Wintun ZIP 失敗: " + WinError();
        return false;
    }

    const std::string script = R"PS1(param([string]$ZipPath,[string]$OutputDir,[string]$ResultFile)
$ErrorActionPreference='Stop'
$Utf8NoBom=New-Object Text.UTF8Encoding($false)
try {
  New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
  $tempRoot=Join-Path ([IO.Path]::GetTempPath()) ('EasyWG-WINTUN-'+[guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null
  try {
    $shell=New-Object -ComObject Shell.Application
    $zipNs=$shell.NameSpace($ZipPath); $destNs=$shell.NameSpace($tempRoot)
    if($null -eq $zipNs -or $null -eq $destNs){throw 'Windows ZIP shell namespace unavailable.'}
    $destNs.CopyHere($zipNs.Items(),20)
    $dll=$null
    for($i=0;$i -lt 300;$i++){
      $dll=Get-ChildItem -Path $tempRoot -Recurse -Filter 'wintun.dll' -ErrorAction SilentlyContinue |
        Where-Object {-not $_.PSIsContainer} |
        Where-Object {$_.FullName -match '[\\/]bin[\\/]amd64[\\/]wintun\.dll$' -or ($_.Name -ieq 'wintun.dll' -and $_.Directory.Name -ieq 'amd64')} |
        Select-Object -First 1
      if($dll){break}; Start-Sleep -Milliseconds 100
    }
    if(-not $dll){throw 'amd64 wintun.dll not found.'}
    Copy-Item -LiteralPath $dll.FullName -Destination (Join-Path $OutputDir 'wintun.dll') -Force
    [IO.File]::WriteAllText($ResultFile,'OK',$Utf8NoBom)
    exit 0
  } finally { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue }
} catch {
  [IO.File]::WriteAllText($ResultFile,('ERROR|'+$_.Exception.Message),$Utf8NoBom)
  exit 1
}
)PS1";

    std::wstring scriptPath;
    if (!WriteTempPowerShellScript(script, scriptPath, err)) {
        DeleteFileW(zipPath.c_str());
        return false;
    }

    wchar_t resultTmp[MAX_PATH]{};
    if (!GetTempFileNameW(tempDir, L"EWR", 0, resultTmp)) {
        DeleteFileW(scriptPath.c_str());
        DeleteFileW(zipPath.c_str());
        err = L"建立 Wintun 結果檔失敗: " + WinError();
        return false;
    }
    const std::wstring resultPath = resultTmp;

    const std::wstring cmd = L"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + scriptPath +
        L"\" -ZipPath \"" + zipPath + L"\" -OutputDir \"" + GetExeDir() +
        L"\" -ResultFile \"" + resultPath + L"\"";

    DWORD ec = 1;
    const bool ran = RunHidden(cmd, 120000, &ec);
    const std::wstring result = ReadUtf8FileSmall(resultPath);

    DeleteFileW(scriptPath.c_str());
    DeleteFileW(zipPath.c_str());
    DeleteFileW(resultPath.c_str());

    if (!ran) {
        err = L"無法啟動 PowerShell 來解壓 Wintun ZIP";
        return false;
    }
    if (ec != 0 || result != L"OK" || !FileExistsNonEmpty(WintunDllPath())) {
        err = L"解壓 Windows 7 Wintun 0.13 失敗";
        if (!result.empty()) err += L": " + result;
        else err += L"（PowerShell / Shell.Application 未回傳成功結果）";
        return false;
    }

    AddLog(L"wintun.dll 已從官方 Wintun 0.13 ZIP 解壓並安裝");
    return true;
}

bool DownloadLegacyWin7Core(std::wstring& err) {
    if (!FileExistsNonEmpty(LegacyTunnelPath())) {
        DeleteFileW(LegacyTunnelPath().c_str());
        std::vector<BYTE> body;
        std::wstring downloadErr;
        if (!HttpGet(kLegacyTunnelUrl, body, downloadErr)) {
            err = L"下載 tunnel-win7.dll 失敗: " + downloadErr;
            return false;
        }
        if (body.empty() || !WriteBytes(LegacyTunnelPath(), body) || !FileExistsNonEmpty(LegacyTunnelPath())) {
            DeleteFileW(LegacyTunnelPath().c_str());
            err = L"寫入 tunnel-win7.dll 失敗";
            return false;
        }
        AddLog(L"tunnel-win7.dll 已下載並安裝");
    }

    if (!FileExistsNonEmpty(WintunDllPath())) {
        DeleteFileW(WintunDllPath().c_str());
        AddLog(L"缺少 wintun.dll，開始下載官方 Wintun 0.13 ZIP…");
        if (!DownloadLegacyWintun(err)) return false;
    }

    if (!LegacyCoreRuntimeReady()) {
        err = L"Windows 7 Legacy Core 未完整就緒：tunnel-win7.dll / wintun.dll";
        return false;
    }
    return true;
}

bool StartServerWin7Legacy(std::wstring& err) {
    gLegacyUapiPipePath.clear();
    gLegacyStatsAvailable = false;
    gLegacyStatsFailureCount = 0;
    if (!LegacyCoreRuntimeReady()) { err = L"缺少 Windows 7 Legacy Core：tunnel-win7.dll / wintun.dll"; return false; }
    std::wstring configPath;
    if (!PrepareLegacyServerConfig(configPath, err)) return false;
    if (!StartLegacyTunnelService(configPath, err)) return false;

    ServerSettings st;
    { std::lock_guard<std::mutex> lk(gDataMutex); st = gSettings; }
    NET_LUID luid{};
    if (!WaitForLegacyAdapterLuid(st.address, luid, 12000)) {
        StopLegacyTunnelService();
        err = L"Win7 Legacy Tunnel 已啟動，但找不到 VPN Server IP " + st.address + L" 對應的 Wintun 介面";
        return false;
    }
    if (!ConfigureLanAccess(luid, err)) {
        StopLegacyTunnelService();
        return false;
    }
    AddFirewallRule(st.port);
    gLegacyWin7Mode = true;
    gRunning = true;
    gStartedAt = std::chrono::steady_clock::now();
    AddLog(L"EasyWG Server 已以 Windows 7 Legacy Core 啟動，UDP Port " + std::to_wstring(st.port));
    UpdateTrayIconTip();
    return true;
}

bool StartServer(std::wstring& err) {
    if (gRunning) return true;
    if (IsWindows7OrEarlier()) return StartServerWin7Legacy(err);
    if (!PathFileExistsW(DllPath().c_str())) { err = L"找不到 wireguard.dll"; return false; }
    if (!gWg.Load(err)) return false;
    gWg.SetLogger(WgLogger);

    GUID guid = {0x5d9e8d14, 0x316a, 0x4abc, {0x9e,0x53,0xe1,0x28,0x11,0x8a,0x77,0x01}};
    gAdapter = gWg.CreateAdapter(kAdapterName, kTunnelType, &guid);
    if (!gAdapter) {
        DWORD createErr = GetLastError();
        gAdapter = gWg.OpenAdapter(kAdapterName);
        if (!gAdapter) { err = L"建立/開啟 WireGuard Adapter 失敗: " + WinError(createErr); return false; }
        AddLog(L"已開啟既有 EasyWG Adapter");
    }
    gWg.SetAdapterLogging(gAdapter, WIREGUARD_ADAPTER_LOG_ON);

    std::vector<BYTE> cfg;
    if (!BuildWgConfig(cfg, err)) { gWg.CloseAdapter(gAdapter); gAdapter = nullptr; return false; }
    auto* iface = reinterpret_cast<WIREGUARD_INTERFACE*>(cfg.data());
    if (!gWg.SetConfiguration(gAdapter, iface, static_cast<DWORD>(cfg.size()))) {
        err = L"套用 WireGuard 設定失敗: " + WinError(); gWg.CloseAdapter(gAdapter); gAdapter = nullptr; return false;
    }
    NET_LUID luid{};
    gWg.GetAdapterLuid(gAdapter, &luid);
    if (!AssignAdapterIp(luid, err)) { gWg.CloseAdapter(gAdapter); gAdapter = nullptr; return false; }
    if (!gWg.SetAdapterState(gAdapter, WIREGUARD_ADAPTER_STATE_UP)) {
        err = L"啟動 WireGuard Adapter 失敗: " + WinError(); gWg.CloseAdapter(gAdapter); gAdapter = nullptr; return false;
    }
    if (!ConfigureLanAccess(luid, err)) {
        gWg.SetAdapterState(gAdapter, WIREGUARD_ADAPTER_STATE_DOWN);
        gWg.CloseAdapter(gAdapter); gAdapter = nullptr;
        return false;
    }
    int port;
    { std::lock_guard<std::mutex> lock(gDataMutex); port = gSettings.port; }
    AddFirewallRule(port);
    gRunning = true;
    gStartedAt = std::chrono::steady_clock::now();
    AddLog(L"EasyWG Server 已啟動，UDP Port " + std::to_wstring(port));
    UpdateTrayIconTip();
    return true;
}

void StopServer() {
    CleanupLanAccess();
    if (gLegacyWin7Mode) {
        StopLegacyTunnelService();
        const std::wstring cfg = LegacyConfigPath();
        if (!cfg.empty()) DeleteFileW(cfg.c_str());
        gLegacyWin7Mode = false;
        gLegacyStatsAvailable = false;
        gLegacyStatsFailureCount = 0;
        gLegacyUapiPipePath.clear();
        gRunning = false;
        AddLog(L"EasyWG Server 已停止（Windows 7 Legacy Core）");
        UpdateTrayIconTip();
        return;
    }
    if (!gAdapter) { gRunning = false; UpdateTrayIconTip(); return; }
    gWg.SetAdapterState(gAdapter, WIREGUARD_ADAPTER_STATE_DOWN);
    gWg.CloseAdapter(gAdapter);
    gAdapter = nullptr;
    gRunning = false;
    AddLog(L"EasyWG Server 已停止");
    UpdateTrayIconTip();
}

bool HexDecode32(const std::string& text, std::array<BYTE, 32>& out) {
    if (text.size() != 64) return false;
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < out.size(); ++i) {
        const int hi = nibble(text[i * 2]);
        const int lo = nibble(text[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<BYTE>((hi << 4) | lo);
    }
    return true;
}

bool ReadNamedPipeUapi(const std::wstring& pipePath, std::string& response) {
    response.clear();
    HANDLE pipe = CreateFileW(pipePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                              OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
    if (pipe == INVALID_HANDLE_VALUE && GetLastError() == ERROR_PIPE_BUSY) {
        if (WaitNamedPipeW(pipePath.c_str(), 500)) {
            pipe = CreateFileW(pipePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                               OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
        }
    }
    if (pipe == INVALID_HANDLE_VALUE) return false;

    auto ioWithTimeout = [pipe](bool writeOp, void* buffer, DWORD size, DWORD& transferred,
                                DWORD timeoutMs) -> bool {
        transferred = 0;
        OVERLAPPED ov{};
        ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!ov.hEvent) return false;
        BOOL ok = writeOp
            ? WriteFile(pipe, buffer, size, &transferred, &ov)
            : ReadFile(pipe, buffer, size, &transferred, &ov);
        if (!ok) {
            DWORD e = GetLastError();
            if (e == ERROR_IO_PENDING) {
                const DWORD wait = WaitForSingleObject(ov.hEvent, timeoutMs);
                if (wait == WAIT_OBJECT_0) {
                    ok = GetOverlappedResult(pipe, &ov, &transferred, FALSE);
                } else {
                    CancelIo(pipe);
                    WaitForSingleObject(ov.hEvent, 1000);
                    DWORD ignored = 0;
                    GetOverlappedResult(pipe, &ov, &ignored, FALSE);
                    ok = FALSE;
                }
            } else {
                ok = FALSE;
            }
        }
        CloseHandle(ov.hEvent);
        return ok != FALSE;
    };

    char request[] = "get=1\n\n";
    DWORD transferred = 0;
    if (!ioWithTimeout(true, request, static_cast<DWORD>(sizeof(request) - 1), transferred, 1000) ||
        transferred != sizeof(request) - 1) {
        CloseHandle(pipe);
        return false;
    }

    char chunk[4096];
    for (int i = 0; i < 64; ++i) {
        DWORD got = 0;
        if (!ioWithTimeout(false, chunk, static_cast<DWORD>(sizeof(chunk)), got, 1000)) {
            CloseHandle(pipe);
            return false;
        }
        if (!got) break;
        response.append(chunk, chunk + got);
        const size_t errnoPos = response.find("errno=");
        if (errnoPos != std::string::npos) {
            const size_t end = response.find("\n\n", errnoPos);
            if (end != std::string::npos) break;
        }
        if (response.size() > 256 * 1024) {
            CloseHandle(pipe);
            return false;
        }
    }
    CloseHandle(pipe);
    return response.find("errno=0") != std::string::npos;
}

std::wstring LegacyAdapterFriendlyNameByIpv4(const std::wstring& ipText) {
    IN_ADDR target{};
    if (InetPtonW(AF_INET, ipText.c_str(), &target) != 1) return L"";
    ULONG size = 0;
    DWORD rc = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &size);
    if (rc != ERROR_BUFFER_OVERFLOW || !size) return L"";
    std::vector<BYTE> buf(size);
    auto* first = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
    rc = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, first, &size);
    if (rc != NO_ERROR) return L"";
    for (auto* aa = first; aa; aa = aa->Next) {
        for (auto* ua = aa->FirstUnicastAddress; ua; ua = ua->Next) {
            if (!ua->Address.lpSockaddr || ua->Address.lpSockaddr->sa_family != AF_INET) continue;
            auto* sa = reinterpret_cast<SOCKADDR_IN*>(ua->Address.lpSockaddr);
            if (sa->sin_addr.S_un.S_addr == target.S_un.S_addr)
                return aa->FriendlyName ? aa->FriendlyName : L"";
        }
    }
    return L"";
}

std::vector<std::wstring> LegacyUapiPipeCandidates() {
    std::vector<std::wstring> names;
    auto addName = [&names](const std::wstring& name) {
        if (name.empty()) return;
        for (const auto& existing : names)
            if (_wcsicmp(existing.c_str(), name.c_str()) == 0) return;
        names.push_back(name);
    };

    // The embeddable tunnel service normally derives the tunnel/interface name
    // from the configuration file stem.
    std::wstring cfg = LegacyConfigPath();
    size_t slash = cfg.find_last_of(L"\\/");
    std::wstring stem = slash == std::wstring::npos ? cfg : cfg.substr(slash + 1);
    size_t dot = stem.find_last_of(L'.');
    if (dot != std::wstring::npos) stem.resize(dot);
    addName(stem);

    ServerSettings st;
    { std::lock_guard<std::mutex> lk(gDataMutex); st = gSettings; }
    addName(LegacyAdapterFriendlyNameByIpv4(st.address));
    addName(L"EasyWG_Server_Win7");
    addName(L"EasyWG");

    std::vector<std::wstring> pipes;
    for (const auto& name : names)
        pipes.push_back(L"\\\\.\\pipe\\ProtectedPrefix\\Administrators\\WireGuard\\" + name);
    return pipes;
}

bool QueryLegacyUapi(std::string& response) {
    if (!gLegacyUapiPipePath.empty() && ReadNamedPipeUapi(gLegacyUapiPipePath, response))
        return true;
    for (const auto& pipe : LegacyUapiPipeCandidates()) {
        if (ReadNamedPipeUapi(pipe, response)) {
            gLegacyUapiPipePath = pipe;
            return true;
        }
    }
    gLegacyUapiPipePath.clear();
    return false;
}

bool RefreshLegacyStats() {
    std::string response;
    if (!QueryLegacyUapi(response)) return false;

    struct StatRow {
        std::array<BYTE, 32> key{};
        uint64_t rx = 0;
        uint64_t tx = 0;
        uint64_t sec = 0;
        uint64_t nsec = 0;
        bool valid = false;
    };
    std::vector<StatRow> rows;
    StatRow* current = nullptr;

    std::istringstream input(response);
    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        const std::string key = line.substr(0, eq);
        const std::string value = line.substr(eq + 1);
        if (key == "public_key") {
            StatRow row;
            row.valid = HexDecode32(value, row.key);
            rows.push_back(row);
            current = &rows.back();
            continue;
        }
        if (!current || !current->valid) continue;
        char* end = nullptr;
        const unsigned __int64 n = _strtoui64(value.c_str(), &end, 10);
        if (!end || *end != '\0') continue;
        if (key == "rx_bytes") current->rx = static_cast<uint64_t>(n);
        else if (key == "tx_bytes") current->tx = static_cast<uint64_t>(n);
        else if (key == "last_handshake_time_sec") current->sec = static_cast<uint64_t>(n);
        else if (key == "last_handshake_time_nsec") current->nsec = static_cast<uint64_t>(n);
    }

    constexpr uint64_t kUnixToFileTimeSeconds = 11644473600ULL;
    std::lock_guard<std::mutex> lock(gDataMutex);
    for (auto& peer : gPeers) {
        peer.rx = 0;
        peer.tx = 0;
        peer.lastHandshake = 0;
        for (const auto& row : rows) {
            if (!row.valid || memcmp(peer.publicKey.data(), row.key.data(), 32) != 0) continue;
            peer.rx = row.rx;
            peer.tx = row.tx;
            if (row.sec > 0 && row.sec < 0x7FFFFFFFFFFFFFFFULL - kUnixToFileTimeSeconds) {
                peer.lastHandshake = (row.sec + kUnixToFileTimeSeconds) * 10000000ULL + row.nsec / 100ULL;
            } else {
                peer.lastHandshake = 0;
            }
            break;
        }
    }
    return true;
}

void RefreshStats() {
    if (!gRunning) return;
    if (gLegacyWin7Mode) {
        const bool ok = RefreshLegacyStats();
        const bool wasAvailable = gLegacyStatsAvailable.exchange(ok);
        if (ok) {
            gLegacyStatsFailureCount = 0;
            if (!wasAvailable)
                AddLog(L"Windows 7 Legacy Peer statistics connected through WireGuard UAPI");
        } else {
            const int failures = ++gLegacyStatsFailureCount;
            if (failures == 5)
                AddLog(L"Windows 7 Legacy Peer statistics UAPI is not reachable yet");
        }
        return;
    }
    if (!gAdapter || !gWg.GetConfiguration) return;
    DWORD bytes = 0;
    if (gWg.GetConfiguration(gAdapter, nullptr, &bytes)) return;
    if (GetLastError() != ERROR_MORE_DATA || !bytes) return;
    std::vector<BYTE> buf(bytes);
    auto* iface = reinterpret_cast<WIREGUARD_INTERFACE*>(buf.data());
    if (!gWg.GetConfiguration(gAdapter, iface, &bytes)) return;

    std::lock_guard<std::mutex> lock(gDataMutex);
    BYTE* cur = buf.data() + sizeof(WIREGUARD_INTERFACE);
    for (DWORD i = 0; i < iface->PeersCount; ++i) {
        auto* peer = reinterpret_cast<WIREGUARD_PEER*>(cur);
        for (auto& p : gPeers) {
            if (!memcmp(p.publicKey.data(), peer->PublicKey, 32)) {
                p.rx = peer->RxBytes; p.tx = peer->TxBytes; p.lastHandshake = peer->LastHandshake; break;
            }
        }
        cur += sizeof(WIREGUARD_PEER) + peer->AllowedIPsCount * sizeof(WIREGUARD_ALLOWED_IP);
        if (cur > buf.data() + bytes) break;
    }
}

uint64_t FileTimeNow100ns() {
    FILETIME ft{}; GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u{}; u.LowPart = ft.dwLowDateTime; u.HighPart = ft.dwHighDateTime;
    return u.QuadPart;
}

std::wstring HandshakeAge(uint64_t ft) {
    if (!ft) return L"—";
    uint64_t now = FileTimeNow100ns();
    if (now <= ft) return T(L"剛剛", L"Just now");
    uint64_t sec = (now - ft) / 10000000ULL;
    if (sec < 60) return std::to_wstring(sec) + T(L" 秒前", L" sec ago");
    if (sec < 3600) return std::to_wstring(sec / 60) + T(L" 分鐘前", L" min ago");
    if (sec < 86400) return std::to_wstring(sec / 3600) + T(L" 小時前", L" hr ago");
    return std::to_wstring(sec / 86400) + T(L" 天前", L" days ago");
}

bool IsPeerActive(uint64_t ft) {
    if (!ft) return false;
    uint64_t now = FileTimeNow100ns();
    return now > ft && (now - ft) < 180ULL * 10000000ULL;
}

// ---------------- UI drawing helpers ----------------

struct UiFonts {
    HFONT normal = nullptr, smallFont = nullptr, nav = nullptr, title = nullptr, h2 = nullptr, bold = nullptr, big = nullptr;
    void Create() {
        normal = CreateFontW(-16,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
        smallFont = CreateFontW(-13,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
        nav = CreateFontW(-18,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
        title = CreateFontW(-25,0,0,0,FW_SEMIBOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
        h2 = CreateFontW(-19,0,0,0,FW_SEMIBOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
        bold = CreateFontW(-16,0,0,0,FW_SEMIBOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
        big = CreateFontW(-28,0,0,0,FW_BOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
    }
    void Destroy() { DeleteObject(normal); DeleteObject(smallFont); DeleteObject(nav); DeleteObject(title); DeleteObject(h2); DeleteObject(bold); DeleteObject(big); }
} gFonts;

COLORREF C(uint32_t rgb) { return RGB((rgb>>16)&255, (rgb>>8)&255, rgb&255); }
COLORREF CLR_BG = C(0xF6F8FC);
COLORREF CLR_CARD = C(0xFFFFFF);
COLORREF CLR_TEXT = C(0x202938);
COLORREF CLR_MUTED = C(0x667085);
COLORREF CLR_BORDER = C(0xE4E9F2);
COLORREF CLR_BLUE = C(0x1769E8);
COLORREF CLR_BLUE_LIGHT = C(0xEAF2FF);
COLORREF CLR_GREEN = C(0x18A957);
COLORREF CLR_GREEN_LIGHT = C(0xEAF9F0);
COLORREF CLR_RED = C(0xE74856);
COLORREF CLR_SIDEBAR = C(0xFFFFFF);
COLORREF CLR_INPUT = C(0xFFFFFF);
COLORREF CLR_SUBTLE = C(0xF7F9FC);
COLORREF CLR_ROW_ALT = C(0xFAFBFD);
bool gDarkTheme = false;
HBRUSH gThemeBgBrush = nullptr;
HBRUSH gThemeCardBrush = nullptr;
HBRUSH gThemeInputBrush = nullptr;
HBRUSH gThemeSubtleBrush = nullptr;

bool SystemPrefersDarkTheme(){
    HKEY key=nullptr;DWORD value=1,size=sizeof(value),type=0;
    LONG rc=RegOpenKeyExW(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",0,KEY_QUERY_VALUE,&key);
    if(rc==ERROR_SUCCESS){
        rc=RegQueryValueExW(key,L"AppsUseLightTheme",nullptr,&type,reinterpret_cast<BYTE*>(&value),&size);
        RegCloseKey(key);
        if(rc==ERROR_SUCCESS&&type==REG_DWORD)return value==0;
    }
    return false;
}

void RecreateThemeBrushes(){
    if(gThemeBgBrush)DeleteObject(gThemeBgBrush);
    if(gThemeCardBrush)DeleteObject(gThemeCardBrush);
    if(gThemeInputBrush)DeleteObject(gThemeInputBrush);
    if(gThemeSubtleBrush)DeleteObject(gThemeSubtleBrush);
    gThemeBgBrush=CreateSolidBrush(CLR_BG);
    gThemeCardBrush=CreateSolidBrush(CLR_CARD);
    gThemeInputBrush=CreateSolidBrush(CLR_INPUT);
    gThemeSubtleBrush=CreateSolidBrush(CLR_SUBTLE);
}

void ApplyThemePalette(){
    std::wstring theme;{std::lock_guard<std::mutex>lk(gDataMutex);theme=gSettings.theme;}
    gDarkTheme=(theme==L"dark")||(theme==L"system"&&SystemPrefersDarkTheme());
    if(gDarkTheme){
        CLR_BG=C(0x111827);CLR_CARD=C(0x182233);CLR_TEXT=C(0xE7EDF7);CLR_MUTED=C(0xA9B5C6);
        CLR_BORDER=C(0x334155);CLR_BLUE=C(0x4D8DFF);CLR_BLUE_LIGHT=C(0x1D3152);
        CLR_GREEN=C(0x35D07F);CLR_GREEN_LIGHT=C(0x173B2B);CLR_RED=C(0xFF6B78);
        CLR_SIDEBAR=C(0x0F1724);CLR_INPUT=C(0x101A2A);CLR_SUBTLE=C(0x202B3C);CLR_ROW_ALT=C(0x1D293A);
    }else{
        CLR_BG=C(0xF6F8FC);CLR_CARD=C(0xFFFFFF);CLR_TEXT=C(0x202938);CLR_MUTED=C(0x667085);
        CLR_BORDER=C(0xE4E9F2);CLR_BLUE=C(0x1769E8);CLR_BLUE_LIGHT=C(0xEAF2FF);
        CLR_GREEN=C(0x18A957);CLR_GREEN_LIGHT=C(0xEAF9F0);CLR_RED=C(0xE74856);
        CLR_SIDEBAR=C(0xFFFFFF);CLR_INPUT=C(0xFFFFFF);CLR_SUBTLE=C(0xF7F9FC);CLR_ROW_ALT=C(0xFAFBFD);
    }
    RecreateThemeBrushes();
}

void ApplyWindowDarkMode(HWND hwnd){
    if(!hwnd)return;
    BOOL dark=gDarkTheme?TRUE:FALSE;
    constexpr DWORD DWMWA_USE_IMMERSIVE_DARK_MODE_VALUE=20;
    DwmSetWindowAttribute(hwnd,DWMWA_USE_IMMERSIVE_DARK_MODE_VALUE,&dark,sizeof(dark));
}

void FillRectC(HDC dc, const RectI& r, COLORREF c) { HBRUSH b=CreateSolidBrush(c);RECT rc{r.x,r.y,r.x+r.w,r.y+r.h};FillRect(dc,&rc,b);DeleteObject(b); }
void Line(HDC dc,int x1,int y1,int x2,int y2,COLORREF c,int width=1){HPEN p=CreatePen(PS_SOLID,width,c);HGDIOBJ o=SelectObject(dc,p);MoveToEx(dc,x1,y1,nullptr);LineTo(dc,x2,y2);SelectObject(dc,o);DeleteObject(p);}
void RoundFill(HDC dc,const RectI&r,COLORREF fill,COLORREF border=CLR_BORDER,int rad=12){HBRUSH b=CreateSolidBrush(fill);HPEN p=CreatePen(PS_SOLID,1,border);HGDIOBJ ob=SelectObject(dc,b),op=SelectObject(dc,p);RoundRect(dc,r.x,r.y,r.x+r.w,r.y+r.h,rad,rad);SelectObject(dc,ob);SelectObject(dc,op);DeleteObject(b);DeleteObject(p);}
void Text(HDC dc,const std::wstring&s,int x,int y,int w,int h,HFONT f,COLORREF c,UINT fmt=DT_LEFT|DT_VCENTER|DT_SINGLELINE){HFONT old=(HFONT)SelectObject(dc,f);SetBkMode(dc,TRANSPARENT);SetTextColor(dc,c);RECT r{x,y,x+w,y+h};DrawTextW(dc,s.c_str(),-1,&r,fmt);SelectObject(dc,old);}
void Dot(HDC dc,int x,int y,int rad,COLORREF c){HBRUSH b=CreateSolidBrush(c);HGDIOBJ o=SelectObject(dc,b);Ellipse(dc,x-rad,y-rad,x+rad,y+rad);SelectObject(dc,o);DeleteObject(b);}
void DrawShield(HDC dc,int x,int y,int z,COLORREF shieldColor=CLR_BLUE){POINT pts[6]={{x+z/2,y},{x+z,y+z/5},{x+z*9/10,y+z*2/3},{x+z/2,y+z},{x+z/10,y+z*2/3},{x,y+z/5}};HBRUSH b=CreateSolidBrush(shieldColor);HPEN p=CreatePen(PS_SOLID,1,shieldColor);auto ob=SelectObject(dc,b);auto op=SelectObject(dc,p);Polygon(dc,pts,6);SelectObject(dc,ob);SelectObject(dc,op);DeleteObject(b);DeleteObject(p);HPEN wp=CreatePen(PS_SOLID,(std::max)(2,z/12),RGB(255,255,255));op=SelectObject(dc,wp);MoveToEx(dc,x+z/4,y+z/2,nullptr);LineTo(dc,x+z*9/20,y+z*7/10);LineTo(dc,x+z*3/4,y+z/3);SelectObject(dc,op);DeleteObject(wp);}
void DrawButton(HDC dc,const RectI&r,const std::wstring&s,bool primary=false,bool danger=false){COLORREF fill=primary?CLR_BLUE:(danger?(gDarkTheme?C(0x4A2027):C(0xFFF2F3)):CLR_CARD);COLORREF border=primary?CLR_BLUE:(danger?(gDarkTheme?C(0x9A3F4A):C(0xFF8C93)):CLR_BORDER);COLORREF text=primary?RGB(255,255,255):(danger?CLR_RED:CLR_TEXT);RoundFill(dc,r,fill,border,8);Text(dc,s,r.x+8,r.y,r.w-16,r.h,gFonts.bold,text,DT_CENTER|DT_VCENTER|DT_SINGLELINE);}
void DrawQuickActionIcon(HDC dc,HICON icon,const RectI& r){
    if(!icon)return;
    int size=(std::min)(64,(std::min)(r.w-20,64));
    int x=r.x+(r.w-size)/2;
    int y=r.y+12;
    DrawIconEx(dc,x,y,icon,size,size,0,nullptr,DI_NORMAL);
}

int gPage=0;
HWND gMainWnd=nullptr;
RectI gStartStopBtn{},gSidebarRestartBtn{},gSidebarToggleBtn{},gAddPeerBtn{},gExportBtn{},gRestartBtn{},gQuickAdd{},gQuickQr{},gQuickExport{},gQuickBackup{};
RectI gUserExportBtn{},gUserQrBtn{},gGitHubBtn{};
std::vector<RectI> gNavRects;
std::vector<RectI> gDashboardPeerActionRects;
std::vector<RectI> gUserPeerActionRects;

// Inline Add User panel embedded in the dashboard (no floating window).
HWND gAddNameEdit=nullptr,gAddOctetEdit=nullptr,gAddCreateBtn=nullptr;
HWND gAddFullTunnelCheck=nullptr;
HWND gAddSaveQrBtn=nullptr,gAddSaveConfigBtn=nullptr;
HWND gAddPrefixLabel=nullptr;
bool gInlineAddVisible=true;
int gInlineSavedWindowWidth=0;
int gInlineSavedWindowX=0;
RectI gInlineAddClose{};
int gAddPanelPeerIndex=-1;
miniqr::QrCode gAddPanelQr;
HICON gQuickActionIcons[4]{};

void DrawQrInRect(HDC dc,const miniqr::QrCode& qr,const RectI& r);

// Inline Settings controls
constexpr int IDC_SET_BASE=3000;
constexpr int IDC_SET_LANGUAGE=3010;
constexpr int IDC_SET_SAVE=3011;
constexpr int IDC_SET_CLOSE_TO_TRAY=3012;
constexpr int IDC_SET_START_WINDOWS=3013;
constexpr int IDC_SET_AUTO_SERVER=3014;
constexpr int IDC_SET_THEME=3015;
HWND gSetEdits[6]{};
HWND gSetLanguage=nullptr,gSetTheme=nullptr,gSetSave=nullptr;
HWND gSetCloseToTray=nullptr,gSetStartWindows=nullptr,gSetAutoServer=nullptr;
bool gSettingsDirty=false,gSettingsLoading=false;
HWND gDashScroll=nullptr,gUsersScroll=nullptr;
int gDashScrollOffset=0,gUsersScrollOffset=0;
std::vector<size_t> gDashboardPeerRowIndices;
std::vector<size_t> gUserPeerRowIndices;

void UpdateTrayIconTip(){
    if(!gTrayAdded)return;
    const int transition=gServerTransition.load();
    std::wstring tip=transition==SERVER_TRANSITION_STARTING?T(L"EasyWG Server - 啟動中...",L"EasyWG Server - Starting...")
                    :transition==SERVER_TRANSITION_STOPPING?T(L"EasyWG Server - 停止中...",L"EasyWG Server - Stopping...")
                    :gRunning?T(L"EasyWG Server - 執行中",L"EasyWG Server - Running")
                             :T(L"EasyWG Server - 已停止",L"EasyWG Server - Stopped");
    wcsncpy_s(gTrayData.szTip,tip.c_str(),_TRUNCATE);
    gTrayData.uFlags=NIF_TIP;
    Shell_NotifyIconW(NIM_MODIFY,&gTrayData);
}

void AddTrayIcon(HWND hwnd){
    if(gTrayAdded)return;
    ZeroMemory(&gTrayData,sizeof(gTrayData));
    gTrayData.cbSize=sizeof(gTrayData);
    gTrayData.hWnd=hwnd;
    gTrayData.uID=1;
    gTrayData.uFlags=NIF_MESSAGE|NIF_ICON|NIF_TIP;
    gTrayData.uCallbackMessage=WM_APP_TRAY;
    gTrayData.hIcon=gAppIconSmall?gAppIconSmall:gAppIcon;
    std::wstring tip=T(L"EasyWG Server - 已停止",L"EasyWG Server - Stopped");
    wcsncpy_s(gTrayData.szTip,tip.c_str(),_TRUNCATE);
    if(Shell_NotifyIconW(NIM_ADD,&gTrayData)){
        gTrayData.uVersion=NOTIFYICON_VERSION_4;
        Shell_NotifyIconW(NIM_SETVERSION,&gTrayData);
        gTrayAdded=true;
        UpdateTrayIconTip();
    }
}

void RemoveTrayIcon(){
    if(gTrayAdded){
        Shell_NotifyIconW(NIM_DELETE,&gTrayData);
        gTrayAdded=false;
    }
}

void ShowMainWindow(HWND hwnd){
    ShowWindow(hwnd,SW_SHOW);
    if(IsIconic(hwnd))ShowWindow(hwnd,SW_RESTORE);
    SetForegroundWindow(hwnd);
}

void ShowTrayMenu(HWND hwnd){
    HMENU menu=CreatePopupMenu();
    if(!menu)return;
    AppendMenuW(menu,MF_STRING,IDM_TRAY_SHOW,T(L"主頁",L"Open Main Window").c_str());
    AppendMenuW(menu,MF_SEPARATOR,0,nullptr);
    const int transition=gServerTransition.load();
    const std::wstring toggleText=transition==SERVER_TRANSITION_STARTING?T(L"啟動中...",L"Starting...")
                                :transition==SERVER_TRANSITION_STOPPING?T(L"停止中...",L"Stopping...")
                                :gRunning?T(L"停止伺服器",L"Stop Server")
                                         :T(L"啟動伺服器",L"Start Server");
    AppendMenuW(menu,MF_STRING|(transition!=SERVER_TRANSITION_IDLE?MF_GRAYED:0),IDM_TRAY_TOGGLE,toggleText.c_str());
    AppendMenuW(menu,MF_SEPARATOR,0,nullptr);
    AppendMenuW(menu,MF_STRING,IDM_TRAY_EXIT,T(L"退出",L"Exit").c_str());
    POINT pt{};GetCursorPos(&pt);
    SetForegroundWindow(hwnd);
    TrackPopupMenu(menu,TPM_RIGHTBUTTON|TPM_BOTTOMALIGN|TPM_LEFTALIGN,pt.x,pt.y,0,hwnd,nullptr);
    DestroyMenu(menu);
    PostMessageW(hwnd,WM_NULL,0,0);
}

std::wstring RuntimeText(){if(!gRunning)return L"—";auto sec=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now()-gStartedAt).count();int d=(int)(sec/86400),h=(int)((sec%86400)/3600),m=(int)((sec%3600)/60),ss=(int)(sec%60);wchar_t b[64];if(gEnglish.load())swprintf_s(b,L"%d d %02d:%02d:%02d",d,h,m,ss);else swprintf_s(b,L"%d 天 %02d:%02d:%02d",d,h,m,ss);return b;}

void CreateSettingsControls(HWND hwnd){
    for(int i=0;i<6;++i){
        gSetEdits[i]=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"",WS_CHILD|ES_AUTOHSCROLL,
                                     0,0,100,28,hwnd,(HMENU)(INT_PTR)(IDC_SET_BASE+i),nullptr,nullptr);
        SendMessageW(gSetEdits[i],WM_SETFONT,(WPARAM)gFonts.normal,TRUE);
    }
    gSetLanguage=CreateWindowW(L"COMBOBOX",L"",WS_CHILD|CBS_DROPDOWNLIST|WS_VSCROLL,
                               0,0,180,200,hwnd,(HMENU)(INT_PTR)IDC_SET_LANGUAGE,nullptr,nullptr);
    SendMessageW(gSetLanguage,WM_SETFONT,(WPARAM)gFonts.normal,TRUE);
    SendMessageW(gSetLanguage,CB_ADDSTRING,0,(LPARAM)L"繁體中文");
    SendMessageW(gSetLanguage,CB_ADDSTRING,0,(LPARAM)L"English");

    gSetTheme=CreateWindowW(L"COMBOBOX",L"",WS_CHILD|CBS_DROPDOWNLIST|WS_VSCROLL,
                            0,0,220,200,hwnd,(HMENU)(INT_PTR)IDC_SET_THEME,nullptr,nullptr);
    SendMessageW(gSetTheme,WM_SETFONT,(WPARAM)gFonts.normal,TRUE);
    SendMessageW(gSetTheme,CB_ADDSTRING,0,(LPARAM)L"跟隨系統");
    SendMessageW(gSetTheme,CB_ADDSTRING,0,(LPARAM)L"日光");
    SendMessageW(gSetTheme,CB_ADDSTRING,0,(LPARAM)L"黑暗");

    gSetCloseToTray=CreateWindowW(L"BUTTON",L"",WS_CHILD|BS_AUTOCHECKBOX,
                                  0,0,340,28,hwnd,(HMENU)(INT_PTR)IDC_SET_CLOSE_TO_TRAY,nullptr,nullptr);
    gSetStartWindows=CreateWindowW(L"BUTTON",L"",WS_CHILD|BS_AUTOCHECKBOX,
                                   0,0,340,28,hwnd,(HMENU)(INT_PTR)IDC_SET_START_WINDOWS,nullptr,nullptr);
    gSetAutoServer=CreateWindowW(L"BUTTON",L"",WS_CHILD|BS_AUTOCHECKBOX,
                                 0,0,340,28,hwnd,(HMENU)(INT_PTR)IDC_SET_AUTO_SERVER,nullptr,nullptr);
    SendMessageW(gSetCloseToTray,WM_SETFONT,(WPARAM)gFonts.normal,TRUE);
    SendMessageW(gSetStartWindows,WM_SETFONT,(WPARAM)gFonts.normal,TRUE);
    SendMessageW(gSetAutoServer,WM_SETFONT,(WPARAM)gFonts.normal,TRUE);

    gSetSave=CreateWindowW(L"BUTTON",L"",WS_CHILD|BS_DEFPUSHBUTTON,
                           0,0,140,38,hwnd,(HMENU)(INT_PTR)IDC_SET_SAVE,nullptr,nullptr);
    SendMessageW(gSetSave,WM_SETFONT,(WPARAM)gFonts.bold,TRUE);
}

void ShowSettingsControls(bool show){
    int cmd=show?SW_SHOW:SW_HIDE;
    for(auto h:gSetEdits)if(h)ShowWindow(h,cmd);
    if(gSetLanguage)ShowWindow(gSetLanguage,cmd);
    if(gSetTheme)ShowWindow(gSetTheme,cmd);
    if(gSetCloseToTray)ShowWindow(gSetCloseToTray,cmd);
    if(gSetStartWindows)ShowWindow(gSetStartWindows,cmd);
    if(gSetAutoServer)ShowWindow(gSetAutoServer,cmd);
    if(gSetSave)ShowWindow(gSetSave,cmd);
}

void LayoutSettingsControls(HWND hwnd){
    if(gPage!=2)return;
    RECT rc{};GetClientRect(hwnd,&rc);
    int x=250,y=22;
    int cardW=rc.right-x-20;
    int baseY=y+80;
    const int step=42;
    int editX=x+250;
    int editW=(std::min)(520,cardW-300);
    for(int i=0;i<6;++i)MoveWindow(gSetEdits[i],editX,baseY+i*step,editW,30,TRUE);
    MoveWindow(gSetLanguage,editX,baseY+6*step,220,180,TRUE);
    MoveWindow(gSetTheme,editX,baseY+7*step,220,180,TRUE);
    MoveWindow(gSetCloseToTray,editX,baseY+9*step,460,28,TRUE);
    MoveWindow(gSetStartWindows,editX,baseY+10*step,460,28,TRUE);
    MoveWindow(gSetAutoServer,editX,baseY+11*step,500,28,TRUE);
    int saveY=(std::max)(baseY+11*step+34,static_cast<int>(rc.bottom)-110);
    MoveWindow(gSetSave,x+40,saveY,160,40,TRUE);
}

std::wstring ReadCtl(HWND h){
    int n=GetWindowTextLengthW(h);
    std::wstring v((size_t)n+1,L'\0');
    if(n)GetWindowTextW(h,v.data(),n+1);
    v.resize((size_t)n);
    return Trim(v);
}
void SetCtl(HWND h,const std::wstring&v){SetWindowTextW(h,v.c_str());}

void UpdateSettingsControlLanguage(){
    if(gSetSave)SetWindowTextW(gSetSave,T(L"儲存設定",L"Save Settings").c_str());
    if(gSetCloseToTray)SetWindowTextW(gSetCloseToTray,T(L"按 X 關閉時不退出，保留在系統列",L"Close button hides to system tray").c_str());
    if(gSetStartWindows)SetWindowTextW(gSetStartWindows,T(L"Windows 登入後以管理員權限自動執行 EasyWG",L"Run EasyWG as administrator when Windows starts").c_str());
    if(gSetAutoServer)SetWindowTextW(gSetAutoServer,T(L"EasyWG 啟動後自動啟動伺服器（管理員啟動）",L"Automatically start server after EasyWG launches (administrator)").c_str());
    if(gSetTheme){
        int sel=(int)SendMessageW(gSetTheme,CB_GETCURSEL,0,0);if(sel<0)sel=0;
        SendMessageW(gSetTheme,CB_RESETCONTENT,0,0);
        SendMessageW(gSetTheme,CB_ADDSTRING,0,(LPARAM)T(L"跟隨系統",L"Follow system").c_str());
        SendMessageW(gSetTheme,CB_ADDSTRING,0,(LPARAM)T(L"日光",L"Light").c_str());
        SendMessageW(gSetTheme,CB_ADDSTRING,0,(LPARAM)T(L"黑暗",L"Dark").c_str());
        SendMessageW(gSetTheme,CB_SETCURSEL,sel,0);
    }
}

void LoadSettingsControls(){
    ServerSettings st;{std::lock_guard<std::mutex>lk(gDataMutex);st=gSettings;}
    gSettingsLoading=true;
    std::wstring vals[]={st.address,std::to_wstring(st.port),st.endpoint,st.clientAllowedIPs,st.dns,st.lanSubnet};
    for(int i=0;i<6;++i)SetCtl(gSetEdits[i],vals[i]);
    SendMessageW(gSetLanguage,CB_SETCURSEL,st.language==L"en"?1:0,0);
    int themeSel=st.theme==L"dark"?2:(st.theme==L"light"?1:0);
    SendMessageW(gSetTheme,CB_SETCURSEL,themeSel,0);
    SendMessageW(gSetCloseToTray,BM_SETCHECK,st.closeToTray?BST_CHECKED:BST_UNCHECKED,0);
    SendMessageW(gSetStartWindows,BM_SETCHECK,st.startWithWindows?BST_CHECKED:BST_UNCHECKED,0);
    SendMessageW(gSetAutoServer,BM_SETCHECK,st.autoStartServer?BST_CHECKED:BST_UNCHECKED,0);
    UpdateSettingsControlLanguage();
    gSettingsLoading=false;
    gSettingsDirty=false;
}

bool SaveSettingsInline(HWND hwnd){
    std::wstring address=ReadCtl(gSetEdits[0]);
    int port=_wtoi(ReadCtl(gSetEdits[1]).c_str());
    std::wstring endpoint=ReadCtl(gSetEdits[2]);
    std::wstring allowed=ReadCtl(gSetEdits[3]);
    std::wstring dns=ReadCtl(gSetEdits[4]);
    std::wstring lan=ReadCtl(gSetEdits[5]);
    IN_ADDR a{},la{};int lp=0;
    if(InetPtonW(AF_INET,address.c_str(),&a)!=1||port<1||port>65535||!ParseIpv4Cidr(lan,la,lp)){
        MessageBoxW(hwnd,T(L"VPN Server IP、Port 或 LAN 網段格式錯誤。",
                           L"Invalid VPN Server IP, port, or LAN subnet.").c_str(),
                    kAppName,MB_ICONWARNING);
        return false;
    }
    int li=(int)SendMessageW(gSetLanguage,CB_GETCURSEL,0,0);
    std::wstring lang=li==1?L"en":L"zh-TW";
    int ti=(int)SendMessageW(gSetTheme,CB_GETCURSEL,0,0);
    std::wstring theme=ti==2?L"dark":(ti==1?L"light":L"system");
    bool closeToTray=SendMessageW(gSetCloseToTray,BM_GETCHECK,0,0)==BST_CHECKED;
    bool startWindows=SendMessageW(gSetStartWindows,BM_GETCHECK,0,0)==BST_CHECKED;
    bool autoServer=SendMessageW(gSetAutoServer,BM_GETCHECK,0,0)==BST_CHECKED;

    std::wstring startupErr;
    if(!ApplyStartupRegistration(startWindows,startupErr)){
        MessageBoxW(hwnd,(T(L"更新開機自動執行設定失敗：",L"Failed to update Windows startup setting: ")+startupErr).c_str(),
                    kAppName,MB_ICONERROR);
        return false;
    }

    bool wasRunning=gRunning;
    {
        std::lock_guard<std::mutex>lk(gDataMutex);
        gSettings.address=address;
        gSettings.prefix=24;
        gSettings.port=port;
        gSettings.endpoint=endpoint;
        gSettings.clientAllowedIPs=allowed.empty()?Ipv4NetworkCidr(address,24):allowed;
        gSettings.dns=dns;
        gSettings.lanAccessMode=L"nat";
        gSettings.lanSubnet=lan;
        gSettings.language=lang;
        gSettings.theme=theme;
        gSettings.closeToTray=closeToTray;
        gSettings.startWithWindows=startWindows;
        gSettings.autoStartServer=autoServer;
    }
    gEnglish=(lang==L"en");
    ApplyThemePalette();
    ApplyWindowDarkMode(hwnd);
    SaveConfig();
    gSettingsDirty=false;
    UpdateSettingsControlLanguage();
    AddLog(T(L"Server 設定已更新",L"Server settings updated"));
    if(wasRunning){
        StopServer();
        std::wstring e;
        if(!StartServer(e))MessageBoxW(hwnd,e.c_str(),kAppName,MB_ICONERROR);
    }
    RedrawWindow(hwnd,nullptr,nullptr,RDW_INVALIDATE|RDW_ERASE|RDW_ALLCHILDREN);
    return true;
}

bool ConfirmLeaveDirtySettings(HWND hwnd){
    if(gPage!=2||!gSettingsDirty)return true;
    int r=MessageBoxW(hwnd,T(L"設定尚未儲存，確定要離開嗎？",
                              L"Settings have not been saved. Leave anyway?").c_str(),
                      kAppName,MB_YESNO|MB_ICONWARNING);
    if(r==IDYES){gSettingsDirty=false;return true;}
    return false;
}

void DrawSidebar(HDC dc,int h){
    FillRectC(dc,{0,0,230,h},CLR_SIDEBAR);
    DrawShield(dc,28,28,42);
    Text(dc,L"EasyWG",82,24,125,34,gFonts.title,CLR_BLUE);
    Text(dc,L"Server",82,57,100,22,gFonts.normal,CLR_MUTED);

    std::wstring items[]={
        T(L"⌂   儀表板",L"⌂   Dashboard"),
        T(L"♙   用戶管理",L"♙   Users"),
        T(L"⚙   設定",L"⚙   Settings"),
        T(L"⊕   路由與網路",L"⊕   Routing & Network"),
        T(L"▤   日誌",L"▤   Logs"),
        T(L"ⓘ   關於",L"ⓘ   About")
    };
    gNavRects.clear();
    for(int i=0;i<6;++i){
        RectI r{16,120+i*55,198,44};
        gNavRects.push_back(r);
        if(gPage==i)RoundFill(dc,r,CLR_BLUE_LIGHT,CLR_BLUE_LIGHT,8);
        Text(dc,items[i],r.x+16,r.y,r.w-22,r.h,gFonts.nav,gPage==i?CLR_BLUE:CLR_TEXT);
    }

    RectI st{20,h-230,190,158};
    RoundFill(dc,st,CLR_CARD,CLR_BORDER,10);
    const int transition=gServerTransition.load();
    const bool starting=transition==SERVER_TRANSITION_STARTING;
    const bool stopping=transition==SERVER_TRANSITION_STOPPING;
    const COLORREF stateColor=(starting||stopping)?CLR_BLUE:(gRunning?CLR_GREEN:CLR_MUTED);
    Dot(dc,38,h-204,6,(starting||stopping)?CLR_BLUE:(gRunning?CLR_GREEN:C(0x98A2B3)));
    Text(dc,starting?T(L"服務狀態：啟動中...",L"Service: Starting...")
                    :stopping?T(L"服務狀態：停止中...",L"Service: Stopping...")
                    :gRunning?T(L"服務狀態：執行中",L"Service: Running")
                             :T(L"服務狀態：已停止",L"Service: Stopped"),
         52,h-220,145,30,gFonts.bold,stateColor);
    Text(dc,starting?T(L"正在建立 VPN 與 NAT",L"Preparing VPN and NAT")
                    :stopping?T(L"正在停止服務",L"Stopping services")
                    :gRunning?T(L"已執行 ",L"Uptime ")+RuntimeText()
                             :T(L"尚未啟動",L"Not started"),
         30,h-188,160,25,gFonts.smallFont,CLR_MUTED);
    gSidebarRestartBtn={30,h-151,150,34};
    DrawButton(dc,gSidebarRestartBtn,T(L"重新啟動服務",L"Restart Service"));
    gSidebarToggleBtn={30,h-108,150,34};
    DrawButton(dc,gSidebarToggleBtn,starting?T(L"啟動中...",L"Starting...")
                                           :stopping?T(L"停止中...",L"Stopping...")
                                           :gRunning?T(L"停止服務",L"Stop Service")
                                                    :T(L"啟動服務",L"Start Service"),false,gRunning&&!stopping);

    Line(dc,18,h-58,212,h-58,CLR_BORDER);
    Text(dc,L"EasyWG Server © 2026",22,h-55,186,24,gFonts.smallFont,CLR_MUTED);
    Text(dc,T(L"版本：",L"Version: ")+std::wstring(EASYWG_VERSION_DISPLAY_W),22,h-33,186,22,gFonts.smallFont,CLR_MUTED);
}
void DrawCardTitle(HDC dc,const RectI&r,const std::wstring&s){
    Text(dc,s,r.x+20,r.y+8,r.w-40,38,gFonts.h2,CLR_TEXT);
    Line(dc,r.x,r.y+48,r.x+r.w,r.y+48,CLR_BORDER);
}

void UpdatePeerScrollbars(int dashboardVisible,int userVisible){
    size_t count=0;{std::lock_guard<std::mutex>lk(gDataMutex);count=gPeers.size();}
    if(gDashScroll){
        bool show=gPage==0&&(int)count>dashboardVisible;ShowWindow(gDashScroll,show?SW_SHOW:SW_HIDE);
        if(show){SCROLLINFO si{sizeof(SCROLLINFO),SIF_RANGE|SIF_PAGE|SIF_POS,0,(int)count-1,(UINT)dashboardVisible,gDashScrollOffset,0};SetScrollInfo(gDashScroll,SB_CTL,&si,TRUE);}
    }
    if(gUsersScroll){
        bool show=gPage==1&&(int)count>userVisible;ShowWindow(gUsersScroll,show?SW_SHOW:SW_HIDE);
        if(show){SCROLLINFO si{sizeof(SCROLLINFO),SIF_RANGE|SIF_PAGE|SIF_POS,0,(int)count-1,(UINT)userVisible,gUsersScrollOffset,0};SetScrollInfo(gUsersScroll,SB_CTL,&si,TRUE);}
    }
}

void DrawDashboard(HDC dc,int w,int h){
    const int panelReserve=390; // dashboard always keeps the Add User panel visible
    int contentW=w-panelReserve;
    int x=238,top=22,gap=12,right=12;
    int cw=(contentW-x-right-gap)/3;
    int large=cw*2+gap;
    RectI status{x,top,large,265},traffic{x+large+gap,top,cw,265};

    RoundFill(dc,status,CLR_CARD);
    DrawCardTitle(dc,status,T(L"伺服器狀態",L"Server Status"));
    const int transition=gServerTransition.load();
    const bool starting=transition==SERVER_TRANSITION_STARTING;
    const bool stopping=transition==SERVER_TRANSITION_STOPPING;
    DrawShield(dc,status.x+30,status.y+78,62,(starting||stopping)?CLR_BLUE:(gRunning?CLR_GREEN:CLR_BLUE));
    int detailX=(std::max)(270,(int)(status.w*0.54));
    Text(dc,starting?T(L"啟動中...",L"Starting...")
                    :stopping?T(L"停止中...",L"Stopping...")
                    :gRunning?T(L"運行中",L"Running")
                             :T(L"已停止",L"Stopped"),
         status.x+112,status.y+76,(std::max)(120,detailX-126),38,gFonts.big,
         (starting||stopping)?CLR_BLUE:(gRunning?CLR_GREEN:CLR_MUTED),DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
    Text(dc,starting?T(L"正在建立 WireGuard 與 NAT",L"Preparing WireGuard and NAT")
                    :stopping?T(L"正在停止隧道與 NAT",L"Stopping tunnel and NAT")
                    :gRunning?T(L"WireGuard 隧道已啟動",L"WireGuard tunnel active")
                             :T(L"WireGuard 隧道未啟動",L"WireGuard tunnel inactive"),
         status.x+112,status.y+113,(std::max)(120,detailX-126),28,gFonts.normal,CLR_MUTED,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
    gStartStopBtn={status.x+30,status.y+168,105,38};
    DrawButton(dc,gStartStopBtn,starting?T(L"啟動中...",L"Starting...")
                                           :stopping?T(L"停止中...",L"Stopping...")
                                           :gRunning?T(L"停止服務",L"Stop")
                                                    :T(L"啟動服務",L"Start"),!gRunning&&!starting,gRunning&&!stopping);

    Line(dc,status.x+detailX-16,status.y+76,status.x+detailX-16,status.y+205,CLR_BORDER);
    ServerSettings ss;{std::lock_guard<std::mutex>lk(gDataMutex);ss=gSettings;}
    std::wstring labs[]={L"VPN IP",T(L"監聽端口",L"Listen Port"),
                         T(L"公網 IP / DDNS",L"Public IP / DDNS"),T(L"運行時間",L"Uptime")};
    std::wstring vals[]={ss.address+L"/24",std::to_wstring(ss.port)+L" (UDP)",
                         ss.endpoint.empty()?T(L"尚未設定",L"Not set"):ss.endpoint,RuntimeText()};
    for(int i=0;i<4;++i){
        Text(dc,labs[i],status.x+detailX,status.y+68+i*42,96,28,gFonts.smallFont,CLR_MUTED,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
        Text(dc,vals[i],status.x+detailX+96,status.y+68+i*42,(std::max)(45,status.w-detailX-108),28,gFonts.normal,CLR_TEXT,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
    }

    RoundFill(dc,traffic,CLR_CARD);
    DrawCardTitle(dc,traffic,T(L"流量統計",L"Traffic"));
    uint64_t rx=0,tx=0;int active=0,total=0;
    {std::lock_guard<std::mutex>lk(gDataMutex);total=(int)gPeers.size();for(auto&p:gPeers){rx+=p.rx;tx+=p.tx;if(IsPeerActive(p.lastHandshake))active++;}}
    int th=(std::max)(70,(traffic.w-40)/2);
    int tx2=traffic.x+20+th;
    Text(dc,T(L"接收",L"Received"),traffic.x+20,traffic.y+70,th-8,25,gFonts.smallFont,CLR_MUTED,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
    Text(dc,FormatBytes(rx),traffic.x+20,traffic.y+99,th-8,34,gFonts.h2,CLR_GREEN,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
    Text(dc,T(L"發送",L"Sent"),tx2,traffic.y+70,th-8,25,gFonts.smallFont,CLR_MUTED,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
    Text(dc,FormatBytes(tx),tx2,traffic.y+99,th-8,34,gFonts.h2,CLR_BLUE,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
    Line(dc,traffic.x+20,traffic.y+155,traffic.x+traffic.w-20,traffic.y+155,CLR_BORDER);
    Text(dc,T(L"總連線數",L"Total users"),traffic.x+20,traffic.y+173,th-8,24,gFonts.smallFont,CLR_MUTED,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
    Text(dc,std::to_wstring(total),traffic.x+20,traffic.y+200,th-8,30,gFonts.h2,CLR_TEXT);
    Text(dc,T(L"活躍連線",L"Active"),tx2,traffic.y+173,th-8,24,gFonts.smallFont,CLR_MUTED,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
    Text(dc,std::to_wstring(active),tx2,traffic.y+200,th-8,30,gFonts.h2,CLR_TEXT);

    RectI users{x,top+281,contentW-x-right,326};
    RoundFill(dc,users,CLR_CARD);
    DrawCardTitle(dc,users,T(L"用戶連線狀態",L"User Connection Status"));
    gAddPeerBtn={};
    gExportBtn={users.x+users.w-265,users.y+8,105,34};
    gRestartBtn={users.x+users.w-150,users.y+8,125,34};
    DrawButton(dc,gExportBtn,T(L"匯出設定",L"Export Config"));
    DrawButton(dc,gRestartBtn,T(L"↻ 重新整理",L"Refresh"));

    int ty=users.y+58;
    std::vector<int> cols={20,(int)(users.w*0.14),(int)(users.w*0.27),(int)(users.w*0.46),
                           (int)(users.w*0.58),(int)(users.w*0.70),(int)(users.w*0.80),users.w-72};
    std::wstring heads[]={T(L"名稱",L"Name"),L"VPN IP",T(L"公鑰",L"Public Key"),
                           T(L"狀態",L"Status"),T(L"最後連線",L"Last Seen"),
                           T(L"接收",L"RX"),T(L"發送",L"TX"),T(L"操作",L"Action")};
    for(int i=0;i<8;++i){
        int hw=(i<7?(std::max)(28,cols[i+1]-cols[i]-6):64);
        Text(dc,heads[i],users.x+cols[i],ty,hw,30,gFonts.smallFont,CLR_MUTED,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
    }
    Line(dc,users.x+15,ty+32,users.x+users.w-15,ty+32,CLR_BORDER);

    std::vector<PeerInfo> peers;{std::lock_guard<std::mutex>lk(gDataMutex);peers=gPeers;}
    UpdatePeerScrollbars(5,16);
    gDashboardPeerActionRects.clear();
    gDashboardPeerRowIndices.clear();
    const int visibleRows=5;
    int maxOffset=(std::max)(0,(int)peers.size()-visibleRows);
    gDashScrollOffset=std::clamp(gDashScrollOffset,0,maxOffset);
    int maxRows=(std::min)(visibleRows,(int)peers.size()-gDashScrollOffset);
    for(int i=0;i<maxRows;++i){
        size_t peerIndex=(size_t)(gDashScrollOffset+i);
        int yy=ty+40+i*45;auto&p=peers[peerIndex];
        Text(dc,p.name,users.x+cols[0],yy,(std::max)(28,cols[1]-cols[0]-6),34,gFonts.normal,CLR_TEXT,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
        Text(dc,p.ip,users.x+cols[1],yy,(std::max)(28,cols[2]-cols[1]-6),34,gFonts.normal,CLR_TEXT,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
        std::wstring pk=Base64Encode(p.publicKey.data(),32);
        if(pk.size()>12)pk=pk.substr(0,8)+L"…"+pk.substr(pk.size()-4);
        Text(dc,pk,users.x+cols[2],yy,(std::max)(28,cols[3]-cols[2]-6),34,gFonts.smallFont,CLR_TEXT,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
        bool on=IsPeerActive(p.lastHandshake);
        RectI pill{users.x+cols[3],yy+5,(std::max)(46,(std::min)(78,cols[4]-cols[3]-8)),24};
        COLORREF pillBg=on?CLR_GREEN_LIGHT:(gDarkTheme?CLR_SUBTLE:C(0xF2F4F7));
        RoundFill(dc,pill,pillBg,pillBg,12);
        Dot(dc,pill.x+14,pill.y+12,4,on?CLR_GREEN:C(0x98A2B3));
        Text(dc,on?T(L"已連線",L"Online"):T(L"離線",L"Offline"),
             pill.x+24,pill.y,pill.w-28,pill.h,gFonts.smallFont,on?CLR_GREEN:CLR_MUTED);
        Text(dc,HandshakeAge(p.lastHandshake),users.x+cols[4],yy,(std::max)(28,cols[5]-cols[4]-6),34,gFonts.smallFont,CLR_TEXT,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
        Text(dc,FormatBytes(p.rx),users.x+cols[5],yy,(std::max)(28,cols[6]-cols[5]-6),34,gFonts.smallFont,CLR_TEXT,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
        Text(dc,FormatBytes(p.tx),users.x+cols[6],yy,(std::max)(28,cols[7]-cols[6]-6),34,gFonts.smallFont,CLR_TEXT,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
        RectI act{users.x+cols[7],yy+1,52,32};
        gDashboardPeerActionRects.push_back(act);
        gDashboardPeerRowIndices.push_back(peerIndex);
        DrawButton(dc,act,L"⋮");
        Line(dc,users.x+15,yy+39,users.x+users.w-15,yy+39,CLR_BORDER);
    }
    if(peers.empty())Text(dc,T(L"尚未建立用戶，按「新增用戶」開始。",L"No users yet. Click Add User to begin."),
                           users.x+20,ty+70,users.w-40,60,gFonts.normal,CLR_MUTED,
                           DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    int bottom=top+623;
    int bh=h-bottom-72;if(bh<210)bh=210;
    RectI quick{x,bottom,contentW-x-right,bh};
    RoundFill(dc,quick,CLR_CARD);
    DrawCardTitle(dc,quick,T(L"快速操作",L"Quick Actions"));
    int bx=quick.x+22,by=quick.y+66;
    int usable=quick.w-44,cardGap=16,bw=(usable-cardGap*3)/4;
    gQuickAdd={bx,by,bw,132};gQuickQr={bx+(bw+cardGap),by,bw,132};
    gQuickExport={bx+2*(bw+cardGap),by,bw,132};gQuickBackup={bx+3*(bw+cardGap),by,bw,132};
    RectI acts[]={gQuickAdd,gQuickQr,gQuickExport,gQuickBackup};
    std::wstring titles[]={T(L"新增用戶",L"Add User"),L"QR Code",T(L"匯出設定檔",L"Export Config"),T(L"備份設定",L"Backup")};
    std::wstring descs[]={T(L"快速建立 VPN 用戶",L"Quickly create a VPN user"),T(L"產生手機掃描碼",L"Create mobile scan code"),T(L"匯出用戶設定",L"Export user config"),T(L"備份所有設定",L"Backup all settings")};
    for(int i=0;i<4;++i){
        RoundFill(dc,acts[i],gDarkTheme?CLR_SUBTLE:C(0xFBFDFF),gDarkTheme?CLR_BORDER:C(0xD9E6F8),10);
        DrawQuickActionIcon(dc,gQuickActionIcons[i],acts[i]);
        Text(dc,titles[i],acts[i].x+6,acts[i].y+70,acts[i].w-12,26,gFonts.bold,CLR_TEXT,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        Text(dc,descs[i],acts[i].x+8,acts[i].y+98,acts[i].w-16,30,gFonts.smallFont,CLR_MUTED,DT_CENTER|DT_WORDBREAK|DT_END_ELLIPSIS);
    }

    {
        RectI panel{contentW+12,22,w-contentW-28,h-86};
        RoundFill(dc,panel,CLR_CARD,CLR_BORDER,12);
        Text(dc,T(L"新增用戶",L"Add User"),panel.x+20,panel.y+8,panel.w-40,40,gFonts.h2,CLR_TEXT);
        gInlineAddClose={};
        Line(dc,panel.x,panel.y+50,panel.x+panel.w,panel.y+50,CLR_BORDER);

        Text(dc,T(L"用戶名稱",L"User Name"),panel.x+20,panel.y+66,panel.w-40,24,gFonts.bold,CLR_TEXT);
        Text(dc,T(L"VPN IP 最後一碼",L"VPN IP last octet"),panel.x+20,panel.y+136,145,36,gFonts.bold,CLR_TEXT,DT_LEFT|DT_VCENTER|DT_SINGLELINE);

        // Leave room for the per-user public-IP/full-tunnel option.
        RectI info{panel.x+16,panel.y+316,panel.w-32,102};
        RoundFill(dc,info,CLR_GREEN_LIGHT,C(0xBFEBD0),10);
        Dot(dc,info.x+24,info.y+26,11,CLR_GREEN);
        HPEN cp=CreatePen(PS_SOLID,2,RGB(255,255,255));
        HGDIOBJ cop=SelectObject(dc,cp);
        MoveToEx(dc,info.x+18,info.y+26,nullptr);LineTo(dc,info.x+23,info.y+31);LineTo(dc,info.x+31,info.y+20);
        SelectObject(dc,cop);DeleteObject(cp);

        PeerInfo panelPeer;bool panelPeerOk=false;
        {std::lock_guard<std::mutex>lk(gDataMutex);if(gAddPanelPeerIndex>=0&&(size_t)gAddPanelPeerIndex<gPeers.size()){panelPeer=gPeers[(size_t)gAddPanelPeerIndex];panelPeerOk=true;}}
        if(panelPeerOk&&gAddPanelQr.size>0){
            Text(dc,T(L"新用戶已建立：",L"User created: ")+panelPeer.name,info.x+48,info.y+10,info.w-62,26,gFonts.bold,CLR_GREEN,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
            Text(dc,panelPeer.ip,info.x+48,info.y+36,info.w-62,22,gFonts.smallFont,CLR_GREEN);
            Text(dc,T(L"金鑰與設定檔已自動產生，可直接掃描或儲存。",L"Keys and config are ready to scan or save."),info.x+18,info.y+62,info.w-36,30,gFonts.smallFont,CLR_TEXT,DT_LEFT|DT_WORDBREAK|DT_END_ELLIPSIS);
        }else{
            Text(dc,T(L"將會自動產生：",L"Will generate automatically:"),info.x+48,info.y+10,info.w-62,26,gFonts.bold,CLR_TEXT);
            Text(dc,T(L"✓ 私鑰 (Private Key)    ✓ 公鑰 (Public Key)",L"✓ Private Key    ✓ Public Key"),info.x+22,info.y+40,info.w-44,22,gFonts.smallFont,CLR_GREEN,DT_LEFT|DT_SINGLELINE|DT_END_ELLIPSIS);
            Text(dc,T(L"✓ 預共享金鑰 (Preshared Key)",L"✓ Preshared Key"),info.x+22,info.y+64,info.w-44,22,gFonts.smallFont,CLR_GREEN,DT_LEFT|DT_SINGLELINE|DT_END_ELLIPSIS);
        }

        const int saveButtonsY=panel.y+panel.h-50;
        RectI hint{panel.x+20,saveButtonsY-62,panel.w-40,48};
        const int qrTop=panel.y+434;
        const int qrBottom=hint.y-12;
        RectI qrBox{panel.x+20,qrTop,panel.w-40,(std::max)(180,qrBottom-qrTop)};
        RoundFill(dc,qrBox,RGB(255,255,255),C(0xD7E0EC),10);
        if(panelPeerOk&&gAddPanelQr.size>0){
            int qrSize=(std::min)(qrBox.w-30,qrBox.h-30);
            DrawQrInRect(dc,gAddPanelQr,{qrBox.x+(qrBox.w-qrSize)/2,qrBox.y+(qrBox.h-qrSize)/2,qrSize,qrSize});
        }else{
            DrawShield(dc,qrBox.x+qrBox.w/2-28,qrBox.y+qrBox.h/2-70,56,C(0xB8C7DC));
            Text(dc,T(L"尚未新增用戶",L"No user created yet"),qrBox.x+20,qrBox.y+qrBox.h/2-2,qrBox.w-40,30,gFonts.bold,CLR_MUTED,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
            Text(dc,T(L"新增後將在此顯示 QR Code",L"The QR Code will appear here after creation"),qrBox.x+20,qrBox.y+qrBox.h/2+30,qrBox.w-40,45,gFonts.smallFont,CLR_MUTED,DT_CENTER|DT_WORDBREAK);
        }

        RoundFill(dc,hint,CLR_BLUE_LIGHT,C(0xCFE0FF),9);
        Dot(dc,hint.x+22,hint.y+24,10,CLR_BLUE);
        Text(dc,L"i",hint.x+16,hint.y+9,12,30,gFonts.bold,RGB(255,255,255),DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        Text(dc,T(L"使用 WireGuard App 掃描此 QR Code 即可加入",L"Scan this QR Code with the WireGuard app to add"),hint.x+42,hint.y+3,hint.w-52,hint.h-6,gFonts.smallFont,CLR_BLUE,DT_LEFT|DT_VCENTER|DT_WORDBREAK|DT_END_ELLIPSIS);
    }
}

void DrawBottomStatusBar(HDC dc,int w,int h){
    RectI bar{230,h-42,w-230,42};
    FillRectC(dc,bar,CLR_CARD);
    Line(dc,bar.x,bar.y,bar.x+bar.w,bar.y,CLR_BORDER);
    int warn=0,err=0;
    if(!CoreRuntimeReady())warn++;
    if(!WinDivertRuntimeReady())warn++;
    if(gRunning&&!gAdapter&&!gLegacyWin7Mode)err++;
    const int transition=gServerTransition.load();
    const bool starting=transition==SERVER_TRANSITION_STARTING;
    const bool stopping=transition==SERVER_TRANSITION_STOPPING;
    Dot(dc,bar.x+24,bar.y+21,6,(starting||stopping)?CLR_BLUE:(gRunning?CLR_GREEN:C(0x98A2B3)));
    Text(dc,starting?T(L"服務啟動中...",L"Service starting...")
                    :stopping?T(L"服務停止中...",L"Service stopping...")
                    :gRunning?T(L"服務運行中",L"Service running")
                             :T(L"服務已停止",L"Service stopped"),
         bar.x+38,bar.y,150,bar.h,gFonts.smallFont,(starting||stopping)?CLR_BLUE:(gRunning?CLR_GREEN:CLR_MUTED));
    Text(dc,L"|",bar.x+188,bar.y,20,bar.h,gFonts.smallFont,CLR_BORDER,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    Text(dc,std::to_wstring(err)+T(L" 個錯誤",L" errors"),bar.x+215,bar.y,110,bar.h,gFonts.smallFont,err?CLR_RED:CLR_MUTED);
    Text(dc,L"|",bar.x+330,bar.y,20,bar.h,gFonts.smallFont,CLR_BORDER,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    Text(dc,std::to_wstring(warn)+T(L" 個警告",L" warnings"),bar.x+357,bar.y,130,bar.h,gFonts.smallFont,warn?C(0xD97706):CLR_MUTED);
}

void DrawSimplePage(HDC dc,int w,int h,int page){
    if(gDashScroll)ShowWindow(gDashScroll,SW_HIDE);
    if(page!=1&&gUsersScroll)ShowWindow(gUsersScroll,SW_HIDE);
    int x=250;
    RectI card{x,22,w-x-20,h-82};
    RoundFill(dc,card,CLR_CARD);
    std::wstring titles[]={
        L"",T(L"用戶管理",L"Users"),T(L"設定",L"Settings"),
        T(L"路由與網路",L"Routing & Network"),T(L"日誌",L"Logs"),T(L"關於",L"About")
    };
    DrawCardTitle(dc,card,titles[page]);

    if(page==1){
        gAddPeerBtn={card.x+card.w-385,card.y+8,120,34};
        gUserExportBtn={card.x+card.w-255,card.y+8,105,34};
        gUserQrBtn={card.x+card.w-140,card.y+8,115,34};
        DrawButton(dc,gAddPeerBtn,T(L"＋ 新增用戶",L"+ Add User"),true);
        DrawButton(dc,gUserExportBtn,T(L"匯出設定",L"Export"));
        DrawButton(dc,gUserQrBtn,L"QR Code");

        std::vector<PeerInfo> peers;{std::lock_guard<std::mutex>lk(gDataMutex);peers=gPeers;}
        const int tableY=card.y+102;
        int visibleRowsForScroll=(std::min)(16,(std::max)(1,(card.y+card.h-20-tableY)/48));
        UpdatePeerScrollbars(5,visibleRowsForScroll);
        gUserPeerActionRects.clear();
        gUserPeerRowIndices.clear();
        int y=tableY;
        int cx[]={35,235,390,520,650,850};
        std::wstring heads[]={T(L"名稱",L"Name"),L"VPN IP",T(L"狀態",L"Status"),
                               T(L"最後連線",L"Last Seen"),T(L"流量 RX / TX",L"Traffic RX / TX"),
                               T(L"管理",L"Manage")};
        COLORREF headColor=gDarkTheme?C(0xCAD7EA):C(0x344054);
        for(int i=0;i<6;++i)Text(dc,heads[i],card.x+cx[i],y-32,170,26,gFonts.bold,headColor);
        Line(dc,card.x+20,y-4,card.x+card.w-20,y-4,CLR_BORDER);

        int visibleRows=(std::max)(1,(card.y+card.h-20-y)/48);
        visibleRows=(std::min)(16,visibleRows);
        int maxOffset=(std::max)(0,(int)peers.size()-visibleRows);
        gUsersScrollOffset=std::clamp(gUsersScrollOffset,0,maxOffset);
        int drawRows=(std::min)(visibleRows,(int)peers.size()-gUsersScrollOffset);
        for(int row=0;row<drawRows;++row){
            size_t i=(size_t)(gUsersScrollOffset+row);
            int yy=y+row*48;
            RoundFill(dc,{card.x+20,yy,card.w-40,42},row%2?CLR_ROW_ALT:CLR_CARD,CLR_BORDER,6);
            Text(dc,peers[i].name,card.x+cx[0],yy,180,42,gFonts.bold,CLR_TEXT,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
            Text(dc,peers[i].ip,card.x+cx[1],yy,140,42,gFonts.normal,CLR_MUTED);
            bool on=IsPeerActive(peers[i].lastHandshake);
            Text(dc,on?T(L"已連線",L"Online"):T(L"離線",L"Offline"),
                 card.x+cx[2],yy,110,42,gFonts.normal,on?CLR_GREEN:CLR_MUTED);
            Text(dc,HandshakeAge(peers[i].lastHandshake),card.x+cx[3],yy,120,42,gFonts.smallFont,CLR_MUTED);
            Text(dc,FormatBytes(peers[i].rx)+L" / "+FormatBytes(peers[i].tx),
                 card.x+cx[4],yy,185,42,gFonts.smallFont,CLR_TEXT);
            RectI act{card.x+cx[5],yy+5,100,32};
            gUserPeerActionRects.push_back(act);
            gUserPeerRowIndices.push_back(i);
            DrawButton(dc,act,T(L"管理 ▾",L"Manage ▾"));
        }
        if(peers.empty())Text(dc,T(L"尚未建立任何用戶",L"No users created"),
                              card.x+20,card.y+120,card.w-40,60,gFonts.normal,CLR_MUTED,
                              DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    }else if(page==2){
        int base=card.y+80;
        const int step=42;
        RectI basicBg{card.x+22,base-12,card.w-44,8*step+22};
        RoundFill(dc,basicBg,CLR_SUBTLE,CLR_BORDER,10);
        std::wstring labs[]={
            L"VPN Server IP",L"Listen Port",T(L"公網 IP / DDNS",L"Public IP / DDNS"),
            L"Client AllowedIPs",T(L"DNS（選填）",L"DNS (optional)"),
            T(L"LAN 網段",L"LAN Subnet"),T(L"介面語言",L"Interface Language"),
            T(L"介面主題",L"Interface Theme")
        };
        for(int i=0;i<8;++i)Text(dc,labs[i],card.x+40,base+i*step,195,30,gFonts.normal,CLR_MUTED);
        int behaviorY=base+8*step+12;
        RectI behaviorBg{card.x+22,behaviorY,card.w-44,3*step+72};
        // Match the native checkbox surface instead of mixing gray and white blocks.
        RoundFill(dc,behaviorBg,CLR_CARD,CLR_BORDER,10);
        Text(dc,T(L"系統列與自動啟動",L"Tray & Startup"),card.x+40,base+8*step+2,220,30,gFonts.h2,CLR_TEXT);
        int noteY=card.y+card.h-82;
        RectI hintBg{card.x+220,noteY-4,card.w-250,58};
        RoundFill(dc,hintBg,CLR_BLUE_LIGHT,CLR_BORDER,9);
        Text(dc,L"i",hintBg.x+14,hintBg.y,26,hintBg.h,gFonts.bold,CLR_BLUE,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        Text(dc,T(L"開機自動執行會建立「最高權限」登入排程，避免每次登入再跳 UAC；修改後請按左下角「儲存設定」。",
                  L"Windows startup creates a highest-privilege logon task to avoid a UAC prompt at each sign-in. Click Save Settings after changes."),
             hintBg.x+48,hintBg.y+6,hintBg.w-60,hintBg.h-12,gFonts.normal,CLR_TEXT,DT_LEFT|DT_VCENTER|DT_WORDBREAK);

    }else if(page==3){
        ServerSettings st;{std::lock_guard<std::mutex>lk(gDataMutex);st=gSettings;}
        std::wstring lanIp=FindLocalIpv4InCidr(st.lanSubnet);
        if(lanIp.empty()){std::wstring c;DetectPrimaryLan(lanIp,c);}
        std::wstring pub;{std::lock_guard<std::mutex>lk(gPublicIpMutex);pub=gCurrentPublicIp;}
        if(pub.empty())pub=T(L"偵測中 / 尚未取得",L"Detecting / unavailable");

        Text(dc,T(L"目前採用 EasyWG Native NAT + Host Alias NAT。一般家用分享器不需要設定靜態路由。",
                  L"EasyWG uses Native NAT + Host Alias NAT. A normal home router does not need a static route."),
             card.x+35,card.y+82,card.w-70,48,gFonts.h2,CLR_TEXT);

        Text(dc,T(L"分享器設定方式",L"Router setup"),card.x+35,card.y+155,400,36,gFonts.title,CLR_BLUE);

        Text(dc,T(L"本機內網 IP",L"LAN host IP"),card.x+35,card.y+210,150,32,gFonts.normal,CLR_MUTED);
        Text(dc,lanIp,card.x+190,card.y+204,260,42,gFonts.h2,CLR_BLUE);
        Text(dc,L"UDP Port",card.x+485,card.y+210,110,32,gFonts.normal,CLR_MUTED);
        Text(dc,std::to_wstring(st.port),card.x+600,card.y+204,180,42,gFonts.h2,C(0xD97706));

        Text(dc,T(L"請到分享器設定 Port Forward／虛擬伺服器，將上面的 UDP Port 對應到本機內網 IP，即可讓外部 WireGuard Client 連線。",
                  L"In your router's Port Forward / Virtual Server settings, forward the UDP port above to the LAN host IP."),
             card.x+35,card.y+265,card.w-70,72,gFonts.h2,CLR_TEXT,DT_LEFT|DT_WORDBREAK);

        Text(dc,T(L"目前外網實體 IP",L"Current public IP"),card.x+35,card.y+365,220,34,gFonts.normal,CLR_MUTED);
        Text(dc,pub,card.x+260,card.y+354,520,50,gFonts.title,CLR_GREEN);

        Text(dc,T(L"若公網 IP 不是固定 IP，請自行申請 DDNS，然後把主機名稱填入「設定 → 公網 IP / DDNS」。",
                  L"If your public IP changes, obtain a DDNS hostname and enter it under Settings → Public IP / DDNS."),
             card.x+35,card.y+425,card.w-70,72,gFonts.h2,CLR_MUTED,DT_LEFT|DT_WORDBREAK);

        Text(dc,T(L"注意：若 ISP 使用 CGNAT／共享公網 IP，即使設定 Port Forward 也可能無法從外網直連。",
                  L"Note: If your ISP uses CGNAT/shared public IP, port forwarding may not allow inbound access."),
             card.x+35,card.y+525,card.w-70,68,gFonts.h2,CLR_RED,DT_LEFT|DT_WORDBREAK);

    }else if(page==4){
        std::vector<std::wstring> logs;{std::lock_guard<std::mutex>lk(gDataMutex);logs=gLogs;}
        int y=card.y+70;
        int start=(std::max)(0,(int)logs.size()-22);
        for(int i=start;i<(int)logs.size();++i)
            Text(dc,logs[i],card.x+25,y+(i-start)*25,card.w-50,24,gFonts.smallFont,CLR_TEXT);

    }else if(page==5){
        const int px=card.x+38;
        const int py=card.y+72;
        DrawShield(dc,px,py,58);
        Text(dc,L"EasyWG Server",px+82,py-4,360,42,gFonts.big,CLR_BLUE);
        Text(dc,EASYWG_VERSION_DISPLAY_W,card.x+card.w-190,py,150,34,gFonts.h2,CLR_MUTED,DT_RIGHT|DT_VCENTER|DT_SINGLELINE);

        Text(dc,T(L"超輕量 Windows WireGuard VPN Server",L"Ultra-light Windows WireGuard VPN Server"),
             px+82,py+39,card.w-170,30,gFonts.h2,CLR_TEXT);
        Text(dc,T(L"原生 C++ / Win32 x64 · Windows 7 / 10 / 11 · 中英文",L"Native C++ / Win32 x64 · Windows 7 / 10 / 11 · Chinese/English"),
             px+82,py+70,card.w-170,28,gFonts.normal,CLR_MUTED);

        Text(dc,T(L"用簡單直覺的圖形介面快速建立與管理 VPN。",L"Quickly create and manage VPNs with a simple, intuitive graphical interface."),
             px,py+125,card.w-76,34,gFonts.h2,CLR_TEXT);
        Text(dc,T(L"無需 Docker 或 Linux。",L"No Docker or Linux required."),
             px,py+161,card.w-76,30,gFonts.h2,CLR_TEXT);

        int boxW=(std::min)(220,(card.w-120)/2);
        int boxH=82;
        int bx1=px,bx2=px+boxW+28;
        int by1=py+220,by2=by1+boxH+22;
        RectI featureBoxes[4]={{bx1,by1,boxW,boxH},{bx2,by1,boxW,boxH},{bx1,by2,boxW,boxH},{bx2,by2,boxW,boxH}};
        std::wstring featureTitle[]={T(L"⚡  超輕量",L"⚡  Ultra-light"),T(L"🪟  原生",L"🪟  Native"),
                                     T(L"👥  多用戶",L"👥  Multi-user"),T(L"🔒  隱私",L"🔒  Privacy")};
        std::wstring featureSub[]={T(L"主程式數百 KB",L"Main EXE: hundreds of KB"),L"Windows Win32",L"Peer / QR",T(L"金鑰 / QR 本機產生",L"Keys / QR generated locally")};
        COLORREF featureAccent[]={C(0xD97706),CLR_BLUE,C(0x7C3AED),CLR_GREEN};
        for(int i=0;i<4;++i){
            RoundFill(dc,featureBoxes[i],gDarkTheme?CLR_SUBTLE:C(0xFBFCFE),CLR_BORDER,10);
            Text(dc,featureTitle[i],featureBoxes[i].x+16,featureBoxes[i].y+10,featureBoxes[i].w-32,30,gFonts.h2,featureAccent[i]);
            Text(dc,featureSub[i],featureBoxes[i].x+16,featureBoxes[i].y+43,featureBoxes[i].w-32,26,gFonts.normal,CLR_TEXT);
        }

        int techY=by2+boxH+35;
        Text(dc,T(L"技術資訊",L"Technical information"),px,techY,260,34,gFonts.h2,CLR_TEXT);
        Text(dc,L"WireGuardNT  ·  Win7 Legacy  ·  Native NAT/PAT  ·  Host Alias",
             px,techY+38,card.w-76,32,gFonts.normal,CLR_MUTED);

        gGitHubBtn={px,techY+88,230,40};
        DrawButton(dc,gGitHubBtn,T(L"開啟 GitHub 專案",L"Open GitHub Project"),true);
        Text(dc,T(L"授權：PolyForm Shield 1.0.0",L"License: PolyForm Shield 1.0.0"),
             px+248,techY+88,card.w-324,40,gFonts.smallFont,CLR_MUTED,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
        Text(dc,L"https://github.com/Terence0816/easy-wireguard-server",
             px,techY+136,card.w-76,30,gFonts.bold,CLR_TEXT,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
        Text(dc,T(L"EasyWG Server 為獨立非官方專案，與 WireGuard 專案無隸屬或背書關係。",
                  L"EasyWG Server is an independent, unofficial project and is not affiliated with or endorsed by WireGuard."),
             px,techY+168,card.w-76,32,gFonts.smallFont,CLR_MUTED,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
    }
}

// ---------------- Modal input windows / peer actions ----------------

struct ModalResult { bool ok=false; bool fullTunnel=false; std::wstring a,b; };
ModalResult gModalResult;
HWND gEdits[2]{};
HWND gPeerListBox=nullptr;
HWND gModalFullTunnelCheck=nullptr;
int gModalMode=0;
int gPeerChoice=-1;
std::wstring gModalInitialA;
std::wstring gModalInitialB;

LRESULT CALLBACK ModalProc(HWND hwnd,UINT msg,WPARAM wp,LPARAM lp){
    switch(msg){
    case WM_CREATE:{
        auto* cs=reinterpret_cast<CREATESTRUCTW*>(lp);
        gModalMode=(int)(INT_PTR)cs->lpCreateParams;
        HFONT f=gFonts.normal;
        if(gModalMode==1){
            HWND lab=CreateWindowW(L"STATIC",T(L"用戶名稱",L"User Name").c_str(),WS_CHILD|WS_VISIBLE,
                                   22,24,440,22,hwnd,nullptr,nullptr,nullptr);
            SendMessageW(lab,WM_SETFONT,(WPARAM)f,TRUE);
            gEdits[0]=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"New Device",
                                      WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL,22,50,440,36,hwnd,
                                      (HMENU)(INT_PTR)100,nullptr,nullptr);
            SendMessageW(gEdits[0],WM_SETFONT,(WPARAM)f,TRUE);
            std::wstring autoIp=T(L"VPN IP 將自動分配未占用位址：",L"VPN IP will be assigned automatically: ")+NextPeerIp();
            HWND ipn=CreateWindowW(L"STATIC",autoIp.c_str(),WS_CHILD|WS_VISIBLE,22,101,440,28,hwnd,nullptr,nullptr,nullptr);
            SendMessageW(ipn,WM_SETFONT,(WPARAM)gFonts.smallFont,TRUE);
            gModalFullTunnelCheck=CreateWindowW(L"BUTTON",
                T(L"需使用 VPN 主機公網 IP 上網\r\n（不勾選仍可連接內網）",
                  L"Use the VPN server's public IP for Internet access\r\n(Unchecked still allows private-network access)").c_str(),
                WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_AUTOCHECKBOX|BS_MULTILINE,
                22,137,440,66,hwnd,(HMENU)(INT_PTR)130,nullptr,nullptr);
            SendMessageW(gModalFullTunnelCheck,WM_SETFONT,(WPARAM)gFonts.bold,TRUE);
            SendMessageW(gModalFullTunnelCheck,BM_SETCHECK,BST_UNCHECKED,0);
            HWND n=CreateWindowW(L"STATIC",T(L"Private Key、Public Key 與 Preshared Key 也會自動產生。",
                                               L"Private/Public/Preshared keys will also be generated automatically.").c_str(),
                                 WS_CHILD|WS_VISIBLE,22,216,440,44,hwnd,nullptr,nullptr,nullptr);
            SendMessageW(n,WM_SETFONT,(WPARAM)gFonts.smallFont,TRUE);
        }else if(gModalMode==2){
            std::wstring labs[]={T(L"用戶名稱",L"User Name"),T(L"VPN IP 位址",L"VPN IP Address")};
            std::wstring vals[]={gModalInitialA,gModalInitialB};
            for(int i=0;i<2;++i){
                HWND lab=CreateWindowW(L"STATIC",labs[i].c_str(),WS_CHILD|WS_VISIBLE,
                                       22,25+i*76,440,22,hwnd,nullptr,nullptr,nullptr);
                SendMessageW(lab,WM_SETFONT,(WPARAM)f,TRUE);
                gEdits[i]=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",vals[i].c_str(),
                                          WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL,
                                          22,49+i*76,440,34,hwnd,
                                          (HMENU)(INT_PTR)(100+i),nullptr,nullptr);
                SendMessageW(gEdits[i],WM_SETFONT,(WPARAM)f,TRUE);
            }
            HWND n=CreateWindowW(L"STATIC",T(L"只修改名稱與 VPN IP，既有金鑰會保留。",L"Only name and VPN IP are changed; existing keys are preserved.").c_str(),WS_CHILD|WS_VISIBLE,
                                 22,188,440,25,hwnd,nullptr,nullptr,nullptr);
            SendMessageW(n,WM_SETFONT,(WPARAM)gFonts.smallFont,TRUE);
        }else if(gModalMode==3){
            HWND lab=CreateWindowW(L"STATIC",T(L"請選擇用戶",L"Select a user").c_str(),
                                   WS_CHILD|WS_VISIBLE,22,18,440,24,hwnd,nullptr,nullptr,nullptr);
            SendMessageW(lab,WM_SETFONT,(WPARAM)f,TRUE);
            gPeerListBox=CreateWindowExW(WS_EX_CLIENTEDGE,L"LISTBOX",L"",
                                         WS_CHILD|WS_VISIBLE|LBS_NOTIFY|WS_VSCROLL,
                                         22,48,440,210,hwnd,(HMENU)(INT_PTR)120,nullptr,nullptr);
            SendMessageW(gPeerListBox,WM_SETFONT,(WPARAM)f,TRUE);
            std::vector<PeerInfo> peers;{std::lock_guard<std::mutex>lk(gDataMutex);peers=gPeers;}
            for(auto&p:peers){
                std::wstring row=p.name+L"    ["+p.ip+L"]";
                SendMessageW(gPeerListBox,LB_ADDSTRING,0,(LPARAM)row.c_str());
            }
            if(!peers.empty())SendMessageW(gPeerListBox,LB_SETCURSEL,0,0);
        }

        int y=gModalMode==1?286:(gModalMode==2?238:278);
        std::wstring okText=gModalMode==1?T(L"產生金鑰與設定",L"Create User"):
                              (gModalMode==2?T(L"儲存修改",L"Save Changes"):T(L"確定",L"OK"));
        RECT cr{};GetClientRect(hwnd,&cr);
        const int okW=125,cancelW=95,btnGap=14,totalW=okW+btnGap+cancelW;
        int btnX=(static_cast<int>(cr.right)-totalW)/2;
        HWND ok=CreateWindowW(L"BUTTON",okText.c_str(),WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON,
                              btnX,y,okW,36,hwnd,(HMENU)IDOK,nullptr,nullptr);
        HWND cancel=CreateWindowW(L"BUTTON",T(L"取消",L"Cancel").c_str(),WS_CHILD|WS_VISIBLE,
                                  btnX+okW+btnGap,y,cancelW,36,hwnd,(HMENU)IDCANCEL,nullptr,nullptr);
        SendMessageW(ok,WM_SETFONT,(WPARAM)f,TRUE);
        SendMessageW(cancel,WM_SETFONT,(WPARAM)f,TRUE);
        return 0;
    }
    case WM_COMMAND:
        if(LOWORD(wp)==IDOK){
            if(gModalMode==1){
                wchar_t b[2048]{};
                GetWindowTextW(gEdits[0],b,_countof(b));gModalResult.a=Trim(b);
                gModalResult.b=NextPeerIp();
                gModalResult.fullTunnel=gModalFullTunnelCheck&&
                    SendMessageW(gModalFullTunnelCheck,BM_GETCHECK,0,0)==BST_CHECKED;
                gModalResult.ok=true;DestroyWindow(hwnd);return 0;
            }
            if(gModalMode==2){
                wchar_t b[2048]{};
                GetWindowTextW(gEdits[0],b,_countof(b));gModalResult.a=Trim(b);
                GetWindowTextW(gEdits[1],b,_countof(b));gModalResult.b=Trim(b);
                gModalResult.ok=true;DestroyWindow(hwnd);return 0;
            }
            if(gModalMode==3){
                int sel=(int)SendMessageW(gPeerListBox,LB_GETCURSEL,0,0);
                if(sel==LB_ERR){
                    MessageBoxW(hwnd,T(L"請先選擇一位用戶。",L"Select a user first.").c_str(),
                                kAppName,MB_ICONINFORMATION);
                    return 0;
                }
                gPeerChoice=sel;DestroyWindow(hwnd);return 0;
            }
        }
        if(LOWORD(wp)==IDCANCEL){DestroyWindow(hwnd);return 0;}
        if(gModalMode==3&&LOWORD(wp)==120&&HIWORD(wp)==LBN_DBLCLK){
            int sel=(int)SendMessageW(gPeerListBox,LB_GETCURSEL,0,0);
            if(sel!=LB_ERR){gPeerChoice=sel;DestroyWindow(hwnd);}
            return 0;
        }
        break;
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX:{
        HDC dc=(HDC)wp;SetTextColor(dc,CLR_TEXT);SetBkColor(dc,CLR_INPUT);
        return (LRESULT)gThemeInputBrush;
    }
    case WM_CTLCOLORSTATIC:{
        HDC dc=(HDC)wp;SetTextColor(dc,CLR_TEXT);SetBkColor(dc,CLR_SUBTLE);
        return (LRESULT)gThemeSubtleBrush;
    }
    case WM_CTLCOLORBTN:{
        HDC dc=(HDC)wp;HWND ctl=(HWND)lp;
        if(ctl==gModalFullTunnelCheck){
            SetBkMode(dc,TRANSPARENT);
            SetTextColor(dc,gDarkTheme?C(0xA99CFF):C(0x4F46C8));
            return (LRESULT)gThemeSubtleBrush;
        }
        SetTextColor(dc,CLR_TEXT);SetBkColor(dc,CLR_SUBTLE);
        return (LRESULT)gThemeSubtleBrush;
    }
    case WM_ERASEBKGND:{
        HDC dc=(HDC)wp;RECT rc{};GetClientRect(hwnd,&rc);
        FillRect(dc,&rc,gThemeSubtleBrush?gThemeSubtleBrush:(HBRUSH)(COLOR_WINDOW+1));
        return 1;
    }
    case WM_CLOSE:DestroyWindow(hwnd);return 0;
    }
    return DefWindowProcW(hwnd,msg,wp,lp);
}

ModalResult ShowModal(HWND owner,int mode){
    gModalResult={};ZeroMemory(gEdits,sizeof(gEdits));gModalFullTunnelCheck=nullptr;
    int w=500,h=(mode==1?410:(mode==2?380:410));
    RECT orc{};GetWindowRect(owner,&orc);
    int x=orc.left+(orc.right-orc.left-w)/2,y=orc.top+(orc.bottom-orc.top-h)/2;
    std::wstring title=mode==1?T(L"新增用戶",L"Add User"):
                       mode==2?T(L"編輯用戶",L"Edit User"):T(L"選擇用戶",L"Select User");
    HWND hwnd=CreateWindowExW(WS_EX_DLGMODALFRAME,kModalClass,title.c_str(),
                              WS_CAPTION|WS_SYSMENU|WS_POPUP|WS_VISIBLE,
                              x,y,w,h,owner,nullptr,GetModuleHandleW(nullptr),(LPVOID)(INT_PTR)mode);
    EnableWindow(owner,FALSE);
    MSG msg;
    while(IsWindow(hwnd)&&GetMessageW(&msg,nullptr,0,0)>0){
        if(!IsDialogMessageW(hwnd,&msg)){TranslateMessage(&msg);DispatchMessageW(&msg);}
    }
    EnableWindow(owner,TRUE);SetForegroundWindow(owner);
    return gModalResult;
}

int ChoosePeer(HWND owner){size_t n;{std::lock_guard<std::mutex>lk(gDataMutex);n=gPeers.size();}if(!n){MessageBoxW(owner,T(L"目前沒有用戶。",L"No users available.").c_str(),kAppName,MB_ICONINFORMATION);return -1;}if(n==1)return 0;gPeerChoice=-1;ShowModal(owner,3);return gPeerChoice;}

bool CreatePeerRecord(HWND hwnd,const std::wstring& name,const std::wstring& ip,bool fullTunnel,size_t* outIndex=nullptr){
    if(name.empty()||ip.empty()){
        MessageBoxW(hwnd,T(L"名稱與 VPN IP 不可空白。",L"Name and VPN IP are required.").c_str(),kAppName,MB_ICONWARNING);return false;
    }
    IN_ADDR a{};
    if(InetPtonW(AF_INET,ip.c_str(),&a)!=1){
        MessageBoxW(hwnd,T(L"VPN IP 格式錯誤。",L"Invalid VPN IP format.").c_str(),kAppName,MB_ICONWARNING);return false;
    }
    {
        bool duplicate=false;
        {std::lock_guard<std::mutex>lk(gDataMutex);for(const auto&x:gPeers)if(x.ip==ip){duplicate=true;break;}}
        if(duplicate){
            MessageBoxW(hwnd,T(L"此 VPN IP 已被使用，請更換最後一碼。",L"This VPN IP is already in use. Choose another last octet.").c_str(),
                        kAppName,MB_ICONWARNING);
            return false;
        }
    }
    PeerInfo peer;peer.name=name;peer.ip=ip;peer.fullTunnel=fullTunnel;
    if(!GenerateKeyPair(peer.publicKey.data(),peer.privateKey.data())||!RandomKey(peer.presharedKey.data())){
        MessageBoxW(hwnd,T(L"金鑰產生失敗。",L"Key generation failed.").c_str(),kAppName,MB_ICONERROR);return false;
    }
    size_t idx=0;
    {
        std::lock_guard<std::mutex>lk(gDataMutex);
        // Re-check after key generation in case another UI path added the same IP.
        for(const auto&x:gPeers)if(x.ip==peer.ip)return false;
        gPeers.push_back(peer);idx=gPeers.size()-1;
    }
    SaveConfig();
    AddLog(T(L"新增用戶: ",L"Added user: ")+peer.name+L" ("+peer.ip+L") - "+
           (peer.fullTunnel?T(L"公網上網",L"full tunnel"):T(L"僅內網",L"private networks only")));
    if(gRunning){StopServer();std::wstring e;if(!StartServer(e))MessageBoxW(hwnd,e.c_str(),kAppName,MB_ICONERROR);}
    if(outIndex)*outIndex=idx;
    if(gMainWnd)InvalidateRect(gMainWnd,nullptr,TRUE);
    return true;
}

void AddPeerUi(HWND hwnd){
    auto r=ShowModal(hwnd,1);if(!r.ok)return;
    CreatePeerRecord(hwnd,r.a,r.b,r.fullTunnel,nullptr);
}

void EditPeerUi(HWND hwnd,size_t idx){
    PeerInfo oldPeer;
    {
        std::lock_guard<std::mutex>lk(gDataMutex);
        if(idx>=gPeers.size())return;
        oldPeer=gPeers[idx];
    }
    gModalInitialA=oldPeer.name;
    gModalInitialB=oldPeer.ip;
    auto r=ShowModal(hwnd,2);
    if(!r.ok)return;
    if(r.a.empty()||r.b.empty()){
        MessageBoxW(hwnd,T(L"名稱與 VPN IP 不可空白。",L"Name and VPN IP are required.").c_str(),kAppName,MB_ICONWARNING);return;
    }
    IN_ADDR a{};
    if(InetPtonW(AF_INET,r.b.c_str(),&a)!=1){
        MessageBoxW(hwnd,T(L"VPN IP 格式錯誤。",L"Invalid VPN IP format.").c_str(),kAppName,MB_ICONWARNING);return;
    }
    {
        std::lock_guard<std::mutex>lk(gDataMutex);
        if(idx>=gPeers.size())return;
        for(size_t i=0;i<gPeers.size();++i){
            if(i!=idx&&gPeers[i].ip==r.b){
                MessageBoxW(hwnd,T(L"此 VPN IP 已被其他用戶使用。",L"This VPN IP is already used by another user.").c_str(),
                            kAppName,MB_ICONWARNING);return;
            }
        }
        gPeers[idx].name=r.a;
        gPeers[idx].ip=r.b;
    }
    SaveConfig();
    AddLog(T(L"已編輯用戶: ",L"Edited user: ")+r.a+L" ("+r.b+L")");
    if(gRunning){StopServer();std::wstring e;if(!StartServer(e))MessageBoxW(hwnd,e.c_str(),kAppName,MB_ICONERROR);}
    InvalidateRect(hwnd,nullptr,TRUE);
}

void RemovePeerUi(HWND hwnd,size_t idx){
    PeerInfo peer;
    {
        std::lock_guard<std::mutex>lk(gDataMutex);
        if(idx>=gPeers.size())return;
        peer=gPeers[idx];
    }
    std::wstring msg=T(L"確定要移除用戶「",L"Remove user \"")+peer.name+
                     T(L"」？\n\n此用戶原有設定檔之後將無法再連線。",L"\"?\n\nIts existing configuration will no longer connect.");
    if(MessageBoxW(hwnd,msg.c_str(),kAppName,MB_YESNO|MB_ICONWARNING)!=IDYES)return;
    {
        std::lock_guard<std::mutex>lk(gDataMutex);
        if(idx>=gPeers.size())return;
        gPeers.erase(gPeers.begin()+idx);
    }
    SaveConfig();
    AddLog(T(L"已移除用戶: ",L"Removed user: ")+peer.name);
    if(gRunning){StopServer();std::wstring e;if(!StartServer(e))MessageBoxW(hwnd,e.c_str(),kAppName,MB_ICONERROR);}
    InvalidateRect(hwnd,nullptr,TRUE);
}

std::wstring BuildPeerConfigText(size_t idx){
    ServerSettings st;PeerInfo p;{std::lock_guard<std::mutex>lk(gDataMutex);if(idx>=gPeers.size())return L"";st=gSettings;p=gPeers[idx];}
    const std::wstring allowed=PeerClientAllowedIPs(st,p);
    std::wstringstream ss;ss<<L"[Interface]\r\nPrivateKey = "<<Base64Encode(p.privateKey.data(),32)<<L"\r\nAddress = "<<p.ip<<L"/32\r\n";if(!st.dns.empty())ss<<L"DNS = "<<st.dns<<L"\r\n";ss<<L"\r\n[Peer]\r\nPublicKey = "<<Base64Encode(st.publicKey.data(),32)<<L"\r\nPresharedKey = "<<Base64Encode(p.presharedKey.data(),32)<<L"\r\nEndpoint = "<<(st.endpoint.empty()?L"<PUBLIC-IP-OR-DDNS>":st.endpoint)<<L":"<<st.port<<L"\r\nAllowedIPs = "<<allowed<<L"\r\nPersistentKeepalive = 25\r\n";return ss.str();
}

bool ExportPeerConfig(HWND hwnd,size_t idx){
    PeerInfo p;{std::lock_guard<std::mutex>lk(gDataMutex);if(idx>=gPeers.size())return false;p=gPeers[idx];}std::wstring cfg=BuildPeerConfigText(idx);wchar_t file[MAX_PATH]{};std::wstring def=p.name+L".conf";wcsncpy_s(file,def.c_str(),_TRUNCATE);OPENFILENAMEW ofn{};ofn.lStructSize=sizeof(ofn);ofn.hwndOwner=hwnd;ofn.lpstrFilter=L"WireGuard Config (*.conf)\0*.conf\0All Files\0*.*\0";ofn.lpstrFile=file;ofn.nMaxFile=MAX_PATH;ofn.Flags=OFN_OVERWRITEPROMPT|OFN_PATHMUSTEXIST;ofn.lpstrDefExt=L"conf";if(!GetSaveFileNameW(&ofn))return false;std::string utf8=WideToUtf8(cfg);HANDLE hf=CreateFileW(file,GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);if(hf==INVALID_HANDLE_VALUE){MessageBoxW(hwnd,T(L"寫入設定檔失敗。",L"Failed to write config file.").c_str(),kAppName,MB_ICONERROR);return false;}DWORD wr=0;BOOL ok=utf8.empty()||WriteFile(hf,utf8.data(),(DWORD)utf8.size(),&wr,nullptr);CloseHandle(hf);if(!ok||wr!=utf8.size()){MessageBoxW(hwnd,T(L"寫入設定檔失敗。",L"Failed to write config file.").c_str(),kAppName,MB_ICONERROR);return false;}AddLog(T(L"已匯出用戶設定: ",L"Exported user config: ")+p.name);return true;
}

void ExportChosenPeer(HWND hwnd){int idx=ChoosePeer(hwnd);if(idx>=0)ExportPeerConfig(hwnd,(size_t)idx);}

miniqr::QrCode gQrCode;
std::wstring gQrPeerName;
LRESULT CALLBACK QrProc(HWND hwnd,UINT msg,WPARAM wp,LPARAM lp){
    switch(msg){
    case WM_PAINT:{PAINTSTRUCT ps{};HDC dc=BeginPaint(hwnd,&ps);RECT rc{};GetClientRect(hwnd,&rc);FillRectC(dc,{0,0,rc.right,rc.bottom},RGB(255,255,255));Text(dc,T(L"使用 WireGuard 手機 App 掃描加入",L"Scan with the WireGuard mobile app"),20,14,rc.right-40,34,gFonts.h2,CLR_TEXT,DT_CENTER|DT_VCENTER|DT_SINGLELINE);Text(dc,gQrPeerName,20,48,rc.right-40,26,gFonts.normal,CLR_MUTED,DT_CENTER|DT_VCENTER|DT_SINGLELINE);int border=4;int avail=(std::min)(rc.right-40,rc.bottom-115);int modules=gQrCode.size+border*2;int scale=(std::max)(1,avail/modules);int total=modules*scale;int ox=(rc.right-total)/2,oy=85;HBRUSH black=CreateSolidBrush(RGB(0,0,0));for(int y=0;y<gQrCode.size;++y)for(int x=0;x<gQrCode.size;++x)if(gQrCode.get(x,y)){RECT r{ox+(x+border)*scale,oy+(y+border)*scale,ox+(x+border+1)*scale,oy+(y+border+1)*scale};FillRect(dc,&r,black);}DeleteObject(black);Text(dc,T(L"QR 內容在本機產生，不會上傳 Private Key。",L"QR data is generated locally; the private key is not uploaded."),20,oy+total+8,rc.right-40,30,gFonts.smallFont,CLR_MUTED,DT_CENTER|DT_VCENTER|DT_SINGLELINE);EndPaint(hwnd,&ps);return 0;}
    case WM_KEYDOWN:if(wp==VK_ESCAPE){DestroyWindow(hwnd);return 0;}break;
    case WM_CLOSE:DestroyWindow(hwnd);return 0;
    }
    return DefWindowProcW(hwnd,msg,wp,lp);
}

void ShowPeerQr(HWND owner,size_t idx){PeerInfo p;{std::lock_guard<std::mutex>lk(gDataMutex);if(idx>=gPeers.size())return;p=gPeers[idx];}std::wstring cfg=BuildPeerConfigText(idx);std::string err;if(!miniqr::EncodeUtf8(WideToUtf8(cfg),gQrCode,err)){MessageBoxW(owner,(T(L"QR Code 產生失敗: ",L"QR Code generation failed: ")+Utf8ToWide(err)).c_str(),kAppName,MB_ICONERROR);return;}gQrPeerName=p.name+L"  ["+p.ip+L"]";RECT orc{};GetWindowRect(owner,&orc);int w=620,h=720,x=orc.left+(orc.right-orc.left-w)/2,y=orc.top+(orc.bottom-orc.top-h)/2;HWND q=CreateWindowExW(WS_EX_DLGMODALFRAME,kQrClass,T(L"WireGuard 手機 QR Code",L"WireGuard Mobile QR Code").c_str(),WS_CAPTION|WS_SYSMENU|WS_POPUP|WS_VISIBLE,x,y,w,h,owner,nullptr,GetModuleHandleW(nullptr),nullptr);EnableWindow(owner,FALSE);MSG m;while(IsWindow(q)&&GetMessageW(&m,nullptr,0,0)>0){TranslateMessage(&m);DispatchMessageW(&m);}EnableWindow(owner,TRUE);SetForegroundWindow(owner);}
void ShowChosenPeerQr(HWND hwnd){int idx=ChoosePeer(hwnd);if(idx>=0)ShowPeerQr(hwnd,(size_t)idx);}

std::wstring VpnPrefix3(){
    ServerSettings st;{std::lock_guard<std::mutex>lk(gDataMutex);st=gSettings;}
    size_t p=st.address.find_last_of(L'.');
    return p==std::wstring::npos?L"10.66.66.":st.address.substr(0,p+1);
}

std::wstring SuggestedLastOctet(){
    std::wstring ip=NextPeerIp();size_t p=ip.find_last_of(L'.');
    return p==std::wstring::npos?L"2":ip.substr(p+1);
}

bool SavePeerQrBmp(HWND owner,size_t idx){
    PeerInfo peer;{std::lock_guard<std::mutex>lk(gDataMutex);if(idx>=gPeers.size())return false;peer=gPeers[idx];}
    miniqr::QrCode qr;std::string e;
    if(!miniqr::EncodeUtf8(WideToUtf8(BuildPeerConfigText(idx)),qr,e)){
        MessageBoxW(owner,(T(L"QR Code 產生失敗: ",L"QR Code generation failed: ")+Utf8ToWide(e)).c_str(),kAppName,MB_ICONERROR);return false;
    }
    wchar_t file[MAX_PATH]{};std::wstring def=peer.name+L"_QR.bmp";wcsncpy_s(file,def.c_str(),_TRUNCATE);
    OPENFILENAMEW ofn{};ofn.lStructSize=sizeof(ofn);ofn.hwndOwner=owner;
    ofn.lpstrFilter=L"Bitmap Image (*.bmp)\0*.bmp\0All Files\0*.*\0";ofn.lpstrFile=file;ofn.nMaxFile=MAX_PATH;
    ofn.Flags=OFN_OVERWRITEPROMPT|OFN_PATHMUSTEXIST;ofn.lpstrDefExt=L"bmp";
    if(!GetSaveFileNameW(&ofn))return false;
    const int border=4,scale=8,modules=qr.size+border*2,width=modules*scale,height=width;
    const int stride=(width*3+3)&~3;
    std::vector<BYTE> pixels((size_t)stride*height,255);
    for(int y=0;y<qr.size;++y)for(int x=0;x<qr.size;++x)if(qr.get(x,y)){
        int px=(x+border)*scale,py=(y+border)*scale;
        for(int yy=0;yy<scale;++yy){BYTE* row=pixels.data()+(size_t)(height-1-(py+yy))*stride;for(int xx=0;xx<scale;++xx){BYTE* b=row+(px+xx)*3;b[0]=b[1]=b[2]=0;}}
    }
    BITMAPFILEHEADER bfh{};BITMAPINFOHEADER bih{};
    bfh.bfType=0x4D42;bfh.bfOffBits=sizeof(bfh)+sizeof(bih);bfh.bfSize=bfh.bfOffBits+(DWORD)pixels.size();
    bih.biSize=sizeof(bih);bih.biWidth=width;bih.biHeight=height;bih.biPlanes=1;bih.biBitCount=24;bih.biCompression=BI_RGB;bih.biSizeImage=(DWORD)pixels.size();
    HANDLE hf=CreateFileW(file,GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(hf==INVALID_HANDLE_VALUE){MessageBoxW(owner,T(L"儲存 QR Code 失敗。",L"Failed to save QR Code.").c_str(),kAppName,MB_ICONERROR);return false;}
    DWORD wr=0;BOOL ok=WriteFile(hf,&bfh,sizeof(bfh),&wr,nullptr)&&wr==sizeof(bfh);
    ok=ok&&WriteFile(hf,&bih,sizeof(bih),&wr,nullptr)&&wr==sizeof(bih);
    ok=ok&&WriteFile(hf,pixels.data(),(DWORD)pixels.size(),&wr,nullptr)&&wr==pixels.size();CloseHandle(hf);
    if(!ok){MessageBoxW(owner,T(L"儲存 QR Code 失敗。",L"Failed to save QR Code.").c_str(),kAppName,MB_ICONERROR);return false;}
    AddLog(T(L"已儲存 QR Code: ",L"Saved QR Code: ")+peer.name);return true;
}

void DrawQrInRect(HDC dc,const miniqr::QrCode&qr,const RectI&r){
    if(qr.size<=0)return;int border=4;int modules=qr.size+border*2;int scale=(std::max)(1,(std::min)(r.w,r.h)/modules);
    int total=modules*scale,ox=r.x+(r.w-total)/2,oy=r.y+(r.h-total)/2;
    HBRUSH wb=CreateSolidBrush(RGB(255,255,255));RECT bg{ox,oy,ox+total,oy+total};FillRect(dc,&bg,wb);DeleteObject(wb);
    HBRUSH black=CreateSolidBrush(RGB(0,0,0));
    for(int y=0;y<qr.size;++y)for(int x=0;x<qr.size;++x)if(qr.get(x,y)){RECT m{ox+(x+border)*scale,oy+(y+border)*scale,ox+(x+border+1)*scale,oy+(y+border+1)*scale};FillRect(dc,&m,black);}DeleteObject(black);
}

void RefreshAddPanelDefaults(){
    if(!gAddNameEdit&&!gAddOctetEdit)return;
    if(gAddNameEdit)SetWindowTextW(gAddNameEdit,T(L"New Device",L"New Device").c_str());
    if(gAddOctetEdit)SetWindowTextW(gAddOctetEdit,SuggestedLastOctet().c_str());
    if(gAddPrefixLabel)SetWindowTextW(gAddPrefixLabel,VpnPrefix3().c_str());
    if(gAddFullTunnelCheck)SendMessageW(gAddFullTunnelCheck,BM_SETCHECK,BST_UNCHECKED,0);
}

RectI InlineAddPanelRect(HWND hwnd){
    RECT rc{};GetClientRect(hwnd,&rc);
    return {rc.right-378,22,362,rc.bottom-86};
}

void ShowInlineAddControls(bool show){
    int cmd=show?SW_SHOW:SW_HIDE;
    HWND ctrls[]={gAddNameEdit,gAddOctetEdit,gAddCreateBtn,gAddPrefixLabel,gAddFullTunnelCheck,gAddSaveQrBtn,gAddSaveConfigBtn};
    for(HWND c:ctrls)if(c)ShowWindow(c,cmd);
    bool ready=show&&gAddPanelPeerIndex>=0&&gAddPanelQr.size>0;
    if(gAddSaveQrBtn)EnableWindow(gAddSaveQrBtn,ready?TRUE:FALSE);
    if(gAddSaveConfigBtn)EnableWindow(gAddSaveConfigBtn,ready?TRUE:FALSE);
}

void LayoutInlineAddControls(HWND hwnd){
    if(gPage!=0){ShowInlineAddControls(false);return;}
    RectI p=InlineAddPanelRect(hwnd);
    int mx=p.x+20,inner=p.w-40;
    if(gAddNameEdit)MoveWindow(gAddNameEdit,mx,p.y+92,inner,34,TRUE);
    if(gAddPrefixLabel)MoveWindow(gAddPrefixLabel,p.x+169,p.y+136,p.w-269,36,TRUE);
    if(gAddOctetEdit)MoveWindow(gAddOctetEdit,p.x+p.w-100,p.y+136,80,36,TRUE);
    if(gAddFullTunnelCheck)MoveWindow(gAddFullTunnelCheck,mx,p.y+180,inner,68,TRUE);
    if(gAddCreateBtn)MoveWindow(gAddCreateBtn,mx,p.y+258,inner,42,TRUE);
    if(gAddSaveQrBtn)MoveWindow(gAddSaveQrBtn,mx,p.y+p.h-50,(inner-10)/2,36,TRUE);
    if(gAddSaveConfigBtn)MoveWindow(gAddSaveConfigBtn,mx+(inner-10)/2+10,p.y+p.h-50,(inner-10)/2,36,TRUE);
    ShowInlineAddControls(true);
}

void CreateInlineAddControls(HWND owner){
    HFONT f=gFonts.normal;
    gAddNameEdit=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"New Device",WS_CHILD|ES_AUTOHSCROLL,0,0,100,34,owner,(HMENU)(INT_PTR)IDC_ADD_NAME,nullptr,nullptr);
    gAddPrefixLabel=CreateWindowW(L"STATIC",L"10.66.66.",WS_CHILD|SS_RIGHT,0,0,100,36,owner,nullptr,nullptr,nullptr);
    gAddOctetEdit=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"2",WS_CHILD|ES_NUMBER|ES_CENTER,0,0,80,36,owner,(HMENU)(INT_PTR)IDC_ADD_OCTET,nullptr,nullptr);
    gAddFullTunnelCheck=CreateWindowW(L"BUTTON",
        T(L"需使用 VPN 主機公網 IP 上網\r\n（不勾選仍可連接內網）",
          L"Use VPN server public IP for Internet\r\n(Unchecked still allows private-network access)").c_str(),
        WS_CHILD|WS_TABSTOP|BS_AUTOCHECKBOX|BS_MULTILINE,0,0,100,48,owner,
        (HMENU)(INT_PTR)IDC_ADD_FULL_TUNNEL,nullptr,nullptr);
    gAddCreateBtn=CreateWindowW(L"BUTTON",T(L"新增用戶",L"Add User").c_str(),WS_CHILD|BS_OWNERDRAW,0,0,100,42,owner,(HMENU)(INT_PTR)IDC_ADD_CREATE,nullptr,nullptr);
    gAddSaveQrBtn=CreateWindowW(L"BUTTON",T(L"儲存 QR Code",L"Save QR Code").c_str(),WS_CHILD|BS_OWNERDRAW,0,0,100,36,owner,(HMENU)(INT_PTR)IDC_ADD_SAVE_QR,nullptr,nullptr);
    gAddSaveConfigBtn=CreateWindowW(L"BUTTON",T(L"儲存設定檔",L"Save Config").c_str(),WS_CHILD|BS_OWNERDRAW,0,0,100,36,owner,(HMENU)(INT_PTR)IDC_ADD_SAVE_CONFIG,nullptr,nullptr);
    for(HWND c:{gAddNameEdit,gAddPrefixLabel,gAddOctetEdit,gAddFullTunnelCheck,gAddCreateBtn,gAddSaveQrBtn,gAddSaveConfigBtn})if(c)SendMessageW(c,WM_SETFONT,(WPARAM)(c==gAddPrefixLabel||c==gAddOctetEdit?gFonts.h2:(c==gAddFullTunnelCheck?gFonts.bold:(c==gAddCreateBtn||c==gAddSaveQrBtn||c==gAddSaveConfigBtn?gFonts.bold:f))),TRUE);
    RefreshAddPanelDefaults();
    ShowInlineAddControls(false);
}

void CloseInlineAddPanel(HWND owner){
    // The add-user panel is a permanent part of the dashboard.
    gInlineAddVisible=true;
    LayoutInlineAddControls(owner);
    InvalidateRect(owner,nullptr,TRUE);
}

void ShowAddUserPanel(HWND owner){
    if(gPage!=0){ShowSettingsControls(false);gPage=0;}
    gInlineAddVisible=true;
    LayoutInlineAddControls(owner);
    if(gAddNameEdit)SetFocus(gAddNameEdit);
    InvalidateRect(owner,nullptr,TRUE);
}

void ShowPeerActionMenu(HWND hwnd,size_t idx){
    size_t count=0;{std::lock_guard<std::mutex>lk(gDataMutex);count=gPeers.size();}
    if(idx>=count)return;
    HMENU menu=CreatePopupMenu();
    if(!menu)return;
    AppendMenuW(menu,MF_STRING,IDM_PEER_EDIT,T(L"編輯用戶",L"Edit User").c_str());
    AppendMenuW(menu,MF_STRING,IDM_PEER_EXPORT,T(L"匯出設定檔",L"Export Config").c_str());
    AppendMenuW(menu,MF_STRING,IDM_PEER_QR,T(L"顯示 QR Code",L"Show QR Code").c_str());
    AppendMenuW(menu,MF_SEPARATOR,0,nullptr);
    AppendMenuW(menu,MF_STRING,IDM_PEER_REMOVE,T(L"移除用戶",L"Remove User").c_str());
    POINT pt{};GetCursorPos(&pt);
    SetForegroundWindow(hwnd);
    UINT cmd=TrackPopupMenu(menu,TPM_RETURNCMD|TPM_RIGHTBUTTON|TPM_LEFTALIGN|TPM_TOPALIGN,
                            pt.x,pt.y,0,hwnd,nullptr);
    DestroyMenu(menu);
    switch(cmd){
    case IDM_PEER_EDIT:EditPeerUi(hwnd,idx);break;
    case IDM_PEER_EXPORT:ExportPeerConfig(hwnd,idx);break;
    case IDM_PEER_QR:ShowPeerQr(hwnd,idx);break;
    case IDM_PEER_REMOVE:RemovePeerUi(hwnd,idx);break;
    }
}

void BackupConfig(HWND hwnd){wchar_t file[MAX_PATH]{};wcscpy_s(file,L"EasyWG_Server_backup.ini");OPENFILENAMEW ofn{};ofn.lStructSize=sizeof(ofn);ofn.hwndOwner=hwnd;ofn.lpstrFilter=L"INI Files (*.ini)\0*.ini\0All Files\0*.*\0";ofn.lpstrFile=file;ofn.nMaxFile=MAX_PATH;ofn.Flags=OFN_OVERWRITEPROMPT;ofn.lpstrDefExt=L"ini";if(GetSaveFileNameW(&ofn)){SaveConfig();if(CopyFileW(IniPath().c_str(),file,FALSE))MessageBoxW(hwnd,L"設定備份完成。",kAppName,MB_ICONINFORMATION);else MessageBoxW(hwnd,WinError().c_str(),kAppName,MB_ICONERROR);}}

void ToggleServer(HWND hwnd){
    if(gServerTransition.load()!=SERVER_TRANSITION_IDLE)return;
    if(gRunning){
        gServerTransition=SERVER_TRANSITION_STOPPING;
        UpdateTrayIconTip();
        InvalidateRect(hwnd,nullptr,TRUE);
        UpdateWindow(hwnd);
        StopServer();
        gServerTransition=SERVER_TRANSITION_IDLE;
        UpdateTrayIconTip();
        InvalidateRect(hwnd,nullptr,TRUE);
        UpdateWindow(hwnd);
        return;
    }
    if(!IsElevated()){
        if(MessageBoxW(hwnd,T(L"WireGuard Adapter 需要系統管理員權限。\n\n是否以系統管理員身分重新啟動？",
                               L"WireGuard Adapter requires administrator rights.\n\nRestart as administrator?").c_str(),
                       kAppName,MB_YESNO|MB_ICONQUESTION)==IDYES&&RelaunchElevated()){
            gExitRequested=true;
            PostMessageW(hwnd,WM_CLOSE,0,0);
        }
        return;
    }
    if(!CoreRuntimeReady()){
        MessageBoxW(hwnd,
            gDllDownloading ? T(L"WireGuard 核心正在自動下載，完成後再試一次。",L"WireGuard core is downloading; try again when complete.").c_str()
                            : (IsWindows7OrEarlier()
                                ? T(L"缺少 Win7 核心：tunnel-win7.dll / wintun.dll。程式將自動下載。",L"Missing Win7 core: tunnel-win7.dll / wintun.dll. EasyWG will download them automatically.").c_str()
                                : T(L"缺少 wireguard.dll。程式將自動從 WireGuard 官方下載站取得。",L"Missing wireguard.dll. EasyWG will download it automatically.").c_str()),
            kAppName,MB_ICONINFORMATION);
        return;
    }
    ServerSettings ss;{std::lock_guard<std::mutex>lk(gDataMutex);ss=gSettings;}
    if(ss.lanAccessMode==L"nat"&&!WinDivertRuntimeReady()){
        const wchar_t* msg = gWinDivertDownloading
            ? L"WinDivert Runtime 正在準備中，完成後再試一次。"
            : (IsWindows7OrEarlier()
                ? L"Windows 7 NAT 模式需要 WinDivert 2.2.0-C Runtime。程式將自動下載並切換至已實測無警告的 C 版。"
                : L"NAT 模式需要 WinDivert Runtime。程式將自動從官方下載。");
        MessageBoxW(hwnd,msg,kAppName,MB_ICONINFORMATION);return;}

    gServerTransition=SERVER_TRANSITION_STARTING;
    UpdateTrayIconTip();
    InvalidateRect(hwnd,nullptr,TRUE);
    UpdateWindow(hwnd);
    std::wstring err;
    const bool ok=StartServer(err);
    gServerTransition=SERVER_TRANSITION_IDLE;
    UpdateTrayIconTip();
    InvalidateRect(hwnd,nullptr,TRUE);
    UpdateWindow(hwnd);
    if(!ok)MessageBoxW(hwnd,err.c_str(),kAppName,MB_ICONERROR);
}

void RestartServerUi(HWND hwnd){
    if(gServerTransition.load()!=SERVER_TRANSITION_IDLE)return;
    if(!gRunning){
        ToggleServer(hwnd);
        return;
    }

    gServerTransition=SERVER_TRANSITION_STOPPING;
    UpdateTrayIconTip();
    InvalidateRect(hwnd,nullptr,TRUE);
    UpdateWindow(hwnd);
    StopServer();

    gServerTransition=SERVER_TRANSITION_STARTING;
    UpdateTrayIconTip();
    InvalidateRect(hwnd,nullptr,TRUE);
    UpdateWindow(hwnd);

    std::wstring err;
    const bool ok=StartServer(err);
    gServerTransition=SERVER_TRANSITION_IDLE;
    UpdateTrayIconTip();
    InvalidateRect(hwnd,nullptr,TRUE);
    UpdateWindow(hwnd);
    if(!ok)MessageBoxW(hwnd,err.c_str(),kAppName,MB_ICONERROR);
}

void StartDllBootstrap(HWND hwnd){
    if(CoreRuntimeReady()||gDllDownloading.exchange(true))return;
    AddLog(IsWindows7OrEarlier()?L"缺少 Windows 7 Legacy Core，開始下載 tunnel-win7.dll + Wintun 0.13…":L"缺少 wireguard.dll，開始從官方下載站取得…");
    InvalidateRect(hwnd,nullptr,TRUE);
    std::thread([hwnd]{
        std::wstring err;
        bool ok=IsWindows7OrEarlier()?DownloadLegacyWin7Core(err):DownloadOfficialWireGuardDll(err);
        if(!ok)AddLog(T(L"WireGuard 核心自動下載失敗: ",L"WireGuard core download failed: ")+err);
        gDllDownloading=false;
        PostMessageW(hwnd,WM_APP_DLL_READY,ok?1:0,0);
    }).detach();
}

void StartWinDivertBootstrap(HWND hwnd){
    if(WinDivertRuntimeReady()||gWinDivertDownloading.exchange(true))return;
    AddLog(IsWindows7OrEarlier()
        ? L"Windows 7：準備下載並切換至 WinDivert 2.2.0-C Runtime…"
        : L"缺少 WinDivert Runtime，開始從官方下載…");
    InvalidateRect(hwnd,nullptr,TRUE);
    std::thread([hwnd]{std::wstring err;bool ok=DownloadOfficialWinDivertRuntime(err);if(!ok)AddLog(L"WinDivert 自動下載失敗: "+err);gWinDivertDownloading=false;PostMessageW(hwnd,WM_APP_WD_READY,ok?1:0,0);}).detach();
}

LRESULT CALLBACK MainProc(HWND hwnd,UINT msg,WPARAM wp,LPARAM lp){
    switch(msg){
    case WM_CREATE:{
        gMainWnd=hwnd;
        AddTrayIcon(hwnd);
        int quickIds[4]={IDI_QUICK_ADD_USER,IDI_QUICK_QR,IDI_QUICK_EXPORT,IDI_QUICK_BACKUP};
        for(int i=0;i<4;++i)gQuickActionIcons[i]=(HICON)LoadImageW(GetModuleHandleW(nullptr),MAKEINTRESOURCEW(quickIds[i]),IMAGE_ICON,64,64,LR_DEFAULTCOLOR);
        ApplyThemePalette();
        ApplyWindowDarkMode(hwnd);
        CreateSettingsControls(hwnd);
        CreateInlineAddControls(hwnd);
        gDashScroll=CreateWindowExW(0,L"SCROLLBAR",nullptr,WS_CHILD|SBS_VERT,0,0,16,100,hwnd,(HMENU)(INT_PTR)IDC_DASH_SCROLL,nullptr,nullptr);
        gUsersScroll=CreateWindowExW(0,L"SCROLLBAR",nullptr,WS_CHILD|SBS_VERT,0,0,16,100,hwnd,(HMENU)(INT_PTR)IDC_USERS_SCROLL,nullptr,nullptr);
        gInlineAddVisible=true;
        ShowSettingsControls(false);
        LayoutInlineAddControls(hwnd);
        SetTimer(hwnd,TIMER_STATS,1000,nullptr);
        StartDllBootstrap(hwnd);
        StartWinDivertBootstrap(hwnd);

        // Refresh current public IP on every launch. Only the first run auto-fills Endpoint.
        std::thread([hwnd]{
            std::wstring ip,err;
            bool ok=DetectPublicIpv4(ip,err);
            if(ok){
                {std::lock_guard<std::mutex> lk(gPublicIpMutex);gCurrentPublicIp=ip;}
                bool fill=false;
                {
                    std::lock_guard<std::mutex> lk(gDataMutex);
                    if(gNeedInitialEndpointDetect&&Trim(gSettings.endpoint).empty()){
                        gSettings.endpoint=ip;
                        fill=true;
                    }
                }
                if(fill){
                    SaveConfig();
                    AddLog(T(L"首次執行已自動填入公網 IP: ",L"First run: detected public IP: ")+ip);
                }else{
                    AddLog(T(L"目前公網 IP: ",L"Current public IP: ")+ip);
                }
            }else{
                AddLog(T(L"公網 IP 偵測失敗: ",L"Public IP detection failed: ")+err);
            }
            PostMessageW(hwnd,WM_APP_PUBLIC_IP_READY,ok?1:0,0);
        }).detach();

        ServerSettings st;{std::lock_guard<std::mutex>lk(gDataMutex);st=gSettings;}
        if(st.autoStartServer){
            gAutoStartRetry=0;
            PostMessageW(hwnd,WM_APP_AUTOSTART_SERVER,0,0);
        }
        return 0;
    }

    case WM_TIMER:
        if(wp==TIMER_STATS){
            RefreshStats();
            InvalidateRect(hwnd,nullptr,FALSE);
        }
        return 0;

    case WM_APP_PUBLIC_IP_READY:
        if(gPage==2&&!gSettingsDirty)LoadSettingsControls();
        InvalidateRect(hwnd,nullptr,TRUE);
        return 0;

    case WM_APP_DLL_READY:
        if(wp)AddLog(IsWindows7OrEarlier()?T(L"Windows 7 Legacy Core 就緒",L"Windows 7 legacy core ready"):T(L"WireGuard DLL 就緒",L"WireGuard DLL ready"));
        else MessageBoxW(hwnd,
                         T(L"WireGuard 核心自動下載失敗。請查看『日誌』頁。\n\nWin7 需要 tunnel-win7.dll + wintun.dll；Win10/11 需要 wireguard.dll。",
                           L"Automatic WireGuard core download failed. Check Logs.\n\nWin7 needs tunnel-win7.dll + wintun.dll; Win10/11 needs wireguard.dll.").c_str(),
                         kAppName,MB_ICONWARNING);
        InvalidateRect(hwnd,nullptr,TRUE);
        return 0;

    case WM_APP_WD_READY:
        if(wp)AddLog(T(L"WinDivert Native NAT Runtime 就緒",L"WinDivert Native NAT runtime ready"));
        else MessageBoxW(hwnd,
                         T(L"WinDivert Runtime 自動下載失敗。請查看『日誌』頁。\n\nNative NAT 暫時無法啟動。",
                           L"Automatic WinDivert Runtime download failed. Check Logs.\n\nNative NAT cannot start until the runtime is available.").c_str(),
                         kAppName,MB_ICONWARNING);
        InvalidateRect(hwnd,nullptr,TRUE);
        return 0;

    case WM_APP_AUTOSTART_SERVER:{
        ServerSettings st;{std::lock_guard<std::mutex>lk(gDataMutex);st=gSettings;}
        if(!st.autoStartServer||gRunning)return 0;
        if(!IsElevated()){
            if(RelaunchElevated()){
                gExitRequested=true;
                PostMessageW(hwnd,WM_CLOSE,0,0);
            }else{
                AddLog(T(L"自動啟動伺服器失敗：無法取得管理員權限",
                         L"Auto-start server failed: administrator rights unavailable"));
            }
            return 0;
        }
        bool ready=CoreRuntimeReady()&&
                   (st.lanAccessMode!=L"nat"||WinDivertRuntimeReady());
        if(!ready){
            if(gAutoStartRetry++<20){
                std::thread([hwnd]{
                    Sleep(1000);
                    if(IsWindow(hwnd))PostMessageW(hwnd,WM_APP_AUTOSTART_SERVER,0,0);
                }).detach();
            }else{
                AddLog(T(L"自動啟動伺服器逾時：Runtime 尚未就緒",
                         L"Auto-start server timed out: runtime files are not ready"));
            }
            return 0;
        }
        gServerTransition=SERVER_TRANSITION_STARTING;
        UpdateTrayIconTip();
        InvalidateRect(hwnd,nullptr,TRUE);
        UpdateWindow(hwnd);
        std::wstring err;
        const bool ok=StartServer(err);
        gServerTransition=SERVER_TRANSITION_IDLE;
        UpdateTrayIconTip();
        if(!ok){
            AddLog(T(L"自動啟動伺服器失敗: ",L"Auto-start server failed: ")+err);
        }else{
            AddLog(T(L"已依設定自動啟動伺服器",L"Server started automatically"));
        }
        InvalidateRect(hwnd,nullptr,TRUE);
        return 0;
    }

    case WM_APP_TRAY:{
        UINT ev=static_cast<UINT>(LOWORD(lp));
        if(ev==0)ev=static_cast<UINT>(lp);
        if(ev==WM_LBUTTONUP||ev==WM_LBUTTONDBLCLK){
            ShowMainWindow(hwnd);
            return 0;
        }
        if(ev==WM_RBUTTONUP||ev==WM_CONTEXTMENU){
            ShowTrayMenu(hwnd);
            return 0;
        }
        return 0;
    }

    case WM_DRAWITEM:{
        auto* dis=reinterpret_cast<DRAWITEMSTRUCT*>(lp);
        if(dis && (dis->CtlID==IDC_ADD_CREATE||dis->CtlID==IDC_ADD_SAVE_QR||dis->CtlID==IDC_ADD_SAVE_CONFIG)){
            bool disabled=(dis->itemState&ODS_DISABLED)!=0;
            bool pressed=(dis->itemState&ODS_SELECTED)!=0;
            COLORREF fill=disabled?C(0xAFC4E7):(pressed?C(0x0F55C8):CLR_BLUE);
            COLORREF border=disabled?C(0xAFC4E7):fill;
            RectI r{dis->rcItem.left,dis->rcItem.top,dis->rcItem.right-dis->rcItem.left,dis->rcItem.bottom-dis->rcItem.top};
            RoundFill(dis->hDC,r,fill,border,8);
            wchar_t text[256]{};GetWindowTextW(dis->hwndItem,text,_countof(text));
            Text(dis->hDC,text,r.x+8,r.y,r.w-16,r.h,gFonts.bold,RGB(255,255,255),DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
            if(dis->itemState&ODS_FOCUS){RECT fr{r.x+3,r.y+3,r.x+r.w-3,r.y+r.h-3};DrawFocusRect(dis->hDC,&fr);}
            return TRUE;
        }
        break;
    }

    case WM_COMMAND:{
        int id=LOWORD(wp),code=HIWORD(wp);
        if(id==IDC_ADD_CREATE&&code==BN_CLICKED){
            std::wstring name=ReadCtl(gAddNameEdit),oct=ReadCtl(gAddOctetEdit);int n=0;
            try{n=std::stoi(oct);}catch(...){n=0;}
            if(n<2||n>254){MessageBoxW(hwnd,T(L"VPN IP 最後一碼請輸入 2～254。",L"Enter a VPN IP last octet from 2 to 254.").c_str(),kAppName,MB_ICONWARNING);return 0;}
            std::wstring ip=VpnPrefix3()+std::to_wstring(n);size_t idx=0;
            const bool fullTunnel=gAddFullTunnelCheck&&
                SendMessageW(gAddFullTunnelCheck,BM_GETCHECK,0,0)==BST_CHECKED;
            if(CreatePeerRecord(hwnd,name,ip,fullTunnel,&idx)){
                gAddPanelPeerIndex=(int)idx;std::string err;gAddPanelQr={};
                if(!miniqr::EncodeUtf8(WideToUtf8(BuildPeerConfigText(idx)),gAddPanelQr,err))AddLog(T(L"新增後 QR 產生失敗: ",L"QR generation after add failed: ")+Utf8ToWide(err));
                RefreshAddPanelDefaults();
                if(gAddCreateBtn)SetWindowTextW(gAddCreateBtn,T(L"再新增一位用戶",L"Add Another User").c_str());
                LayoutInlineAddControls(hwnd);InvalidateRect(hwnd,nullptr,TRUE);
            }
            return 0;
        }
        if(id==IDC_ADD_SAVE_QR&&code==BN_CLICKED&&gAddPanelPeerIndex>=0){SavePeerQrBmp(hwnd,(size_t)gAddPanelPeerIndex);return 0;}
        if(id==IDC_ADD_SAVE_CONFIG&&code==BN_CLICKED&&gAddPanelPeerIndex>=0){ExportPeerConfig(hwnd,(size_t)gAddPanelPeerIndex);return 0;}
        if(id>=IDC_SET_BASE&&id<IDC_SET_BASE+6&&code==EN_CHANGE){
            if(!gSettingsLoading)gSettingsDirty=true;
            return 0;
        }
        if((id==IDC_SET_LANGUAGE||id==IDC_SET_THEME)&&code==CBN_SELCHANGE){
            if(!gSettingsLoading)gSettingsDirty=true;
            return 0;
        }
        if((id==IDC_SET_CLOSE_TO_TRAY||id==IDC_SET_START_WINDOWS||id==IDC_SET_AUTO_SERVER)&&code==BN_CLICKED){
            if(!gSettingsLoading)gSettingsDirty=true;
            return 0;
        }
        if(id==IDC_SET_SAVE&&code==BN_CLICKED){
            SaveSettingsInline(hwnd);
            return 0;
        }

        if(id==IDM_TRAY_SHOW){
            ShowMainWindow(hwnd);
            return 0;
        }
        if(id==IDM_TRAY_TOGGLE){
            ToggleServer(hwnd);
            return 0;
        }
        if(id==IDM_TRAY_EXIT){
            gExitRequested=true;
            PostMessageW(hwnd,WM_CLOSE,0,0);
            return 0;
        }
        break;
    }

    case WM_CTLCOLOREDIT:{
        HDC dc=(HDC)wp;SetTextColor(dc,CLR_TEXT);SetBkColor(dc,CLR_INPUT);return (LRESULT)gThemeInputBrush;
    }
    case WM_CTLCOLORLISTBOX:{
        HDC dc=(HDC)wp;SetTextColor(dc,CLR_TEXT);SetBkColor(dc,CLR_INPUT);return (LRESULT)gThemeInputBrush;
    }
    case WM_CTLCOLORSTATIC:{
        HDC dc=(HDC)wp;SetTextColor(dc,CLR_TEXT);SetBkColor(dc,CLR_CARD);return (LRESULT)gThemeCardBrush;
    }
    case WM_CTLCOLORBTN:{
        HDC dc=(HDC)wp;HWND ctl=(HWND)lp;
        if(ctl==gAddFullTunnelCheck){
            SetBkMode(dc,TRANSPARENT);
            SetTextColor(dc,gDarkTheme?C(0xA99CFF):C(0x4F46C8));
            return (LRESULT)gThemeCardBrush;
        }
        if(ctl==gSetCloseToTray||ctl==gSetStartWindows||ctl==gSetAutoServer){
            SetTextColor(dc,CLR_TEXT);SetBkColor(dc,CLR_CARD);return (LRESULT)gThemeCardBrush;
        }
        SetTextColor(dc,CLR_TEXT);SetBkColor(dc,CLR_CARD);return (LRESULT)gThemeCardBrush;
    }
    case WM_SETTINGCHANGE:{
        ServerSettings st;{std::lock_guard<std::mutex>lk(gDataMutex);st=gSettings;}
        if(st.theme==L"system"){ApplyThemePalette();ApplyWindowDarkMode(hwnd);InvalidateRect(hwnd,nullptr,TRUE);}
        return 0;
    }

    case WM_ERASEBKGND:
        return 1;

    case WM_PAINT:{
        PAINTSTRUCT ps{};HDC dc=BeginPaint(hwnd,&ps);
        RECT rc{};GetClientRect(hwnd,&rc);int w=rc.right,h=rc.bottom;
        HDC mem=CreateCompatibleDC(dc);
        HBITMAP bmp=CreateCompatibleBitmap(dc,w,h);
        HGDIOBJ old=SelectObject(mem,bmp);
        FillRectC(mem,{0,0,w,h},CLR_BG);
        DrawSidebar(mem,h);
        if(gPage==0)DrawDashboard(mem,w,h);else DrawSimplePage(mem,w,h,gPage);
        DrawBottomStatusBar(mem,w,h);
        BitBlt(dc,0,0,w,h,mem,0,0,SRCCOPY);
        SelectObject(mem,old);DeleteObject(bmp);DeleteDC(mem);
        EndPaint(hwnd,&ps);
        return 0;
    }

    case WM_LBUTTONUP:{
        int x=GET_X_LPARAM(lp),y=GET_Y_LPARAM(lp);

        // These custom-drawn sidebar controls are available on every page.
        if(PtIn(gSidebarRestartBtn,x,y)){
            RestartServerUi(hwnd);
            return 0;
        }
        if(PtIn(gSidebarToggleBtn,x,y)){
            ToggleServer(hwnd);
            return 0;
        }

        for(size_t i=0;i<gNavRects.size();++i){
            if(PtIn(gNavRects[i],x,y)){
                int next=(int)i;
                if(next==gPage)return 0;
                if(!ConfirmLeaveDirtySettings(hwnd))return 0;
                ShowSettingsControls(false);
                gPage=next;
                UpdatePeerScrollbars(5,16);
                LayoutInlineAddControls(hwnd);
                if(gPage==2){
                    LoadSettingsControls();
                    ShowSettingsControls(true);
                    LayoutSettingsControls(hwnd);
                }
                InvalidateRect(hwnd,nullptr,TRUE);
                return 0;
            }
        }

        if(gPage==0){
            if(PtIn(gStartStopBtn,x,y)){ToggleServer(hwnd);return 0;}
            if(PtIn(gQuickAdd,x,y)){AddPeerUi(hwnd);return 0;}
            if(PtIn(gExportBtn,x,y)||PtIn(gQuickExport,x,y)){ExportChosenPeer(hwnd);return 0;}
            if(PtIn(gRestartBtn,x,y)){RefreshStats();InvalidateRect(hwnd,nullptr,TRUE);return 0;}
            if(PtIn(gQuickQr,x,y)){ShowChosenPeerQr(hwnd);return 0;}
            if(PtIn(gQuickBackup,x,y)){BackupConfig(hwnd);return 0;}
            for(size_t i=0;i<gDashboardPeerActionRects.size();++i){
                if(PtIn(gDashboardPeerActionRects[i],x,y)){
                    if(i<gDashboardPeerRowIndices.size())ShowPeerActionMenu(hwnd,gDashboardPeerRowIndices[i]);
                    return 0;
                }
            }
        }else if(gPage==1){
            if(PtIn(gAddPeerBtn,x,y)){AddPeerUi(hwnd);return 0;}
            if(PtIn(gUserExportBtn,x,y)){ExportChosenPeer(hwnd);return 0;}
            if(PtIn(gUserQrBtn,x,y)){ShowChosenPeerQr(hwnd);return 0;}
            for(size_t i=0;i<gUserPeerActionRects.size();++i){
                if(PtIn(gUserPeerActionRects[i],x,y)){
                    if(i<gUserPeerRowIndices.size())ShowPeerActionMenu(hwnd,gUserPeerRowIndices[i]);
                    return 0;
                }
            }
        }else if(gPage==5&&PtIn(gGitHubBtn,x,y)){
            ShellExecuteW(hwnd,L"open",
                          L"https://github.com/Terence0816/easy-wireguard-server",
                          nullptr,nullptr,SW_SHOWNORMAL);
            return 0;
        }
        return 0;
    }

    case WM_VSCROLL:{
        HWND src=(HWND)lp;
        int* pos=nullptr;int visible=1;
        if(src==gDashScroll){pos=&gDashScrollOffset;visible=5;}
        else if(src==gUsersScroll){
            RECT rc{};GetClientRect(hwnd,&rc);visible=(std::min)(16,(std::max)(1,(static_cast<int>(rc.bottom)-204)/48));pos=&gUsersScrollOffset;
        }
        if(pos){
            size_t count=0;{std::lock_guard<std::mutex>lk(gDataMutex);count=gPeers.size();}
            int maxPos=(std::max)(0,(int)count-visible);
            int code=LOWORD(wp),track=HIWORD(wp),next=*pos;
            if(code==SB_LINEUP)next--;else if(code==SB_LINEDOWN)next++;else if(code==SB_PAGEUP)next-=visible;else if(code==SB_PAGEDOWN)next+=visible;
            else if(code==SB_THUMBPOSITION||code==SB_THUMBTRACK)next=track;else if(code==SB_TOP)next=0;else if(code==SB_BOTTOM)next=maxPos;
            *pos=std::clamp(next,0,maxPos);
            SetScrollPos(src,SB_CTL,*pos,TRUE);InvalidateRect(hwnd,nullptr,FALSE);return 0;
        }
        break;
    }

    case WM_MOUSEWHEEL:{
        int delta=GET_WHEEL_DELTA_WPARAM(wp);
        if(gPage==0&&IsWindowVisible(gDashScroll)){gDashScrollOffset=(std::max)(0,gDashScrollOffset-(delta/WHEEL_DELTA));InvalidateRect(hwnd,nullptr,FALSE);return 0;}
        if(gPage==1&&IsWindowVisible(gUsersScroll)){gUsersScrollOffset=(std::max)(0,gUsersScrollOffset-(delta/WHEEL_DELTA));InvalidateRect(hwnd,nullptr,FALSE);return 0;}
        break;
    }

    case WM_SIZE:{
        LayoutSettingsControls(hwnd);
        LayoutInlineAddControls(hwnd);
        RECT rc{};GetClientRect(hwnd,&rc);
        int panelReserve=390,contentW=rc.right-panelReserve,x=238,top=22,right=12;
        RectI users{x,top+281,contentW-x-right,326};
        if(gDashScroll)MoveWindow(gDashScroll,users.x+users.w-17,users.y+92,16,225,TRUE);
        RectI userCard{250,22,rc.right-250-20,rc.bottom-82};
        if(gUsersScroll)MoveWindow(gUsersScroll,userCard.x+userCard.w-17,userCard.y+98,16,(std::max)(80,userCard.h-122),TRUE);
        InvalidateRect(hwnd,nullptr,TRUE);
        return 0;
    }

    case WM_CLOSE:{
        ServerSettings st;{std::lock_guard<std::mutex>lk(gDataMutex);st=gSettings;}
        if(!gExitRequested&&st.closeToTray){
            ShowWindow(hwnd,SW_HIDE);
            AddLog(T(L"主視窗已隱藏至系統列",L"Main window hidden to system tray"));
            return 0;
        }
        if(!ConfirmLeaveDirtySettings(hwnd)){
            gExitRequested=false;
            return 0;
        }
        if(gRunning&&MessageBoxW(hwnd,
            T(L"退出程式會停止目前的 WireGuard Server。\n\n確定要退出？",
              L"Exiting the app will stop the current WireGuard Server.\n\nExit now?").c_str(),
            kAppName,MB_YESNO|MB_ICONQUESTION)!=IDYES){
            gExitRequested=false;
            return 0;
        }
        DestroyWindow(hwnd);
        return 0;
    }

    case WM_DESTROY:
        KillTimer(hwnd,TIMER_STATS);
        for(HICON &ic:gQuickActionIcons){if(ic){DestroyIcon(ic);ic=nullptr;}}
        RemoveTrayIcon();
        if(gThemeBgBrush){DeleteObject(gThemeBgBrush);gThemeBgBrush=nullptr;}
        if(gThemeCardBrush){DeleteObject(gThemeCardBrush);gThemeCardBrush=nullptr;}
        if(gThemeInputBrush){DeleteObject(gThemeInputBrush);gThemeInputBrush=nullptr;}
        if(gThemeSubtleBrush){DeleteObject(gThemeSubtleBrush);gThemeSubtleBrush=nullptr;}
        StopServer();
        gWg.Unload();
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd,msg,wp,lp);
}

} // namespace

int WINAPI wWinMain(HINSTANCE hInst,HINSTANCE,LPWSTR,int nCmdShow){
    int argc=0;
    LPWSTR* argv=CommandLineToArgvW(GetCommandLineW(),&argc);
    if(argv&&argc>=3&&_wcsicmp(argv[1],L"/legacy-service")==0){
        std::wstring cfg=argv[2];
        DWORD parentPid=0;
        if(argc>=4) parentPid=wcstoul(argv[3],nullptr,10);
        LocalFree(argv);
        return RunLegacyTunnelServiceMode(cfg,parentPid);
    }
    if(argv)LocalFree(argv);

    gSingleInstanceMutex=CreateMutexW(nullptr,FALSE,kSingleInstanceMutexName);
    if(gSingleInstanceMutex&&GetLastError()==ERROR_ALREADY_EXISTS){
        HWND existing=FindWindowW(kMainClass,nullptr);
        if(existing){
            ShowWindow(existing,SW_SHOW);
            if(IsIconic(existing))ShowWindow(existing,SW_RESTORE);
            SetForegroundWindow(existing);
        }
        CloseHandle(gSingleInstanceMutex);
        gSingleInstanceMutex=nullptr;
        return 0;
    }

    SetProcessDPIAware();
    WSADATA wsa{};WSAStartup(MAKEWORD(2,2),&wsa);
    gFonts.Create();

    gFirstRun=!PathFileExistsW(IniPath().c_str());
    LoadConfig();
    if(gFirstRun){
        std::wstring lanIp,lanCidr;
        if(DetectPrimaryLan(lanIp,lanCidr)&&!lanCidr.empty()){
            std::lock_guard<std::mutex>lk(gDataMutex);
            gSettings.lanSubnet=lanCidr;
        }
        gNeedInitialEndpointDetect=true;
    }
    SaveConfig();
    AddLog(T(L"EasyWG Server 啟動",L"EasyWG Server started"));

    gAppIcon=(HICON)LoadImageW(hInst,MAKEINTRESOURCEW(IDI_EASYWG),IMAGE_ICON,32,32,LR_DEFAULTCOLOR);
    gAppIconSmall=(HICON)LoadImageW(hInst,MAKEINTRESOURCEW(IDI_EASYWG),IMAGE_ICON,16,16,LR_DEFAULTCOLOR);
    if(!gAppIcon)gAppIcon=LoadIcon(nullptr,IDI_APPLICATION);
    if(!gAppIconSmall)gAppIconSmall=gAppIcon;

    WNDCLASSEXW mc{};mc.cbSize=sizeof(mc);mc.hInstance=hInst;mc.lpfnWndProc=MainProc;mc.lpszClassName=kMainClass;mc.hCursor=LoadCursor(nullptr,IDC_ARROW);mc.hIcon=gAppIcon;mc.hIconSm=gAppIconSmall;mc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);mc.style=CS_DBLCLKS;RegisterClassExW(&mc);
    WNDCLASSEXW dc{};dc.cbSize=sizeof(dc);dc.hInstance=hInst;dc.lpfnWndProc=ModalProc;dc.lpszClassName=kModalClass;dc.hCursor=LoadCursor(nullptr,IDC_ARROW);dc.hIcon=gAppIcon;dc.hIconSm=gAppIconSmall;dc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);RegisterClassExW(&dc);
    WNDCLASSEXW qc{};qc.cbSize=sizeof(qc);qc.hInstance=hInst;qc.lpfnWndProc=QrProc;qc.lpszClassName=kQrClass;qc.hCursor=LoadCursor(nullptr,IDC_ARROW);qc.hIcon=gAppIcon;qc.hIconSm=gAppIconSmall;qc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);RegisterClassExW(&qc);

    int sw=GetSystemMetrics(SM_CXSCREEN),sh=GetSystemMetrics(SM_CYSCREEN);int w=(std::min)(1500,sw-80),h=(std::min)(980,sh-80);if(w<1100)w=1100;if(h<760)h=760;
    HWND hwnd=CreateWindowExW(0,kMainClass,kAppName,WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,(sw-w)/2,(sh-h)/2,w,h,nullptr,nullptr,hInst,nullptr);
    if(!hwnd){if(gSingleInstanceMutex){CloseHandle(gSingleInstanceMutex);gSingleInstanceMutex=nullptr;}gFonts.Destroy();WSACleanup();return 1;}ShowWindow(hwnd,nCmdShow);UpdateWindow(hwnd);
    MSG msg{};while(GetMessageW(&msg,nullptr,0,0)>0){TranslateMessage(&msg);DispatchMessageW(&msg);}if(gSingleInstanceMutex){CloseHandle(gSingleInstanceMutex);gSingleInstanceMutex=nullptr;}gFonts.Destroy();WSACleanup();return static_cast<int>(msg.wParam);
}
