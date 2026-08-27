#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <commdlg.h>
#include <objidl.h>
#include <gdiplus.h>
#include <shellapi.h>
#include <shlobj.h>
#include <wincrypt.h>
#include <cryptuiapi.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "codec.hpp"
#include "resources.hpp"

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Gdiplus.lib")
#pragma comment(lib, "Comdlg32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Cryptui.lib")

namespace {

constexpr uint16_t PORT = 18088;
constexpr size_t MAX_HEADER = 16 * 1024;
constexpr size_t MAX_BODY = 64 * 1024;
constexpr DWORD HELPER_TIMEOUT_MS = 30000;
constexpr UINT WM_TRAY = WM_APP + 1;
constexpr UINT WM_SERVER_ERROR = WM_APP + 2;
constexpr UINT ID_TRAY_SETTINGS = 1001;
constexpr UINT ID_TRAY_STATUS = 1002;
constexpr UINT ID_TRAY_EXIT = 1003;
constexpr UINT ID_DLL_EDIT = 2001;
constexpr UINT ID_DLL_BROWSE = 2002;
constexpr UINT ID_DEVICE_EDIT = 2003;
constexpr UINT ID_APPLICATION_EDIT = 2004;
constexpr UINT ID_CONTAINER_EDIT = 2005;
constexpr UINT ID_CONFIG_SAVE = 2006;
constexpr UINT ID_CONFIG_CLOSE = 2007;
constexpr UINT ID_CONFIG_PROBE = 2008;
constexpr UINT ID_ARCH_LABEL = 2009;
constexpr UINT ID_CONFIG_EXPORT_CERT = 2010;
constexpr UINT ID_TITLE_LABEL = 2011;
constexpr UINT ID_INFO_LABEL = 2012;
constexpr UINT ID_DLL_LABEL = 2013;
constexpr UINT ID_DEVICE_LABEL = 2014;
constexpr UINT ID_APPLICATION_LABEL = 2015;
constexpr UINT ID_CONTAINER_LABEL = 2016;
constexpr UINT ID_CERT_LIST = 3001;
constexpr UINT ID_CERT_DETAILS = 3002;
constexpr UINT ID_CERT_VIEW = 3003;
constexpr UINT ID_CERT_EXPORT = 3004;
constexpr UINT ID_CERT_CLOSE = 3005;
constexpr wchar_t REGISTRY_PATH[] = L"Software\\CryptoKit\\UKeyAgent";

struct Config {
    std::wstring dll_path;
    std::wstring device_name;
    std::wstring application_name;
    std::wstring container_name;
};

enum class DllArch { Unknown, X86, X64 };

std::atomic<bool> running{true};
SOCKET listen_socket = INVALID_SOCKET;
std::mutex config_mutex;
Config current_config;
std::wstring app_directory;
std::wstring helper_x86_path;
std::wstring helper_x64_path;
HWND tray_window = nullptr;
HWND settings_window = nullptr;
HWND certificate_window = nullptr;
HICON app_icon = nullptr;
ULONG_PTR gdiplus_token = 0;
UINT taskbar_created_message = 0;
std::thread http_thread;

struct CertificateEntry {
    std::wstring title;
    std::vector<uint8_t> der;
    std::wstring details;
    bool signing = true;
};

std::vector<CertificateEntry> certificates;

std::vector<uint8_t> resource_data(int identifier) {
    HRSRC resource = FindResourceW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(identifier),
                                   MAKEINTRESOURCEW(10));
    if (!resource) throw std::runtime_error("embedded resource is missing");
    HGLOBAL loaded = LoadResource(GetModuleHandleW(nullptr), resource);
    DWORD size = SizeofResource(GetModuleHandleW(nullptr), resource);
    const auto *data = static_cast<const uint8_t *>(LockResource(loaded));
    if (!loaded || !data || size == 0) throw std::runtime_error("embedded resource is invalid");
    return std::vector<uint8_t>(data, data + size);
}

std::wstring helper_storage_directory() {
    std::array<wchar_t, MAX_PATH> local{};
    if (SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA | CSIDL_FLAG_CREATE, nullptr,
                         SHGFP_TYPE_CURRENT, local.data()) != S_OK)
        throw std::runtime_error("cannot locate local application data");
    std::wstring root = std::wstring(local.data()) + L"\\CryptoKit";
    CreateDirectoryW(root.c_str(), nullptr);
    root += L"\\UKeyAgent";
    CreateDirectoryW(root.c_str(), nullptr);
    root += L"\\1.1.4";
    CreateDirectoryW(root.c_str(), nullptr);
    return root;
}

void extract_resource_file(int identifier, const std::wstring &path) {
    std::vector<uint8_t> data = resource_data(identifier);
    std::wstring temporary = path + L".tmp";
    HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, nullptr);
    if (file == INVALID_HANDLE_VALUE) throw std::runtime_error("cannot prepare embedded helper");
    size_t offset = 0;
    while (offset < data.size()) {
        DWORD written = 0;
        DWORD chunk = static_cast<DWORD>(std::min<size_t>(data.size() - offset, 1024 * 1024));
        if (!WriteFile(file, data.data() + offset, chunk, &written, nullptr) || written == 0) {
            CloseHandle(file);
            DeleteFileW(temporary.c_str());
            throw std::runtime_error("cannot write embedded helper");
        }
        offset += written;
    }
    CloseHandle(file);
    if (!MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(temporary.c_str());
        throw std::runtime_error("cannot activate embedded helper");
    }
    SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
}

std::wstring exe_directory() {
    std::vector<wchar_t> path(32768);
    DWORD size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (size == 0 || size >= path.size()) throw std::runtime_error("cannot resolve executable path");
    std::wstring value(path.data(), size);
    size_t slash = value.find_last_of(L"\\/");
    return slash == std::wstring::npos ? L"." : value.substr(0, slash);
}

std::string wide_to_utf8(const std::wstring &value) {
    if (value.empty()) return {};
    int count = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                                    nullptr, 0, nullptr, nullptr);
    if (count <= 0) throw std::runtime_error("text conversion failed");
    std::string out(static_cast<size_t>(count), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                        out.data(), count, nullptr, nullptr);
    return out;
}

std::wstring utf8_to_wide(const std::string &value) {
    if (value.empty()) return {};
    int count = MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (count <= 0) throw std::runtime_error("text conversion failed");
    std::wstring out(static_cast<size_t>(count), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), out.data(), count);
    return out;
}

std::string trim(std::string value) {
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) value.erase(value.begin());
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) value.pop_back();
    return value;
}

std::wstring registry_string(HKEY key, const wchar_t *name) {
    DWORD type = 0;
    DWORD bytes = 0;
    if (RegQueryValueExW(key, name, nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS ||
        (type != REG_SZ && type != REG_EXPAND_SZ) || bytes < sizeof(wchar_t)) return {};
    std::vector<wchar_t> buffer(bytes / sizeof(wchar_t) + 1, L'\0');
    if (RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<BYTE *>(buffer.data()), &bytes) != ERROR_SUCCESS)
        return {};
    return std::wstring(buffer.data());
}

Config load_config() {
    Config cfg;
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, REGISTRY_PATH, 0, KEY_READ, &key) == ERROR_SUCCESS) {
        cfg.dll_path = registry_string(key, L"SkfDll");
        cfg.device_name = registry_string(key, L"DeviceName");
        cfg.application_name = registry_string(key, L"ApplicationName");
        cfg.container_name = registry_string(key, L"ContainerName");
        RegCloseKey(key);
    }
    return cfg;
}

void set_registry_string(HKEY key, const wchar_t *name, const std::wstring &value) {
    const DWORD bytes = static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t));
    if (RegSetValueExW(key, name, 0, REG_SZ, reinterpret_cast<const BYTE *>(value.c_str()), bytes) != ERROR_SUCCESS)
        throw std::runtime_error("cannot save settings");
}

void save_config(const Config &cfg) {
    HKEY key = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, REGISTRY_PATH, 0, nullptr, 0, KEY_WRITE,
                        nullptr, &key, nullptr) != ERROR_SUCCESS)
        throw std::runtime_error("cannot open user settings");
    try {
        set_registry_string(key, L"SkfDll", cfg.dll_path);
        set_registry_string(key, L"DeviceName", cfg.device_name);
        set_registry_string(key, L"ApplicationName", cfg.application_name);
        set_registry_string(key, L"ContainerName", cfg.container_name);
    } catch (...) {
        RegCloseKey(key);
        throw;
    }
    RegCloseKey(key);
}

Config config_snapshot() {
    std::lock_guard<std::mutex> guard(config_mutex);
    return current_config;
}

DllArch detect_dll_architecture(const std::wstring &path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return DllArch::Unknown;
    IMAGE_DOS_HEADER dos{};
    file.read(reinterpret_cast<char *>(&dos), sizeof(dos));
    if (!file || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0) return DllArch::Unknown;
    file.seekg(dos.e_lfanew, std::ios::beg);
    DWORD signature = 0;
    IMAGE_FILE_HEADER header{};
    file.read(reinterpret_cast<char *>(&signature), sizeof(signature));
    file.read(reinterpret_cast<char *>(&header), sizeof(header));
    if (!file || signature != IMAGE_NT_SIGNATURE) return DllArch::Unknown;
    if (header.Machine == IMAGE_FILE_MACHINE_I386) return DllArch::X86;
    if (header.Machine == IMAGE_FILE_MACHINE_AMD64) return DllArch::X64;
    return DllArch::Unknown;
}

const wchar_t *architecture_text(DllArch arch) {
    if (arch == DllArch::X86) return L"32 位（x86）";
    if (arch == DllArch::X64) return L"64 位（x64）";
    return L"未识别";
}

std::wstring helper_for(const Config &cfg) {
    DllArch arch = detect_dll_architecture(cfg.dll_path);
    if (arch == DllArch::X86) return helper_x86_path;
    if (arch == DllArch::X64) return helper_x64_path;
    throw std::runtime_error("selected file is not an x86/x64 Windows DLL");
}

std::wstring quote_arg(const std::wstring &arg) {
    std::wstring out = L"\"";
    size_t backslashes = 0;
    for (wchar_t ch : arg) {
        if (ch == L'\\') ++backslashes;
        else if (ch == L'\"') {
            out.append(backslashes * 2 + 1, L'\\');
            out.push_back(L'\"');
            backslashes = 0;
        } else {
            out.append(backslashes, L'\\');
            backslashes = 0;
            out.push_back(ch);
        }
    }
    out.append(backslashes * 2, L'\\');
    out.push_back(L'\"');
    return out;
}

std::string run_helper(const Config &cfg, std::string &input) {
    if (cfg.dll_path.empty()) throw std::runtime_error("SKF DLL is not configured");
    if (GetFileAttributesW(cfg.dll_path.c_str()) == INVALID_FILE_ATTRIBUTES)
        throw std::runtime_error("configured SKF DLL does not exist");
    std::wstring helper_path = helper_for(cfg);
    if (GetFileAttributesW(helper_path.c_str()) == INVALID_FILE_ATTRIBUTES)
        throw std::runtime_error("matching helper executable is missing");

    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    HANDLE child_stdin_read = nullptr, parent_stdin_write = nullptr;
    HANDLE parent_stdout_read = nullptr, child_stdout_write = nullptr;
    if (!CreatePipe(&child_stdin_read, &parent_stdin_write, &security, 0) ||
        !SetHandleInformation(parent_stdin_write, HANDLE_FLAG_INHERIT, 0) ||
        !CreatePipe(&parent_stdout_read, &child_stdout_write, &security, 0) ||
        !SetHandleInformation(parent_stdout_read, HANDLE_FLAG_INHERIT, 0))
        throw std::runtime_error("cannot create helper pipes");

    std::string dll_utf8 = wide_to_utf8(cfg.dll_path);
    std::string dll_encoded = base64url_encode(
        reinterpret_cast<const uint8_t *>(dll_utf8.data()), dll_utf8.size());
    std::wstring command = quote_arg(helper_path) + L" --dll-base64url " + utf8_to_wide(dll_encoded);
    std::vector<wchar_t> command_line(command.begin(), command.end());
    command_line.push_back(L'\0');

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = child_stdin_read;
    startup.hStdOutput = child_stdout_write;
    startup.hStdError = child_stdout_write;
    PROCESS_INFORMATION process{};
    BOOL created = CreateProcessW(helper_path.c_str(), command_line.data(), nullptr, nullptr,
                                  TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process);
    CloseHandle(child_stdin_read);
    CloseHandle(child_stdout_write);
    if (!created) {
        CloseHandle(parent_stdin_write);
        CloseHandle(parent_stdout_read);
        throw std::runtime_error("cannot start helper: " + std::to_string(GetLastError()));
    }

    DWORD written = 0;
    size_t offset = 0;
    while (offset < input.size()) {
        DWORD chunk = static_cast<DWORD>(std::min<size_t>(input.size() - offset, 16384));
        if (!WriteFile(parent_stdin_write, input.data() + offset, chunk, &written, nullptr)) break;
        offset += written;
    }
    secure_clear(input);
    CloseHandle(parent_stdin_write);

    DWORD wait = WaitForSingleObject(process.hProcess, HELPER_TIMEOUT_MS);
    if (wait == WAIT_TIMEOUT) {
        TerminateProcess(process.hProcess, 124);
        WaitForSingleObject(process.hProcess, 5000);
    }
    std::string output;
    std::array<char, 2048> buffer{};
    DWORD read = 0;
    while (ReadFile(parent_stdout_read, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr) && read) {
        if (output.size() + read > MAX_BODY) break;
        output.append(buffer.data(), read);
    }
    CloseHandle(parent_stdout_read);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    if (wait == WAIT_TIMEOUT) return "{\"ok\":false,\"error\":\"helper_timeout\"}";
    if (output.empty()) return "{\"ok\":false,\"error\":\"helper_failed_or_crashed\"}";
    while (!output.empty() && (output.back() == '\r' || output.back() == '\n')) output.pop_back();
    return output;
}

std::string encoded_line(const std::wstring &value) {
    std::string utf8 = wide_to_utf8(value);
    return base64url_encode(reinterpret_cast<const uint8_t *>(utf8.data()), utf8.size());
}

std::string common_helper_input(const std::string &operation, const std::string &challenge,
                                const std::string &pin, const std::string &user_id,
                                const std::string &request_id, const Config &cfg,
                                const std::string &certificate_type = "") {
    auto encode = [](const std::string &value) {
        return base64url_encode(reinterpret_cast<const uint8_t *>(value.data()), value.size());
    };
    return operation + "\n" + challenge + "\n" + encode(pin) + "\n" + user_id + "\n" +
           encode(request_id) + "\n" + encoded_line(cfg.device_name) + "\n" +
           encoded_line(cfg.application_name) + "\n" + encoded_line(cfg.container_name) + "\n" +
           certificate_type + "\n";
}

struct HttpRequest {
    std::string method;
    std::string path;
    std::map<std::string, std::string> headers;
    std::string body;
};

std::string lower(std::string value) {
    for (char &ch : value) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    return value;
}

bool recv_request(SOCKET client, HttpRequest &request) {
    std::string data;
    std::array<char, 4096> buffer{};
    size_t header_end = std::string::npos;
    while ((header_end = data.find("\r\n\r\n")) == std::string::npos) {
        int count = recv(client, buffer.data(), static_cast<int>(buffer.size()), 0);
        if (count <= 0) return false;
        data.append(buffer.data(), count);
        if (data.size() > MAX_HEADER) return false;
    }
    std::istringstream head(data.substr(0, header_end));
    std::string line;
    if (!std::getline(head, line)) return false;
    if (!line.empty() && line.back() == '\r') line.pop_back();
    std::istringstream first(line);
    first >> request.method >> request.path;
    if (request.method.empty() || request.path.empty()) return false;
    while (std::getline(head, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        size_t colon = line.find(':');
        if (colon != std::string::npos)
            request.headers[lower(trim(line.substr(0, colon)))] = trim(line.substr(colon + 1));
    }
    size_t content_length = 0;
    auto it = request.headers.find("content-length");
    if (it != request.headers.end()) content_length = std::stoul(it->second);
    if (content_length > MAX_BODY) return false;
    request.body = data.substr(header_end + 4);
    while (request.body.size() < content_length) {
        int count = recv(client, buffer.data(), static_cast<int>(buffer.size()), 0);
        if (count <= 0) return false;
        request.body.append(buffer.data(), count);
        if (request.body.size() > MAX_BODY) return false;
    }
    request.body.resize(content_length);
    return true;
}

void send_all(SOCKET client, const std::string &data) {
    size_t offset = 0;
    while (offset < data.size()) {
        int count = send(client, data.data() + offset,
                         static_cast<int>(std::min<size_t>(data.size() - offset, 16384)), 0);
        if (count <= 0) break;
        offset += static_cast<size_t>(count);
    }
}

void respond(SOCKET client, int status, const std::string &reason, const std::string &body,
             const HttpRequest &request,
             const char *content_type = "application/json; charset=utf-8") {
    auto actual = request.headers.find("origin");
    std::string origin = actual == request.headers.end() ? "*" : actual->second;
    std::ostringstream out;
    out << "HTTP/1.1 " << status << ' ' << reason << "\r\n"
        << "Content-Type: " << content_type << "\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Access-Control-Allow-Origin: " << origin << "\r\n"
        << "Vary: Origin\r\n"
        << "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        << "Access-Control-Allow-Headers: Content-Type\r\n"
        << "Access-Control-Allow-Private-Network: true\r\n"
        << "Cache-Control: no-store\r\nConnection: close\r\n\r\n" << body;
    send_all(client, out.str());
}

std::string make_sign_input(std::string &body, const Config &cfg) {
    std::string challenge, pin, user_id, user_id_b64, request_id;
    if (!json_string(body, "challenge_base64url", challenge) || challenge.empty())
        throw std::runtime_error("challenge_base64url is required");
    if (!json_string(body, "pin", pin) || pin.empty())
        throw std::runtime_error("pin is required");
    json_string(body, "request_id", request_id);
    std::vector<uint8_t> challenge_bytes = base64url_decode(challenge);
    if (challenge_bytes.empty() || challenge_bytes.size() > 4096)
        throw std::runtime_error("challenge must contain 1..4096 bytes");
    if (pin.size() > 64) throw std::runtime_error("pin is too long");
    if (json_string(body, "user_id_base64url", user_id_b64)) {
        if (base64url_decode(user_id_b64).size() > 8192) throw std::runtime_error("user_id is too long");
    } else {
        if (!json_string(body, "user_id", user_id)) user_id = "1234567812345678";
        user_id_b64 = base64url_encode(reinterpret_cast<const uint8_t *>(user_id.data()), user_id.size());
    }
    std::string input = common_helper_input("sign", challenge, pin, user_id_b64, request_id, cfg);
    secure_clear(pin);
    secure_clear(body);
    return input;
}

std::string make_certificate_input(std::string &body, const Config &cfg) {
    std::string request_id, certificate_type;
    json_string(body, "request_id", request_id);
    if (!json_string(body, "certificate_type", certificate_type)) certificate_type = "sign";
    if (certificate_type != "sign" && certificate_type != "encrypt")
        throw std::runtime_error("certificate_type must be sign or encrypt");
    secure_clear(body);
    return common_helper_input("certificate", "", "", "", request_id, cfg, certificate_type);
}

void handle_client(SOCKET client) {
    HttpRequest request;
    Config cfg = config_snapshot();
    try {
        if (!recv_request(client, request)) {
            respond(client, 400, "Bad Request", "{\"ok\":false,\"error\":\"invalid_http_request\"}", request);
        } else if (request.method == "OPTIONS") {
            respond(client, 204, "No Content", "", request);
        } else if (request.method == "GET" && request.path == "/v1/health") {
            DllArch arch = cfg.dll_path.empty() ? DllArch::Unknown : detect_dll_architecture(cfg.dll_path);
            std::string body = "{\"ok\":true,\"service\":\"ukey-agent\",\"version\":\"1.1.4\","
                "\"architecture\":\"x64-agent+x86/x64-helper\",\"port\":18088,\"configured\":" +
                std::string(cfg.dll_path.empty() ? "false" : "true") + ",\"dll_architecture\":\"" +
                (arch == DllArch::X86 ? "x86" : arch == DllArch::X64 ? "x64" : "unknown") + "\"}";
            respond(client, 200, "OK", body, request);
        } else if (request.method == "GET" && request.path == "/ukey-agent.js") {
            std::vector<uint8_t> script = resource_data(IDR_WEB_JS);
            respond(client, 200, "OK", std::string(script.begin(), script.end()), request,
                    "application/javascript; charset=utf-8");
        } else if (request.method == "GET" && request.path == "/bridge/pin") {
            std::vector<uint8_t> page = resource_data(IDR_PIN_BRIDGE_HTML);
            respond(client, 200, "OK", std::string(page.begin(), page.end()), request,
                    "text/html; charset=utf-8");
        } else if (request.method == "POST" && request.path == "/v1/sign") {
            std::string helper_input;
            try { helper_input = make_sign_input(request.body, cfg); }
            catch (...) { secure_clear(request.body); throw; }
            respond(client, 200, "OK", run_helper(cfg, helper_input), request);
        } else if (request.method == "POST" && request.path == "/v1/certificate") {
            std::string helper_input = make_certificate_input(request.body, cfg);
            respond(client, 200, "OK", run_helper(cfg, helper_input), request);
        } else {
            respond(client, 404, "Not Found", "{\"ok\":false,\"error\":\"not_found\"}", request);
        }
    } catch (const std::exception &error) {
        respond(client, 400, "Bad Request",
                "{\"ok\":false,\"error\":\"" + json_escape(error.what()) + "\"}", request);
    }
}

void server_loop() {
    WSADATA winsock{};
    try {
        if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) throw std::runtime_error("WSAStartup failed");
        listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listen_socket == INVALID_SOCKET) throw std::runtime_error("socket failed");
        BOOL exclusive = TRUE;
        setsockopt(listen_socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                   reinterpret_cast<const char *>(&exclusive), sizeof(exclusive));
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(PORT);
        inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
        if (bind(listen_socket, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == SOCKET_ERROR)
            throw std::runtime_error("端口 18088 已被占用");
        if (listen(listen_socket, SOMAXCONN) == SOCKET_ERROR) throw std::runtime_error("本地服务启动失败");
        while (running) {
            SOCKET client = accept(listen_socket, nullptr, nullptr);
            if (client == INVALID_SOCKET) break;
            DWORD timeout = 35000;
            setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&timeout), sizeof(timeout));
            setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char *>(&timeout), sizeof(timeout));
            handle_client(client);
            shutdown(client, SD_BOTH);
            closesocket(client);
        }
    } catch (const std::exception &error) {
        std::string *message = new std::string(error.what());
        if (tray_window) PostMessageW(tray_window, WM_SERVER_ERROR, 0, reinterpret_cast<LPARAM>(message));
        else delete message;
    }
    if (listen_socket != INVALID_SOCKET) {
        closesocket(listen_socket);
        listen_socket = INVALID_SOCKET;
    }
    WSACleanup();
}

HICON load_embedded_png_icon() {
    std::vector<uint8_t> png = resource_data(IDR_LOGO_PNG);
    HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, png.size());
    if (!memory) return nullptr;
    void *target = GlobalLock(memory);
    if (!target) {
        GlobalFree(memory);
        return nullptr;
    }
    memcpy(target, png.data(), png.size());
    GlobalUnlock(memory);
    IStream *stream = nullptr;
    if (CreateStreamOnHGlobal(memory, TRUE, &stream) != S_OK) {
        GlobalFree(memory);
        return nullptr;
    }
    HICON icon = nullptr;
    {
        Gdiplus::Bitmap bitmap(stream);
        if (bitmap.GetLastStatus() == Gdiplus::Ok && bitmap.GetHICON(&icon) != Gdiplus::Ok)
            icon = nullptr;
    }
    stream->Release();
    return icon;
}

void add_tray_icon(HWND window) {
    NOTIFYICONDATAW data{};
    data.cbSize = sizeof(data);
    data.hWnd = window;
    data.uID = 1;
    data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    data.uCallbackMessage = WM_TRAY;
    data.hIcon = app_icon ? app_icon : LoadIconW(nullptr, MAKEINTRESOURCEW(32512));
    wcscpy_s(data.szTip, L"CryptoKit UKey 插件 - 127.0.0.1:18088");
    Shell_NotifyIconW(NIM_ADD, &data);
    data.uVersion = NOTIFYICON_VERSION_4;
    Shell_NotifyIconW(NIM_SETVERSION, &data);
}

void remove_tray_icon(HWND window) {
    NOTIFYICONDATAW data{};
    data.cbSize = sizeof(data);
    data.hWnd = window;
    data.uID = 1;
    Shell_NotifyIconW(NIM_DELETE, &data);
}

std::wstring control_text(HWND window, int id) {
    HWND control = GetDlgItem(window, id);
    int length = GetWindowTextLengthW(control);
    std::vector<wchar_t> buffer(static_cast<size_t>(length) + 1, L'\0');
    if (length) GetWindowTextW(control, buffer.data(), length + 1);
    return std::wstring(buffer.data());
}

void set_all_fonts(HWND window) {
    HFONT font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
    EnumChildWindows(window, [](HWND child, LPARAM value) -> BOOL {
        SendMessageW(child, WM_SETFONT, static_cast<WPARAM>(value), TRUE);
        return TRUE;
    }, reinterpret_cast<LPARAM>(font));
}

HWND add_control(HWND parent, const wchar_t *klass, const wchar_t *text, DWORD style,
                 int x, int y, int width, int height, int id) {
    return CreateWindowExW(wcscmp(klass, L"EDIT") == 0 ? WS_EX_CLIENTEDGE : 0, klass, text,
                           WS_CHILD | WS_VISIBLE | style, x, y, width, height, parent,
                           reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
                           GetModuleHandleW(nullptr), nullptr);
}

void update_arch_label(HWND window) {
    std::wstring path = control_text(window, ID_DLL_EDIT);
    std::wstring text = L"DLL 位数：";
    text += architecture_text(detect_dll_architecture(path));
    SetWindowTextW(GetDlgItem(window, ID_ARCH_LABEL), text.c_str());
}

void populate_settings(HWND window) {
    Config cfg = config_snapshot();
    SetWindowTextW(GetDlgItem(window, ID_DLL_EDIT), cfg.dll_path.c_str());
    SetWindowTextW(GetDlgItem(window, ID_DEVICE_EDIT), cfg.device_name.c_str());
    SetWindowTextW(GetDlgItem(window, ID_APPLICATION_EDIT), cfg.application_name.c_str());
    SetWindowTextW(GetDlgItem(window, ID_CONTAINER_EDIT), cfg.container_name.c_str());
    update_arch_label(window);
}

Config config_from_controls(HWND window) {
    Config cfg;
    cfg.dll_path = control_text(window, ID_DLL_EDIT);
    cfg.device_name = control_text(window, ID_DEVICE_EDIT);
    cfg.application_name = control_text(window, ID_APPLICATION_EDIT);
    cfg.container_name = control_text(window, ID_CONTAINER_EDIT);
    return cfg;
}

void browse_dll(HWND window) {
    std::array<wchar_t, 32768> path{};
    std::wstring current = control_text(window, ID_DLL_EDIT);
    if (current.size() < path.size()) wcscpy_s(path.data(), path.size(), current.c_str());
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = window;
    dialog.lpstrFilter = L"SKF 动态库 (*.dll)\0*.dll\0所有文件 (*.*)\0*.*\0";
    dialog.lpstrFile = path.data();
    dialog.nMaxFile = static_cast<DWORD>(path.size());
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    dialog.lpstrTitle = L"选择厂商 SKF DLL";
    if (GetOpenFileNameW(&dialog)) {
        SetWindowTextW(GetDlgItem(window, ID_DLL_EDIT), path.data());
        update_arch_label(window);
    }
}

void save_settings_window(HWND window) {
    Config cfg = config_from_controls(window);
    if (cfg.dll_path.empty() || GetFileAttributesW(cfg.dll_path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        MessageBoxW(window, L"请选择本机存在的厂商 SKF DLL。", L"UKey 插件", MB_OK | MB_ICONWARNING);
        return;
    }
    if (detect_dll_architecture(cfg.dll_path) == DllArch::Unknown) {
        MessageBoxW(window, L"该文件不是受支持的 32 位或 64 位 Windows DLL。", L"UKey 插件", MB_OK | MB_ICONWARNING);
        return;
    }
    try {
        save_config(cfg);
        {
            std::lock_guard<std::mutex> guard(config_mutex);
            current_config = cfg;
        }
        MessageBoxW(window, L"设置已保存。浏览器可通过 127.0.0.1:18088 使用插件。",
                    L"UKey 插件", MB_OK | MB_ICONINFORMATION);
    } catch (const std::exception &error) {
        MessageBoxW(window, utf8_to_wide(error.what()).c_str(), L"保存失败", MB_OK | MB_ICONERROR);
    }
}

void probe_from_settings(HWND window) {
    Config cfg = config_from_controls(window);
    if (cfg.dll_path.empty()) {
        MessageBoxW(window, L"请先选择厂商 SKF DLL。", L"检测配置", MB_OK | MB_ICONWARNING);
        return;
    }
    try {
        std::string input = common_helper_input("probe", "", "", "", "", cfg);
        std::string result = run_helper(cfg, input);
        std::string device, application, container;
        if (!json_string(result, "device", device)) {
            std::string error;
            json_string(result, "error", error);
            throw std::runtime_error(error.empty() ? "设备检测失败" : error);
        }
        json_string(result, "application", application);
        json_string(result, "container", container);
        SetWindowTextW(GetDlgItem(window, ID_DEVICE_EDIT), utf8_to_wide(device).c_str());
        SetWindowTextW(GetDlgItem(window, ID_APPLICATION_EDIT), utf8_to_wide(application).c_str());
        SetWindowTextW(GetDlgItem(window, ID_CONTAINER_EDIT), utf8_to_wide(container).c_str());
        MessageBoxW(window, L"已检测并填入第一个设备、应用和容器。点击“保存”即可使用。",
                    L"检测成功", MB_OK | MB_ICONINFORMATION);
    } catch (const std::exception &error) {
        MessageBoxW(window, utf8_to_wide(error.what()).c_str(), L"检测失败", MB_OK | MB_ICONWARNING);
    }
}

std::wstring certificate_name(PCCERT_CONTEXT context, bool issuer) {
    DWORD flags = issuer ? CERT_NAME_ISSUER_FLAG : 0;
    DWORD count = CertGetNameStringW(context, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags,
                                     nullptr, nullptr, 0);
    if (count <= 1) return L"（未提供）";
    std::vector<wchar_t> text(count, L'\0');
    CertGetNameStringW(context, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags,
                       nullptr, text.data(), count);
    return std::wstring(text.data());
}

std::wstring certificate_details(const std::vector<uint8_t> &der) {
    PCCERT_CONTEXT context = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, der.data(), static_cast<DWORD>(der.size()));
    if (!context) return L"无法解析该证书的 X.509 信息。";
    SYSTEMTIME before{}, after{};
    FileTimeToSystemTime(&context->pCertInfo->NotBefore, &before);
    FileTimeToSystemTime(&context->pCertInfo->NotAfter, &after);
    std::wstring serial;
    for (DWORD i = context->pCertInfo->SerialNumber.cbData; i > 0; --i) {
        wchar_t byte[4]{};
        swprintf_s(byte, L"%02X", context->pCertInfo->SerialNumber.pbData[i - 1]);
        serial += byte;
    }
    std::wostringstream text;
    text << L"主题：" << certificate_name(context, false)
         << L"\r\n颁发者：" << certificate_name(context, true)
         << L"\r\n序列号：" << serial
         << L"\r\n有效期：" << before.wYear << L"-" << before.wMonth << L"-" << before.wDay
         << L" 至 " << after.wYear << L"-" << after.wMonth << L"-" << after.wDay
         << L"\r\nDER 长度：" << der.size() << L" 字节";
    CertFreeCertificateContext(context);
    return text.str();
}

bool fetch_certificate(const Config &cfg, const std::string &type, CertificateEntry &entry,
                       std::string &error) {
    try {
        std::string input = common_helper_input("certificate", "", "", "", "", cfg, type);
        std::string result = run_helper(cfg, input);
        std::string certificate_base64;
        if (!json_string(result, "certificate_base64", certificate_base64)) {
            json_string(result, "error", error);
            if (error.empty()) error = "certificate not found";
            return false;
        }
        entry.der = base64url_decode(certificate_base64);
        if (entry.der.empty()) {
            error = "empty certificate";
            return false;
        }
        entry.title = type == "sign" ? L"签名证书" : L"加密证书";
        entry.signing = type == "sign";
        entry.details = certificate_details(entry.der);
        return true;
    } catch (const std::exception &exception) {
        error = exception.what();
        return false;
    }
}

int selected_certificate(HWND window) {
    LRESULT selected = SendMessageW(GetDlgItem(window, ID_CERT_LIST), LB_GETCURSEL, 0, 0);
    if (selected == LB_ERR || static_cast<size_t>(selected) >= certificates.size()) return -1;
    return static_cast<int>(selected);
}

void update_certificate_details(HWND window) {
    int selected = selected_certificate(window);
    SetWindowTextW(GetDlgItem(window, ID_CERT_DETAILS),
                   selected < 0 ? L"请选择一张证书。" : certificates[static_cast<size_t>(selected)].details.c_str());
}

void view_selected_certificate(HWND window) {
    int selected = selected_certificate(window);
    if (selected < 0) return;
    const auto &entry = certificates[static_cast<size_t>(selected)];
    PCCERT_CONTEXT context = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, entry.der.data(), static_cast<DWORD>(entry.der.size()));
    if (!context) {
        MessageBoxW(window, L"无法解析该证书。", L"查看证书", MB_OK | MB_ICONWARNING);
        return;
    }
    CRYPTUI_VIEWCERTIFICATE_STRUCTW view{};
    view.dwSize = sizeof(view);
    view.hwndParent = window;
    view.szTitle = entry.title.c_str();
    view.pCertContext = context;
    BOOL changed = FALSE;
    CryptUIDlgViewCertificateW(&view, &changed);
    CertFreeCertificateContext(context);
}

void export_selected_certificate(HWND window) {
    int selected = selected_certificate(window);
    if (selected < 0) {
        MessageBoxW(window, L"请先选择要导出的证书。", L"导出证书", MB_OK | MB_ICONWARNING);
        return;
    }
    const auto &entry = certificates[static_cast<size_t>(selected)];
    std::array<wchar_t, 32768> path{};
    wcscpy_s(path.data(), path.size(), entry.signing
        ? L"ukey-sign-certificate.cer" : L"ukey-encrypt-certificate.cer");
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = window;
    dialog.lpstrFilter = L"X.509 证书 (*.cer)\0*.cer\0所有文件 (*.*)\0*.*\0";
    dialog.lpstrFile = path.data();
    dialog.nMaxFile = static_cast<DWORD>(path.size());
    dialog.lpstrDefExt = L"cer";
    dialog.Flags = OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;
    dialog.lpstrTitle = L"导出所选 UKey 证书";
    if (!GetSaveFileNameW(&dialog)) return;
    std::ofstream file(path.data(), std::ios::binary | std::ios::trunc);
    file.write(reinterpret_cast<const char *>(entry.der.data()),
               static_cast<std::streamsize>(entry.der.size()));
    if (!file) MessageBoxW(window, L"证书文件写入失败。", L"导出失败", MB_OK | MB_ICONERROR);
}

void layout_certificate_window(HWND window) {
    RECT area{};
    GetClientRect(window, &area);
    int width = area.right;
    int height = area.bottom;
    int list_width = std::max(140, width / 3);
    MoveWindow(GetDlgItem(window, ID_CERT_LIST), 14, 14, list_width, std::max(140, height - 70), TRUE);
    MoveWindow(GetDlgItem(window, ID_CERT_DETAILS), 24 + list_width, 14,
               std::max(180, width - list_width - 38), std::max(140, height - 70), TRUE);
    MoveWindow(GetDlgItem(window, ID_CERT_VIEW), std::max(14, width - 292), height - 44, 88, 28, TRUE);
    MoveWindow(GetDlgItem(window, ID_CERT_EXPORT), std::max(110, width - 196), height - 44, 88, 28, TRUE);
    MoveWindow(GetDlgItem(window, ID_CERT_CLOSE), std::max(206, width - 100), height - 44, 88, 28, TRUE);
}

LRESULT CALLBACK certificate_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    switch (message) {
    case WM_CREATE:
        add_control(window, L"LISTBOX", L"", LBS_NOTIFY | WS_BORDER | WS_VSCROLL,
                    0, 0, 1, 1, ID_CERT_LIST);
        add_control(window, L"EDIT", L"请选择一张证书。",
                    ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL,
                    0, 0, 1, 1, ID_CERT_DETAILS);
        add_control(window, L"BUTTON", L"查看详情", BS_PUSHBUTTON, 0, 0, 1, 1, ID_CERT_VIEW);
        add_control(window, L"BUTTON", L"导出所选", BS_PUSHBUTTON, 0, 0, 1, 1, ID_CERT_EXPORT);
        add_control(window, L"BUTTON", L"关闭", BS_PUSHBUTTON, 0, 0, 1, 1, ID_CERT_CLOSE);
        set_all_fonts(window);
        for (const auto &entry : certificates)
            SendMessageW(GetDlgItem(window, ID_CERT_LIST), LB_ADDSTRING, 0,
                         reinterpret_cast<LPARAM>(entry.title.c_str()));
        if (!certificates.empty()) SendMessageW(GetDlgItem(window, ID_CERT_LIST), LB_SETCURSEL, 0, 0);
        update_certificate_details(window);
        layout_certificate_window(window);
        return 0;
    case WM_SIZE:
        layout_certificate_window(window);
        return 0;
    case WM_GETMINMAXINFO: {
        auto *info = reinterpret_cast<MINMAXINFO *>(lparam);
        info->ptMinTrackSize.x = 480;
        info->ptMinTrackSize.y = 300;
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wparam) == ID_CERT_LIST && HIWORD(wparam) == LBN_SELCHANGE) update_certificate_details(window);
        else if (LOWORD(wparam) == ID_CERT_VIEW) view_selected_certificate(window);
        else if (LOWORD(wparam) == ID_CERT_EXPORT) export_selected_certificate(window);
        else if (LOWORD(wparam) == ID_CERT_CLOSE) DestroyWindow(window);
        return 0;
    case WM_CLOSE:
        DestroyWindow(window);
        return 0;
    case WM_DESTROY:
        certificate_window = nullptr;
        return 0;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

void show_certificates_from_settings(HWND window) {
    Config cfg = config_from_controls(window);
    if (cfg.dll_path.empty()) {
        MessageBoxW(window, L"请先选择厂商 SKF DLL。", L"查看证书", MB_OK | MB_ICONWARNING);
        return;
    }
    certificates.clear();
    std::string sign_error, encrypt_error;
    CertificateEntry sign, encrypt;
    if (fetch_certificate(cfg, "sign", sign, sign_error)) certificates.push_back(std::move(sign));
    if (fetch_certificate(cfg, "encrypt", encrypt, encrypt_error)) certificates.push_back(std::move(encrypt));
    if (certificates.empty()) {
        std::string message = "签名证书: " + sign_error + "\n加密证书: " + encrypt_error;
        MessageBoxW(window, utf8_to_wide(message).c_str(), L"未读取到证书", MB_OK | MB_ICONWARNING);
        return;
    }
    if (certificate_window) DestroyWindow(certificate_window);
    certificate_window = CreateWindowExW(WS_EX_APPWINDOW, L"CryptoKitUKeyCertificates",
        L"UKey 证书", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 620, 380,
        window, nullptr, GetModuleHandleW(nullptr), nullptr);
    ShowWindow(certificate_window, SW_SHOWNORMAL);
    SetForegroundWindow(certificate_window);
}

void layout_settings(HWND window) {
    RECT area{};
    GetClientRect(window, &area);
    const int width = std::max(320L, area.right - area.left);
    const int margin = 16;
    const int content = width - margin * 2;
    const int browse_width = 88;
    MoveWindow(GetDlgItem(window, ID_TITLE_LABEL), 76, 16, width - 92, 26, TRUE);
    MoveWindow(GetDlgItem(window, ID_INFO_LABEL), 76, 43, width - 92, 38, TRUE);
    MoveWindow(GetDlgItem(window, ID_DLL_LABEL), margin, 86, content, 20, TRUE);
    MoveWindow(GetDlgItem(window, ID_DLL_EDIT), margin, 107, content - browse_width - 8, 25, TRUE);
    MoveWindow(GetDlgItem(window, ID_DLL_BROWSE), width - margin - browse_width, 106, browse_width, 27, TRUE);
    MoveWindow(GetDlgItem(window, ID_ARCH_LABEL), margin, 136, content, 20, TRUE);
    MoveWindow(GetDlgItem(window, ID_DEVICE_LABEL), margin, 164, content, 20, TRUE);
    MoveWindow(GetDlgItem(window, ID_DEVICE_EDIT), margin, 185, content, 25, TRUE);
    MoveWindow(GetDlgItem(window, ID_APPLICATION_LABEL), margin, 218, content, 20, TRUE);
    MoveWindow(GetDlgItem(window, ID_APPLICATION_EDIT), margin, 239, content, 25, TRUE);
    MoveWindow(GetDlgItem(window, ID_CONTAINER_LABEL), margin, 272, content, 20, TRUE);
    MoveWindow(GetDlgItem(window, ID_CONTAINER_EDIT), margin, 293, content, 25, TRUE);

    const int gap = 7;
    const int button_width = (content - gap * 3) / 4;
    int x = margin;
    MoveWindow(GetDlgItem(window, ID_CONFIG_PROBE), x, 335, button_width, 30, TRUE);
    x += button_width + gap;
    MoveWindow(GetDlgItem(window, ID_CONFIG_EXPORT_CERT), x, 335, button_width, 30, TRUE);
    x += button_width + gap;
    MoveWindow(GetDlgItem(window, ID_CONFIG_SAVE), x, 335, button_width, 30, TRUE);
    x += button_width + gap;
    MoveWindow(GetDlgItem(window, ID_CONFIG_CLOSE), x, 335, button_width, 30, TRUE);
}

LRESULT CALLBACK settings_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    (void)lparam;
    switch (message) {
    case WM_CREATE: {
        add_control(window, L"STATIC", L"CryptoKit UKey 插件", SS_LEFT, 0, 0, 1, 1, ID_TITLE_LABEL);
        add_control(window, L"STATIC", L"本地服务 127.0.0.1:18088\n名称留空时自动选择第一个",
                    SS_LEFT, 0, 0, 1, 1, ID_INFO_LABEL);
        add_control(window, L"STATIC", L"厂商 SKF DLL", SS_LEFT, 0, 0, 1, 1, ID_DLL_LABEL);
        add_control(window, L"EDIT", L"", ES_AUTOHSCROLL, 0, 0, 1, 1, ID_DLL_EDIT);
        add_control(window, L"BUTTON", L"导入 DLL...", BS_PUSHBUTTON, 0, 0, 1, 1, ID_DLL_BROWSE);
        add_control(window, L"STATIC", L"DLL 位数：未识别", SS_LEFT, 0, 0, 1, 1, ID_ARCH_LABEL);
        add_control(window, L"STATIC", L"设备名称（可选）", SS_LEFT, 0, 0, 1, 1, ID_DEVICE_LABEL);
        add_control(window, L"EDIT", L"", ES_AUTOHSCROLL, 0, 0, 1, 1, ID_DEVICE_EDIT);
        add_control(window, L"STATIC", L"应用名称（可选）", SS_LEFT, 0, 0, 1, 1, ID_APPLICATION_LABEL);
        add_control(window, L"EDIT", L"", ES_AUTOHSCROLL, 0, 0, 1, 1, ID_APPLICATION_EDIT);
        add_control(window, L"STATIC", L"容器名称（可选）", SS_LEFT, 0, 0, 1, 1, ID_CONTAINER_LABEL);
        add_control(window, L"EDIT", L"", ES_AUTOHSCROLL, 0, 0, 1, 1, ID_CONTAINER_EDIT);
        add_control(window, L"BUTTON", L"检测设备", BS_PUSHBUTTON, 0, 0, 1, 1, ID_CONFIG_PROBE);
        add_control(window, L"BUTTON", L"查看证书", BS_PUSHBUTTON, 0, 0, 1, 1, ID_CONFIG_EXPORT_CERT);
        add_control(window, L"BUTTON", L"保存", BS_DEFPUSHBUTTON, 0, 0, 1, 1, ID_CONFIG_SAVE);
        add_control(window, L"BUTTON", L"关闭", BS_PUSHBUTTON, 0, 0, 1, 1, ID_CONFIG_CLOSE);
        set_all_fonts(window);
        populate_settings(window);
        layout_settings(window);
        return 0;
    }
    case WM_SIZE:
        layout_settings(window);
        InvalidateRect(window, nullptr, TRUE);
        return 0;
    case WM_GETMINMAXINFO: {
        auto *info = reinterpret_cast<MINMAXINFO *>(lparam);
        info->ptMinTrackSize.x = 340;
        info->ptMinTrackSize.y = 430;
        return 0;
    }
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wparam);
        SetBkMode(dc, TRANSPARENT);
        return reinterpret_cast<LRESULT>(GetStockObject(HOLLOW_BRUSH));
    }
    case WM_PAINT: {
        PAINTSTRUCT paint{};
        HDC dc = BeginPaint(window, &paint);
        if (app_icon) DrawIconEx(dc, 24, 18, app_icon, 56, 56, 0, nullptr, DI_NORMAL);
        EndPaint(window, &paint);
        return 0;
    }
    case WM_COMMAND:
        switch (LOWORD(wparam)) {
        case ID_DLL_BROWSE: browse_dll(window); return 0;
        case ID_CONFIG_SAVE: save_settings_window(window); return 0;
        case ID_CONFIG_PROBE: probe_from_settings(window); return 0;
        case ID_CONFIG_EXPORT_CERT: show_certificates_from_settings(window); return 0;
        case ID_CONFIG_CLOSE: ShowWindow(window, SW_HIDE); return 0;
        default: break;
        }
        break;
    case WM_CLOSE:
        ShowWindow(window, SW_HIDE);
        return 0;
    case WM_DESTROY:
        settings_window = nullptr;
        return 0;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

void show_settings() {
    if (!settings_window) {
        settings_window = CreateWindowExW(WS_EX_APPWINDOW, L"CryptoKitUKeySettings",
            L"CryptoKit UKey 插件设置", WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT, CW_USEDEFAULT, 350, 460, tray_window, nullptr, GetModuleHandleW(nullptr), nullptr);
    } else populate_settings(settings_window);
    ShowWindow(settings_window, SW_SHOWNORMAL);
    SetForegroundWindow(settings_window);
}

void show_tray_menu(HWND window) {
    POINT point{};
    GetCursorPos(&point);
    HMENU menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING, ID_TRAY_SETTINGS, L"设置...");
    AppendMenuW(menu, MF_STRING, ID_TRAY_STATUS, L"查看状态");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, ID_TRAY_EXIT, L"退出");
    SetForegroundWindow(window);
    TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN,
                   point.x, point.y, 0, window, nullptr);
    DestroyMenu(menu);
}

LRESULT CALLBACK tray_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    if (message == taskbar_created_message) {
        add_tray_icon(window);
        return 0;
    }
    switch (message) {
    case WM_CREATE:
        add_tray_icon(window);
        return 0;
    case WM_TRAY:
        if (LOWORD(lparam) == WM_CONTEXTMENU || LOWORD(lparam) == WM_RBUTTONUP) show_tray_menu(window);
        else if (LOWORD(lparam) == WM_LBUTTONDBLCLK) show_settings();
        return 0;
    case WM_COMMAND:
        if (LOWORD(wparam) == ID_TRAY_SETTINGS) show_settings();
        else if (LOWORD(wparam) == ID_TRAY_STATUS) {
            Config cfg = config_snapshot();
            std::wstring text = L"本地服务：127.0.0.1:18088\nSKF DLL：";
            text += cfg.dll_path.empty() ? L"尚未配置" : cfg.dll_path;
            if (!cfg.dll_path.empty()) {
                text += L"\nDLL 位数：";
                text += architecture_text(detect_dll_architecture(cfg.dll_path));
            }
            MessageBoxW(window, text.c_str(), L"CryptoKit UKey 插件", MB_OK | MB_ICONINFORMATION);
        } else if (LOWORD(wparam) == ID_TRAY_EXIT) DestroyWindow(window);
        return 0;
    case WM_SERVER_ERROR: {
        std::string *error = reinterpret_cast<std::string *>(lparam);
        std::wstring text = error ? utf8_to_wide(*error) : L"本地服务异常";
        delete error;
        MessageBoxW(window, text.c_str(), L"UKey 插件服务错误", MB_OK | MB_ICONERROR);
        return 0;
    }
    case WM_DESTROY:
        remove_tray_icon(window);
        running = false;
        if (listen_socket != INVALID_SOCKET) closesocket(listen_socket);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
    HANDLE single_instance = CreateMutexW(nullptr, TRUE, L"Local\\CryptoKitUKeyAgent");
    if (!single_instance || GetLastError() == ERROR_ALREADY_EXISTS) {
        MessageBoxW(nullptr, L"CryptoKit UKey 插件已经在运行。", L"UKey 插件", MB_OK | MB_ICONINFORMATION);
        if (single_instance) CloseHandle(single_instance);
        return 0;
    }
    try {
        app_directory = exe_directory();
        std::wstring helper_directory = helper_storage_directory();
        helper_x86_path = helper_directory + L"\\ukey-helper-x86.exe";
        helper_x64_path = helper_directory + L"\\ukey-helper-x64.exe";
        extract_resource_file(IDR_HELPER_X86, helper_x86_path);
        extract_resource_file(IDR_HELPER_X64, helper_x64_path);
        current_config = load_config();

        Gdiplus::GdiplusStartupInput gdiplus_input;
        Gdiplus::GdiplusStartup(&gdiplus_token, &gdiplus_input, nullptr);
        app_icon = load_embedded_png_icon();
        taskbar_created_message = RegisterWindowMessageW(L"TaskbarCreated");

        WNDCLASSEXW tray_class{sizeof(tray_class)};
        tray_class.lpfnWndProc = tray_proc;
        tray_class.hInstance = instance;
        tray_class.hIcon = app_icon;
        tray_class.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
        tray_class.lpszClassName = L"CryptoKitUKeyTray";
        RegisterClassExW(&tray_class);

        WNDCLASSEXW settings_class{sizeof(settings_class)};
        settings_class.lpfnWndProc = settings_proc;
        settings_class.hInstance = instance;
        settings_class.hIcon = app_icon;
        settings_class.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
        settings_class.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
        settings_class.lpszClassName = L"CryptoKitUKeySettings";
        RegisterClassExW(&settings_class);

        WNDCLASSEXW certificate_class{sizeof(certificate_class)};
        certificate_class.lpfnWndProc = certificate_proc;
        certificate_class.hInstance = instance;
        certificate_class.hIcon = app_icon;
        certificate_class.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
        certificate_class.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
        certificate_class.lpszClassName = L"CryptoKitUKeyCertificates";
        RegisterClassExW(&certificate_class);

        tray_window = CreateWindowExW(0, L"CryptoKitUKeyTray", L"CryptoKit UKey Agent",
                                      WS_OVERLAPPED, 0, 0, 0, 0, nullptr, nullptr, instance, nullptr);
        if (!tray_window) throw std::runtime_error("cannot create tray window");
        http_thread = std::thread(server_loop);
        if (current_config.dll_path.empty()) PostMessageW(tray_window, WM_COMMAND, ID_TRAY_SETTINGS, 0);

        MSG message{};
        while (GetMessageW(&message, nullptr, 0, 0) > 0) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        running = false;
        if (listen_socket != INVALID_SOCKET) closesocket(listen_socket);
        if (http_thread.joinable()) http_thread.join();
        if (app_icon) DestroyIcon(app_icon);
        if (gdiplus_token) Gdiplus::GdiplusShutdown(gdiplus_token);
        ReleaseMutex(single_instance);
        CloseHandle(single_instance);
        return 0;
    } catch (const std::exception &error) {
        MessageBoxW(nullptr, utf8_to_wide(error.what()).c_str(), L"UKey 插件启动失败", MB_OK | MB_ICONERROR);
        running = false;
        if (http_thread.joinable()) http_thread.join();
        if (app_icon) DestroyIcon(app_icon);
        if (gdiplus_token) Gdiplus::GdiplusShutdown(gdiplus_token);
        ReleaseMutex(single_instance);
        CloseHandle(single_instance);
        return 2;
    }
}
