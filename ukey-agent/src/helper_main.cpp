#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "codec.hpp"
#include "skf_min.hpp"

namespace {

template <typename T>
T load_symbol(HMODULE module, const char *name) {
    FARPROC value = GetProcAddress(module, name);
    if (!value) throw std::runtime_error(std::string("missing SKF export: ") + name);
    return reinterpret_cast<T>(value);
}

std::string hex_status(SKF_ULONG status) {
    char text[16]{};
    sprintf_s(text, "0x%08X", status);
    return text;
}

std::string first_name(const std::vector<char> &buffer) {
    if (buffer.empty() || buffer[0] == '\0') return {};
    size_t length = 0;
    while (length < buffer.size() && buffer[length] != '\0') ++length;
    return std::string(buffer.data(), length);
}

template <typename Fn, typename... Prefix>
std::string enumerate_first(Fn fn, Prefix... prefix) {
    SKF_ULONG size = 0;
    SKF_ULONG status = fn(prefix..., nullptr, &size);
    if (status != SAR_OK) throw std::runtime_error("enum:size:" + hex_status(status));
    if (size == 0 || size > 1024 * 1024) throw std::runtime_error("enum:empty");
    std::vector<char> names(size + 2, '\0');
    status = fn(prefix..., names.data(), &size);
    if (status != SAR_OK) throw std::runtime_error("enum:data:" + hex_status(status));
    std::string value = first_name(names);
    if (value.empty()) throw std::runtime_error("enum:empty");
    return value;
}

struct Api {
    HMODULE module = nullptr;
    FnEnumDev enum_dev = nullptr;
    FnConnectDev connect_dev = nullptr;
    FnDisconnectDev disconnect_dev = nullptr;
    FnEnumApplication enum_application = nullptr;
    FnOpenApplication open_application = nullptr;
    FnCloseApplication close_application = nullptr;
    FnVerifyPIN verify_pin = nullptr;
    FnClearSecureState clear_secure_state = nullptr;
    FnEnumContainer enum_container = nullptr;
    FnOpenContainer open_container = nullptr;
    FnCloseContainer close_container = nullptr;
    FnExportPublicKey export_public_key = nullptr;
    FnExportCertificate export_certificate = nullptr;
    FnDigestInit digest_init = nullptr;
    FnDigestUpdate digest_update = nullptr;
    FnDigestFinal digest_final = nullptr;
    FnCloseHandle close_handle = nullptr;
    FnECCSignData ecc_sign_data = nullptr;

    explicit Api(const std::wstring &dll_path) {
        module = LoadLibraryExW(dll_path.c_str(), nullptr,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
        if (!module) {
            module = LoadLibraryW(dll_path.c_str());
        }
        if (!module) throw std::runtime_error("load_dll:" + std::to_string(GetLastError()));
        enum_dev = load_symbol<FnEnumDev>(module, "SKF_EnumDev");
        connect_dev = load_symbol<FnConnectDev>(module, "SKF_ConnectDev");
        disconnect_dev = load_symbol<FnDisconnectDev>(module, "SKF_DisConnectDev");
        enum_application = load_symbol<FnEnumApplication>(module, "SKF_EnumApplication");
        open_application = load_symbol<FnOpenApplication>(module, "SKF_OpenApplication");
        close_application = load_symbol<FnCloseApplication>(module, "SKF_CloseApplication");
        verify_pin = load_symbol<FnVerifyPIN>(module, "SKF_VerifyPIN");
        clear_secure_state = load_symbol<FnClearSecureState>(module, "SKF_ClearSecureState");
        enum_container = load_symbol<FnEnumContainer>(module, "SKF_EnumContainer");
        open_container = load_symbol<FnOpenContainer>(module, "SKF_OpenContainer");
        close_container = load_symbol<FnCloseContainer>(module, "SKF_CloseContainer");
        export_public_key = load_symbol<FnExportPublicKey>(module, "SKF_ExportPublicKey");
        export_certificate = load_symbol<FnExportCertificate>(module, "SKF_ExportCertificate");
        digest_init = load_symbol<FnDigestInit>(module, "SKF_DigestInit");
        digest_update = load_symbol<FnDigestUpdate>(module, "SKF_DigestUpdate");
        digest_final = load_symbol<FnDigestFinal>(module, "SKF_DigestFinal");
        close_handle = load_symbol<FnCloseHandle>(module, "SKF_CloseHandle");
        ecc_sign_data = load_symbol<FnECCSignData>(module, "SKF_ECCSignData");
    }

    ~Api() { if (module) FreeLibrary(module); }
};

struct Handles {
    Api &api;
    SKF_HANDLE device = nullptr;
    SKF_HANDLE application = nullptr;
    SKF_HANDLE container = nullptr;
    SKF_HANDLE digest = nullptr;
    bool authenticated = false;

    ~Handles() {
        if (digest) api.close_handle(digest);
        if (authenticated && application) api.clear_secure_state(application);
        if (container) api.close_container(container);
        if (application) api.close_application(application);
        if (device) api.disconnect_dev(device);
    }
};

void require_ok(const char *stage, SKF_ULONG status) {
    if (status != SAR_OK) throw std::runtime_error(std::string(stage) + ":" + hex_status(status));
}

std::wstring utf8_to_wide(const std::string &value) {
    if (value.empty()) return {};
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                                    static_cast<int>(value.size()), nullptr, 0);
    if (count <= 0) throw std::runtime_error("dll_path:not_utf8");
    std::wstring out(count, L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                        static_cast<int>(value.size()), out.data(), count);
    return out;
}

std::string read_line_required(const char *name) {
    std::string value;
    if (!std::getline(std::cin, value)) throw std::runtime_error(std::string("input:") + name);
    if (!value.empty() && value.back() == '\r') value.pop_back();
    return value;
}

std::string choose_name(const std::string &configured, const std::string &kind) {
    if (!configured.empty()) return configured;
    throw std::runtime_error(kind + ":empty");
}

struct TargetNames {
    std::string device;
    std::string application;
    std::string container;
};

void open_device_and_application(Api &api, Handles &handles, TargetNames &names,
                                 const std::string &configured_device,
                                 const std::string &configured_application) {
    names.device = configured_device.empty()
        ? enumerate_first(api.enum_dev, static_cast<SKF_BOOL>(1))
        : choose_name(configured_device, "device");
    require_ok("SKF_ConnectDev", api.connect_dev(names.device.data(), &handles.device));
    names.application = configured_application.empty()
        ? enumerate_first(api.enum_application, handles.device)
        : choose_name(configured_application, "application");
    require_ok("SKF_OpenApplication",
               api.open_application(handles.device, names.application.data(), &handles.application));
}

void open_container(Api &api, Handles &handles, TargetNames &names,
                    const std::string &configured_container) {
    names.container = configured_container.empty()
        ? enumerate_first(api.enum_container, handles.application)
        : choose_name(configured_container, "container");
    require_ok("SKF_OpenContainer",
               api.open_container(handles.application, names.container.data(), &handles.container));
}

std::string sign(const std::wstring &dll_path, const std::vector<uint8_t> &challenge,
                 std::string &pin, const std::vector<uint8_t> &user_id,
                 const std::string &request_id, const std::string &configured_device,
                 const std::string &configured_application,
                 const std::string &configured_container) {
    Api api(dll_path);
    Handles handles{api};
    TargetNames names;
    open_device_and_application(api, handles, names, configured_device, configured_application);

    SKF_ULONG retries = 0;
    SKF_ULONG status = api.verify_pin(handles.application, USER_TYPE, pin.data(), &retries);
    secure_clear(pin);
    if (status != SAR_OK) {
        throw std::runtime_error("SKF_VerifyPIN:" + hex_status(status) + ":retries=" +
                                 std::to_string(retries));
    }
    handles.authenticated = true;

    open_container(api, handles, names, configured_container);

    std::vector<uint8_t> public_blob(sizeof(ECCPUBLICKEYBLOB));
    SKF_ULONG public_size = static_cast<SKF_ULONG>(public_blob.size());
    status = api.export_public_key(handles.container, 1, public_blob.data(), &public_size);
    if (status != SAR_OK && public_size > public_blob.size() && public_size <= 4096) {
        public_blob.resize(public_size);
        status = api.export_public_key(handles.container, 1, public_blob.data(), &public_size);
    }
    require_ok("SKF_ExportPublicKey", status);
    if (public_size < sizeof(ECCPUBLICKEYBLOB)) throw std::runtime_error("public_key:short");
    ECCPUBLICKEYBLOB public_key{};
    memcpy(&public_key, public_blob.data(), sizeof(public_key));

    auto *id_ptr = user_id.empty() ? nullptr : const_cast<SKF_BYTE *>(user_id.data());
    require_ok("SKF_DigestInit",
               api.digest_init(handles.device, SGD_SM3, &public_key, id_ptr,
                               static_cast<SKF_ULONG>(user_id.size()), &handles.digest));
    require_ok("SKF_DigestUpdate",
               api.digest_update(handles.digest, const_cast<SKF_BYTE *>(challenge.data()),
                                 static_cast<SKF_ULONG>(challenge.size())));

    std::array<uint8_t, 64> digest{};
    SKF_ULONG digest_size = static_cast<SKF_ULONG>(digest.size());
    require_ok("SKF_DigestFinal", api.digest_final(handles.digest, digest.data(), &digest_size));
    api.close_handle(handles.digest);
    handles.digest = nullptr;
    if (digest_size != 32) throw std::runtime_error("digest:length=" + std::to_string(digest_size));

    ECCSIGNATUREBLOB signature{};
    require_ok("SKF_ECCSignData",
               api.ecc_sign_data(handles.container, digest.data(), digest_size, &signature));

    SKF_ULONG certificate_size = 0;
    SKF_ULONG certificate_status = api.export_certificate(
        handles.container, 1, nullptr, &certificate_size);
    if (certificate_status != SAR_OK && certificate_size == 0) {
        require_ok("SKF_ExportCertificate:size", certificate_status);
    }
    if (certificate_size == 0 || certificate_size > 1024 * 1024) {
        throw std::runtime_error("certificate:length");
    }
    std::vector<uint8_t> certificate_der(certificate_size);
    require_ok("SKF_ExportCertificate",
               api.export_certificate(handles.container, 1, certificate_der.data(),
                                      &certificate_size));
    certificate_der.resize(certificate_size);

    std::array<uint8_t, 64> raw_signature{};
    memcpy(raw_signature.data(), signature.r + 32, 32);
    memcpy(raw_signature.data() + 32, signature.s + 32, 32);

    const uint8_t *x = public_key.XCoordinate + 32;
    const uint8_t *y = public_key.YCoordinate + 32;
    std::ostringstream out;
    out << "{\"ok\":true"
        << ",\"request_id\":\"" << json_escape(request_id) << "\""
        << ",\"algorithm\":\"SM2-SM3\""
        << ",\"signature_format\":\"raw-rs\""
        << ",\"signature_base64url\":\""
        << base64url_encode(raw_signature.data(), raw_signature.size()) << "\""
        << ",\"digest_base64url\":\"" << base64url_encode(digest.data(), digest_size) << "\""
        << ",\"certificate_base64\":\""
        << base64_encode(certificate_der.data(), certificate_der.size()) << "\""
        << ",\"public_key\":{\"format\":\"sm2-uncompressed\",\"x_base64url\":\""
        << base64url_encode(x, 32) << "\",\"y_base64url\":\""
        << base64url_encode(y, 32) << "\"}"
        << ",\"helper_architecture\":\"" << (sizeof(void *) == 8 ? "x64" : "x86") << "\""
        << ",\"device\":\"" << json_escape(names.device) << "\""
        << ",\"application\":\"" << json_escape(names.application) << "\""
        << ",\"container\":\"" << json_escape(names.container) << "\"}"
        << std::endl;
    return out.str();
}

std::string certificate(const std::wstring &dll_path, const std::string &request_id,
                        const std::string &configured_device,
                        const std::string &configured_application,
                        const std::string &configured_container, bool signing_certificate) {
    Api api(dll_path);
    Handles handles{api};
    TargetNames names;
    open_device_and_application(api, handles, names, configured_device, configured_application);
    open_container(api, handles, names, configured_container);

    SKF_ULONG size = 0;
    SKF_ULONG status = api.export_certificate(handles.container,
                                              signing_certificate ? 1 : 0, nullptr, &size);
    if (status != SAR_OK && size == 0) require_ok("SKF_ExportCertificate:size", status);
    if (size == 0 || size > 1024 * 1024) throw std::runtime_error("certificate:length");
    std::vector<uint8_t> der(size);
    require_ok("SKF_ExportCertificate",
               api.export_certificate(handles.container, signing_certificate ? 1 : 0,
                                      der.data(), &size));
    der.resize(size);

    std::ostringstream out;
    out << "{\"ok\":true,\"request_id\":\"" << json_escape(request_id) << "\""
        << ",\"certificate_type\":\"" << (signing_certificate ? "sign" : "encrypt")
        << "\",\"certificate_format\":\"X.509-DER\""
        << ",\"certificate_base64\":\"" << base64_encode(der.data(), der.size()) << "\""
        << ",\"helper_architecture\":\"" << (sizeof(void *) == 8 ? "x64" : "x86") << "\""
        << ",\"device\":\"" << json_escape(names.device) << "\""
        << ",\"application\":\"" << json_escape(names.application) << "\""
        << ",\"container\":\"" << json_escape(names.container) << "\"}" << std::endl;
    return out.str();
}

std::string probe(const std::wstring &dll_path, const std::string &configured_device,
                  const std::string &configured_application,
                  const std::string &configured_container) {
    Api api(dll_path);
    Handles handles{api};
    TargetNames names;
    open_device_and_application(api, handles, names, configured_device, configured_application);
    open_container(api, handles, names, configured_container);
    std::ostringstream out;
    out << "{\"ok\":true,\"helper_architecture\":\""
        << (sizeof(void *) == 8 ? "x64" : "x86") << "\""
        << ",\"device\":\"" << json_escape(names.device) << "\""
        << ",\"application\":\"" << json_escape(names.application) << "\""
        << ",\"container\":\"" << json_escape(names.container) << "\"}" << std::endl;
    return out.str();
}

} // namespace

int main(int argc, char **argv) {
    SetConsoleOutputCP(CP_UTF8);
    try {
        if (argc != 3 || std::string(argv[1]) != "--dll-base64url") {
            throw std::runtime_error("usage: ukey-helper.exe --dll-base64url PATH");
        }
        std::string dll_encoded = argv[2];
        std::vector<uint8_t> dll_bytes = base64url_decode(dll_encoded);
        std::string dll_utf8(dll_bytes.begin(), dll_bytes.end());

        std::string operation = read_line_required("operation");
        std::string challenge_text = read_line_required("challenge");
        std::string pin_text = read_line_required("pin");
        std::string user_id_text = read_line_required("user_id");
        std::string request_id_text = read_line_required("request_id");
        std::string device_text = read_line_required("device");
        std::string application_text = read_line_required("application");
        std::string container_text = read_line_required("container");
        std::string certificate_type = read_line_required("certificate_type");

        std::vector<uint8_t> challenge = base64url_decode(challenge_text);
        std::vector<uint8_t> pin_bytes = base64url_decode(pin_text);
        std::vector<uint8_t> user_id = base64url_decode(user_id_text);
        std::vector<uint8_t> request_id_bytes = base64url_decode(request_id_text);
        std::vector<uint8_t> device_bytes = base64url_decode(device_text);
        std::vector<uint8_t> application_bytes = base64url_decode(application_text);
        std::vector<uint8_t> container_bytes = base64url_decode(container_text);
        std::string pin(pin_bytes.begin(), pin_bytes.end());
        std::string request_id(request_id_bytes.begin(), request_id_bytes.end());
        std::string configured_device(device_bytes.begin(), device_bytes.end());
        std::string configured_application(application_bytes.begin(), application_bytes.end());
        std::string configured_container(container_bytes.begin(), container_bytes.end());
        std::fill(pin_bytes.begin(), pin_bytes.end(), static_cast<uint8_t>(0));
        secure_clear(pin_text);

        if (challenge.size() > 4096) throw std::runtime_error("challenge:length");
        if (pin.size() > 64) throw std::runtime_error("pin:length");
        if (user_id.size() > 8192) throw std::runtime_error("user_id:length");
        try {
            if (operation == "sign") {
                if (challenge.empty()) throw std::runtime_error("challenge:length");
                if (pin.empty()) throw std::runtime_error("pin:length");
                std::cout << sign(utf8_to_wide(dll_utf8), challenge, pin, user_id, request_id,
                                  configured_device, configured_application, configured_container);
            } else if (operation == "certificate") {
                std::cout << certificate(utf8_to_wide(dll_utf8), request_id, configured_device,
                                         configured_application, configured_container,
                                         certificate_type != "encrypt");
            } else if (operation == "probe") {
                std::cout << probe(utf8_to_wide(dll_utf8), configured_device,
                                   configured_application, configured_container);
            } else {
                throw std::runtime_error("operation:not_supported");
            }
            secure_clear(pin);
        } catch (...) {
            secure_clear(pin);
            throw;
        }
        return 0;
    } catch (const std::exception &error) {
        std::cout << "{\"ok\":false,\"error\":\"" << json_escape(error.what()) << "\"}" << std::endl;
        return 2;
    }
}
