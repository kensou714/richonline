#include "control_pipe.hpp"
#include <sddl.h>
#include <array>
#include <vector>

namespace richnet {
namespace {
constexpr std::uint32_t max_message = 65536;
std::wstring current_user_acl() {
    HANDLE raw_token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token))
        throw windows_error("process_token");
    WindowsHandle token(raw_token);
    DWORD size = 0;
    GetTokenInformation(token.get(), TokenUser, nullptr, 0, &size);
    if (size == 0) throw windows_error("token_size");
    std::vector<std::uint8_t> buffer(size);
    if (!GetTokenInformation(token.get(), TokenUser, buffer.data(), size, &size))
        throw windows_error("token_user");
    LPWSTR sid = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, &sid))
        throw windows_error("token_sid");
    const std::wstring result = L"D:P(A;;GA;;;" + std::wstring(sid) + L")";
    LocalFree(sid);
    return result;
}
HANDLE create_pipe(const std::wstring& name) {
    if (name.empty() || name.size() > 80 ||
        name.find_first_not_of(L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.") != std::wstring::npos)
        throw std::runtime_error("invalid_pipe_name");
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const auto acl = current_user_acl();
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.c_str(), SDDL_REVISION_1, &descriptor, nullptr))
        throw windows_error("pipe_acl");
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
    const auto path = L"\\\\.\\pipe\\" + name;
    const HANDLE pipe = CreateNamedPipeW(path.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, max_message + 4, max_message + 4, 5000, &security);
    const DWORD error = GetLastError();
    LocalFree(descriptor);
    if (pipe == INVALID_HANDLE_VALUE) {
        SetLastError(error);
        throw windows_error("create_pipe");
    }
    return pipe;
}
}

ControlPipe::ControlPipe(const std::wstring& name) : pipe_(create_pipe(name)) {}
ControlPipe::~ControlPipe() { CancelIoEx(pipe_.get(), nullptr); }

void ControlPipe::accept() {
    WindowsHandle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!event.valid()) throw windows_error("pipe_event");
    OVERLAPPED operation{};
    operation.hEvent = event.get();
    if (!ConnectNamedPipe(pipe_.get(), &operation)) {
        const DWORD error = GetLastError();
        if (error == ERROR_IO_PENDING) {
            if (WaitForSingleObject(event.get(), INFINITE) != WAIT_OBJECT_0)
                throw windows_error("pipe_accept_wait");
            DWORD transferred = 0;
            if (!GetOverlappedResult(pipe_.get(), &operation, &transferred, FALSE))
                throw windows_error("pipe_accept");
        } else if (error != ERROR_PIPE_CONNECTED) {
            throw windows_error("pipe_connect");
        }
    }
    deadline_ = std::chrono::steady_clock::now() + std::chrono::seconds(5);
}

void ControlPipe::transfer(std::span<std::uint8_t> bytes, bool writing) {
    WindowsHandle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!event.valid()) throw windows_error("pipe_event");
    while (!bytes.empty()) {
        OVERLAPPED operation{};
        operation.hEvent = event.get();
        ResetEvent(event.get());
        DWORD transferred = 0;
        const BOOL done = writing
            ? WriteFile(pipe_.get(), bytes.data(), static_cast<DWORD>(bytes.size()), &transferred, &operation)
            : ReadFile(pipe_.get(), bytes.data(), static_cast<DWORD>(bytes.size()), &transferred, &operation);
        if (!done) {
            if (GetLastError() != ERROR_IO_PENDING) throw windows_error("pipe_io");
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline_ - std::chrono::steady_clock::now()).count();
            const auto wait = remaining <= 0 ? WAIT_TIMEOUT
                : WaitForSingleObject(event.get(), static_cast<DWORD>(remaining));
            if (wait != WAIT_OBJECT_0) {
                CancelIoEx(pipe_.get(), &operation);
                GetOverlappedResult(pipe_.get(), &operation, &transferred, TRUE);
                throw std::runtime_error("pipe_io_timeout");
            }
            if (!GetOverlappedResult(pipe_.get(), &operation, &transferred, FALSE))
                throw windows_error("pipe_io_result");
        }
        if (transferred == 0) throw std::runtime_error("pipe_peer_closed");
        bytes = bytes.subspan(transferred);
    }
}

std::string ControlPipe::read() {
    std::array<std::uint8_t, 4> header{};
    transfer(header, false);
    std::uint32_t length = 0;
    for (std::size_t index = 0; index < header.size(); ++index)
        length |= static_cast<std::uint32_t>(header[index]) << (index * 8U);
    if (length == 0 || length > max_message) throw std::runtime_error("control_frame_length_invalid");
    std::vector<std::uint8_t> body(length);
    transfer(body, false);
    return std::string(body.begin(), body.end());
}

void ControlPipe::write(const std::string& text) {
    if (text.empty() || text.size() > max_message) throw std::runtime_error("control_response_too_large");
    std::vector<std::uint8_t> bytes;
    bytes.reserve(text.size() + 4);
    for (std::size_t index = 0; index < 4; ++index)
        bytes.push_back(static_cast<std::uint8_t>((text.size() >> (index * 8U)) & 255U));
    bytes.insert(bytes.end(), text.begin(), text.end());
    transfer(bytes, true);
}

void ControlPipe::await_client_close() {
    WindowsHandle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!event.valid()) throw windows_error("pipe_event");
    OVERLAPPED operation{};
    operation.hEvent = event.get();
    std::uint8_t extra = 0;
    DWORD count = 0;
    BOOL completed = ReadFile(pipe_.get(), &extra, 1, &count, &operation);
    if (!completed && GetLastError() == ERROR_IO_PENDING) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline_ - std::chrono::steady_clock::now()).count();
        const auto wait = remaining <= 0 ? WAIT_TIMEOUT
            : WaitForSingleObject(event.get(), static_cast<DWORD>(remaining));
        if (wait != WAIT_OBJECT_0) {
            CancelIoEx(pipe_.get(), &operation);
            GetOverlappedResult(pipe_.get(), &operation, &count, TRUE);
            throw std::runtime_error("control_client_close_timeout");
        }
        completed = GetOverlappedResult(pipe_.get(), &operation, &count, FALSE);
    }
    if (!completed && GetLastError() == ERROR_BROKEN_PIPE) return;
    if (!completed) throw windows_error("pipe_drain");
    throw std::runtime_error("control_one_request_per_connection");
}

void ControlPipe::disconnect() {
    if (!DisconnectNamedPipe(pipe_.get()) && GetLastError() != ERROR_PIPE_NOT_CONNECTED)
        throw windows_error("pipe_disconnect");
}
}
