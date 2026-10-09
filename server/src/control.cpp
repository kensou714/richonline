#include "control.hpp"
#include "control_pipe.hpp"
#include "storage.hpp"
#include "lobby_runtime.hpp"
#include "richonline_boss_runtime.hpp"
#include "diagnostic_log.hpp"
#include <chrono>

namespace richnet {
namespace {
using Json = nlohmann::json;
std::string utf8_path(const std::filesystem::path& path) {
    const auto encoded = path.u8string();
    return std::string(encoded.begin(), encoded.end());
}
Json request_fields(const std::string& raw) {
    Json request = Json::parse(raw, nullptr, false);
    if (request.is_discarded() || !request.is_object()) throw std::runtime_error("control_json_invalid");
    if (!request.contains("version") || request.at("version") != 1 ||
        !request.contains("requestId") || !request.at("requestId").is_string() ||
        !request.contains("command") || !request.at("command").is_string() ||
        !request.contains("payload") || !request.at("payload").is_object())
        throw std::runtime_error("control_request_invalid");
    const auto& id = request.at("requestId").get_ref<const std::string&>();
    const auto& command = request.at("command").get_ref<const std::string&>();
    if (id.empty() || id.size() > 128 || command.empty() || command.size() > 64 ||
        command.find_first_not_of("abcdefghijklmnopqrstuvwxyz._") != std::string::npos)
        throw std::runtime_error("control_request_invalid");
    return request;
}
}

void run_control(const std::filesystem::path& directory, const std::wstring& pipe_name, const ControlLog& sink,
                 ClientProfile profile, bool adopt_untagged_profile) {
    const auto log=nonthrowing_diagnostic_log(sink);
    const auto absolute = std::filesystem::absolute(directory).lexically_normal();
    std::filesystem::create_directories(absolute);
    const auto lock_path = absolute / L"server.lock";
    WindowsHandle lock(CreateFileW(lock_path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                    OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!lock.valid()) throw windows_error("data_directory_locked");
    Storage storage(absolute / L"richonline.sqlite3", profile, adopt_untagged_profile);
    const auto bootstrap = absolute / L"lobby-bootstrap.json";
    LobbyRuntime listeners(storage, bootstrap, log, load_richonline_boss_runtime(storage, bootstrap, log));
    ControlPipe pipe(pipe_name);
    const std::string instance = std::to_string(GetCurrentProcessId()) + "-" + std::to_string(
        std::chrono::steady_clock::now().time_since_epoch().count());
    const Json state{{"pid", GetCurrentProcessId()}, {"instanceId", instance}, {"protocolVersion", 1},
        {"dataDirectory", utf8_path(absolute)}, {"clientProfile", client_profile_name(profile)},
        {"gameReady", false}, {"state", "running"},
        {"capabilities", {"accounts.list", "accounts.create", "accounts.update", "config.get", "config.update", "database.backup", "stop"}}};
    Json ready = state;
    ready.update(listeners.status());
    ready["pipe"] = std::string(pipe_name.begin(), pipe_name.end());
    log("ready", ready);
    bool stopping = false;
    while (!stopping) {
        pipe.accept();
        std::string id;
        std::string command;
        try {
            const auto request = request_fields(pipe.read());
            id = request.at("requestId").get<std::string>();
            command = request.at("command").get<std::string>();
            Json result;
            if (command == "status") { result = state; result.update(listeners.status()); }
            else if (command == "stop") result = {{"stopping", true}};
            else result = storage.dispatch(command, request.at("payload"));
            pipe.write(Json{{"version", 1}, {"requestId", id}, {"ok", true}, {"result", result}}.dump());
            stopping = command == "stop";
            log("control_completed", {{"command", command}});
        } catch (const nlohmann::json::exception&) {
            const Json error{{"code", "control_payload_invalid"}, {"message", "control_payload_invalid"}};
            log("control_failed", {{"command", command}, {"code", "control_payload_invalid"}, {"level", "warning"}});
            try { pipe.write(Json{{"version", 1}, {"requestId", id}, {"ok", false}, {"error", error}}.dump()); }
            catch (const std::exception& failure) { log("control_reply_failed", {{"reason", failure.what()}, {"level", "warning"}}); }
        } catch (const std::exception& failure) {
            const std::string reason = failure.what();
            log("control_failed", {{"command", command}, {"code", reason}, {"level", "warning"}});
            try { pipe.write(Json{{"version", 1}, {"requestId", id}, {"ok", false},
                {"error", {{"code", reason}, {"message", reason}}}}.dump()); }
            catch (const std::exception& reply) { log("control_reply_failed", {{"reason", reply.what()}, {"level", "warning"}}); }
        }
        try { pipe.await_client_close(); }
        catch (const std::exception& drain) {
            log("control_client_close_failed", {{"reason", drain.what()}, {"level", "warning"}});
        }
        pipe.disconnect();
    }
    listeners.stop();
    log("stopped", {{"instanceId", instance}});
}
}
