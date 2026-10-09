#include "windows_handle.hpp"
#include <nlohmann/json.hpp>
#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace {
using Json = nlohmann::json;
using richnet::WindowsHandle;
using Clock = std::chrono::steady_clock;
void check(bool value,const char* reason) { if (!value) throw std::runtime_error(reason); }
std::string utf8(const std::filesystem::path& path) { const auto bytes = path.u8string(); return {bytes.begin(),bytes.end()}; }
WindowsHandle log_file(const std::filesystem::path& path) {
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES),nullptr,TRUE};
    WindowsHandle result(CreateFileW(path.c_str(),GENERIC_WRITE,FILE_SHARE_READ,&security,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr));
    check(result.valid(),"child_log_create_failed"); return result;
}
struct Child {
    std::optional<WindowsHandle> process;
    DWORD pid = 0;
    std::filesystem::path stderr_path;
    Child(const std::filesystem::path& executable,const std::filesystem::path& data,const std::wstring& pipe)
        : stderr_path(data.parent_path()/(pipe+L"-stderr.jsonl")) {
        auto output = log_file(data.parent_path()/(pipe+L"-stdout.jsonl")); auto error = log_file(stderr_path);
        SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES),nullptr,TRUE};
        WindowsHandle input(CreateFileW(L"NUL",GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,&security,OPEN_EXISTING,0,nullptr));
        check(input.valid(),"child_stdin_open_failed");
        STARTUPINFOW startup{}; startup.cb = sizeof(startup); startup.dwFlags = STARTF_USESTDHANDLES;
        startup.hStdInput = input.get(); startup.hStdOutput = output.get(); startup.hStdError = error.get();
        PROCESS_INFORMATION information{};
        auto command = L"\""+executable.wstring()+L"\" --data-dir \""+data.wstring()+L"\" --pipe "+pipe;
        check(CreateProcessW(executable.c_str(),command.data(),nullptr,nullptr,TRUE,CREATE_NO_WINDOW,nullptr,
            data.parent_path().c_str(),&startup,&information) != FALSE,"child_start_failed");
        process.emplace(information.hProcess); WindowsHandle thread(information.hThread); pid = information.dwProcessId;
    }
    ~Child() {
        if (WaitForSingleObject(process->get(),0) == WAIT_TIMEOUT) {
            TerminateProcess(process->get(),99); WaitForSingleObject(process->get(),5000);
        }
    }
    DWORD exit_within(DWORD timeout) const {
        check(WaitForSingleObject(process->get(),timeout) == WAIT_OBJECT_0,"child_exit_timeout");
        DWORD status = 0; check(GetExitCodeProcess(process->get(),&status) != FALSE,"child_exit_code_failed"); return status;
    }
};
class Client {
public:
    Client(const std::wstring& pipe,DWORD pid) {
        const auto deadline = Clock::now()+std::chrono::seconds(8);
        const auto path = L"\\\\.\\pipe\\"+pipe;
        while (Clock::now() < deadline) {
            handle_.emplace(CreateFileW(path.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,nullptr));
            if (handle_->valid()) break;
            const auto error = GetLastError();
            check(error == ERROR_PIPE_BUSY || error == ERROR_FILE_NOT_FOUND,"pipe_connect_failed");
            if (error == ERROR_PIPE_BUSY) WaitNamedPipeW(path.c_str(),100); else Sleep(20);
        }
        check(handle_ && handle_->valid(),"pipe_connect_timeout");
        ULONG actual = 0; check(GetNamedPipeServerProcessId(handle_->get(),&actual) != FALSE && actual == pid,"pipe_owner_mismatch");
    }
    Json call(const std::string& command) {
        const auto text = Json{{"version",1},{"requestId","native-boss-control-test"},{"command",command},{"payload",Json::object()}}.dump();
        std::vector<std::uint8_t> bytes(4);
        for (std::size_t i = 0; i < 4; ++i) bytes[i] = static_cast<std::uint8_t>(text.size() >> (8*i));
        bytes.insert(bytes.end(),text.begin(),text.end()); transfer(bytes,true);
        std::array<std::uint8_t,4> prefix{}; transfer(prefix,false);
        std::uint32_t length = 0;
        for (std::size_t i = 0; i < 4; ++i) length |= static_cast<std::uint32_t>(prefix[i]) << (8*i);
        check(length > 0 && length <= 65536,"response_length_invalid");
        bytes.resize(length); transfer(bytes,false);
        const auto result = Json::parse(bytes.begin(),bytes.end());
        check(result.at("version") == 1 && result.at("requestId") == "native-boss-control-test" && result.at("ok") == true,"control_response_invalid");
        return result.at("result");
    }
private:
    void transfer(std::span<std::uint8_t> bytes,bool writing) {
        const auto deadline = Clock::now()+std::chrono::seconds(8);
        WindowsHandle event(CreateEventW(nullptr,TRUE,FALSE,nullptr)); check(event.valid(),"pipe_event_failed");
        while (!bytes.empty()) {
            OVERLAPPED operation{}; operation.hEvent = event.get(); ResetEvent(event.get());
            DWORD count = 0;
            const BOOL ready = writing ? WriteFile(handle_->get(),bytes.data(),static_cast<DWORD>(bytes.size()),&count,&operation)
                : ReadFile(handle_->get(),bytes.data(),static_cast<DWORD>(bytes.size()),&count,&operation);
            if (!ready) {
                check(GetLastError() == ERROR_IO_PENDING,"pipe_io_failed");
                const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline-Clock::now()).count();
                if (remaining <= 0 || WaitForSingleObject(event.get(),static_cast<DWORD>(remaining)) != WAIT_OBJECT_0) {
                    CancelIoEx(handle_->get(),&operation); GetOverlappedResult(handle_->get(),&operation,&count,TRUE);
                    throw std::runtime_error("pipe_io_timeout");
                }
                check(GetOverlappedResult(handle_->get(),&operation,&count,FALSE) != FALSE,"pipe_completion_failed");
            }
            check(count > 0,"pipe_closed_early"); bytes = bytes.subspan(count);
        }
    }
    std::optional<WindowsHandle> handle_;
};
Json configuration(const std::filesystem::path& resources) {
    Json config{{"provenance","Isolated actual control process fixture; no native client or completed gameplay claim."},
        {"game_capacity",8},{"player_capacity",100},{"stage_progress",{1,1,2,0}},{"setting_text","14"},{"room_unknown_prefix",9},
        {"network",{{"bind_host","127.0.0.1"},{"advertised_host","127.0.0.1"},{"lobby_port",0},{"http_port",0},{"black_port",0}}},
        {"richonline_boss_game",{{"version",1},{"provenance","Explicit isolated control runtime configuration."},
            {"client_root",utf8(resources)},{"advertised_ipv4",{127,0,0,1}},{"port",0},{"manager",0},{"admission_ttl_ms",30000},
            {"spawn_policy","resource-straight-road-farthest-v1"},{"token_policy","system-random-echo"},{"filler_policy","system-random-unconsumed"},
            {"wire",{{"provenance","Constructor f64 plus explicit test session values and unread wire bytes."},
                {"game_server_id",0x1234},{"calendar_counter",0x4567},{"year",2026},{"month",10},{"day",9},{"weekday",5},
                {"opaque_f64_hex","000000000000f03f"},{"opaque_header_byte",0xa1},{"opaque_trailing",{0xb1,0xc1}},
                {"synthetic_unconsumed_skill_bytes",{1,2,3,4,5,6,7,8,9,10}},{"envelope",{{"tag",7},{"mode",-2}}}}}}},
        {"richonline_boss_turn_policy",{{"provenance","Control entry test; ordinary movement only and actual landings rejected."},
            {"opaque_turn7",0xa2},{"inactive_ui_dice",{-7,9}},{"opaque20_23",{0xa3,0xb3,0xc3,0xd3}},
            {"optional_tail_hex",""},{"scope","ordinary-movement-unimplemented-landings-rejected"}}}};
    for (const auto& [name,size] : std::initializer_list<std::pair<const char*,std::size_t>>{
        {"unknown_channel_record_hex",80},{"unknown_role_record_hex",208},{"unknown_profile_record_hex",272},
        {"unknown_login_result_hex",16},{"unknown_identity_record_hex",16},{"unknown_empty_list_hex",4},{"unknown_bank_config_hex",32}})
        config[name] = std::string(size*2,'0');
    config["unknown_completion_hex"] = std::string(40,'0')+"000000000000f03f";
    return config;
}
void save(const std::filesystem::path& directory,const Json& config) {
    std::filesystem::create_directories(directory);
    std::ofstream file(directory/L"lobby-bootstrap.json",std::ios::binary); file << config;
    check(file.good(),"fixture_write_failed");
}
bool reported_failure(const std::filesystem::path& path,std::string_view expected) {
    std::ifstream file(path,std::ios::binary); check(file.good(),"child_stderr_unavailable");
    std::string line;
    while (std::getline(file,line)) {
        const auto record = Json::parse(line,nullptr,false);
        if (!record.is_discarded() && record.value("event","") == "startup_or_runtime_failed" && record.value("reason","") == expected)
            return true;
    }
    return false;
}
}
int wmain(int argc,wchar_t** argv) {
    try {
        check(argc == 3,"usage: richonline_control_runtime_tests <server.exe> <Richonline-resource-root>");
        const auto executable = std::filesystem::absolute(argv[1]), resources = std::filesystem::absolute(argv[2]);
        check(std::filesystem::is_regular_file(executable),"server_executable_missing");
        check(std::filesystem::is_regular_file(resources/L"Map"/L"BS_1_1.emp"),"actual_resource_map_missing");
        const auto unique = std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64());
        const auto root = std::filesystem::absolute(L"richonline-control-runtime-"+unique);
        const auto pipe = L"richonline-control-runtime-"+unique;
        const auto complete = configuration(resources);
        std::cout << "Isolated artifacts: " << utf8(root) << std::endl;
        save(root/L"complete",complete);
        {
            Child child(executable,root/L"complete",pipe);
            Json status;
            { Client client(pipe,child.pid); status = client.call("status"); }
            check(status.at("pid") == child.pid && status.at("clientProfile") == "richonline","control_identity_mismatch");
            check(status.at("gameListenerReady") == true && status.at("gamePort") > 0 && status.at("gameReady") == false,
                "configured_game_listener_not_started_or_playability_overclaimed");
            check(status.at("lobbyReady") == true && status.at("httpReady") == true && status.at("blackReady") == true,"auxiliary_listener_not_started");
            { Client client(pipe,child.pid); check(client.call("stop").at("stopping") == true,"stop_ack_missing"); }
            check(child.exit_within(5000) == 0,"complete_configuration_unclean_stop");
        }
        std::cout << "PASS actual control process starts game listener without claiming gameReady, and stops cleanly\n";
        unsigned index = 0;
        for (const auto missing : {"richonline_boss_game","richonline_boss_turn_policy"}) {
            auto partial = complete; partial.erase(missing); ++index;
            const auto directory = root/(L"partial-"+std::to_wstring(index)); save(directory,partial);
            Child child(executable,directory,pipe+L"-partial-"+std::to_wstring(index));
            check(child.exit_within(5000) != 0,"incomplete_game_configuration_silently_accepted");
            check(reported_failure(child.stderr_path,"richonline_boss_runtime_config_incomplete"),"incomplete_configuration_reason_missing");
        }
        std::cout << "PASS either incomplete BOSS configuration fails with explicit startup reason\n";
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
