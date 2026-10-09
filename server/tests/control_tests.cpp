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
void check(bool condition,const char* message) {
    if (!condition) throw std::runtime_error(message);
}
std::string utf8(const std::filesystem::path& path) {
    const auto text=path.u8string(); return {text.begin(),text.end()};
}
WindowsHandle log_file(const std::filesystem::path& path) {
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES),nullptr,TRUE};
    WindowsHandle handle(CreateFileW(path.c_str(),GENERIC_WRITE,FILE_SHARE_READ,&security,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr));
    check(handle.valid(),"create child output log"); return handle;
}
class Child {
public:
    Child(const std::filesystem::path& executable,const std::filesystem::path& data,const std::wstring& pipe,
          const std::wstring& options=L"") {
        std::filesystem::create_directories(data.parent_path());
        const auto suffix=std::to_wstring(GetTickCount64());
        auto output=log_file(data.parent_path()/(L"stdout-"+pipe+L"-"+suffix+L".jsonl"));
        auto error=log_file(data.parent_path()/(L"stderr-"+pipe+L"-"+suffix+L".jsonl"));
        SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES),nullptr,TRUE};
        WindowsHandle input(CreateFileW(L"NUL",GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,&security,OPEN_EXISTING,0,nullptr));
        check(input.valid(),"open child stdin");
        STARTUPINFOW startup{}; startup.cb=sizeof(startup); startup.dwFlags=STARTF_USESTDHANDLES;
        startup.hStdInput=input.get(); startup.hStdOutput=output.get(); startup.hStdError=error.get();
        PROCESS_INFORMATION information{};
        auto command=L"\""+executable.wstring()+L"\" --data-dir \""+data.wstring()+L"\" --pipe "+pipe+L" "+options;
        check(CreateProcessW(executable.c_str(),command.data(),nullptr,nullptr,TRUE,CREATE_NO_WINDOW,nullptr,
                             data.parent_path().c_str(),&startup,&information)!=FALSE,"start test child");
        process_.emplace(information.hProcess); WindowsHandle thread(information.hThread); pid_=information.dwProcessId;
    }
    ~Child() {
        if (WaitForSingleObject(process_->get(),0)==WAIT_TIMEOUT) {
            TerminateProcess(process_->get(),99); WaitForSingleObject(process_->get(),5000);
        }
    }
    DWORD pid() const { return pid_; }
    DWORD exit_within(DWORD milliseconds) const {
        check(WaitForSingleObject(process_->get(),milliseconds)==WAIT_OBJECT_0,"child exit timeout");
        DWORD code=0; check(GetExitCodeProcess(process_->get(),&code)!=FALSE,"read child exit code"); return code;
    }
private:
    std::optional<WindowsHandle> process_;
    DWORD pid_{};
};

class Client {
public:
    Client(const std::wstring& pipe,DWORD pid,DWORD wait_ms=7000) {
        const auto end=Clock::now()+std::chrono::milliseconds(wait_ms);
        const auto path=L"\\\\.\\pipe\\"+pipe;
        while (Clock::now()<end) {
            handle_.emplace(CreateFileW(path.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,nullptr));
            if (handle_->valid()) break;
            const DWORD error=GetLastError();
            check(error==ERROR_PIPE_BUSY || error==ERROR_FILE_NOT_FOUND,"unexpected pipe connection failure");
            if (error==ERROR_PIPE_BUSY) WaitNamedPipeW(path.c_str(),100);
            else Sleep(20);
        }
        check(handle_ && handle_->valid(),"connect deadline exceeded");
        ULONG actual=0; check(GetNamedPipeServerProcessId(handle_->get(),&actual)!=FALSE && actual==pid,"test pipe ownership mismatch");
    }
    void send(std::span<const std::uint8_t> bytes) {
        std::vector<std::uint8_t> writable(bytes.begin(),bytes.end()); transfer(writable,true);
    }
    void header(std::uint32_t size) {
        std::array<std::uint8_t,4> bytes{};
        for (std::size_t i=0;i<4;++i) bytes[i]=static_cast<std::uint8_t>(size>>(i*8));
        send(bytes);
    }
    void text(const std::string& raw) {
        header(static_cast<std::uint32_t>(raw.size()));
        send({reinterpret_cast<const std::uint8_t*>(raw.data()),raw.size()});
    }
    Json receive() {
        std::array<std::uint8_t,4> header_bytes{}; transfer(header_bytes,false);
        std::uint32_t size=0;
        for (std::size_t i=0;i<4;++i) size|=static_cast<std::uint32_t>(header_bytes[i])<<(i*8);
        check(size>0 && size<=65536,"response length invalid");
        std::vector<std::uint8_t> body(size); transfer(body,false);
        return Json::parse(body.begin(),body.end());
    }
private:
    void transfer(std::span<std::uint8_t> bytes,bool writing) {
        const auto deadline=Clock::now()+std::chrono::seconds(8);
        WindowsHandle event(CreateEventW(nullptr,TRUE,FALSE,nullptr)); check(event.valid(),"create IO event");
        while (!bytes.empty()) {
            OVERLAPPED operation{}; operation.hEvent=event.get(); ResetEvent(event.get());
            DWORD transferred=0;
            const BOOL complete=writing?WriteFile(handle_->get(),bytes.data(),static_cast<DWORD>(bytes.size()),&transferred,&operation)
                :ReadFile(handle_->get(),bytes.data(),static_cast<DWORD>(bytes.size()),&transferred,&operation);
            if (!complete) {
                check(GetLastError()==ERROR_IO_PENDING,"pipe IO failed");
                const auto remaining=std::chrono::duration_cast<std::chrono::milliseconds>(deadline-Clock::now()).count();
                if (remaining<=0 || WaitForSingleObject(event.get(),static_cast<DWORD>(remaining))!=WAIT_OBJECT_0) {
                    CancelIoEx(handle_->get(),&operation); GetOverlappedResult(handle_->get(),&operation,&transferred,TRUE);
                    throw std::runtime_error("test pipe IO timeout");
                }
                check(GetOverlappedResult(handle_->get(),&operation,&transferred,FALSE)!=FALSE,"pipe IO completion failed");
            }
            check(transferred>0,"pipe unexpectedly closed"); bytes=bytes.subspan(transferred);
        }
    }
    std::optional<WindowsHandle> handle_;
};

Json request(const std::wstring& pipe,DWORD pid,const std::string& command) {
    Client client(pipe,pid);
    client.text(Json{{"version",1},{"requestId","integration"},{"command",command},{"payload",Json::object()}}.dump());
    auto response=client.receive();
    check(response.at("requestId")=="integration" && response.at("version")==1,"response correlation invalid");
    return response;
}
void status(const std::wstring& pipe,DWORD pid,const char* profile="richonline") {
    const auto response=request(pipe,pid,"status");
    check(response.at("ok")==true,"status rejected");
    check(response.at("result").at("pid")==pid,"status PID mismatch");
    check(response.at("result").at("gameReady")==false,"unimplemented gameplay advertised ready");
    check(response.at("result").at("protocolVersion")==1,"status protocol version mismatch");
    check(response.at("result").at("clientProfile")==profile,"status client profile mismatch");
}
void error(const Json& response,const char* code) {
    check(response.at("ok")==false && response.at("error").at("code")==code,"unexpected protocol error");
}
void write_original_bootstrap(const std::filesystem::path& directory, bool auxiliary = false) {
    Json config{{"version",1},{"client_profile","original"},
        {"provenance","Synthetic control lifecycle fixture; not production protocol defaults."},
        {"room_id",3},{"game_capacity",8},{"player_capacity",100},{"item_grid_count",32},{"item_per_space",2},
        {"stage_progress_hex","01010200"},{"setting_text","4096"},{"tutorial_dismissal_mask",14},
        {"network",{{"bind_host","127.0.0.1"},{"lobby_port",0}}}};
    if (auxiliary) config["network"]["auxiliary"] = {{"advertised_host","127.0.0.1"},{"http_port",0},{"black_port",0}};
    for (const auto& [key,size] : std::initializer_list<std::pair<const char*,std::size_t>>{
        {"room_template_hex",220},{"role_template_hex",208},{"profile_template_hex",268},
        {"login_template_hex",16},{"identity_template_hex",16},{"bank_template_hex",32},{"completion_template_hex",28}})
        config[key] = std::string(size*2,'a');
    config["bank_template_hex"] = "1616161616161616000000000000594000000000000059400000000000408f40";
    constexpr std::string_view source = __FILE__;
    const auto options = (std::filesystem::path(std::u8string(source.begin(),source.end())).parent_path().parent_path().parent_path()/"Data"/"Option.kpd").u8string();
    config["client_options_path"] = std::string(options.begin(),options.end());
    std::ofstream output(directory/L"lobby-bootstrap.json",std::ios::binary);
    output << config.dump(); check(output.good(),"original control fixture write failed");
}
}

int wmain(int argc,wchar_t** argv) {
    try {
        check(argc==2,"usage: control_tests server.exe");
        const auto executable=std::filesystem::absolute(argv[1]);
        const auto unique=std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64());
        const auto root=std::filesystem::absolute(L"control-test-"+unique);
        const auto directory=root/L"tempdata";
        const auto pipe=L"richonline-control-test-"+unique;
        std::cout<<"Isolated artifacts: "<<utf8(root)<<std::endl;
        Child child(executable,directory,pipe);
        status(pipe,child.pid());
        std::cout<<"PASS status identity and experimental readiness\n";
        { Client client(pipe,child.pid()); client.text("{"); error(client.receive(),"control_json_invalid"); }
        for (const std::uint32_t size:{0U,65537U}) {
            Client client(pipe,child.pid()); client.header(size); error(client.receive(),"control_frame_length_invalid");
        }
        error(request(pipe,child.pid(),"unsupported.command"),"command_unknown");
        std::cout<<"PASS malformed JSON, bounded lengths, unknown command\n";
        {
            Client client(pipe,child.pid()); client.header(32);
            const std::array<std::uint8_t,2> partial{'{','"'}; client.send(partial);
        }
        status(pipe,child.pid());
        std::cout<<"PASS disconnected partial-frame recovery\n";
        {
            Child duplicate(executable,directory,pipe+L"-duplicate");
            check(duplicate.exit_within(5000)!=0,"second writer accepted same data directory");
        }
        status(pipe,child.pid());
        std::cout<<"PASS exclusive data directory lock\n";
        {
            Client held(pipe,child.pid());
            held.text(Json{{"version",1},{"requestId","held"},{"command","status"},{"payload",Json::object()}}.dump());
            check(held.receive().at("ok")==true,"held-client response failed");
            const auto start=Clock::now();
            status(pipe,child.pid());
            check(Clock::now()-start>=std::chrono::seconds(4),"held client was not kept until timeout");
        }
        std::cout<<"PASS five-second client-close timeout recovery\n";
        const auto stopped=request(pipe,child.pid(),"stop");
        check(stopped.at("ok")==true && stopped.at("result").at("stopping")==true,"stop response invalid");
        check(child.exit_within(5000)==0,"normal stop returned failure");
        std::cout<<"PASS stop acknowledgement and clean process exit\n";
        const auto original_directory=root/L"original-data";
        {
            Child original(executable,original_directory,pipe+L"-original",L"--client-profile original");
            status(pipe+L"-original",original.pid(),"original");
            request(pipe+L"-original",original.pid(),"stop");
            check(original.exit_within(5000)==0,"original clean stop");
        }
        write_original_bootstrap(original_directory);
        {
            Child reopened(executable,original_directory,pipe+L"-reopened",L"--client-profile original");
            status(pipe+L"-reopened",reopened.pid(),"original");
            const auto listener=request(pipe+L"-reopened",reopened.pid(),"status").at("result");
            check(listener.at("lobbyReady")==true && listener.at("lobbyPort")>0 &&
                listener.at("httpReady")==false && listener.at("blackReady")==false,
                "original configured listener readiness incorrect");
            request(pipe+L"-reopened",reopened.pid(),"stop");
            check(reopened.exit_within(5000)==0,"original reopen clean stop");
        }
        write_original_bootstrap(original_directory,true);
        {
            Child enabled(executable,original_directory,pipe+L"-auxiliary",L"--client-profile original");
            const auto listeners=request(pipe+L"-auxiliary",enabled.pid(),"status").at("result");
            check(listeners.at("lobbyReady")==true && listeners.at("httpReady")==true && listeners.at("blackReady")==true &&
                listeners.at("httpPort")>0 && listeners.at("blackPort")>0 && listeners.at("gameReady")==false,
                "original auxiliary executable readiness incorrect");
            request(pipe+L"-auxiliary",enabled.pid(),"stop");
            check(enabled.exit_within(5000)==0,"original auxiliary clean stop");
        }
        {
            Child mismatch(executable,original_directory,pipe+L"-mismatch");
            check(mismatch.exit_within(5000)!=0,"profile mismatch accepted");
            Child invalid(executable,root/L"invalid-data",pipe+L"-invalid",L"--client-profile invalid");
            check(invalid.exit_within(5000)!=0,"invalid profile accepted");
            Child adoption(executable,root/L"adoption-data",pipe+L"-adoption",L"--client-profile original --adopt-client-profile richonline");
            check(adoption.exit_within(5000)!=0,"conflicting adoption accepted");
        }
        std::cout<<"PASS original profile status, configured listener, reopen, mismatch, and invalid CLI rejection\n";
        return 0;
    } catch (const std::exception& failure) {
        std::cerr<<"FAIL "<<failure.what()<<'\n'; return 1;
    }
}
