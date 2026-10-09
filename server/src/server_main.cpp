#include "control.hpp"
#include "storage.hpp"
#include <windows.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <mutex>
#include <sstream>

namespace {
using Json = nlohmann::json;
std::string timestamp() {
    SYSTEMTIME now{};
    GetSystemTime(&now);
    std::ostringstream result;
    result << std::setfill('0') << std::setw(4) << now.wYear << '-' << std::setw(2) << now.wMonth << '-'
           << std::setw(2) << now.wDay << 'T' << std::setw(2) << now.wHour << ':' << std::setw(2) << now.wMinute
           << ':' << std::setw(2) << now.wSecond << '.' << std::setw(3) << now.wMilliseconds << 'Z';
    return result.str();
}
}

int wmain(int argc, wchar_t** argv) {
    try {
        std::filesystem::path directory;
        std::filesystem::path source;
        std::wstring pipe_name;
        auto profile = richnet::ClientProfile::richonline;
        std::optional<richnet::ClientProfile> adoption;
        for (int index = 1; index < argc; index += 2) {
            if (index + 1 >= argc) throw std::runtime_error("option_value_missing");
            const std::wstring option(argv[index]);
            if (option == L"--data-dir") directory = argv[index + 1];
            else if (option == L"--pipe") pipe_name = argv[index + 1];
            else if (option == L"--import-db") source = argv[index + 1];
            else if (option == L"--client-profile" || option == L"--adopt-client-profile") {
                const std::wstring value(argv[index + 1]);
                const auto parsed = richnet::parse_client_profile(std::string(value.begin(), value.end()));
                if (option == L"--client-profile") profile = parsed;
                else adoption = parsed;
            }
            else throw std::runtime_error("option_unknown");
        }
        if (directory.empty() || !directory.is_absolute()) throw std::runtime_error("absolute_data_directory_required");
        if (adoption && *adoption != profile) throw std::runtime_error("client_profile_adoption_mismatch");
        if (!source.empty()) {
            if (adoption) throw std::runtime_error("import_cannot_adopt_profile");
            if (!pipe_name.empty()) throw std::runtime_error("import_cannot_start_service");
            std::filesystem::create_directories(directory);
            const auto destination = richnet::Storage::import_database(source, directory / L"richonline.sqlite3");
            const auto encoded = destination.u8string();
            std::cout << Json{{"event", "database_imported"}, {"path", std::string(encoded.begin(), encoded.end())}}.dump() << std::endl;
            return 0;
        }
        if (pipe_name.empty()) throw std::runtime_error("pipe_name_required");
        std::filesystem::create_directories(directory / L"logs");
        const auto filename = L"native-" + std::to_wstring(GetCurrentProcessId()) + L".jsonl";
        std::ofstream logfile(directory / L"logs" / filename, std::ios::app | std::ios::binary);
        if (!logfile) throw std::runtime_error("log_open_failed");
        std::mutex log_mutex;
        richnet::run_control(directory, pipe_name, [&](const std::string& event, const Json& details) {
            Json entry = details;
            entry["event"] = event;
            entry["timestamp"] = timestamp();
            if (!entry.contains("level")) entry["level"] = "info";
            const auto line = entry.dump();
            const std::lock_guard guard(log_mutex);
            logfile << line << '\n';
            logfile.flush();
            if (!logfile) throw std::runtime_error("log_write_failed");
            std::cout << line << std::endl;
        }, profile, adoption.has_value());
        return 0;
    } catch (const std::exception& error) {
        std::cerr << Json{{"timestamp", timestamp()}, {"level", "error"}, {"event", "startup_or_runtime_failed"},
                         {"reason", error.what()}}.dump() << std::endl;
        return 1;
    }
}
