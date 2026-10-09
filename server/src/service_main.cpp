#include "service.hpp"

#include <charconv>
#include <iostream>
#include <string>

namespace {
std::uint16_t port_from(const char* value) {
    unsigned int parsed = 0;
    const std::string text(value);
    const auto result = std::from_chars(text.data(), text.data() + text.size(), parsed);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size() || parsed > 65535U)
        throw std::runtime_error("invalid_port");
    return static_cast<std::uint16_t>(parsed);
}
}

int main(int argc, char** argv) {
    try {
        richnet::ServiceOptions options;
        if (argc != 5 || std::string(argv[1]) != "--port" || std::string(argv[3]) != "--client-version")
            throw std::runtime_error("diagnostic only; usage: richnet_game_service --port PORT --client-version richonline|legacy");
        options.port = port_from(argv[2]);
        const std::string version(argv[4]);
        if (version == "richonline") options.version = richnet::ClientVersion::richonline;
        else if (version == "legacy") options.version = richnet::ClientVersion::legacy;
        else throw std::runtime_error("invalid_client_version");
        richnet::GameService service(options, [] { return richnet::GameCallbacks{}; },
            [](const std::string& message) { std::cout << message << std::endl; });
        service.run();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
