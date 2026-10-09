#include "auxiliary_internal.hpp"
#include "richonline_auxiliary.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cmath>
#include <iomanip>
#include <limits>
#include <locale>
#include <sstream>

namespace richnet::auxiliary_detail {
namespace {
Response http_response(unsigned status, std::string_view label, const std::string& body,
                       std::string_view reason) {
    const auto header = "HTTP/1.1 " + std::to_string(status) + " " + std::string(label) +
        "\r\nContent-Type: text/plain; charset=Big5\r\nContent-Length: " +
        std::to_string(body.size()) + "\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n";
    Bytes bytes(header.begin(), header.end());
    bytes.insert(bytes.end(), body.begin(), body.end());
    return {std::move(bytes), reason, std::nullopt};
}

std::string channel_name_big5(const std::string& name) {
    if (name.empty() || name.size() > 512 || name.find_first_of("\r\n[]=\0", 0, 6) != std::string::npos)
        throw CodecError("auxiliary_channel_name_invalid");
    const auto size = static_cast<int>(name.size());
    const auto wide_size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name.data(), size, nullptr, 0);
    if (wide_size == 0) throw CodecError("auxiliary_channel_name_invalid_utf8");
    std::wstring wide(static_cast<std::size_t>(wide_size), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name.data(), size, wide.data(), wide_size) != wide_size)
        throw CodecError("auxiliary_channel_name_decode_failed");
    BOOL replaced = FALSE;
    const auto encoded_size = WideCharToMultiByte(950, WC_NO_BEST_FIT_CHARS, wide.data(), wide_size, nullptr, 0, nullptr, &replaced);
    if (encoded_size == 0 || encoded_size > 127 || replaced)
        throw CodecError("auxiliary_channel_name_not_big5");
    std::string encoded(static_cast<std::size_t>(encoded_size), '\0');
    if (WideCharToMultiByte(950, WC_NO_BEST_FIT_CHARS, wide.data(), wide_size, encoded.data(), encoded_size, nullptr, &replaced) != encoded_size || replaced)
        throw CodecError("auxiliary_channel_name_encode_failed");
    return encoded;
}

std::string bootstrap_document(const AuxiliaryOptions& options) {
    static constexpr std::array types{"CHU", "ZHONG", "GAO", "XIN"};
    if (!options.channels.empty()) {
        if (options.channels.size() > 256) throw CodecError("auxiliary_channel_count_invalid");
        std::ostringstream body;
        body.imbue(std::locale::classic());
        body << std::setprecision(std::numeric_limits<double>::max_digits10)
             << "[area]\nareasum=1\n[area0]\nchannelsum=" << options.channels.size() << '\n';
        for (std::size_t index = 0; index < options.channels.size(); ++index) {
            const auto& channel = options.channels[index];
            if (channel.key != index || channel.lobby_type >= types.size() || channel.player_capacity == 0 ||
                channel.player_capacity > static_cast<std::uint32_t>(std::numeric_limits<int>::max()) ||
                !std::isfinite(channel.min_gold) || !std::isfinite(channel.max_gold) ||
                channel.min_gold < 0 || channel.max_gold < channel.min_gold || channel.max_level < channel.min_level ||
                channel.max_level > static_cast<std::uint32_t>(std::numeric_limits<int>::max()) ||
                channel.status > static_cast<std::uint32_t>(std::numeric_limits<int>::max()))
                throw CodecError("auxiliary_channel_catalog_invalid");
            const auto players = options.channel_players ? options.channel_players(channel.key) : 0;
            if (players > static_cast<std::uint32_t>(std::numeric_limits<int>::max()))
                throw CodecError("auxiliary_channel_population_invalid");
            body << "[channel0_" << index << "]\nLobbyName=" << channel_name_big5(channel.name_utf8)
                 << "\nMaxPlayerNum=" << channel.player_capacity << "\nNowPlayerNum=" << players
                 << "\nIPAddress=" << options.advertised_host << "\nPort=" << options.lobby_port
                 << "\nLobbyStatus=" << channel.status << "\nJDMin=" << channel.min_gold << "\nJDMax=" << channel.max_gold
                 << "\nLvMin=" << channel.min_level << "\nLvMax=" << channel.max_level
                 << "\nChannelID=" << channel.key << "\nLobbyType=" << types[channel.lobby_type] << '\n';
        }
        return body.str();
    }
    const auto players = options.current_players ? options.current_players() : 0;
    std::ostringstream body;
    body << "[area]\nareasum=1\n[area0]\nchannelsum=1\n[channel0_0]\nLobbyName=Local\n"
         << "MaxPlayerNum=" << options.capacity << "\nNowPlayerNum=" << players
         << "\nIPAddress=" << options.advertised_host << "\nPort=" << options.lobby_port
         << "\nLobbyStatus=1\nJDMin=0\nJDMax=999999999\nLvMin=0\nLvMax=999\nChannelID="
         << options.channel_id << '\n';
    if (options.lobby_type) body << "LobbyType=" << *options.lobby_type << '\n';
    return body.str();
}

std::optional<Response> http(View input, const AuxiliaryOptions& options) {
    const std::string request(input.begin(), input.end());
    if (request.find("\r\n\r\n") == std::string::npos) return std::nullopt;
    const auto line_end = request.find("\r\n");
    const auto first_space = request.find(' ');
    const auto second_space = request.find(' ', first_space == std::string::npos ? 0 : first_space + 1);
    if (first_space == std::string::npos || second_space == std::string::npos || second_space >= line_end)
        return http_response(400, "Bad Request", "bad_request\n", "invalid_http_request_line");
    const auto version = request.substr(second_space + 1, line_end - second_space - 1);
    if (version != "HTTP/1.0" && version != "HTTP/1.1")
        return http_response(400, "Bad Request", "bad_request\n", "unsupported_http_version");
    if (request.substr(0, first_space) != "GET")
        return http_response(405, "Method Not Allowed", "method_not_allowed\n", "http_method_unsupported");
    const auto target = request.substr(first_space + 1, second_space - first_space - 1);
    const auto path = target.substr(0, target.find('?'));
    if (path != "/gameinfo/RichNetLogin.txt" && path != "/gameinfo/RichNetServer.txt")
        return http_response(404, "Not Found", "not_found\n", "http_route_not_found");
    return http_response(200, "OK", bootstrap_document(options), "configured_channel_list");
}

std::optional<Response> black(View input, const AuxiliaryOptions& options) {
    if (input.size() < 10) return std::nullopt;
    if (input[0] != 13 || input[1] != 10) throw CodecError("black_invalid_magic");
    const auto type = read_le(input.subspan(2, 4));
    const auto length = read_le(input.subspan(6, 4));
    if (type > (options.black_response ? 4U : 3U)) throw CodecError("black_type_unsupported");
    const auto expected = type == 4 ? 97U : (type == 1 || type == 2 ? 96U : 64U);
    if (length != expected) throw CodecError("black_invalid_payload_length");
    if (input.size() < 10 + length) return std::nullopt;
    if (input.size() != 10 + length) throw CodecError("black_unexpected_trailing_bytes");
    if (options.black_response)
        return Response{options.black_response(input), type == 4 ? "original_blacklist_flag_saved_no_reply" : "original_blacklist_completed", type};
    if (type != 0) throw CodecError("black_operation_not_implemented");
    // No blacklist mutations exist in this service. Its dataset is actually empty.
    // 0x858FB0 branches on name[0] before reading flag; the terminator's other bytes are unused.
    Bytes bytes{13, 10};
    append_le(bytes, 0, 4);
    append_le(bytes, 33, 4);
    bytes.resize(43, 0);
    return Response{std::move(bytes), "empty_blacklist_terminator_auth_not_asserted", type};
}
}

std::optional<Response> response(AuxiliaryKind kind, View input, const AuxiliaryOptions& options) {
    switch (kind) {
        case AuxiliaryKind::http: return http(input, options);
        case AuxiliaryKind::black: return black(input, options);
        case AuxiliaryKind::intro: {
            if (!decode_richonline_intro_request(input)) return std::nullopt;
            if (!options.intro_response) throw CodecError("intro_provider_unavailable");
            auto result = options.intro_response(input);
            if (!result) throw CodecError("intro_provider_incomplete_response");
            const View bytes(*result);
            if (bytes.size() < 40 || bytes.size() > 440 || read_le(bytes.first(4)) != 0 ||
                read_le(bytes.subspan(4, 4)) != bytes.size() - 8)
                throw CodecError("intro_provider_invalid_response");
            return Response{std::move(*result), "richonline_introduction_loaded", 0};
        }
        case AuxiliaryKind::inquiry: {
            const auto request = decode_richonline_inquiry_request(input);
            if (!request) return std::nullopt;
            if (!options.inquiry_response) throw CodecError("inquiry_provider_unavailable");
            auto result = options.inquiry_response(input);
            if (!result) throw CodecError("inquiry_provider_incomplete_response");
            const View bytes(*result);
            const auto type = static_cast<std::uint32_t>(request->type);
            constexpr std::array<std::size_t,3> minimum{44,4,4};
            constexpr std::array<std::size_t,3> maximum{3644,4404,4};
            if (bytes.size() < 8+minimum[type] || bytes.size() > 8+maximum[type] ||
                read_le(bytes.first(4)) != type || read_le(bytes.subspan(4,4)) != bytes.size()-8)
                throw CodecError("inquiry_provider_invalid_response");
            if (type < 2) {
                const std::size_t count_offset = type == 0 ? 48U : 8U;
                const std::size_t record_size = type == 0 ? 36U : 44U;
                const auto count = read_le(bytes.subspan(count_offset,4));
                if (count > 100 || bytes.size() != 8+minimum[type]+record_size*count)
                    throw CodecError("inquiry_provider_invalid_row_count");
            }
            return Response{std::move(*result), "richonline_ranking_loaded", type};
        }
    }
    throw CodecError("auxiliary_kind_invalid");
}
}
