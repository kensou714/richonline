#include "codec.hpp"
#include "lua_policy.hpp"

#include <charconv>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <string_view>

namespace {
using namespace richnet;

std::uint64_t number(std::string_view token, int base = 10) {
    std::uint64_t value = 0;
    const auto result = std::from_chars(token.data(), token.data() + token.size(), value, base);
    if (result.ec != std::errc{} || result.ptr != token.data() + token.size())
        throw CodecError("invalid_integer");
    return value;
}

Bytes unhex(const std::string& token) {
    if (token == "-") return {};
    if (token.size() % 2 != 0) throw CodecError("invalid_hex_length");
    Bytes data;
    data.reserve(token.size() / 2);
    for (std::size_t index = 0; index < token.size(); index += 2)
        data.push_back(static_cast<std::uint8_t>(number(std::string_view(token).substr(index, 2), 16)));
    return data;
}

std::string hex(View data) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (const auto byte : data) output << std::setw(2) << static_cast<unsigned int>(byte);
    return output.str();
}

std::string next(std::istringstream& input) {
    std::string token;
    if (!(input >> std::quoted(token))) throw CodecError("missing_argument");
    return token;
}

Transport transport(std::istringstream& input) {
    const auto name = next(input);
    const auto channel = [&] {
        if (name == "lobby_c2s") return Channel::lobby_c2s;
        if (name == "lobby_s2c") return Channel::lobby_s2c;
        if (name == "game_c2s") return Channel::game_c2s;
        if (name == "game_s2c") return Channel::game_s2c;
        throw CodecError("invalid_channel");
    }();
    const auto token = next(input);
    std::optional<std::int32_t> key;
    if (token != "-") {
        const auto value = number(token);
        if (value > 0x7fffffff) throw CodecError("key_out_of_nonnegative_i32_subset");
        key = static_cast<std::int32_t>(value);
    }
    return {channel, key};
}

void complete(std::istringstream& input) {
    std::string extra;
    if (input >> extra) throw CodecError("unexpected_argument");
}

void run_line(const std::string& line) {
    std::istringstream input(line);
    const auto command = next(input);
    if (command == "frame") {
        const auto link = transport(input);
        const auto packet = unhex(next(input));
        complete(input);
        std::cout << hex(encode_frame(decode_frame(packet, link), link)) << '\n';
    } else if (command == "frame_decode") {
        const auto link = transport(input);
        const auto packet = unhex(next(input));
        complete(input);
        const auto frame = decode_frame(packet, link);
        std::cout << frame.wire_type << ' ' << (frame.payload.empty() ? "-" : hex(frame.payload)) << '\n';
    } else if (command == "frame_encode") {
        const auto link = transport(input);
        const auto wire_type = number(next(input));
        if (wire_type > std::numeric_limits<std::uint32_t>::max()) throw CodecError("wire_type_out_of_u32_range");
        const auto payload = unhex(next(input));
        complete(input);
        std::cout << hex(encode_frame(Frame{static_cast<std::uint32_t>(wire_type), payload}, link)) << '\n';
    } else if (command == "stream") {
        const auto link = transport(input);
        StreamDecoder stream(link);
        std::string chunk;
        while (input >> chunk)
            for (const auto& frame : stream.feed(unhex(chunk)))
                std::cout << hex(encode_frame(frame, link)) << '\n';
        stream.finish();
    } else if (command == "inner_encode") {
        const auto plain = unhex(next(input));
        const auto filler = unhex(next(input));
        complete(input);
        std::cout << hex(encode_inner(plain, filler)) << '\n';
    } else if (command == "inner_decode") {
        const auto encoded = unhex(next(input));
        complete(input);
        std::cout << hex(decode_inner(encoded)) << '\n';
    } else if (command == "envelope") {
        const auto packet = unhex(next(input));
        complete(input);
        const Transport link{Channel::game_c2s, std::nullopt};
        std::cout << hex(encode_frame(encode_envelope(decode_envelope(decode_frame(packet, link))), link)) << '\n';
    } else if (command == "envelope_decode") {
        const auto packet = unhex(next(input));
        complete(input);
        const auto envelope = decode_envelope(decode_frame(packet, Transport{Channel::game_c2s, std::nullopt}));
        std::cout << envelope.inner_type << ' ' << static_cast<int>(envelope.mode) << ' '
                  << (envelope.encoded.empty() ? "-" : hex(envelope.encoded)) << ' ' << hex(envelope.tail) << '\n';
    } else if (command == "policy") {
        const auto path = next(input);
        auto values = next(input);
        complete(input);
        std::vector<std::int64_t> draws;
        std::size_t start = 0;
        do {
            const auto end = values.find(',', start);
            const auto value = number(std::string_view(values).substr(start, end == std::string::npos ? end : end - start));
            if (value > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
                throw CodecError("random_draw_out_of_range");
            draws.push_back(static_cast<std::int64_t>(value));
            if (end == std::string::npos) break;
            start = end + 1;
        } while (true);
        for (const auto& attack : run_policy(path, draws)) std::cout << attack << '\n';
    } else {
        throw CodecError("unknown_command");
    }
}
}

int main() {
    try {
        std::string line;
        while (std::getline(std::cin, line)) {
            if (!line.empty()) run_line(line);
        }
        if (std::cin.bad()) throw richnet::CodecError("stdin_read_failed");
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
