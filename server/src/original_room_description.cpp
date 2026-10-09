#include "original_room_description.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <fstream>
#include <string_view>

namespace richnet {
namespace {
constexpr std::size_t maximum_index_size = 1024U * 1024U;
constexpr std::size_t maximum_maps = 4096;
// S2C5/10 add two DWORDs before the description, plus the eight-byte frame header.
constexpr std::size_t maximum_description_size = max_frame_total - 16U;

std::string ascii_lower(std::string value) {
    for (auto& byte : value) {
        if (byte == '\0' || static_cast<unsigned char>(byte) > 127U)
            throw CodecError("original_map_name_invalid");
        if (byte >= 'A' && byte <= 'Z') byte = static_cast<char>(byte - 'A' + 'a');
    }
    return value;
}

std::array<std::uint8_t, 16> signature(std::string_view encoded) {
    if (encoded.size() != 32) throw CodecError("original_map_signature_invalid");
    const auto nibble = [](char byte) -> std::uint8_t {
        if (byte >= '0' && byte <= '9') return static_cast<std::uint8_t>(byte - '0');
        if (byte >= 'a' && byte <= 'f') return static_cast<std::uint8_t>(byte - 'a' + 10);
        if (byte >= 'A' && byte <= 'F') return static_cast<std::uint8_t>(byte - 'A' + 10);
        throw CodecError("original_map_signature_invalid");
    };
    std::array<std::uint8_t, 16> result;
    for (std::size_t i = 0; i < result.size(); ++i)
        result[i] = static_cast<std::uint8_t>((nibble(encoded[i * 2]) << 4) | nibble(encoded[i * 2 + 1]));
    return result;
}
}

OriginalMapCatalog OriginalMapCatalog::load(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) throw CodecError("original_map_index_open_failed");
    const auto size = file.tellg();
    if (size <= 0 || size > static_cast<std::streamoff>(maximum_index_size))
        throw CodecError("original_map_index_size_invalid");
    std::string text(static_cast<std::size_t>(size), '\0');
    file.seekg(0);
    if (!file.read(text.data(), static_cast<std::streamsize>(text.size())) || file.peek() != std::char_traits<char>::eof())
        throw CodecError("original_map_index_read_failed");
    try {
        const auto records = nlohmann::json::parse(text, [](int depth, nlohmann::json::parse_event_t, nlohmann::json&) {
            if (depth > 16) throw CodecError("original_map_index_depth_invalid");
            return true;
        });
        if (!records.is_array() || records.empty() || records.size() > maximum_maps)
            throw CodecError("original_map_index_records_invalid");
        OriginalMapCatalog catalog;
        for (const auto& record : records) {
            if (!record.is_object() || !record.contains("source") || !record.at("source").is_string() ||
                !record.contains("signature_hex") || !record.at("signature_hex").is_string())
                throw CodecError("original_map_index_record_invalid");
            const auto source = record.at("source").get<std::string>();
            const auto key = ascii_lower(source);
            if (key.size() <= 4 || key.size() > 31 || !key.ends_with(".emp"))
                throw CodecError("original_map_source_invalid");
            const auto alias = key.substr(0, key.size() - 4);
            const Resource resource{source, signature(record.at("signature_hex").get<std::string>())};
            if (!catalog.resources_.emplace(key, resource).second || !catalog.resources_.emplace(alias, resource).second)
                throw CodecError("original_map_index_duplicate");
        }
        return catalog;
    } catch (const nlohmann::json::exception&) {
        throw CodecError("original_map_index_json_invalid");
    }
}

std::string OriginalMapCatalog::validate(View extension) const {
    if (extension.size() < 48) throw CodecError("original_map_extension_missing");
    if (extension.size() > maximum_description_size - 128)
        throw CodecError("original_map_extension_size_invalid");
    const auto name = extension.first(32);
    const auto terminator = std::find(name.begin(), name.end(), std::uint8_t{0});
    if (terminator == name.end() || terminator == name.begin()) throw CodecError("original_map_name_invalid");
    const auto key = ascii_lower(std::string(name.begin(), terminator));
    const auto resource = resources_.find(key);
    if (resource == resources_.end()) throw CodecError("original_map_resource_unknown");
    if (!std::equal(resource->second.signature.begin(), resource->second.signature.end(), extension.begin() + 32))
        throw CodecError("original_map_signature_mismatch");
    return resource->second.source;
}

OriginalGameDescription parse_original_game_description(View data, const OriginalMapCatalog& maps) {
    if (data.size() < 128) throw CodecError("original_game_description_truncated");
    if (data.size() > maximum_description_size) throw CodecError("original_game_description_size_invalid");
    if (read_le(data.subspan(120, 4)) != data.size() - 128)
        throw CodecError("original_game_description_length_mismatch");
    if ((read_le(data.subspan(32, 4)) & 0x40U) == 0) throw CodecError("original_game_extension_flag_missing");
    const auto name = data.first(32);
    if (name.front() == 0 || std::find(name.begin(), name.end(), std::uint8_t{0}) == name.end())
        throw CodecError("original_game_name_invalid");
    const auto minimum = read_le(data.subspan(40, 4));
    const auto maximum = read_le(data.subspan(44, 4));
    if (minimum < 1 || minimum > maximum || maximum > 4)
        throw CodecError("original_game_player_capacity_invalid");
    auto map_name = maps.validate(data.subspan(128));
    Bytes canonical(data.begin(), data.end());
    // G+124 is a process-local extension pointer; client relocation supplies the receiving address.
    std::fill(canonical.begin() + 124, canonical.begin() + 128, std::uint8_t{0});
    return {std::move(canonical), std::move(map_name), maximum};
}
}
