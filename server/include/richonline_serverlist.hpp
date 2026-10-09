#pragma once
#include "channel_catalog.hpp"
#include "codec.hpp"

namespace richnet {
struct RichonlineServerLabel {
    std::uint32_t server_id,channel_id;
    Bytes name_big5;
    bool operator==(const RichonlineServerLabel&) const=default;
};
std::vector<RichonlineServerLabel> parse_richonline_serverlist(View text);
std::vector<RichonlineServerLabel> decode_richonline_serverlist(View packed);
// Emits the existing client resource format. The additive byte is explicit;
// callers can preserve it from the original resource, without touching it.
Bytes encode_richonline_serverlist(const ChannelCatalog& channels,std::uint32_t server_id,std::uint8_t additive_byte);
void validate_richonline_serverlist(View packed,const ChannelCatalog& channels,std::uint32_t server_id);
}
