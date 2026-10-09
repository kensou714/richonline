#include "game_admission.hpp"

#include <algorithm>

namespace richnet {
namespace {

std::size_t payload_size(ClientVersion version) {
    // 此处是载荷长度；新版总帧为 32 字节，旧版总帧为 40 字节。
    switch (version) {
    case ClientVersion::legacy: return 32;
    case ClientVersion::richonline: return 24;
    }
    throw CodecError("unsupported_game_admission_version");
}

}

GameAdmission decode_game_admission(const Frame& frame, ClientVersion version) {
    const auto size = payload_size(version);
    if (frame.wire_type != 0) throw CodecError("invalid_game_admission_type");
    if (frame.payload.size() != size) throw CodecError("invalid_game_admission_length");

    const View payload(frame.payload);
    GameAdmission admission;
    admission.id0 = read_le(payload.subspan(0, 4));
    admission.id1 = read_le(payload.subspan(4, 4));
    admission.id2 = read_le(payload.subspan(8, 4));
    const auto opaque = payload.subspan(12, 8);
    std::copy(opaque.begin(), opaque.end(), admission.opaque8.begin());
    admission.field20 = read_le(payload.subspan(20, 4));
    if (version == ClientVersion::legacy) {
        admission.legacy_fields = std::array<std::uint32_t, 2>{
            read_le(payload.subspan(24, 4)), read_le(payload.subspan(28, 4))};
    }
    return admission;
}

Frame encode_game_admission(const GameAdmission& admission, ClientVersion version) {
    const auto size = payload_size(version);
    if (version == ClientVersion::legacy && !admission.legacy_fields)
        throw CodecError("missing_legacy_game_admission_fields");
    if (version == ClientVersion::richonline && admission.legacy_fields)
        throw CodecError("richonline_game_admission_has_legacy_fields");

    Frame frame{0, {}};
    frame.payload.reserve(size);
    append_le(frame.payload, admission.id0, 4);
    append_le(frame.payload, admission.id1, 4);
    append_le(frame.payload, admission.id2, 4);
    frame.payload.insert(frame.payload.end(), admission.opaque8.begin(), admission.opaque8.end());
    append_le(frame.payload, admission.field20, 4);
    if (admission.legacy_fields) {
        for (const auto value : *admission.legacy_fields) append_le(frame.payload, value, 4);
    }
    return frame;
}

}
