#pragma once
#include "codec.hpp"
#include "lua_server.hpp"

namespace richnet {
inline std::string lua_bytes(View value) { return {value.begin(), value.end()}; }
inline Bytes lua_bytes(const LuaValue& value) {
    const auto& text = value.get_ref<const std::string&>();
    if (text.size() > 1024U * 1024U) throw CodecError("lua_packet_too_large");
    return {text.begin(), text.end()};
}
inline LuaValue lua_frame(const Frame& frame) {
    return {{"opcode", frame.wire_type}, {"payload", lua_bytes(View(frame.payload))}};
}
inline LuaValue lua_frames(const std::vector<Frame>& frames) {
    auto result = LuaValue::array();
    for (const auto& frame : frames) result.push_back(lua_frame(frame));
    return result;
}
inline std::vector<Frame> lua_frames(const LuaValue& value) {
    if (!value.is_array() || value.size() > 1024) throw CodecError("lua_frames_invalid");
    std::vector<Frame> frames;
    for (const auto& frame : value) {
        const auto& code = frame.at("opcode");
        if (!code.is_number_integer() || code < 0 || code > 0xffffffffULL) throw CodecError("lua_opcode_invalid");
        frames.push_back({code.get<std::uint32_t>(), lua_bytes(frame.at("payload"))});
    }
    return frames;
}
}
